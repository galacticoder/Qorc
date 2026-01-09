/**
 * Secure Calling Service
 */

import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { PostQuantumKEM } from '../cryptography/kem';
import { PostQuantumHash } from '../cryptography/hash';
import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumSignature } from '../cryptography/signature';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SecureMemory } from '../cryptography/secure-memory';
import { QuicTransport, quicTransport } from './quic-transport';
import { SecureConnection, SecureStream } from './secure-transport';
import { PQNoiseSession } from './pq-noise-session';
import { screenSharingSettings } from '../screen-sharing-settings';
import { X25519KeyPair, PeerKeys } from '../types/noise-types';
import { generateX25519KeyPair } from '../utils/noise-utils';
import websocketClient from '../websocket/websocket';
import {
    CALL_TIMEOUT,
    CALL_RING_TIMEOUT,
    CALL_AUDIO_PADDING_BLOCK,
    CALL_KEY_ROTATION_INTERVAL,
    QualityOption
} from '../constants';
import {
    CallState,
    CallSignal,
    MediaEncryptionContext,
} from '../types/calling-types';

export type { CallState, CallSignal, MediaEncryptionContext };

// Calling Service
export class SecureCallingService {
    private localStream: MediaStream | null = null;
    private remoteStream: MediaStream | null = null;
    private remoteScreenStream: MediaStream | null = null;
    private screenStream: MediaStream | null = null;
    private currentCall: CallState | null = null;
    private isScreenSharing: boolean = false;
    private localUsername: string = '';
    private preferredCameraDeviceId: string | null = null;

    // Transport
    private transport: QuicTransport;
    private callConnection: SecureConnection | null = null;
    private audioStream: SecureStream | null = null;
    private videoStream: SecureStream | null = null;
    private screenShareStream: SecureStream | null = null;

    // Encryption
    private encryptionContext: MediaEncryptionContext | null = null;
    private keyRotationTimer: ReturnType<typeof setInterval> | null = null;

    // PQ keys
    private pqSigningKey: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
    private kyberKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private dilithiumKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private x25519KeyPair: X25519KeyPair | null;

    // Peer keys cache
    private peerKeysCache: Map<string, PeerKeys> = new Map();

    // Callbacks
    private onIncomingCallCallback: ((call: CallState) => void) | null = null;
    private onCallStateChangeCallback: ((call: CallState) => void) | null = null;
    private onRemoteStreamCallback: ((stream: MediaStream | null) => void) | null = null;
    private onRemoteScreenStreamCallback: ((stream: MediaStream | null) => void) | null = null;
    private onLocalStreamCallback: ((stream: MediaStream) => void) | null = null;

    // Timers
    private callTimeoutId: ReturnType<typeof setTimeout> | null = null;
    private ringStartAt: number | null = null;

    private qualityToJpeg(quality: QualityOption): number {
        switch (quality) {
            case 'low': return 0.6;
            case 'medium': return 0.8;
            case 'high': return 0.95;
            default: return 0.8;
        }
    }

    constructor(username: string) {
        this.localUsername = username;
        this.transport = quicTransport;
        this.initializeKeys();
    }

    // Initialize keys
    private async initializeKeys(): Promise<void> {
        // Generate ML-DSA-87 signing key
        if (!this.pqSigningKey) {
            const kp = await PostQuantumSignature.generateKeyPair();
            this.pqSigningKey = {
                publicKey: new Uint8Array(kp.publicKey),
                privateKey: new Uint8Array(kp.secretKey)
            };

            if (!this.dilithiumKeyPair) {
                this.dilithiumKeyPair = {
                    publicKey: new Uint8Array(kp.publicKey),
                    secretKey: new Uint8Array(kp.secretKey)
                };
            }
        }

        // Generate Dilithium key
        if (!this.dilithiumKeyPair) {
            const kp = await PostQuantumSignature.generateKeyPair();
            this.dilithiumKeyPair = {
                publicKey: new Uint8Array(kp.publicKey),
                secretKey: new Uint8Array(kp.secretKey)
            };
        }

        // Generate ML-KEM-1024 key
        if (!this.kyberKeyPair) {
            const kp = PostQuantumKEM.generateKeyPair();
            this.kyberKeyPair = { publicKey: kp.publicKey, secretKey: kp.secretKey };
        }

        // Generate X25519 key
        if (!this.x25519KeyPair) {
            this.x25519KeyPair = generateX25519KeyPair();
        }
    }

    // Initialize calling service
    async initialize(): Promise<void> {
        await this.initializeKeys();

        // Load preferred camera
        try {
            const { encryptedStorage } = await import('../database/encrypted-storage');
            const storedCamera = await encryptedStorage.getItem('preferred_camera_deviceId_v1');
            if (storedCamera && typeof storedCamera === 'string') {
                this.preferredCameraDeviceId = storedCamera;
            }
        } catch { }

        if (typeof window !== 'undefined') {
            window.addEventListener('beforeunload', () => {
                if (this.currentCall && this.currentCall.status !== 'ended') {
                    this.endCall('shutdown').catch(() => { });
                }
            });
        }

        if (typeof window !== 'undefined') {
            window.addEventListener(EventType.CALL_SIGNAL, ((event: CustomEvent<CallSignal>) => {
                this.handleCallSignal(event.detail).catch(console.error);
            }) as EventListener);
        }
    }

    // Set Dilithium keys for signing
    setDilithiumKeys(keys: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
        this.dilithiumKeyPair = keys;
    }

    // Cache peer keys
    setPeerKeys(username: string, keys: PeerKeys): void {
        this.peerKeysCache.set(username, keys);
    }

    // Check if keys are available for a peer
    hasPeerKeys(username: string): boolean {
        return this.peerKeysCache.has(username);
    }

    // Start a call to peer
    async startCall(targetUser: string, callType: 'audio' | 'video' = 'audio'): Promise<string> {
        if (this.currentCall) {
            throw new Error('Another call is already in progress');
        }

        const callId = this.generateCallId();

        this.currentCall = {
            id: callId,
            type: callType,
            direction: 'outgoing',
            status: 'connecting',
            peer: targetUser
        };

        this.ringStartAt = Date.now();
        this.onCallStateChangeCallback?.(this.currentCall);

        try {
            const peerKeys = this.peerKeysCache.get(targetUser);
            if (!peerKeys) { throw new Error(`No keys available for ${targetUser}`); }

            // Set up local media
            const actualCallType = await this.setupLocalMedia(callType);
            this.currentCall.type = actualCallType;

            if (!this.currentCall || this.currentCall.id !== callId) { throw new Error('Call was cancelled'); }

            const pendingConn = (this.transport as any).getConnection?.(targetUser);
            if (pendingConn) { this.callConnection = pendingConn; }

            const role = await this.establishCallConnection(targetUser, peerKeys);

            if (!this.currentCall || (this.currentCall.id !== callId && this.currentCall.peer !== targetUser)) {
                throw new Error('Call was cancelled');
            }

            const activeCallId = this.currentCall.id;

            await this.sendCallSignal({
                type: 'offer',
                callId: activeCallId,
                from: this.localUsername,
                to: targetUser,
                data: { callType: this.currentCall.type },
                timestamp: Date.now()
            });

            this.currentCall.status = 'ringing';
            this.onCallStateChangeCallback?.(this.currentCall);

            this.callTimeoutId = setTimeout(() => {
                if (this.currentCall?.status === 'ringing') {
                    this.endCall('timeout');
                }
            }, CALL_TIMEOUT);

            return activeCallId;

        } catch (error: any) {
            if (this.currentCall?.id === callId) {
                this.endCall('failed');
            }
            throw error;
        }
    }

    // Answer incoming call
    async answerCall(callId: string): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== callId) { throw new Error('No matching incoming call found'); }

        if (this.currentCall.status !== 'ringing') { return; }

        try {
            const peerKeys = this.peerKeysCache.get(this.currentCall.peer);
            if (!peerKeys) {
                throw new Error(`No keys available for ${this.currentCall.peer}`);
            }

            // Set up local media
            await this.setupLocalMedia(this.currentCall.type);

            if (!this.callConnection) {
                await this.establishCallConnection(this.currentCall.peer, peerKeys);
            }

            await this.sendCallSignal({
                type: 'answer',
                callId,
                from: this.localUsername,
                to: this.currentCall.peer,
                data: { accepted: true },
                timestamp: Date.now()
            });

            this.currentCall.status = 'connecting';
            this.onCallStateChangeCallback?.(this.currentCall);

            await this.startMediaStreaming();
            this.markConnected('answer');

        } catch { }
    }

    // Decline incoming call
    async declineCall(callId: string): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== callId) { return; }

        await this.sendCallSignal({
            type: 'decline-call',
            callId,
            from: this.localUsername,
            to: this.currentCall.peer,
            timestamp: Date.now()
        });

        this.currentCall.status = 'declined';
        this.currentCall.endTime = Date.now();
        const start = this.currentCall.startTime ?? this.ringStartAt ?? Date.now();
        this.currentCall.duration = Math.max(0, Date.now() - start);
        this.onCallStateChangeCallback?.(this.currentCall);

        this.cleanup();
    }

    // End the current call
    async endCall(reason: string = 'user'): Promise<void> {
        if (!this.currentCall) { return; }

        if (this.currentCall.status !== 'ended') {
            const endTime = Date.now();
            let duration = 0;
            if (this.currentCall.startTime) {
                duration = endTime - this.currentCall.startTime;
            }

            await this.sendCallSignal({
                type: 'end-call',
                callId: this.currentCall.id,
                from: this.localUsername,
                to: this.currentCall.peer,
                data: { reason, duration },
                timestamp: Date.now()
            });

            this.currentCall.endTime = endTime;
            this.currentCall.duration = duration;
        }

        this.currentCall.status = 'ended';
        this.currentCall.endReason = reason as CallState['endReason'];
        this.onCallStateChangeCallback?.(this.currentCall);

        this.cleanup();
    }

    // Toggle mute state
    toggleMute(): boolean {
        if (!this.localStream) { return false; }

        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;
            return !audioTrack.enabled;
        }
        return false;
    }

    // Toggle video state
    async toggleVideo(): Promise<boolean> {
        if (!this.localStream) { return false; }

        let videoTrack = this.localStream.getVideoTracks()[0];

        if (!videoTrack || videoTrack.readyState === 'ended') {
            try {
                const constraints: MediaStreamConstraints = {
                    video: this.preferredCameraDeviceId
                        ? { deviceId: { exact: this.preferredCameraDeviceId } }
                        : true,
                    audio: false
                };

                const newStream = await navigator.mediaDevices.getUserMedia(constraints);
                videoTrack = newStream.getVideoTracks()[0];

                if (videoTrack) {
                    this.localStream.addTrack(videoTrack);
                    this.onLocalStreamCallback?.(this.localStream);
                }
            } catch (e) {
                return false;
            }
        }

        videoTrack.enabled = !videoTrack.enabled;
        return videoTrack.enabled;
    }

    // Switch camera device
    async switchCamera(deviceId?: string): Promise<void> {
        if (!this.localStream) return;

        const videoTrack = this.localStream.getVideoTracks()[0];
        if (!videoTrack) return;

        try {
            let newStream: MediaStream;

            if (deviceId) {
                newStream = await navigator.mediaDevices.getUserMedia({
                    video: { deviceId: { exact: deviceId } },
                    audio: false
                });
            } else {
                const constraints = videoTrack.getConstraints();
                const newFacingMode = constraints.facingMode === 'user' ? 'environment' : 'user';
                newStream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: newFacingMode },
                    audio: false
                });
            }

            const newVideoTrack = newStream.getVideoTracks()[0];
            this.localStream.removeTrack(videoTrack);
            this.localStream.addTrack(newVideoTrack);
            videoTrack.stop();

            this.onLocalStreamCallback?.(this.localStream);

        } catch { }
    }

    // Switch microphone device
    async switchMicrophone(deviceId: string): Promise<void> {
        if (!this.localStream) return;

        const audioTrack = this.localStream.getAudioTracks()[0];
        if (!audioTrack) return;

        try {
            const newStream = await navigator.mediaDevices.getUserMedia({
                audio: { deviceId: { exact: deviceId } },
                video: false
            });
            const newAudioTrack = newStream.getAudioTracks()[0];

            newAudioTrack.enabled = audioTrack.enabled;
            this.localStream.removeTrack(audioTrack);
            this.localStream.addTrack(newAudioTrack);
            audioTrack.stop();

            this.onLocalStreamCallback?.(this.localStream);

        } catch { }
    }

    // Start screen sharing
    async startScreenShare(selectedSource?: { id: string; name: string; type?: 'screen' | 'window' }): Promise<void> {
        if (!this.callConnection) { throw new Error('No active call'); }
        if (this.isScreenSharing) { throw new Error('Screen sharing already active'); }

        try {
            const settings = await screenSharingSettings.getSettings();
            const resolution = settings.resolution;

            let screenStream: MediaStream;
            if (typeof window !== 'undefined' && (window as any).electronAPI?.getScreenSources) {
                let sourceId = selectedSource?.id;

                if (!sourceId) {
                    const sources = await (window as any).electronAPI.getScreenSources();
                    if (sources && sources.length > 0) {
                        sourceId = sources[0].id;
                    }
                }

                if (!sourceId) { throw new Error('No screen source available'); }

                try {
                    screenStream = await navigator.mediaDevices.getUserMedia({
                        audio: false,
                        video: {
                            mandatory: {
                                chromeMediaSource: 'desktop',
                                chromeMediaSourceId: sourceId,
                                maxWidth: resolution.width,
                                maxHeight: resolution.height,
                                maxFrameRate: 30
                            }
                        }
                    } as any);
                } catch (streamErr) {
                    throw new Error('Failed to capture screen: ' + (streamErr instanceof Error ? streamErr.message : String(streamErr)));
                }
            } else {
                screenStream = await navigator.mediaDevices.getDisplayMedia({
                    video: {
                        width: resolution.width,
                        height: resolution.height,
                        frameRate: 30
                    },
                    audio: false
                });
            }

            this.screenStream = screenStream;
            this.isScreenSharing = true;

            this.screenShareStream = await this.callConnection.createStream({
                type: 'call-screen',
                lossy: true
            });

            await this.sendCallSignal({
                type: 'screen-share-start',
                callId: this.currentCall!.id,
                from: this.localUsername,
                to: this.currentCall!.peer,
                timestamp: Date.now()
            });

            await this.startScreenStreaming();

        } catch (error) {
            throw error;
        }
    }

    // Stop screen sharing
    async stopScreenShare(): Promise<void> {
        if (!this.isScreenSharing || !this.screenStream) {
            return;
        }

        // Stop tracks
        this.screenStream.getTracks().forEach(track => track.stop());
        this.screenStream = null;

        // Close stream
        if (this.screenShareStream) {
            await this.screenShareStream.close();
            this.screenShareStream = null;
        }

        this.isScreenSharing = false;

        if (this.currentCall) {
            await this.sendCallSignal({
                type: 'screen-share-stop',
                callId: this.currentCall.id,
                from: this.localUsername,
                to: this.currentCall.peer,
                timestamp: Date.now()
            });
        }
    }

    // Set up local media capture
    private async setupLocalMedia(callType: 'audio' | 'video'): Promise<'audio' | 'video'> {
        const attempts: Array<{ video: boolean | MediaTrackConstraints; resultingType: 'audio' | 'video'; label: string }> = [];

        if (callType === 'video') {
            if (this.preferredCameraDeviceId) {
                attempts.push({
                    video: { deviceId: { exact: this.preferredCameraDeviceId } },
                    resultingType: 'video',
                    label: 'preferred camera'
                });
            }

            attempts.push({
                video: true,
                resultingType: 'video',
                label: 'any available camera'
            });
        }

        attempts.push({
            video: false,
            resultingType: 'audio',
            label: 'audio-only fallback'
        });

        let lastError: unknown = null;

        for (const attempt of attempts) {
            try {
                this.localStream = await navigator.mediaDevices.getUserMedia({
                    audio: true,
                    video: attempt.video
                });

                this.onLocalStreamCallback?.(this.localStream);
                return attempt.resultingType;

            } catch (error) {
                lastError = error;
                const errorName = (error as Error).name;
                const isDeviceMissing = errorName === 'NotFoundError' || errorName === 'OverconstrainedError';

                if (!isDeviceMissing || attempt.resultingType === 'audio') {
                    throw error;
                }
            }
        }

        throw lastError instanceof Error ? lastError : new Error('Failed to initialize local media');
    }

    // Establish call connection
    private async establishCallConnection(peer: string, peerKeys: PeerKeys): Promise<'initiator' | 'responder'> {
        if (!this.kyberKeyPair || !this.dilithiumKeyPair || !this.x25519KeyPair) {
            throw new Error('Local keys not initialized');
        }

        const peerIdentity = {
            username: peer,
            kyberPublicKey: peerKeys.kyberPublicKey,
            dilithiumPublicKey: peerKeys.dilithiumPublicKey,
            x25519PublicKey: peerKeys.x25519PublicKey
        };
        const effectivePeerIdentity: any = peerIdentity;

        try {
            await this.transport.disconnect(peer);
        } catch {}

        this.callConnection = await this.transport.connect(peer, {
            peerIdentity: effectivePeerIdentity,
            timeout: 30_000
        });

        const effectiveRole = (this.callConnection as any).getEffectiveRole?.() || 'initiator';

        // Setup streams...
        this.audioStream = await this.callConnection.createStream({
            type: 'call-audio',
            lossy: true
        });

        if (this.currentCall?.type === 'video') {
            this.videoStream = await this.callConnection.createStream({
                type: 'call-video',
                lossy: true
            });
        }

        await this.setupMediaEncryption();
        this.startKeyRotation();

        return effectiveRole;
    }

    // Set up media encryption context
    private async setupMediaEncryption(): Promise<void> {
        if (!this.callConnection) return;

        const session = (this.callConnection as any).getSession?.() as PQNoiseSession | null;
        if (!session) {
            throw new Error('No encryption session');
        }

        // Derive per-stream keys from session secret
        const status = session.getStatus();
        if (!status.sendKey || !status.receiveKey) {
            throw new Error('Session keys not ready');
        }

        // Use a initiator send key as base material on both sides
        const baseKeyMaterial = status.role === 'initiator' ? status.sendKey : status.receiveKey;

        const baseKey = PostQuantumHash.deriveKey(
            baseKeyMaterial,
            new TextEncoder().encode('media-encryption-salt-v1'),
            'media-base-key',
            32
        );

        const audioKey = PostQuantumHash.blake3(
            new Uint8Array([...baseKey, ...new TextEncoder().encode('audio')]),
            { dkLen: 32 }
        );

        const videoKey = PostQuantumHash.blake3(
            new Uint8Array([...baseKey, ...new TextEncoder().encode('video')]),
            { dkLen: 32 }
        );

        const screenKey = PostQuantumHash.blake3(
            new Uint8Array([...baseKey, ...new TextEncoder().encode('screen')]),
            { dkLen: 32 }
        );

        this.encryptionContext = {
            session,
            audioKey,
            videoKey,
            screenKey,
            frameCounter: 0n
        };

        SecureMemory.zeroBuffer(baseKey);
    }

    // Start streaming media frames
    private async startMediaStreaming(): Promise<void> {
        if (!this.localStream || !this.encryptionContext) return;

        // Set up audio processing
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            this.startAudioStreaming(audioTrack);
        }

        // Set up video processing
        const videoTrack = this.localStream.getVideoTracks()[0];
        if (videoTrack && this.videoStream) {
            this.startVideoStreaming(videoTrack);
        }

        this.startReceivingMedia();
    }

    // Stream audio frames
    private async startAudioStreaming(track: MediaStreamTrack): Promise<void> {
        if (!this.audioStream || !this.encryptionContext) return;

        const audioContext = new AudioContext();
        await this.loadAudioWorklet(audioContext);

        const source = audioContext.createMediaStreamSource(new MediaStream([track]));

        try {
            const workletNode = new AudioWorkletNode(audioContext, 'audio-sender-processor');

            workletNode.port.onmessage = async (e) => {
                if (!this.encryptionContext || !this.audioStream) return;

                const inputData = e.data;
                const rawData = new Uint8Array(inputData.buffer);

                const paddedLength = Math.ceil(rawData.length / CALL_AUDIO_PADDING_BLOCK) * CALL_AUDIO_PADDING_BLOCK;
                const paddedData = new Uint8Array(paddedLength);
                paddedData.set(rawData);

                // Encrypt frame
                const frameNum = this.encryptionContext.frameCounter;
                this.encryptionContext.frameCounter += 1n;
                const nonce = new Uint8Array(12);
                new DataView(nonce.buffer).setBigUint64(4, frameNum, false);

                const { ciphertext, tag } = PostQuantumAEAD.encrypt(
                    paddedData,
                    this.encryptionContext.audioKey,
                    nonce
                );

                // Build frame
                const frame = new Uint8Array(8 + ciphertext.length + 32);
                new DataView(frame.buffer).setBigUint64(0, BigInt(frameNum), false);
                frame.set(ciphertext, 8);
                frame.set(tag, 8 + ciphertext.length);

                try {
                    await this.audioStream.write(frame);
                } catch { }
            };

            source.connect(workletNode);
            workletNode.connect(audioContext.destination);
        } catch { }
    }

    // Load audio worklet
    private async loadAudioWorklet(context: AudioContext): Promise<void> {
        try {
            await context.audioWorklet.addModule('audio-worklet-processor.js');
        } catch (error) {
            console.error('[SecureCall] Failed to load audio worklet:', error);
            throw error;
        }
    }

    // Stream video frames
    private async startVideoStreaming(track: MediaStreamTrack): Promise<void> {
        if (!this.videoStream || !this.encryptionContext) return;

        const video = document.createElement('video');
        video.srcObject = new MediaStream([track]);
        video.play();

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d')!;

        const captureFrame = async () => {
            if (!this.videoStream || !this.encryptionContext) return;

            const settings = await screenSharingSettings.getSettings();
            canvas.width = settings.resolution.width;
            canvas.height = settings.resolution.height;
            ctx.drawImage(video, 0, 0);

            // Get jpeg compressed frame
            const blob = await new Promise<Blob>((resolve) => {
                canvas.toBlob(b => resolve(b!), 'image/jpeg', this.qualityToJpeg(settings.quality));
            });

            const rawData = new Uint8Array(await blob.arrayBuffer());

            // Encrypt frame
            const frameNum = this.encryptionContext!.frameCounter;
            this.encryptionContext!.frameCounter += 1n;
            const nonce = new Uint8Array(12);
            new DataView(nonce.buffer).setBigUint64(4, BigInt(frameNum), false);

            const { ciphertext, tag } = PostQuantumAEAD.encrypt(
                rawData,
                this.encryptionContext!.videoKey,
                nonce
            );

            const frame = new Uint8Array(8 + ciphertext.length + 32);
            new DataView(frame.buffer).setBigUint64(0, BigInt(frameNum), false);
            frame.set(ciphertext, 8);
            frame.set(tag, 8 + ciphertext.length);

            try {
                await this.videoStream!.write(frame);
            } catch { }

            if (this.videoStream && !this.videoStream.closed) {
                setTimeout(captureFrame, 1000 / settings.frameRate);
            }
        };

        video.onloadedmetadata = () => captureFrame();
    }

    // Stream screen frames
    private async startScreenStreaming(): Promise<void> {
        if (!this.screenStream || !this.screenShareStream || !this.encryptionContext) return;

        const track = this.screenStream.getVideoTracks()[0];
        if (!track) return;

        const video = document.createElement('video');
        video.srcObject = this.screenStream;
        video.play();

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d')!;

        const captureFrame = async () => {
            if (!this.screenShareStream || !this.encryptionContext || !this.isScreenSharing) return;

            const settings = await screenSharingSettings.getSettings();
            canvas.width = settings.resolution.width;
            canvas.height = settings.resolution.height;
            ctx.drawImage(video, 0, 0);

            const blob = await new Promise<Blob>((resolve) => {
                canvas.toBlob(b => resolve(b!), 'image/jpeg', this.qualityToJpeg(settings.quality));
            });

            const rawData = new Uint8Array(await blob.arrayBuffer());

            const frameNum = this.encryptionContext!.frameCounter;
            this.encryptionContext!.frameCounter += 1n;
            const nonce = new Uint8Array(12);
            new DataView(nonce.buffer).setBigUint64(4, BigInt(frameNum), false);

            const { ciphertext, tag } = PostQuantumAEAD.encrypt(
                rawData,
                this.encryptionContext!.screenKey,
                nonce
            );

            const frame = new Uint8Array(8 + ciphertext.length + 32);
            new DataView(frame.buffer).setBigUint64(0, BigInt(frameNum), false);
            frame.set(ciphertext, 8);
            frame.set(tag, 8 + ciphertext.length);

            try {
                await this.screenShareStream!.write(frame);
            } catch { }

            if (this.isScreenSharing && this.screenShareStream && !this.screenShareStream.closed) {
                setTimeout(captureFrame, 1000 / settings.frameRate);
            }
        };

        video.onloadedmetadata = () => captureFrame();
    }

    // Start receiving remote media
    private async startReceivingMedia(): Promise<void> {
        // Receive audio
        if (this.audioStream) {
            this.receiveAudioStream();
        }

        // Receive video
        if (this.videoStream) {
            this.receiveVideoStream();
        }

        // Listen for incoming screen share stream
        if (this.callConnection) {
            this.callConnection.onStream((stream) => {
                if (stream.type === 'call-screen') {
                    this.receiveScreenStream(stream);
                }
            });
        }
    }

    // Receive and decode audio stream
    private async receiveAudioStream(): Promise<void> {
        if (!this.audioStream || !this.encryptionContext) return;

        const audioContext = new AudioContext({ sampleRate: 48000 });
        await this.loadAudioWorklet(audioContext);

        try {
            const workletNode = new AudioWorkletNode(audioContext, 'audio-receiver-processor');
            workletNode.connect(audioContext.destination);

            for await (const data of this.audioStream) {
                if (!this.encryptionContext) break;

                try {
                    // Extract frame parts
                    const frameNum = new DataView(data.buffer, data.byteOffset, 8).getBigUint64(0, false);
                    const ciphertext = data.subarray(8, data.length - 32);
                    const tag = data.subarray(data.length - 32);

                    const nonce = new Uint8Array(12);
                    new DataView(nonce.buffer).setBigUint64(4, frameNum, false);

                    const decrypted = PostQuantumAEAD.decrypt(
                        ciphertext,
                        this.encryptionContext.audioKey,
                        nonce,
                        tag
                    );

                    if (decrypted) {
                        const audioData = new Float32Array(decrypted.length / 4);
                        new Uint8Array(audioData.buffer).set(decrypted);

                        workletNode.port.postMessage(audioData);
                    }
                } catch { }
            }
        } catch { }
    }

    // Receive and decode video stream
    private async receiveVideoStream(): Promise<void> {
        if (!this.videoStream || !this.encryptionContext) return;

        const settings = await screenSharingSettings.getSettings();

        // Create canvas for video rendering
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d')!;
        canvas.width = settings.resolution.width;
        canvas.height = settings.resolution.height;

        const video = document.createElement('video');
        video.autoplay = true;
        video.muted = true;
        video.playsInline = true;

        const canvasStream = canvas.captureStream(settings.frameRate);

        if (!this.remoteStream) {
            this.remoteStream = new MediaStream();
            this.onRemoteStreamCallback?.(this.remoteStream);
        }

        const videoTrack = canvasStream.getVideoTracks()[0];
        if (videoTrack) {
            this.remoteStream.addTrack(videoTrack);
        }

        const frameQueue: ImageBitmap[] = [];
        let isRendering = false;

        const renderLoop = async () => {
            if (!isRendering || frameQueue.length === 0) {
                requestAnimationFrame(renderLoop);
                return;
            }

            const bitmap = frameQueue.shift()!;
            canvas.width = bitmap.width;
            canvas.height = bitmap.height;
            ctx.drawImage(bitmap, 0, 0);
            bitmap.close();

            requestAnimationFrame(renderLoop);
        };

        isRendering = true;
        renderLoop();

        for await (const frame of this.videoStream) {
            if (!this.encryptionContext) break;

            try {
                const frameNum = new DataView(frame.buffer, frame.byteOffset).getBigUint64(0, false);
                const ciphertext = frame.slice(8, frame.length - 32);
                const tag = frame.slice(frame.length - 32);

                const nonce = new Uint8Array(12);
                new DataView(nonce.buffer).setBigUint64(4, frameNum, false);

                const decrypted = PostQuantumAEAD.decrypt(
                    ciphertext,
                    this.encryptionContext.videoKey,
                    nonce,
                    tag
                );

                const blob = new Blob([new Uint8Array(decrypted)], { type: 'image/jpeg' });
                const bitmap = await createImageBitmap(blob);

                // Queue frame for rendering
                if (frameQueue.length < 5) {
                    frameQueue.push(bitmap);
                } else {
                    bitmap.close();
                }

            } catch { }
        }

        isRendering = false;
        if (videoTrack) {
            videoTrack.stop();
            this.remoteStream?.removeTrack(videoTrack);
        }
    }

    // Receive screen share stream
    private async receiveScreenStream(stream: SecureStream): Promise<void> {
        if (!this.encryptionContext) return;

        const settings = await screenSharingSettings.getSettings();

        // Create canvas for screen rendering
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d')!;
        canvas.width = settings.resolution.width;
        canvas.height = settings.resolution.height;

        const canvasStream = canvas.captureStream(settings.frameRate);

        if (!this.remoteScreenStream) {
            this.remoteScreenStream = new MediaStream();
            this.onRemoteScreenStreamCallback?.(this.remoteScreenStream);
        }

        // Add video track to screen stream
        const videoTrack = canvasStream.getVideoTracks()[0];
        if (videoTrack) {
            this.remoteScreenStream.addTrack(videoTrack);
        }

        const frameQueue: ImageBitmap[] = [];
        let isRendering = false;

        const renderLoop = async () => {
            if (!isRendering || frameQueue.length === 0) {
                requestAnimationFrame(renderLoop);
                return;
            }

            const bitmap = frameQueue.shift()!;
            canvas.width = bitmap.width;
            canvas.height = bitmap.height;
            ctx.drawImage(bitmap, 0, 0);
            bitmap.close();

            requestAnimationFrame(renderLoop);
        };

        isRendering = true;
        renderLoop();

        for await (const frame of stream) {
            if (!this.encryptionContext) break;

            try {
                const frameNum = new DataView(frame.buffer, frame.byteOffset).getBigUint64(0, false);
                const ciphertext = frame.slice(8, frame.length - 32);
                const tag = frame.slice(frame.length - 32);

                const nonce = new Uint8Array(12);
                new DataView(nonce.buffer).setBigUint64(4, frameNum, false);

                const decrypted = PostQuantumAEAD.decrypt(
                    ciphertext,
                    this.encryptionContext.screenKey,
                    nonce,
                    tag
                );

                const blob = new Blob([new Uint8Array(decrypted)], { type: 'image/jpeg' });
                const bitmap = await createImageBitmap(blob);

                // Queue for rendering
                if (frameQueue.length < 5) {
                    frameQueue.push(bitmap);
                } else {
                    bitmap.close();
                }

            } catch { }
        }

        isRendering = false;
        if (videoTrack) {
            videoTrack.stop();
            this.remoteScreenStream?.removeTrack(videoTrack);
        }
    }

    // Start periodic key rotation during call
    private startKeyRotation(): void {
        if (this.keyRotationTimer) return;

        this.keyRotationTimer = setInterval(() => {
            if (this.encryptionContext) {
                this.rotateMediaKeys();
            }
        }, CALL_KEY_ROTATION_INTERVAL);
    }

    // Rotate media encryption keys
    private rotateMediaKeys(): void {
        if (!this.encryptionContext) return;

        // Derive new keys from current keys
        const newAudioKey = PostQuantumHash.blake3(
            new Uint8Array([...this.encryptionContext.audioKey, ...new TextEncoder().encode('rotate')]),
            { dkLen: 32 }
        );

        const newVideoKey = PostQuantumHash.blake3(
            new Uint8Array([...this.encryptionContext.videoKey, ...new TextEncoder().encode('rotate')]),
            { dkLen: 32 }
        );

        const newScreenKey = PostQuantumHash.blake3(
            new Uint8Array([...this.encryptionContext.screenKey, ...new TextEncoder().encode('rotate')]),
            { dkLen: 32 }
        );

        SecureMemory.zeroBuffer(this.encryptionContext.audioKey);
        SecureMemory.zeroBuffer(this.encryptionContext.videoKey);
        SecureMemory.zeroBuffer(this.encryptionContext.screenKey);

        this.encryptionContext.audioKey = newAudioKey;
        this.encryptionContext.videoKey = newVideoKey;
        this.encryptionContext.screenKey = newScreenKey;
    }

    // Send a call signal to the peer
    private async sendCallSignal(signal: CallSignal): Promise<void> {
        try {
            // Sign the signal
            if (this.pqSigningKey) {
                const payload = `${signal.callId}:${signal.type}:${signal.timestamp}:${signal.from}:${signal.to}`;
                const message = new TextEncoder().encode(payload);
                const signature = PostQuantumSignature.sign(message, this.pqSigningKey.privateKey);

                signal.pqSignature = {
                    signature: PostQuantumUtils.uint8ArrayToBase64(signature),
                    publicKey: PostQuantumUtils.uint8ArrayToBase64(this.pqSigningKey.publicKey)
                };
            }

            const edgeApi = (window as any).edgeApi;
            if (!edgeApi) throw new Error('System encryption API not available');

            const hasSession = await edgeApi.hasSession({
                selfUsername: this.localUsername,
                peerUsername: signal.to,
                deviceId: 1
            });

            if (!hasSession?.hasSession) {
                // Request bundle
                await websocketClient.sendSecureControlMessage({
                    type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                    username: signal.to,
                    from: this.localUsername,
                    timestamp: Date.now(),
                    deviceId: 1
                });

                await new Promise<void>((resolve, reject) => {
                    const timeout = setTimeout(() => {
                        cleanup();
                        reject(new Error('Timeout waiting for session establishment'));
                    }, 10000);

                    const onSessionReady = (event: CustomEvent) => {
                        if (event.detail?.peer === signal.to) {
                            cleanup();
                            resolve();
                        }
                    };

                    const cleanup = () => {
                        clearTimeout(timeout);
                        window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY as any, onSessionReady);
                    };

                    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY as any, onSessionReady);
                });
            }

            if (this.callConnection && (this.callConnection as any).state === 'connected' && this.callConnection.peerId === signal.to) {
                try {
                    await (this.transport as any).sendMessage(signal.to, signal, SignalType.CALL_SIGNAL as any);
                    return;
                } catch (err) {
                    console.error('[SecureCallingService] Direct P2P signaling failed, falling back to WS:', err);
                }
            }

            const peerKeys = this.peerKeysCache.get(signal.to);
            if (!peerKeys || !peerKeys.kyberPublicKey) { throw new Error('Missing peer cryptographic keys'); }

            const signalPayload = {
                type: EventType.CALL_SIGNAL,
                content: JSON.stringify(signal),
                from: this.localUsername,
                callId: signal.callId,
                timestamp: Date.now()
            };

            const encryptionResult = await edgeApi.encrypt({
                fromUsername: this.localUsername,
                toUsername: signal.to,
                plaintext: JSON.stringify(signalPayload),
                recipientKyberPublicKey: PostQuantumUtils.uint8ArrayToBase64(peerKeys.kyberPublicKey)
            });

            if (!encryptionResult?.success || !encryptionResult.encryptedPayload) {
                throw new Error(encryptionResult?.error || 'Encryption failed');
            }

            const payload = {
                type: SignalType.ENCRYPTED_MESSAGE,
                to: signal.to,
                encryptedPayload: encryptionResult.encryptedPayload
            };

            websocketClient.send(JSON.stringify(payload));
        } catch (error) { throw error; }
    }

    // Handle incoming call signal
    private async handleCallSignal(signal: CallSignal): Promise<void> {
        // Verify signature
        if (signal.pqSignature) {
            const payload = `${signal.callId}:${signal.type}:${signal.timestamp}:${signal.from}:${signal.to}`;
            const message = new TextEncoder().encode(payload);
            const signature = PostQuantumUtils.base64ToUint8Array(signal.pqSignature.signature);
            const publicKey = PostQuantumUtils.base64ToUint8Array(signal.pqSignature.publicKey);

            const valid = PostQuantumSignature.verify(signature, message, publicKey);
            if (!valid) { return; }
        }

        switch (signal.type) {
            case 'offer':
                await this.handleCallOffer(signal);
                break;

            case 'answer':
                await this.handleCallAnswer(signal);
                break;

            case 'decline-call':
                await this.handleCallDecline(signal);
                break;

            case 'end-call':
                await this.handleCallEnd(signal);
                break;

            case 'connected':
                this.markConnected('remote-signal');
                break;

            case 'screen-share-start':
                this.remoteScreenStream = new MediaStream();
                this.onRemoteScreenStreamCallback?.(this.remoteScreenStream);
                break;

            case 'screen-share-stop':
                if (this.remoteScreenStream) {
                    this.remoteScreenStream.getTracks().forEach(t => t.stop());
                    this.remoteScreenStream = null;
                    this.onRemoteScreenStreamCallback?.(null);
                }
                break;
        }
    }

    // Handle incoming call offer
    private async handleCallOffer(signal: CallSignal): Promise<void> {
        if (this.currentCall) {
            // Collision Detection
            if (this.currentCall.peer === signal.from && (this.currentCall.status === 'connecting' || this.currentCall.status === 'ringing')) {
                // Lexicographical Arbitration lower username stays as initiator
                if (this.localUsername < signal.from) {
                    await this.sendCallSignal({
                        type: 'decline-call',
                        callId: signal.callId,
                        from: this.localUsername,
                        to: signal.from,
                        data: { reason: 'collision-loss' },
                        timestamp: Date.now()
                    });
                    return;
                } else {
                    if (this.callTimeoutId) {
                        clearTimeout(this.callTimeoutId);
                        this.callTimeoutId = null;
                    }
                    this.ringStartAt = null;
                }
            } else {
                await this.sendCallSignal({
                    type: 'decline-call',
                    callId: signal.callId,
                    from: this.localUsername,
                    to: signal.from,
                    timestamp: Date.now()
                });
                return;
            }
        }

        this.currentCall = {
            id: signal.callId,
            type: signal.data?.callType || 'audio',
            direction: 'incoming',
            status: 'ringing',
            peer: signal.from
        };

        this.ringStartAt = Date.now();
        this.onIncomingCallCallback?.(this.currentCall);
        this.onCallStateChangeCallback?.(this.currentCall);

        this.callTimeoutId = setTimeout(() => {
            if (this.currentCall?.status === 'ringing') {
                this.currentCall.status = 'missed';
                this.onCallStateChangeCallback?.(this.currentCall);
                this.cleanup();
            }
        }, CALL_RING_TIMEOUT);
    }

    // Handle incoming call answer
    private async handleCallAnswer(signal: CallSignal): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== signal.callId) { return; }
        if (this.currentCall.direction !== 'outgoing') { return; }

        this.currentCall.status = 'connected';
        this.currentCall.startTime = Date.now();
        this.onCallStateChangeCallback?.(this.currentCall);

        await this.startMediaStreaming();
        this.markConnected('answer-received');
    }

    // Handle incoming call end
    private async handleCallEnd(signal: CallSignal): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== signal.callId) return;

        this.currentCall.status = 'ended';
        this.currentCall.endTime = Date.now();
        this.currentCall.endReason = 'remote';
        if (this.currentCall.startTime) {
            this.currentCall.duration = Date.now() - this.currentCall.startTime;
        }
        this.onCallStateChangeCallback?.(this.currentCall);
        this.cleanup();
    }

    // Handle incoming call decline
    private async handleCallDecline(signal: CallSignal): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== signal.callId) return;

        this.currentCall.status = 'declined';
        this.currentCall.endTime = Date.now();
        this.onCallStateChangeCallback?.(this.currentCall);

        const role = (this.callConnection as any)?.getEffectiveRole?.();
        const keepConnection = signal.data?.reason === 'collision-loss' || role === 'responder';

        this.cleanup(keepConnection);
    }

    // Generate a random call ID
    private generateCallId(): string {
        return PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
    }

    // Mark call as connected
    private markConnected(source: string): void {
        if (this.currentCall && this.currentCall.status === 'connecting') {
            this.currentCall.status = 'connected';
            this.currentCall.startTime = Date.now();

            if (this.callTimeoutId) {
                clearTimeout(this.callTimeoutId);
                this.callTimeoutId = null;
            }

            this.onCallStateChangeCallback?.(this.currentCall);
        }
    }

    // Cleanup call resources
    private cleanup(keepConnection: boolean = false): void {
        // Stop local media
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }

        // Stop screen share
        if (this.screenStream) {
            this.screenStream.getTracks().forEach(track => track.stop());
            this.screenStream = null;
            this.isScreenSharing = false;
        }

        // Close streams
        if (this.audioStream) {
            this.audioStream.close();
            this.audioStream = null;
        }
        if (this.videoStream) {
            this.videoStream.close();
            this.videoStream = null;
        }
        if (this.screenShareStream) {
            this.screenShareStream.close();
            this.screenShareStream = null;
        }

        // Close connection
        if (this.callConnection && !keepConnection) {
            this.callConnection.close('call-cleanup');
            this.callConnection = null;
        } else if (keepConnection) { }

        // Clear encryption context
        if (this.encryptionContext) {
            SecureMemory.zeroBuffer(this.encryptionContext.audioKey);
            SecureMemory.zeroBuffer(this.encryptionContext.videoKey);
            SecureMemory.zeroBuffer(this.encryptionContext.screenKey);
            this.encryptionContext = null;
        }

        // Stop key rotation
        if (this.keyRotationTimer) {
            clearInterval(this.keyRotationTimer);
            this.keyRotationTimer = null;
        }

        // Clear timeouts
        if (this.callTimeoutId) {
            clearTimeout(this.callTimeoutId);
            this.callTimeoutId = null;
        }

        this.remoteStream = null;
        this.remoteScreenStream = null;
        this.ringStartAt = null;

        const lastCall = this.currentCall;
        this.currentCall = null;

        if (lastCall && lastCall.status !== 'ended') {
            this.onCallStateChangeCallback?.({
                ...lastCall,
                status: 'ended',
                endTime: Date.now()
            });
        }
    }

    // Set incoming call callback
    onIncomingCall(callback: (call: CallState) => void): void {
        this.onIncomingCallCallback = callback;
    }

    // Set call state change callback
    onCallStateChange(callback: (call: CallState) => void): void {
        this.onCallStateChangeCallback = callback;
    }

    // Set remote stream callback
    onRemoteStream(callback: (stream: MediaStream | null) => void): void {
        this.onRemoteStreamCallback = callback;
    }

    // Set remote screen stream callback
    onRemoteScreenStream(callback: (stream: MediaStream | null) => void): void {
        this.onRemoteScreenStreamCallback = callback;
    }

    // Set local stream callback
    onLocalStream(callback: (stream: MediaStream) => void): void {
        this.onLocalStreamCallback = callback;
    }

    // Get screen sharing status
    getScreenSharingStatus(): boolean {
        return this.isScreenSharing;
    }

    // Get available screen sources
    async getAvailableScreenSources(): Promise<Array<{ id: string; name: string; type: 'screen' | 'window' }>> {
        const electronApi = (window as any).electronAPI;
        const edgeApi = (window as any).edgeApi;

        const getScreenSourcesFn =
            (typeof electronApi?.getScreenSources === 'function' ? electronApi.getScreenSources : null) ||
            (typeof edgeApi?.getScreenSources === 'function' ? edgeApi.getScreenSources : null);

        if (!getScreenSourcesFn) {
            return [];
        }

        try {
            const sources = await getScreenSourcesFn();
            return sources.map((s: any) => ({
                id: s.id as string,
                name: s.name as string,
                type: s.id?.startsWith('screen:') ? 'screen' : 'window' as 'screen' | 'window'
            }));
        } catch {
            return [];
        }
    }

    // Destroy the calling service
    destroy(): void {
        this.cleanup();

        if (this.pqSigningKey) {
            SecureMemory.zeroBuffer(this.pqSigningKey.privateKey);
            this.pqSigningKey = null;
        }

        if (this.kyberKeyPair) {
            SecureMemory.zeroBuffer(this.kyberKeyPair.secretKey);
            this.kyberKeyPair = null;
        }

        if (this.dilithiumKeyPair) {
            SecureMemory.zeroBuffer(this.dilithiumKeyPair.secretKey);
            this.dilithiumKeyPair = null;
        }

        if (this.x25519KeyPair) {
            SecureMemory.zeroBuffer(this.x25519KeyPair.secretKey);
            this.x25519KeyPair = null;
        }

        this.peerKeysCache.clear();
    }
}

export function createSecureCallingService(username: string): SecureCallingService {
    return new SecureCallingService(username);
}
