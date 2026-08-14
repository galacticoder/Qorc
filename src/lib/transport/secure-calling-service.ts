/**
 * Secure Calling Service
 */

import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { PostQuantumHash } from '../cryptography/hash';
import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SecureMemory } from '../cryptography/secure-memory';
import { P2PTransport, p2pTransport } from './p2p-transport';
import {
    MAX_CALL_FRAME_SIZE,
    NOISE_FRAME_OVERHEAD,
    SecureConnection,
    SecureStream
} from './secure-transport';
import { PQNoiseSession } from './pq-noise-session';
import { screenSharingSettings } from '../database/screen-sharing-settings';
import { STORAGE_KEYS } from '../database/storage-keys';
import { encryptedStorage } from '../database/encrypted-storage';
import { unifiedSignalTransport } from './unified-signal-transport';
import {
    CALL_TIMEOUT,
    CALL_RING_TIMEOUT,
    CALL_AUDIO_PADDING_BLOCK,
    CALL_DEVICE_SETTLE_MS,
    CALL_KEY_ROTATION_INTERVAL,
    MAX_CALL_SIGNAL_CLOCK_SKEW_MS,
    P2P_CONNECTION_TIMEOUT_MS,
    PQ_AEAD_CIPHERTEXT_OVERHEAD,
    PQ_AEAD_MAC_SIZE,
    PQ_AEAD_NONCE_SIZE,
    QualityOption
} from '../constants';
import {
    signal as signalApi,
    system,
    isTauri,
    requireNativeMediaAccess,
} from '../tauri-bindings';
import {
    isExactCallSignal,
    isValidCallId,
    isValidCallingUsername,
    isValidMediaDeviceId
} from '../utils/calling-utils';
import { hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import {
    CallState,
    CallSignal,
    LocalCallEndReason,
    MediaEncryptionContext,
} from '../types/calling-types';
import { cloneScreenSharingSettings, type ScreenSharingSettings, type ScreenSource } from '../types/screen-sharing-types';
import { blockingSystem } from '../blocking/blocking-system';
import { keyTransparencyClient } from '../key-transparency/client';
import { validateJpegContainer } from '../utils/image-container-validation';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export type { CallState, CallSignal, MediaEncryptionContext };

type MediaKind = 'audio' | 'video' | 'screen';
type MediaKeyFamily = { audio: Uint8Array; video: Uint8Array; screen: Uint8Array };
type JpegEncodeProfile = { signature: string; scale: number; quality: number };
type PendingScreenShareReady = {
    callId: string;
    streamId: string;
    generation: number;
    timeoutId: ReturnType<typeof setTimeout>;
    finish: (ready: boolean) => void;
};

const MEDIA_FRAME_HEADER_SIZE = 12;
const MEDIA_FRAME_OVERHEAD = MEDIA_FRAME_HEADER_SIZE + PQ_AEAD_NONCE_SIZE +
    PQ_AEAD_MAC_SIZE + PQ_AEAD_CIPHERTEXT_OVERHEAD;
const MAX_MEDIA_EPOCH_ADVANCE = 64;
const MEDIA_REPLAY_WINDOW_SIZE = 4096;
const MEDIA_REPLAY_WINDOW_FRAMES = BigInt(MEDIA_REPLAY_WINDOW_SIZE);
const MAX_AUDIO_PLAINTEXT_BYTES = 64 * 1024;
const MAX_VIDEO_PLAINTEXT_BYTES = MAX_CALL_FRAME_SIZE - NOISE_FRAME_OVERHEAD - MEDIA_FRAME_OVERHEAD;
const MAX_DECODED_MEDIA_WIDTH = 3840;
const MAX_DECODED_MEDIA_HEIGHT = 2160;
const MAX_DECODED_MEDIA_PIXELS = MAX_DECODED_MEDIA_WIDTH * MAX_DECODED_MEDIA_HEIGHT;
const MAX_DECODED_FRAME_QUEUE = 2;
const MAX_MEDIA_FRAME_NUMBER = (1n << 64n) - 1n;
const MAX_REMOTE_SCREEN_SHARES_PER_CALL = 128;
const MAX_PENDING_SIGNAL_SESSION_WAITS = 8;
const MAX_CALL_SIGNAL_ERROR_RETRIES = 3;
const CALL_SIGNAL_RETRY_BASE_DELAY_MS = 250;
const CALL_OFFER_RATE_WINDOW_MS = 60_000;
const MAX_CALL_OFFERS_PER_PEER = 4;
const MAX_CALL_OFFERS_GLOBAL = 16;
const MAX_CALL_OFFER_RATE_PEERS = 128;
const MAX_SCREEN_SOURCES = 128;
const MAX_SCREEN_SOURCE_NAME_LENGTH = 256;
const SCREEN_SHARE_READY_TIMEOUT_MS = 10_000;
const SCREEN_SOURCE_ID_REGEX = {
    screen: /^screen:[0-9]{1,3}$/,
    window: /^window:(?:0x[0-9a-f]{1,16}|[0-9]{1,20})$/i
} as const;
const mediaKeyEncoder = new TextEncoder();
const CALL_MEDIA_SALT = mediaKeyEncoder.encode(PROTOCOL_KEYS.CALL_MEDIA_SALT);
const CALL_MEDIA_AUDIO_LABEL = mediaKeyEncoder.encode(PROTOCOL_KEYS.CALL_MEDIA_AUDIO);
const CALL_MEDIA_VIDEO_LABEL = mediaKeyEncoder.encode(PROTOCOL_KEYS.CALL_MEDIA_VIDEO);
const CALL_MEDIA_SCREEN_LABEL = mediaKeyEncoder.encode(PROTOCOL_KEYS.CALL_MEDIA_SCREEN);
const CALL_MEDIA_ROTATE_LABEL = mediaKeyEncoder.encode(PROTOCOL_KEYS.CALL_MEDIA_ROTATE);

function deriveLabeledMediaKey(key: Uint8Array, label: Uint8Array): Uint8Array {
    const material = new Uint8Array(key.length + label.length);
    material.set(key, 0);
    material.set(label, key.length);
    try {
        return PostQuantumHash.blake3(material, { dkLen: 32 });
    } finally {
        SecureMemory.zeroBuffer(material);
    }
}

type ScreenCaptureSelection = ScreenSource;

function isValidScreenSourceId(value: unknown, type: 'screen' | 'window'): value is string {
    return typeof value === 'string' &&
        value.length <= 96 &&
        SCREEN_SOURCE_ID_REGEX[type].test(value);
}

function isValidScreenCaptureSelection(value: unknown): value is ScreenCaptureSelection {
    if (
        !isPlainObject(value) ||
        hasPrototypePollutionKeys(value) ||
        Object.keys(value).sort().join(',') !== 'id,name,type' ||
        (value.type !== 'screen' && value.type !== 'window') ||
        !isValidScreenSourceId(value.id, value.type) ||
        typeof value.name !== 'string' ||
        value.name.length === 0 ||
        value.name.length > MAX_SCREEN_SOURCE_NAME_LENGTH ||
        /[\x00-\x1f\x7f]/.test(value.name)
    ) {
        return false;
    }
    return true;
}

// Calling Service
export class SecureCallingService {
    private localStream: MediaStream | null = null;
    private remoteStream: MediaStream | null = null;
    private remoteScreenStream: MediaStream | null = null;
    private screenStream: MediaStream | null = null;
    private currentCall: CallState | null = null;
    private isScreenSharing: boolean = false;
    private screenSharePending: boolean = false;
    private localUsername: string = '';
    private preferredCameraDeviceId: string | null = null;

    // Transport
    private transport: P2PTransport;
    private callConnection: SecureConnection | null = null;
    private audioStream: SecureStream | null = null;
    private videoStream: SecureStream | null = null;
    private screenShareStream: SecureStream | null = null;
    private incomingScreenStream: SecureStream | null = null;
    private expectedRemoteScreenStreamId: string | null = null;
    private pendingScreenShareReady: PendingScreenShareReady | null = null;
    private seenRemoteScreenStreamIds = new Set<string>();
    private sharedAudioContext: AudioContext | null = null;
    private audioWorkletLoaded = false;
    private callAudioSource: MediaStreamAudioSourceNode | null = null;
    private callAudioNode: AudioWorkletNode | null = null;
    private sharedReceiveAudioContext: AudioContext | null = null;
    private receiveAudioWorkletLoaded = false;
    private callReceiveAudioNode: AudioWorkletNode | null = null;

    private captureVideoEl: HTMLVideoElement | null = null;
    private screenCaptureVideoEl: HTMLVideoElement | null = null;
    private remoteVideoRenderId = 0;
    private lastCaptureReleaseAt = 0;

    // Encryption
    private encryptionContext: MediaEncryptionContext | null = null;
    private mediaReplayWindows = new Map<string, {
        highest: bigint;
        slots: Array<bigint | undefined>;
    }>();
    private keyRotationTimer: ReturnType<typeof setInterval> | null = null;
    private mediaGeneration = 0;
    private screenShareGeneration = 0;
    private cameraSwitchGeneration = 0;
    private microphoneSwitchGeneration = 0;
    private callStreamUnsubscribe: (() => void) | null = null;

    // Lifecycle
    private initialized = false;
    private destroyed = false;
    private initializationPromise: Promise<void> | null = null;
    private lifecycleGeneration = 0;
    private pendingSignalSessionWaitCancels = new Set<() => void>();
    private incomingOfferRates = new Map<string, { windowStart: number; count: number }>();
    private incomingOfferGlobal = { windowStart: 0, count: 0 };
    private mediaSettings: ScreenSharingSettings | null = null;
    private mediaSettingsUnsubscribe: (() => void) | null = null;
    private securityQuarantined = keyTransparencyClient.isSecurityIncidentActive();

    // Callbacks
    private onIncomingCallCallback: ((call: CallState) => void) | null = null;
    private onCallStateChangeCallback: ((call: CallState) => void) | null = null;
    private onRemoteStreamCallback: ((stream: MediaStream | null) => void) | null = null;
    private onRemoteScreenStreamCallback: ((stream: MediaStream | null) => void) | null = null;
    private onLocalStreamCallback: ((stream: MediaStream) => void) | null = null;

    // Timers
    private callTimeoutId: ReturnType<typeof setTimeout> | null = null;
    private ringStartAt: number | null = null;

    private readonly beforeUnloadHandler = (): void => {
        if (this.currentCall && this.currentCall.status !== 'ended') {
            void this.endCall('shutdown');
        }
    };

    private readonly callSignalHandler = (event: Event): void => {
        if (!(event instanceof CustomEvent)) return;
        void this.handleCallSignal(event.detail).catch(() => { });
    };

    private readonly userBlockedHandler = (event: Event): void => {
        if (!(event instanceof CustomEvent)) return;
        const detail = event.detail;
        if (
            !isPlainObject(detail) ||
            hasPrototypePollutionKeys(detail) ||
            Object.keys(detail).sort().join(',') !== 'username' ||
            typeof detail.username !== 'string' ||
            !isValidCallingUsername(detail.username) ||
            detail.username !== detail.username.trim().toLowerCase() ||
            this.currentCall?.peer !== detail.username
        ) return;
        void this.endCall('blocked');
    };

    private readonly keyTransparencySecurityIncidentHandler = (): void => {
        if (this.securityQuarantined) return;
        this.securityQuarantined = true;
        this.lifecycleGeneration += 1;

        const call = this.currentCall;
        if (call) {
            const endTime = Date.now();
            call.status = 'ended';
            call.endTime = endTime;
            call.duration = call.startTime ? Math.max(0, endTime - call.startTime) : 0;
            call.endReason = 'shutdown';
            this.notifyCallState(call);
        }
        
        this.cleanup();
    };

    private qualityToJpeg(quality: QualityOption): number {
        switch (quality) {
            case 'low': return 0.6;
            case 'medium': return 0.8;
            case 'high': return 0.95;
            default: return 0.8;
        }
    }

    private resolveCaptureDimensions(
        settings: ScreenSharingSettings,
        video: HTMLVideoElement
    ): { width: number; height: number } {
        const requestedWidth = settings.resolution.isNative
            ? video.videoWidth
            : settings.resolution.width;
        const requestedHeight = settings.resolution.isNative
            ? video.videoHeight
            : settings.resolution.height;
        if (
            !Number.isInteger(requestedWidth) ||
            !Number.isInteger(requestedHeight) ||
            requestedWidth < 1 ||
            requestedHeight < 1
        ) {
            throw new Error('Media capture dimensions are unavailable');
        }
        const scale = Math.min(
            1,
            MAX_DECODED_MEDIA_WIDTH / requestedWidth,
            MAX_DECODED_MEDIA_HEIGHT / requestedHeight,
            Math.sqrt(MAX_DECODED_MEDIA_PIXELS / (requestedWidth * requestedHeight))
        );
        return {
            width: Math.max(1, Math.floor(requestedWidth * scale)),
            height: Math.max(1, Math.floor(requestedHeight * scale))
        };
    }

    private async encodeBoundedJpegFrame(
        video: HTMLVideoElement,
        canvas: HTMLCanvasElement,
        context: CanvasRenderingContext2D,
        settings: ScreenSharingSettings,
        profile: JpegEncodeProfile
    ): Promise<Uint8Array | null> {
        const dimensions = this.resolveCaptureDimensions(settings, video);
        const requestedQuality = this.qualityToJpeg(settings.quality);
        const signature = `${dimensions.width}x${dimensions.height}:${requestedQuality}`;
        if (profile.signature !== signature) {
            profile.signature = signature;
            profile.scale = 1;
            profile.quality = requestedQuality;
        }

        for (let attempt = 0; attempt < 4; attempt += 1) {
            const width = Math.max(1, Math.floor(dimensions.width * profile.scale));
            const height = Math.max(1, Math.floor(dimensions.height * profile.scale));
            if (canvas.width !== width) canvas.width = width;
            if (canvas.height !== height) canvas.height = height;
            context.drawImage(video, 0, 0, width, height);

            const blob = await new Promise<Blob | null>((resolve) => {
                canvas.toBlob(resolve, 'image/jpeg', profile.quality);
            });
            if (!blob || blob.size === 0) return null;
            if (blob.size <= MAX_VIDEO_PLAINTEXT_BYTES) {
                const bytes = new Uint8Array(await blob.arrayBuffer());
                if (bytes.length > 0 && bytes.length <= MAX_VIDEO_PLAINTEXT_BYTES) return bytes;
                SecureMemory.zeroBuffer(bytes);
                return null;
            }

            profile.scale = Math.max(0.5, profile.scale * 0.75);
            profile.quality = Math.max(0.45, Math.min(0.8, profile.quality * 0.8));
        }
        return null;
    }

    private initialRenderDimensions(settings: ScreenSharingSettings): { width: number; height: number } {
        if (settings.resolution.isNative) return { width: 1280, height: 720 };
        return {
            width: Math.max(1, Math.min(settings.resolution.width, MAX_DECODED_MEDIA_WIDTH)),
            height: Math.max(1, Math.min(settings.resolution.height, MAX_DECODED_MEDIA_HEIGHT))
        };
    }

    private async getMediaSettings(): Promise<ScreenSharingSettings> {
        if (!this.mediaSettings) {
            const settings = await screenSharingSettings.getSettings();
            if (this.destroyed) throw new Error('Calling service is destroyed');
            this.mediaSettings = cloneScreenSharingSettings(settings);
        }
        if (!this.mediaSettingsUnsubscribe) {
            this.mediaSettingsUnsubscribe = screenSharingSettings.subscribe((settings) => {
                if (!this.destroyed) {
                    this.mediaSettings = cloneScreenSharingSettings(settings);
                }
            });
        }
        return this.mediaSettings;
    }

    constructor(username: string) {
        const normalized = typeof username === 'string' ? username.trim().toLowerCase() : '';
        if (normalized !== username || !isValidCallingUsername(normalized)) {
            throw new Error('Invalid local calling identity');
        }
        this.localUsername = normalized;
        this.transport = p2pTransport;
    }

    private notifyIncomingCall(call: CallState): void {
        try {
            this.onIncomingCallCallback?.({ ...call });
        } catch (error) {
            console.error('[SecureCall] Incoming call observer failed:', error);
        }
    }

    private notifyCallState(call: CallState): void {
        try {
            this.onCallStateChangeCallback?.({ ...call });
        } catch (error) {
            console.error('[SecureCall] Call state observer failed:', error);
        }
    }

    private notifyRemoteStream(stream: MediaStream | null): void {
        try {
            this.onRemoteStreamCallback?.(stream);
        } catch (error) {
            console.error('[SecureCall] Remote stream observer failed:', error);
        }
    }

    private notifyRemoteScreenStream(stream: MediaStream | null): void {
        try {
            this.onRemoteScreenStreamCallback?.(stream);
        } catch (error) {
            console.error('[SecureCall] Remote screen observer failed:', error);
        }
    }

    private notifyLocalStream(stream: MediaStream): void {
        try {
            this.onLocalStreamCallback?.(stream);
        } catch (error) {
            console.error('[SecureCall] Local stream observer failed:', error);
        }
    }

    private stopMediaStream(stream: MediaStream | null, clearEndedHandlers = false): void {
        if (!stream) return;
        try {
            for (const track of stream.getTracks()) {
                if (clearEndedHandlers) {
                    try { track.onended = null; } catch { }
                }
                try { track.stop(); } catch { }
            }
        } catch { }
    }

    private closeSecureStream(stream: SecureStream | null): void {
        if (!stream) return;
        try {
            void stream.close().catch(() => { });
        } catch { }
    }

    private abortSecureStream(stream: SecureStream | null, reason: string): void {
        if (!stream) return;
        try { stream.abort(reason); } catch { }
    }

    private unsubscribeCallStreams(): void {
        const unsubscribe = this.callStreamUnsubscribe;
        this.callStreamUnsubscribe = null;
        if (!unsubscribe) return;
        try { unsubscribe(); } catch { }
    }

    private closeAudioContext(context: AudioContext | null): void {
        if (!context) return;
        try {
            void context.close().catch(() => { });
        } catch { }
    }

    // Initialize calling service
    async initialize(): Promise<void> {
        if (this.securityQuarantined || keyTransparencyClient.isSecurityIncidentActive()) {
            this.securityQuarantined = true;
            throw new Error('Calling is disabled by key-transparency quarantine');
        }
        if (this.destroyed) {
            throw new Error('Calling service has been destroyed');
        }
        if (this.initialized) return;
        if (this.initializationPromise) {
            await this.initializationPromise;
            return;
        }

        const attempt = this.performInitialization();
        this.initializationPromise = attempt;
        try {
            await attempt;
        } finally {
            if (this.initializationPromise === attempt) {
                this.initializationPromise = null;
            }
        }
    }

    private async performInitialization(): Promise<void> {
        // Load preferred camera
        try {
            const storedCamera = await encryptedStorage.getItem(STORAGE_KEYS.PREFERRED_CAMERA);
            if (isValidMediaDeviceId(storedCamera)) {
                this.preferredCameraDeviceId = storedCamera;
            }
        } catch { }

        if (this.destroyed) {
            throw new Error('Calling service was destroyed during initialization');
        }

        if (typeof window !== 'undefined') {
            window.addEventListener('beforeunload', this.beforeUnloadHandler);
            window.addEventListener(EventType.CALL_SIGNAL, this.callSignalHandler);
            window.addEventListener(EventType.USER_BLOCKED, this.userBlockedHandler);
            window.addEventListener(
                EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT,
                this.keyTransparencySecurityIncidentHandler
            );
        }
        this.initialized = true;
    }

    // Start a call to peer
    async startCall(targetUser: string, callType: 'audio' | 'video' = 'audio'): Promise<string> {
        await this.initialize();
        if (this.securityQuarantined || keyTransparencyClient.isSecurityIncidentActive()) {
            throw new Error('Calling is disabled by key-transparency quarantine');
        }
        if (callType !== 'audio' && callType !== 'video') {
            throw new Error('Invalid call type');
        }
        const normalizedTarget = typeof targetUser === 'string' ? targetUser.trim().toLowerCase() : '';
        if (
            normalizedTarget !== targetUser ||
            !isValidCallingUsername(normalizedTarget) ||
            normalizedTarget === this.localUsername
        ) {
            throw new Error('Invalid call recipient');
        }
        targetUser = normalizedTarget;
        if (!blockingSystem.isEnforcementReady() || blockingSystem.isBlockedSync(targetUser)) {
            throw new Error('recipient-blocked');
        }
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
        this.notifyCallState(this.currentCall);

        try {
            const signalingGeneration = this.lifecycleGeneration;
            await this.waitForSignalSession(targetUser, signalingGeneration);
            if (
                signalingGeneration !== this.lifecycleGeneration ||
                !this.currentCall ||
                this.currentCall.id !== callId ||
                this.currentCall.peer !== targetUser
            ) {
                throw new Error('Call was cancelled while preparing secure signaling');
            }

            // Set up local media
            const actualCallType = await this.setupLocalMedia(callType, callId);
            if (!this.currentCall || this.currentCall.id !== callId) { throw new Error('Call was cancelled'); }
            this.currentCall.type = actualCallType;

            await this.establishCallConnection(targetUser, callId);

            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== targetUser) {
                throw new Error('Call was cancelled');
            }

            const activeCallId = this.currentCall.id;
            this.currentCall.status = 'ringing';
            this.notifyCallState(this.currentCall);

            this.callTimeoutId = setTimeout(() => {
                if (this.currentCall?.id === activeCallId && this.currentCall.status === 'ringing') {
                    void this.endCall('timeout');
                }
            }, CALL_TIMEOUT);

            await this.sendCallSignal({
                type: 'offer',
                callId: activeCallId,
                from: this.localUsername,
                to: targetUser,
                data: { callType: this.currentCall.type },
                timestamp: Date.now()
            });

            if (!this.currentCall || this.currentCall.id !== activeCallId || this.currentCall.peer !== targetUser) {
                throw new Error('Call ended while the offer was being delivered');
            }

            return activeCallId;

        } catch (error: unknown) {
            if (this.currentCall?.id === callId) {
                const failedCall = this.currentCall;
                failedCall.status = 'ended';
                failedCall.endReason = 'failed';
                failedCall.endTime = Date.now();
                failedCall.duration = failedCall.startTime ? failedCall.endTime - failedCall.startTime : 0;
                this.notifyCallState(failedCall);
                this.cleanup();
            }
            throw error;
        }
    }

    // Answer incoming call
    async answerCall(callId: string): Promise<void> {
        await this.initialize();
        if (this.securityQuarantined || keyTransparencyClient.isSecurityIncidentActive()) {
            throw new Error('Calling is disabled by key-transparency quarantine');
        }
        if (
            !this.currentCall ||
            this.currentCall.id !== callId ||
            this.currentCall.direction !== 'incoming'
        ) { throw new Error('No matching incoming call found'); }

        if (this.currentCall.status !== 'ringing') { return; }

        const peer = this.currentCall.peer;
        if (!blockingSystem.isEnforcementReady() || blockingSystem.isBlockedSync(peer)) {
            await this.endCall('blocked');
            throw new Error('recipient-blocked');
        }
        const callType = this.currentCall.type;
        this.currentCall.status = 'connecting';
        this.notifyCallState(this.currentCall);

        try {
            const signalingGeneration = this.lifecycleGeneration;
            await this.waitForSignalSession(peer, signalingGeneration);
            if (
                signalingGeneration !== this.lifecycleGeneration ||
                !this.currentCall ||
                this.currentCall.id !== callId ||
                this.currentCall.peer !== peer
            ) {
                throw new Error('Call was cancelled while preparing secure signaling');
            }

            // Set up local media
            const actualCallType = await this.setupLocalMedia(callType, callId);
            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== peer) {
                throw new Error('Call was cancelled');
            }
            this.currentCall.type = actualCallType;

            if (!this.callConnection || !this.audioStream || !this.encryptionContext) {
                await this.establishCallConnection(peer, callId);
            }

            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== peer) {
                throw new Error('Call was cancelled');
            }

            await this.sendCallSignal({
                type: 'answer',
                callId,
                from: this.localUsername,
                to: peer,
                timestamp: Date.now()
            });

            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== peer) {
                throw new Error('Call ended while the answer was being delivered');
            }

            await this.startMediaStreaming(callId);
            this.markConnected(callId);

        } catch (error) {
            if (this.currentCall?.id === callId) {
                await this.endCall('failed');
            }
            throw error;
        }
    }

    // Decline incoming call
    async declineCall(callId: string): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== callId) { return; }
        if (this.currentCall.direction !== 'incoming' || this.currentCall.status !== 'ringing') { return; }

        const call = this.currentCall;
        const signal: CallSignal = {
            type: 'decline-call',
            callId,
            from: this.localUsername,
            to: call.peer,
            timestamp: Date.now()
        };

        call.status = 'declined';
        call.endTime = Date.now();
        const start = call.startTime ?? this.ringStartAt ?? call.endTime;
        call.duration = Math.max(0, call.endTime - start);
        call.endReason = 'declined';
        this.notifyCallState(call);

        this.cleanup();
        await this.sendCallSignalBestEffort(signal);
    }

    // End the current call
    async endCall(reason: LocalCallEndReason = 'user'): Promise<void> {
        if (!this.currentCall) { return; }

        const call = this.currentCall;
        const endTime = Date.now();
        const duration = call.startTime ? Math.max(0, endTime - call.startTime) : 0;
        const signal: CallSignal = {
                type: 'end-call',
                callId: call.id,
                from: this.localUsername,
                to: call.peer,
                timestamp: Date.now()
        };

        call.endTime = endTime;
        call.duration = duration;
        call.status = 'ended';
        call.endReason = reason;
        this.notifyCallState(call);

        this.cleanup();
        await this.sendCallSignalBestEffort(signal);
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

        const activeStream = this.localStream;
        const activeCallId = this.currentCall?.id;
        const switchGeneration = ++this.cameraSwitchGeneration;
        let videoTrack = activeStream.getVideoTracks()[0];

        if (!videoTrack || videoTrack.readyState === 'ended') {
            let newStream: MediaStream | null = null;
            try {
                const constraints: MediaStreamConstraints = {
                    video: this.preferredCameraDeviceId
                        ? { deviceId: { exact: this.preferredCameraDeviceId } }
                        : true,
                    audio: false
                };

                await requireNativeMediaAccess('video');
                newStream = await navigator.mediaDevices.getUserMedia(constraints);
                videoTrack = newStream.getVideoTracks()[0];

                const existingVideoTrack = activeStream.getVideoTracks().find(track => track.readyState !== 'ended');
                if (
                    !videoTrack ||
                    existingVideoTrack ||
                    switchGeneration !== this.cameraSwitchGeneration ||
                    this.localStream !== activeStream ||
                    this.currentCall?.id !== activeCallId ||
                    !this.videoStream ||
                    !this.encryptionContext
                ) {
                    this.stopMediaStream(newStream);
                    return existingVideoTrack?.enabled ?? false;
                }

                videoTrack.enabled = true;
                activeStream.addTrack(videoTrack);
                await this.startVideoStreaming(videoTrack);
                if (
                    switchGeneration !== this.cameraSwitchGeneration ||
                    this.localStream !== activeStream ||
                    this.currentCall?.id !== activeCallId
                ) {
                    try { activeStream.removeTrack(videoTrack); } catch { }
                    this.stopMediaStream(newStream);
                    return false;
                }
                for (const endedTrack of activeStream.getVideoTracks()) {
                    if (endedTrack !== videoTrack && endedTrack.readyState === 'ended') {
                        try { activeStream.removeTrack(endedTrack); } catch { }
                    }
                }
                this.notifyLocalStream(activeStream);
                return true;
            } catch {
                if (videoTrack) {
                    try { activeStream.removeTrack(videoTrack); } catch { }
                }
                this.stopMediaStream(newStream);
                return false;
            }
        }

        videoTrack.enabled = !videoTrack.enabled;
        return videoTrack.enabled;
    }

    // Switch camera device
    async switchCamera(deviceId?: string): Promise<void> {
        if (!this.localStream) throw new Error('No active local media stream');
        if (deviceId !== undefined && !isValidMediaDeviceId(deviceId)) {
            throw new Error('Invalid camera device identifier');
        }

        const activeStream = this.localStream;
        const activeCallId = this.currentCall?.id;
        const switchGeneration = ++this.cameraSwitchGeneration;
        const videoTrack = activeStream.getVideoTracks()[0];
        if (!videoTrack) throw new Error('No active video track');

        let newStream: MediaStream | null = null;
        let installed = false;
        try {
            await requireNativeMediaAccess('video');

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
            if (
                !newVideoTrack ||
                switchGeneration !== this.cameraSwitchGeneration ||
                this.localStream !== activeStream ||
                this.currentCall?.id !== activeCallId ||
                activeStream.getVideoTracks()[0] !== videoTrack
            ) {
                this.stopMediaStream(newStream);
                newStream = null;
                throw new Error('Call changed while the camera was switching');
            }
            activeStream.addTrack(newVideoTrack);
            installed = true;
            if (this.captureVideoEl && this.videoStream && this.encryptionContext) {
                await this.startVideoStreaming(newVideoTrack);
            }
            if (
                switchGeneration !== this.cameraSwitchGeneration ||
                this.localStream !== activeStream ||
                this.currentCall?.id !== activeCallId ||
                !activeStream.getVideoTracks().includes(newVideoTrack)
            ) {
                throw new Error('Call changed while the camera was switching');
            }
            activeStream.removeTrack(videoTrack);
            try { videoTrack.stop(); } catch { }

            const selectedDeviceId = deviceId || newVideoTrack.getSettings().deviceId;
            if (isValidMediaDeviceId(selectedDeviceId)) {
                this.preferredCameraDeviceId = selectedDeviceId;
                const account = this.localUsername;
                void Promise.resolve().then(() => {
                    if (
                        this.destroyed ||
                        this.localUsername !== account ||
                        this.preferredCameraDeviceId !== selectedDeviceId
                    ) return;
                    return encryptedStorage.setItem(STORAGE_KEYS.PREFERRED_CAMERA, selectedDeviceId);
                }).catch(() => { });
            }
            this.notifyLocalStream(activeStream);
        } catch (error) {
            if (newStream) {
                const newVideoTrack = newStream.getVideoTracks()[0];
                if (installed && newVideoTrack && this.localStream === activeStream) {
                    try { activeStream.removeTrack(newVideoTrack); } catch { }
                    if (
                        switchGeneration === this.cameraSwitchGeneration &&
                        videoTrack.readyState !== 'ended' &&
                        this.captureVideoEl &&
                        this.videoStream &&
                        this.encryptionContext
                    ) {
                        try { await this.startVideoStreaming(videoTrack); } catch { }
                    }
                }
                this.stopMediaStream(newStream);
            }
            throw error;
        }
    }

    // Switch microphone device
    async switchMicrophone(deviceId: string): Promise<void> {
        if (!this.localStream) throw new Error('No active local media stream');
        if (!isValidMediaDeviceId(deviceId)) throw new Error('Invalid microphone device identifier');

        const activeStream = this.localStream;
        const activeCallId = this.currentCall?.id;
        const switchGeneration = ++this.microphoneSwitchGeneration;
        const audioTrack = activeStream.getAudioTracks()[0];
        if (!audioTrack) throw new Error('No active audio track');

        let newStream: MediaStream | null = null;
        let installed = false;
        try {
            await requireNativeMediaAccess('audio');
            newStream = await navigator.mediaDevices.getUserMedia({
                audio: { deviceId: { exact: deviceId } },
                video: false
            });
            const newAudioTrack = newStream.getAudioTracks()[0];
            if (
                !newAudioTrack ||
                switchGeneration !== this.microphoneSwitchGeneration ||
                this.localStream !== activeStream ||
                this.currentCall?.id !== activeCallId ||
                activeStream.getAudioTracks()[0] !== audioTrack
            ) {
                this.stopMediaStream(newStream);
                newStream = null;
                throw new Error('Call changed while the microphone was switching');
            }

            newAudioTrack.enabled = audioTrack.enabled;
            activeStream.addTrack(newAudioTrack);
            installed = true;
            if (this.callAudioNode && this.audioStream && this.encryptionContext) {
                await this.startAudioStreaming(newAudioTrack);
            }
            if (
                switchGeneration !== this.microphoneSwitchGeneration ||
                this.localStream !== activeStream ||
                this.currentCall?.id !== activeCallId ||
                !activeStream.getAudioTracks().includes(newAudioTrack)
            ) {
                throw new Error('Call changed while the microphone was switching');
            }
            activeStream.removeTrack(audioTrack);
            try { audioTrack.stop(); } catch { }

            this.notifyLocalStream(activeStream);

        } catch (error) {
            if (newStream) {
                const newAudioTrack = newStream.getAudioTracks()[0];
                if (installed && newAudioTrack && this.localStream === activeStream) {
                    try { activeStream.removeTrack(newAudioTrack); } catch { }
                    if (
                        switchGeneration === this.microphoneSwitchGeneration &&
                        audioTrack.readyState !== 'ended' &&
                        this.callAudioNode &&
                        this.audioStream &&
                        this.encryptionContext
                    ) {
                        try { await this.startAudioStreaming(audioTrack); } catch { }
                    }
                }
                this.stopMediaStream(newStream);
            }
            throw error;
        }
    }

    // Start screen sharing
    async startScreenShare(selectedSource?: ScreenCaptureSelection): Promise<void> {
        if (
            !this.callConnection ||
            !this.currentCall ||
            this.currentCall.status !== 'connected' ||
            !this.encryptionContext
        ) {
            throw new Error('No active call');
        }
        if (this.isScreenSharing || this.screenSharePending) {
            throw new Error('Screen sharing already active or starting');
        }
        if (selectedSource !== undefined && !isValidScreenCaptureSelection(selectedSource)) {
            throw new Error('Invalid screen source selection');
        }
        if (isTauri() && selectedSource === undefined) {
            throw new Error('A selected screen source is required');
        }

        const callId = this.currentCall.id;
        const peer = this.currentCall.peer;
        const connection = this.callConnection;
        const generation = ++this.screenShareGeneration;
        this.screenSharePending = true;
        let acquiredStream: MediaStream | null = null;
        let transportStream: SecureStream | null = null;
        const shareIsCurrent = () =>
            generation === this.screenShareGeneration &&
            this.currentCall?.id === callId &&
            this.currentCall.status === 'connected' &&
            this.callConnection === connection &&
            !!this.encryptionContext;

        try {
            const settings = await this.getMediaSettings();
            if (!shareIsCurrent()) {
                throw new Error('Call ended before screen capture');
            }
            const resolution = settings.resolution;

            transportStream = await connection.createStream({
                type: 'call-screen',
                lossy: true
            });
            if (!shareIsCurrent()) {
                throw new Error('Call ended while screen sharing was starting');
            }
            this.screenShareStream = transportStream;

            const readyPromise = this.waitForScreenShareReady(
                callId,
                transportStream.id,
                generation
            );
            await this.sendCallSignal({
                type: 'screen-share-start',
                callId,
                from: this.localUsername,
                to: peer,
                data: { streamId: transportStream.id },
                timestamp: Date.now()
            });
            if (
                generation !== this.screenShareGeneration ||
                this.screenShareStream !== transportStream ||
                !shareIsCurrent()
            ) {
                throw new Error('Call ended while screen sharing was being announced');
            }
            if (!await readyPromise || !shareIsCurrent() || this.screenShareStream !== transportStream) {
                throw new Error('Peer did not confirm the screen share');
            }

            let screenStream: MediaStream;
            if (typeof window !== 'undefined' && isTauri()) {
                const sourceId = selectedSource!.id;
                if (!shareIsCurrent()) {
                    throw new Error('Call ended before screen capture');
                }

                try {
                    await requireNativeMediaAccess('video');
                    const mandatory: Record<string, string | number> = {
                        chromeMediaSource: 'desktop',
                        chromeMediaSourceId: sourceId,
                        maxFrameRate: settings.frameRate
                    };
                    if (!resolution.isNative) {
                        mandatory.maxWidth = resolution.width;
                        mandatory.maxHeight = resolution.height;
                    }
                    screenStream = await navigator.mediaDevices.getUserMedia({
                        audio: false,
                        video: {
                            mandatory
                        }
                    } as any);
                } catch (streamErr) {
                    throw new Error('Failed to capture screen: ' + (streamErr instanceof Error ? streamErr.message : String(streamErr)));
                }
            } else {
                const videoConstraints: MediaTrackConstraints = {
                    frameRate: settings.frameRate
                };
                if (!resolution.isNative) {
                    videoConstraints.width = resolution.width;
                    videoConstraints.height = resolution.height;
                }
                if (!shareIsCurrent()) {
                    throw new Error('Call ended before screen capture');
                }
                screenStream = await navigator.mediaDevices.getDisplayMedia({
                    video: videoConstraints,
                    audio: false
                });
            }

            acquiredStream = screenStream;
            if (!shareIsCurrent()) {
                throw new Error('Call ended while screen capture was starting');
            }

            this.screenStream = screenStream;
            this.isScreenSharing = true;
            const screenTrack = screenStream.getVideoTracks()[0];
            if (!screenTrack) throw new Error('Screen capture did not provide a video track');
            screenTrack.onended = () => { void this.stopScreenShare(); };

            if (
                generation !== this.screenShareGeneration ||
                this.screenStream !== screenStream ||
                this.screenShareStream !== transportStream ||
                !shareIsCurrent()
            ) {
                throw new Error('Call ended while screen sharing was starting');
            }
            await this.startScreenStreaming();

        } catch (error) {
            if (acquiredStream && this.screenStream !== acquiredStream) {
                this.stopMediaStream(acquiredStream);
            }
            if (transportStream && this.screenShareStream !== transportStream) {
                this.closeSecureStream(transportStream);
            }
            if (generation === this.screenShareGeneration) {
                this.cleanupScreenShareLocal();
            }
            if (transportStream && this.currentCall?.id === callId && this.currentCall.peer === peer) {
                await this.sendCallSignalBestEffort({
                    type: 'screen-share-stop',
                    callId,
                    from: this.localUsername,
                    to: peer,
                    data: { streamId: transportStream.id },
                    timestamp: Date.now()
                });
            }
            throw error;
        } finally {
            if (generation === this.screenShareGeneration) {
                this.screenSharePending = false;
            }
        }
    }

    // Stop screen sharing
    async stopScreenShare(): Promise<void> {
        if (!this.isScreenSharing && !this.screenSharePending) {
            return;
        }

        const call = this.currentCall;
        const streamId = this.screenShareStream?.id ?? null;
        this.cleanupScreenShareLocal();

        if (call && streamId) {
            await this.sendCallSignalBestEffort({
                type: 'screen-share-stop',
                callId: call.id,
                from: this.localUsername,
                to: call.peer,
                data: { streamId },
                timestamp: Date.now()
            });
        }
    }

    // Set up local media capture
    private async setupLocalMedia(callType: 'audio' | 'video', expectedCallId: string): Promise<'audio' | 'video'> {
        this.teardownCallMediaElements();
        if (this.localStream) {
            this.stopMediaStream(this.localStream);
            this.localStream = null;
            this.lastCaptureReleaseAt = Date.now();
        }
        
        const sinceRelease = Date.now() - this.lastCaptureReleaseAt;
        if (this.lastCaptureReleaseAt > 0 && sinceRelease < CALL_DEVICE_SETTLE_MS) {
            await new Promise(resolve => setTimeout(resolve, CALL_DEVICE_SETTLE_MS - sinceRelease));
        }
        const callIsCurrent = () => this.currentCall?.id === expectedCallId;
        if (!callIsCurrent()) {
            throw new Error('Call was cancelled before media capture');
        }
        const attempts: Array<{ video: boolean | MediaTrackConstraints; resultingType: 'audio' | 'video' }> = [];

        if (callType === 'video') {
            if (this.preferredCameraDeviceId) {
                attempts.push({
                    video: { deviceId: { exact: this.preferredCameraDeviceId } },
                    resultingType: 'video'
                });
            }

            attempts.push({
                video: true,
                resultingType: 'video'
            });
        }

        attempts.push({
            video: false,
            resultingType: 'audio'
        });

        let lastError: unknown = null;

        for (const attempt of attempts) {
            if (!callIsCurrent()) {
                throw new Error('Call was cancelled before media capture');
            }
            try {
                await requireNativeMediaAccess(attempt.video ? 'audio-video' : 'audio');
                const acquiredStream = await navigator.mediaDevices.getUserMedia({
                    audio: true,
                    video: attempt.video
                });

                if (!callIsCurrent()) {
                    this.stopMediaStream(acquiredStream);
                    throw new Error('Call was cancelled while media permission was pending');
                }

                this.localStream = acquiredStream;

                this.notifyLocalStream(this.localStream);
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
    private async establishCallConnection(
        peer: string,
        expectedCallId: string
    ): Promise<'initiator' | 'responder'> {
        const existingConnection = this.transport.getConnection(peer);
        const connection = existingConnection && existingConnection.state === 'connected'
            ? existingConnection
            : await this.transport.connect(peer, {
                timeout: P2P_CONNECTION_TIMEOUT_MS
            });

        const callIsCurrent = () =>
            this.currentCall?.id === expectedCallId && this.currentCall.peer === peer;
        if (!callIsCurrent()) throw new Error('Call was cancelled while connecting');

        let audioStream: SecureStream | null = null;
        let videoStream: SecureStream | null = null;
        let context: MediaEncryptionContext | null = null;
        try {
            audioStream = await connection.createStream({
                type: 'call-audio',
                id: `call-audio:${expectedCallId}`,
                lossy: true
            });
            if (!callIsCurrent()) throw new Error('Call was cancelled while opening audio');

            if (this.currentCall?.type === 'video') {
                videoStream = await connection.createStream({
                    type: 'call-video',
                    id: `call-video:${expectedCallId}`,
                    lossy: true
                });
                if (!callIsCurrent()) throw new Error('Call was cancelled while opening video');
            }

            context = this.createMediaEncryptionContext(connection, expectedCallId);
            if (!callIsCurrent()) throw new Error('Call was cancelled while creating media keys');

            this.clearEncryptionContext();
            this.mediaGeneration += 1;
            this.callConnection = connection;
            this.audioStream = audioStream;
            this.videoStream = videoStream;
            this.encryptionContext = context;
            this.startKeyRotation();

            const role = (connection as any).getEffectiveRole?.();
            return role === 'responder' ? 'responder' : 'initiator';
        } catch (error) {
            if (audioStream && this.audioStream !== audioStream) this.closeSecureStream(audioStream);
            if (videoStream && this.videoStream !== videoStream) this.closeSecureStream(videoStream);
            if (context && this.encryptionContext !== context) this.zeroEncryptionContext(context);
            throw error;
        }
    }

    private zeroEncryptionContext(ctx: MediaEncryptionContext): void {
        this.zeroMediaFamily({
            audio: ctx.sendAudioKey,
            video: ctx.sendVideoKey,
            screen: ctx.sendScreenKey
        });
        this.zeroMediaFamily({
            audio: ctx.recvAudioKey,
            video: ctx.recvVideoKey,
            screen: ctx.recvScreenKey
        });
        if (ctx.previousRecvKeys) this.zeroMediaFamily(ctx.previousRecvKeys);
    }

    private createMediaEncryptionContext(
        connection: SecureConnection,
        callId: string
    ): MediaEncryptionContext {
        if (!isValidCallId(callId)) throw new Error('Invalid call key context');
        const session = (connection as any).getSession?.() as PQNoiseSession | null;
        if (!session) {
            throw new Error('No encryption session');
        }

        // Derive per-stream keys from session secret
        const status = session.exportDirectionalKeyMaterial();

        const sendDir = status.role === 'initiator' ? 'i2r' : 'r2i';
        const recvDir = status.role === 'initiator' ? 'r2i' : 'i2r';

        const deriveFamily = (keyMaterial: Uint8Array, dir: string): MediaKeyFamily => {
            let base: Uint8Array | null = null;
            let audio: Uint8Array | null = null;
            let video: Uint8Array | null = null;
            let screen: Uint8Array | null = null;
            try {
                base = PostQuantumHash.deriveKey(
                    keyMaterial,
                    CALL_MEDIA_SALT,
                    `${PROTOCOL_KEYS.CALL_MEDIA_CONTEXT_PREFIX}${dir}:${callId}`,
                    32
                );
                audio = deriveLabeledMediaKey(base, CALL_MEDIA_AUDIO_LABEL);
                video = deriveLabeledMediaKey(base, CALL_MEDIA_VIDEO_LABEL);
                screen = deriveLabeledMediaKey(base, CALL_MEDIA_SCREEN_LABEL);
                return { audio, video, screen };
            } catch (error) {
                audio?.fill(0);
                video?.fill(0);
                screen?.fill(0);
                throw error;
            } finally {
                base?.fill(0);
            }
        };

        let send: MediaKeyFamily | null = null;
        let recv: MediaKeyFamily | null = null;
        try {
            send = deriveFamily(status.sendKey, sendDir);
            recv = deriveFamily(status.receiveKey, recvDir);
            this.mediaReplayWindows.clear();

            const context: MediaEncryptionContext = {
                session,
                sendAudioKey: send.audio,
                sendVideoKey: send.video,
                sendScreenKey: send.screen,
                recvAudioKey: recv.audio,
                recvVideoKey: recv.video,
                recvScreenKey: recv.screen,
                sendEpoch: 0,
                recvEpoch: 0,
                previousRecvKeys: null,
                frameCounter: 0n
            };
            send = null;
            recv = null;
            return context;
        } finally {
            if (send) this.zeroMediaFamily(send);
            if (recv) this.zeroMediaFamily(recv);
            SecureMemory.zeroBuffer(status.sendKey);
            SecureMemory.zeroBuffer(status.receiveKey);
        }
    }

    private mediaKey(family: MediaKeyFamily, kind: MediaKind): Uint8Array {
        return family[kind];
    }

    private rotateMediaKey(key: Uint8Array): Uint8Array {
        return deriveLabeledMediaKey(key, CALL_MEDIA_ROTATE_LABEL);
    }

    private rotateMediaFamily(family: MediaKeyFamily): MediaKeyFamily {
        let audio: Uint8Array | null = null;
        let video: Uint8Array | null = null;
        let screen: Uint8Array | null = null;
        try {
            audio = this.rotateMediaKey(family.audio);
            video = this.rotateMediaKey(family.video);
            screen = this.rotateMediaKey(family.screen);
            return { audio, video, screen };
        } catch (error) {
            audio?.fill(0);
            video?.fill(0);
            screen?.fill(0);
            throw error;
        }
    }

    private zeroMediaFamily(family: MediaKeyFamily): void {
        SecureMemory.zeroBuffer(family.audio);
        SecureMemory.zeroBuffer(family.video);
        SecureMemory.zeroBuffer(family.screen);
    }

    private clearEncryptionContext(): void {
        const ctx = this.encryptionContext;
        if (!ctx) return;

        this.zeroEncryptionContext(ctx);
        this.encryptionContext = null;
        this.mediaReplayWindows.clear();
    }

    private isMediaFrameFresh(epoch: number, kind: MediaKind, frameNumber: bigint): boolean {
        const window = this.mediaReplayWindows.get(`${epoch}:${kind}`);
        if (!window) return true;
        if (frameNumber + MEDIA_REPLAY_WINDOW_FRAMES <= window.highest) return false;
        const slot = Number(frameNumber % MEDIA_REPLAY_WINDOW_FRAMES);
        return window.slots[slot] !== frameNumber;
    }

    private commitMediaFrame(epoch: number, kind: MediaKind, frameNumber: bigint): boolean {
        const key = `${epoch}:${kind}`;
        let window = this.mediaReplayWindows.get(key);
        if (!window) {
            window = {
                highest: frameNumber,
                slots: new Array<bigint | undefined>(MEDIA_REPLAY_WINDOW_SIZE)
            };
            this.mediaReplayWindows.set(key, window);
        }
        const slot = Number(frameNumber % MEDIA_REPLAY_WINDOW_FRAMES);
        if (
            window.slots[slot] === frameNumber ||
            frameNumber + MEDIA_REPLAY_WINDOW_FRAMES <= window.highest
        ) {
            return false;
        }
        if (frameNumber > window.highest) window.highest = frameNumber;
        
        window.slots[slot] = frameNumber;
        for (const replayKey of this.mediaReplayWindows.keys()) {
            const separator = replayKey.indexOf(':');
            const replayEpoch = Number(replayKey.slice(0, separator));
            if (Number.isSafeInteger(replayEpoch) && replayEpoch + 1 < epoch) {
                this.mediaReplayWindows.delete(replayKey);
            }
        }
        return true;
    }

    private validateJpegDimensions(bytes: Uint8Array): { width: number; height: number } {
        return validateJpegContainer(
            bytes,
            {
                maxWidth: MAX_DECODED_MEDIA_WIDTH,
                maxHeight: MAX_DECODED_MEDIA_HEIGHT,
                maxPixels: MAX_DECODED_MEDIA_PIXELS
            },
            'media JPEG',
            'Decoded media dimensions exceed limit'
        );
    }

    private createJpegBlob(bytes: Uint8Array): Blob {
        const snapshot = new Uint8Array(new ArrayBuffer(bytes.byteLength));
        snapshot.set(bytes);
        try {
            return new Blob([snapshot.buffer], { type: 'image/jpeg' });
        } finally {
            snapshot.fill(0);
        }
    }

    private encryptMediaFrame(plaintext: Uint8Array, kind: MediaKind): Uint8Array {
        const ctx = this.encryptionContext;
        if (!ctx) throw new Error('Media encryption context unavailable');
        const maxPlaintext = kind === 'audio' ? MAX_AUDIO_PLAINTEXT_BYTES : MAX_VIDEO_PLAINTEXT_BYTES;
        if (
            plaintext.length === 0 ||
            plaintext.length > maxPlaintext ||
            (kind === 'audio' && plaintext.length % Float32Array.BYTES_PER_ELEMENT !== 0)
        ) {
            throw new Error('Media plaintext size is invalid');
        }

        const frameNum = ctx.frameCounter;
        if (frameNum > MAX_MEDIA_FRAME_NUMBER) throw new Error('Media frame counter exhausted');
        ctx.frameCounter += 1n;

        const header = new Uint8Array(MEDIA_FRAME_HEADER_SIZE);
        const headerView = new DataView(header.buffer);
        headerView.setBigUint64(0, BigInt.asUintN(64, frameNum), false);
        headerView.setUint32(8, ctx.sendEpoch, false);

        const sendFamily: MediaKeyFamily = {
            audio: ctx.sendAudioKey,
            video: ctx.sendVideoKey,
            screen: ctx.sendScreenKey
        };
        let encrypted: { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array } | null = null;
        try {
            encrypted = PostQuantumAEAD.encrypt(
                plaintext,
                this.mediaKey(sendFamily, kind),
                header
            );

            const frame = new Uint8Array(
                MEDIA_FRAME_HEADER_SIZE + PQ_AEAD_NONCE_SIZE + encrypted.ciphertext.length + PQ_AEAD_MAC_SIZE
            );
            frame.set(header, 0);
            frame.set(encrypted.nonce, MEDIA_FRAME_HEADER_SIZE);
            frame.set(encrypted.ciphertext, MEDIA_FRAME_HEADER_SIZE + PQ_AEAD_NONCE_SIZE);
            frame.set(encrypted.tag, frame.length - PQ_AEAD_MAC_SIZE);
            return frame;
        } finally {
            SecureMemory.zeroBuffer(header);
            if (encrypted) {
                SecureMemory.zeroBuffer(encrypted.ciphertext);
                SecureMemory.zeroBuffer(encrypted.nonce);
                SecureMemory.zeroBuffer(encrypted.tag);
            }
        }
    }

    private decryptMediaFrame(frame: Uint8Array, kind: MediaKind): Uint8Array {
        const ctx = this.encryptionContext;
        if (!ctx) throw new Error('Media encryption context unavailable');

        const minimumLength = MEDIA_FRAME_HEADER_SIZE + PQ_AEAD_NONCE_SIZE + PQ_AEAD_MAC_SIZE;
        if (frame.length <= minimumLength) throw new Error('Media frame is too short');

        const header = frame.subarray(0, MEDIA_FRAME_HEADER_SIZE);
        const headerView = new DataView(header.buffer, header.byteOffset, header.byteLength);
        const frameNumber = headerView.getBigUint64(0, false);
        const epoch = headerView.getUint32(8, false);
        if (!this.isMediaFrameFresh(epoch, kind, frameNumber)) {
            throw new Error('Media frame replay rejected');
        }
        const nonceStart = MEDIA_FRAME_HEADER_SIZE;
        const ciphertextStart = nonceStart + PQ_AEAD_NONCE_SIZE;
        const tagStart = frame.length - PQ_AEAD_MAC_SIZE;
        const nonce = frame.subarray(nonceStart, ciphertextStart);
        const ciphertext = frame.subarray(ciphertextStart, tagStart);
        const tag = frame.subarray(tagStart);

        let receiveKey: Uint8Array;
        let commit = (): void => { };
        let discard = (): void => { };

        if (epoch === ctx.recvEpoch) {
            receiveKey = this.mediaKey({
                audio: ctx.recvAudioKey,
                video: ctx.recvVideoKey,
                screen: ctx.recvScreenKey
            }, kind);
        } else if (ctx.previousRecvKeys && epoch === ctx.previousRecvKeys.epoch) {
            receiveKey = this.mediaKey(ctx.previousRecvKeys, kind);
        } else {
            if (epoch < ctx.recvEpoch) throw new Error('Media frame epoch is too old');
            const advance = epoch - ctx.recvEpoch;
            if (advance > MAX_MEDIA_EPOCH_ADVANCE) throw new Error('Media frame epoch is too far ahead');

            const generated: MediaKeyFamily[] = [];
            let family: MediaKeyFamily = {
                audio: ctx.recvAudioKey,
                video: ctx.recvVideoKey,
                screen: ctx.recvScreenKey
            };
            try {
                for (let i = 0; i < advance; i += 1) {
                    family = this.rotateMediaFamily(family);
                    generated.push(family);
                }
            } catch (error) {
                generated.forEach(candidate => this.zeroMediaFamily(candidate));
                throw error;
            }

            receiveKey = this.mediaKey(generated[generated.length - 1], kind);
            discard = (): void => {
                generated.forEach(candidate => this.zeroMediaFamily(candidate));
            };
            commit = (): void => {
                const previous = ctx.previousRecvKeys;
                if (previous) this.zeroMediaFamily(previous);

                const oldCurrent: MediaKeyFamily = {
                    audio: ctx.recvAudioKey,
                    video: ctx.recvVideoKey,
                    screen: ctx.recvScreenKey
                };
                const nextCurrent = generated[generated.length - 1];
                const nextPrevious = advance === 1 ? oldCurrent : generated[generated.length - 2];

                if (advance > 1) {
                    this.zeroMediaFamily(oldCurrent);
                    generated.slice(0, -2).forEach(candidate => this.zeroMediaFamily(candidate));
                }

                ctx.previousRecvKeys = {
                    epoch: epoch - 1,
                    audio: nextPrevious.audio,
                    video: nextPrevious.video,
                    screen: nextPrevious.screen
                };
                ctx.recvAudioKey = nextCurrent.audio;
                ctx.recvVideoKey = nextCurrent.video;
                ctx.recvScreenKey = nextCurrent.screen;
                ctx.recvEpoch = epoch;
            };
        }

        try {
            const plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, receiveKey, header);
            const maxPlaintext = kind === 'audio' ? MAX_AUDIO_PLAINTEXT_BYTES : MAX_VIDEO_PLAINTEXT_BYTES;
            if (
                plaintext.length === 0 ||
                plaintext.length > maxPlaintext ||
                (kind === 'audio' && plaintext.length % Float32Array.BYTES_PER_ELEMENT !== 0)
            ) {
                plaintext.fill(0);
                throw new Error('Media plaintext size is invalid');
            }
            if (!this.commitMediaFrame(epoch, kind, frameNumber)) {
                plaintext.fill(0);
                throw new Error('Media frame replay rejected');
            }
            commit();
            return plaintext;
        } catch (error) {
            discard();
            throw error;
        }
    }

    // Start streaming media frames
    private async startMediaStreaming(expectedCallId: string): Promise<void> {
        if (
            this.currentCall?.id !== expectedCallId ||
            this.currentCall.status !== 'connecting' ||
            !this.localStream ||
            !this.encryptionContext
        ) {
            throw new Error('Call media startup is stale or incomplete');
        }

        const generation = this.mediaGeneration;
        const starters: Promise<void>[] = [];

        // Set up audio processing
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            starters.push(this.startAudioStreaming(audioTrack));
        }

        // Set up video processing
        const videoTrack = this.localStream.getVideoTracks()[0];
        if (videoTrack && this.videoStream) {
            starters.push(this.startVideoStreaming(videoTrack));
        }

        await Promise.all(starters);
        if (
            generation !== this.mediaGeneration ||
            this.currentCall?.id !== expectedCallId ||
            this.currentCall.status !== 'connecting' ||
            !this.encryptionContext
        ) {
            throw new Error('Call ended while media was starting');
        }
        this.startReceivingMedia();
    }

    // Get the single shared capture AudioContext
    private async getSharedAudioContext(): Promise<AudioContext> {
        if (this.sharedAudioContext && this.sharedAudioContext.state !== 'closed') {
            if (this.sharedAudioContext.state === 'suspended') {
                try { await this.sharedAudioContext.resume(); } catch { }
            }
            return this.sharedAudioContext;
        }
        const ctx = new AudioContext({ sampleRate: 48_000 });
        this.sharedAudioContext = ctx;
        this.audioWorkletLoaded = false;
        return ctx;
    }

    // Shared playback AudioContext
    private async getSharedReceiveAudioContext(): Promise<AudioContext> {
        if (this.sharedReceiveAudioContext && this.sharedReceiveAudioContext.state !== 'closed') {
            if (this.sharedReceiveAudioContext.state === 'suspended') {
                try { await this.sharedReceiveAudioContext.resume(); } catch { }
            }
            return this.sharedReceiveAudioContext;
        }
        const ctx = new AudioContext({ sampleRate: 48000 });
        this.sharedReceiveAudioContext = ctx;
        this.receiveAudioWorkletLoaded = false;
        return ctx;
    }

    private disconnectAudioSender(
        source: MediaStreamAudioSourceNode | null,
        node: AudioWorkletNode | null
    ): void {
        this.destroyAudioWorkletNode(node);
        if (source) {
            try { source.disconnect(); } catch { }
        }
    }

    private destroyAudioWorkletNode(node: AudioWorkletNode | null): void {
        if (!node) return;
        try { node.port.postMessage({ type: 'destroy' }); } catch { }
        try { node.port.onmessage = null; } catch { }
        try { node.disconnect(); } catch { }
    }

    private teardownCallAudioSender(): void {
        const source = this.callAudioSource;
        const node = this.callAudioNode;
        this.callAudioSource = null;
        this.callAudioNode = null;
        this.disconnectAudioSender(source, node);
    }

    // Tear down this call audio graph nodes
    private teardownCallAudioNodes(): void {
        this.teardownCallAudioSender();
        if (this.callReceiveAudioNode) {
            this.destroyAudioWorkletNode(this.callReceiveAudioNode);
            this.callReceiveAudioNode = null;
        }
    }

    // Detach this call video elements
    private detachMediaElement(el: HTMLVideoElement | null): void {
        if (!el) return;
        try { el.onloadedmetadata = null; } catch { }
        try { el.pause(); } catch { }
        try { el.srcObject = null; } catch { }
        try { el.removeAttribute('src'); } catch { }
        try { el.load?.(); } catch { }
        try { el.remove(); } catch { }
    }

    private teardownCallMediaElements(): void {
        this.remoteVideoRenderId += 1;
        for (const el of [this.captureVideoEl, this.screenCaptureVideoEl]) {
            this.detachMediaElement(el);
        }
        this.captureVideoEl = null;
        this.screenCaptureVideoEl = null;
    }

    private waitForScreenShareReady(
        callId: string,
        streamId: string,
        generation: number
    ): Promise<boolean> {
        this.cancelPendingScreenShareReady();
        return new Promise<boolean>((resolve) => {
            let settled = false;
            let pending!: PendingScreenShareReady;
            const finish = (ready: boolean) => {
                if (settled) return;
                settled = true;
                clearTimeout(pending.timeoutId);
                if (this.pendingScreenShareReady === pending) {
                    this.pendingScreenShareReady = null;
                }
                resolve(ready);
            };
            pending = {
                callId,
                streamId,
                generation,
                timeoutId: setTimeout(() => finish(false), SCREEN_SHARE_READY_TIMEOUT_MS),
                finish
            };
            this.pendingScreenShareReady = pending;
        });
    }

    private acceptScreenShareReady(
        signal: Extract<CallSignal, { type: 'screen-share-ready' }>
    ): void {
        const pending = this.pendingScreenShareReady;
        if (
            !pending ||
            pending.callId !== signal.callId ||
            pending.streamId !== signal.data.streamId ||
            pending.generation !== this.screenShareGeneration ||
            this.currentCall?.id !== signal.callId ||
            this.currentCall.peer !== signal.from ||
            this.currentCall.status !== 'connected' ||
            this.screenShareStream?.id !== signal.data.streamId
        ) return;
        pending.finish(true);
    }

    private cancelPendingScreenShareReady(): void {
        this.pendingScreenShareReady?.finish(false);
    }

    private cleanupScreenShareLocal(): void {
        this.cancelPendingScreenShareReady();
        this.screenShareGeneration += 1;
        this.screenSharePending = false;
        const stream = this.screenStream;
        this.screenStream = null;
        this.isScreenSharing = false;
        this.stopMediaStream(stream, true);

        const transportStream = this.screenShareStream;
        this.screenShareStream = null;
        this.closeSecureStream(transportStream);

        this.detachMediaElement(this.screenCaptureVideoEl);
        this.screenCaptureVideoEl = null;
    }

    private cleanupRemoteScreenShare(): void {
        this.expectedRemoteScreenStreamId = null;
        const incoming = this.incomingScreenStream;
        this.incomingScreenStream = null;
        this.abortSecureStream(incoming, 'Screen sharing stopped');

        this.stopMediaStream(this.remoteScreenStream);
        this.remoteScreenStream = null;
        this.notifyRemoteScreenStream(null);
    }

    private receiveExpectedScreenStream(stream: SecureStream, connection: SecureConnection): void {
        if (
            stream.type !== 'call-screen' ||
            stream.id !== this.expectedRemoteScreenStreamId ||
            this.callConnection !== connection ||
            !this.currentCall ||
            this.currentCall.status !== 'connected' ||
            !this.encryptionContext
        ) {
            this.abortSecureStream(stream, 'Unannounced call screen stream');
            return;
        }
        if (this.incomingScreenStream === stream) return;

        void this.receiveScreenStream(stream).catch(() => {
            if (this.incomingScreenStream === stream) {
                this.cleanupRemoteScreenShare();
            } else {
                this.abortSecureStream(stream, 'Failed to initialize screen stream');
            }
        });
    }

    // Stream audio frames
    private async startAudioStreaming(track: MediaStreamTrack): Promise<void> {
        if (!this.audioStream || !this.encryptionContext) return;

        const generation = this.mediaGeneration;
        const stream = this.audioStream;

        const audioContext = await this.getSharedAudioContext();
        if (!this.audioWorkletLoaded) {
            await this.loadAudioWorklet(audioContext);
            this.audioWorkletLoaded = true;
        }

        if (generation !== this.mediaGeneration || this.audioStream !== stream || !this.encryptionContext) return;

        const source = audioContext.createMediaStreamSource(new MediaStream([track]));
        let workletNode: AudioWorkletNode | null = null;

        try {
            workletNode = new AudioWorkletNode(audioContext, 'audio-sender-processor');
            const senderNode = workletNode;

            // Backpressure guard
            let sendInFlight = false;
            senderNode.port.onmessage = async (e) => {
                const inputData = e.data;
                if (!(inputData instanceof Float32Array)) return;
                const incomingBytes = new Uint8Array(
                    inputData.buffer,
                    inputData.byteOffset,
                    inputData.byteLength
                );
                if (inputData.byteLength === 0 || inputData.byteLength > MAX_AUDIO_PLAINTEXT_BYTES) {
                    SecureMemory.zeroBuffer(incomingBytes);
                    return;
                }
                if (
                    generation !== this.mediaGeneration ||
                    !this.encryptionContext ||
                    this.audioStream !== stream ||
                    this.callAudioNode !== senderNode ||
                    sendInFlight
                ) {
                    SecureMemory.zeroBuffer(incomingBytes);
                    return;
                }
                sendInFlight = true;
                let rawData: Uint8Array | null = null;
                let paddedData: Uint8Array | null = null;
                let frame: Uint8Array | null = null;
                try {
                    rawData = incomingBytes;

                    const paddedLength = Math.ceil(rawData.length / CALL_AUDIO_PADDING_BLOCK) * CALL_AUDIO_PADDING_BLOCK;
                    if (paddedLength > MAX_AUDIO_PLAINTEXT_BYTES) return;
                    paddedData = new Uint8Array(paddedLength);
                    paddedData.set(rawData);

                    frame = this.encryptMediaFrame(paddedData, 'audio');

                    await stream.write(frame);
                } catch { } finally {
                    if (rawData) SecureMemory.zeroBuffer(rawData);
                    if (paddedData) SecureMemory.zeroBuffer(paddedData);
                    if (frame) SecureMemory.zeroBuffer(frame);
                    sendInFlight = false;
                }
            };

            source.connect(senderNode);
            senderNode.connect(audioContext.destination);
            if (
                generation !== this.mediaGeneration ||
                this.audioStream !== stream ||
                !this.encryptionContext
            ) {
                this.disconnectAudioSender(source, senderNode);
                return;
            }

            const previousSource = this.callAudioSource;
            const previousNode = this.callAudioNode;
            this.callAudioSource = source;
            this.callAudioNode = senderNode;
            this.disconnectAudioSender(previousSource, previousNode);
        } catch (error) {
            this.disconnectAudioSender(source, workletNode);
            throw error;
        }
    }

    // Load audio worklet
    private async loadAudioWorklet(context: AudioContext): Promise<void> {
        try {
            await context.audioWorklet.addModule('audio-worklet-processor.js');
        } catch (error) {
            throw error;
        }
    }

    // Stream video frames
    private async startVideoStreaming(track: MediaStreamTrack): Promise<void> {
        if (!this.videoStream || !this.encryptionContext) return;

        const generation = this.mediaGeneration;
        const stream = this.videoStream;
        const initialSettings = await this.getMediaSettings();
        if (generation !== this.mediaGeneration || this.videoStream !== stream || !this.encryptionContext) return;

        const video = document.createElement('video');
        video.muted = true;
        video.playsInline = true;
        video.srcObject = new MediaStream([track]);

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) {
            this.detachMediaElement(video);
            throw new Error('Video capture canvas is unavailable');
        }
        const encodeProfile: JpegEncodeProfile = { signature: '', scale: 1, quality: 0.8 };

        const isActive = () =>
            generation === this.mediaGeneration &&
            this.captureVideoEl === video &&
            this.videoStream === stream &&
            !stream.closed &&
            !!this.encryptionContext;

        const captureFrame = async (): Promise<void> => {
            if (!isActive()) return;

            const settings = this.mediaSettings ?? initialSettings;
            const frameRate = settings.frameRate;
            let rawData: Uint8Array | null = null;
            let encryptedFrame: Uint8Array | null = null;
            try {
                rawData = await this.encodeBoundedJpegFrame(video, canvas, ctx, settings, encodeProfile);
                if (!rawData || !isActive()) return;
                if (!isActive()) return;
                encryptedFrame = this.encryptMediaFrame(rawData, 'video');
                await stream.write(encryptedFrame);
            } catch { } finally {
                if (rawData) SecureMemory.zeroBuffer(rawData);
                if (encryptedFrame) SecureMemory.zeroBuffer(encryptedFrame);
            }

            if (isActive()) {
                setTimeout(() => { void captureFrame(); }, 1000 / Math.max(1, frameRate));
            }
        };

        try {
            await video.play();
            if (
                generation !== this.mediaGeneration ||
                this.videoStream !== stream ||
                !this.encryptionContext
            ) {
                this.detachMediaElement(video);
                return;
            }
            const previous = this.captureVideoEl;
            this.captureVideoEl = video;
            if (previous !== video) this.detachMediaElement(previous);
            void captureFrame();
        } catch (error) {
            this.detachMediaElement(video);
            throw error;
        }
    }

    // Stream screen frames
    private async startScreenStreaming(): Promise<void> {
        if (!this.screenStream || !this.screenShareStream || !this.encryptionContext) {
            throw new Error('Screen media startup is incomplete');
        }

        const generation = this.mediaGeneration;
        const sourceStream = this.screenStream;
        const transportStream = this.screenShareStream;
        const initialSettings = await this.getMediaSettings();
        if (
            generation !== this.mediaGeneration ||
            this.screenStream !== sourceStream ||
            this.screenShareStream !== transportStream ||
            !this.encryptionContext
        ) return;

        const track = this.screenStream.getVideoTracks()[0];
        if (!track) return;

        const video = document.createElement('video');
        video.srcObject = sourceStream;
        this.screenCaptureVideoEl = video;

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('Screen capture canvas is unavailable');
        const encodeProfile: JpegEncodeProfile = { signature: '', scale: 1, quality: 0.8 };

        const isActive = () =>
            generation === this.mediaGeneration &&
            this.isScreenSharing &&
            this.screenStream === sourceStream &&
            this.screenShareStream === transportStream &&
            this.screenCaptureVideoEl === video &&
            !transportStream.closed &&
            !!this.encryptionContext;

        const captureFrame = async (): Promise<void> => {
            if (!isActive()) return;

            const settings = this.mediaSettings ?? initialSettings;
            const frameRate = settings.frameRate;
            let rawData: Uint8Array | null = null;
            let encryptedFrame: Uint8Array | null = null;
            try {
                rawData = await this.encodeBoundedJpegFrame(video, canvas, ctx, settings, encodeProfile);
                if (!rawData || !isActive()) return;
                if (!isActive()) return;
                encryptedFrame = this.encryptMediaFrame(rawData, 'screen');
                await transportStream.write(encryptedFrame);
            } catch { } finally {
                if (rawData) SecureMemory.zeroBuffer(rawData);
                if (encryptedFrame) SecureMemory.zeroBuffer(encryptedFrame);
            }

            if (isActive()) {
                setTimeout(() => { void captureFrame(); }, 1000 / Math.max(1, frameRate));
            }
        };

        let started = false;
        const beginCapture = () => {
            if (started) return;
            started = true;
            void captureFrame();
        };
        video.onloadedmetadata = beginCapture;
        await video.play();
        if (!isActive()) {
            this.detachMediaElement(video);
            throw new Error('Screen sharing ended while capture was starting');
        }
        if (video.readyState >= 1) beginCapture();
    }

    // Start receiving remote media
    private startReceivingMedia(): void {
        // Receive audio
        if (this.audioStream) {
            void this.receiveAudioStream().catch(() => { });
        }

        // Receive video
        if (this.videoStream) {
            void this.receiveVideoStream().catch(() => { });
        }

        // Listen for incoming screen share stream
        if (this.callConnection) {
            this.unsubscribeCallStreams();
            const connection = this.callConnection;
            this.callStreamUnsubscribe = connection.onStream((stream) => {
                if (stream.type === 'call-screen') this.receiveExpectedScreenStream(stream, connection);
            });
        }
    }

    // Receive and decode audio stream
    private async receiveAudioStream(): Promise<void> {
        if (!this.audioStream || !this.encryptionContext) return;

        const generation = this.mediaGeneration;
        const stream = this.audioStream;

        const audioContext = await this.getSharedReceiveAudioContext();
        if (!this.receiveAudioWorkletLoaded) {
            await this.loadAudioWorklet(audioContext);
            this.receiveAudioWorkletLoaded = true;
        }

        if (generation !== this.mediaGeneration || this.audioStream !== stream || !this.encryptionContext) return;

        let workletNode: AudioWorkletNode | null = null;
        try {
            workletNode = new AudioWorkletNode(audioContext, 'audio-receiver-processor');
            this.callReceiveAudioNode = workletNode;
            workletNode.connect(audioContext.destination);

            for await (const data of stream) {
                try {
                    if (generation !== this.mediaGeneration || !this.encryptionContext) break;

                    let decrypted: Uint8Array | null = null;
                    let audioData: Float32Array | null = null;
                    try {
                        decrypted = this.decryptMediaFrame(data, 'audio');
                        audioData = new Float32Array(decrypted.length / Float32Array.BYTES_PER_ELEMENT);
                        new Uint8Array(audioData.buffer).set(decrypted);
                        for (let index = 0; index < audioData.length; index += 1) {
                            const sample = audioData[index];
                            if (!Number.isFinite(sample)) {
                                throw new Error('Invalid remote audio sample');
                            }
                            audioData[index] = Math.max(-1, Math.min(1, sample));
                        }
                        workletNode.port.postMessage(audioData, [audioData.buffer]);
                        audioData = null;
                    } finally {
                        if (decrypted) SecureMemory.zeroBuffer(decrypted);
                        if (audioData && audioData.byteLength > 0) {
                            SecureMemory.zeroBuffer(new Uint8Array(
                                audioData.buffer,
                                audioData.byteOffset,
                                audioData.byteLength
                            ));
                        }
                    }
                } catch { } finally {
                    SecureMemory.zeroBuffer(data);
                }
            }
        } catch { }
        finally {
            if (workletNode && this.callReceiveAudioNode === workletNode) {
                this.destroyAudioWorkletNode(workletNode);
                this.callReceiveAudioNode = null;
            }
        }
    }

    // Receive and decode video stream
    private async receiveVideoStream(): Promise<void> {
        if (!this.videoStream || !this.encryptionContext) return;

        const generation = this.mediaGeneration;
        const stream = this.videoStream;

        const settings = await this.getMediaSettings();
        if (generation !== this.mediaGeneration || this.videoStream !== stream || !this.encryptionContext) return;

        // Create canvas for video rendering
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('Video canvas is unavailable');
        const initialDimensions = this.initialRenderDimensions(settings);
        canvas.width = initialDimensions.width;
        canvas.height = initialDimensions.height;

        const canvasStream = canvas.captureStream(settings.frameRate);

        const videoTrack = canvasStream.getVideoTracks()[0];
        if (!videoTrack) throw new Error('Video renderer did not provide a track');

        if (!this.remoteStream) {
            this.remoteStream = new MediaStream();
            this.notifyRemoteStream(this.remoteStream);
        }
        const outputStream = this.remoteStream;
        outputStream.addTrack(videoTrack);

        const frameQueue: ImageBitmap[] = [];
        let receiverActive = true;
        let animationFrameId: number | null = null;
        const renderId = ++this.remoteVideoRenderId;

        const renderLoop = () => {
            animationFrameId = null;
            if (!receiverActive || this.remoteVideoRenderId !== renderId || generation !== this.mediaGeneration) {
                while (frameQueue.length > 0) { try { frameQueue.shift()!.close(); } catch { } }
                return;
            }
            if (frameQueue.length === 0) return;

            const bitmap = frameQueue.shift()!;
            if (canvas.width !== bitmap.width) canvas.width = bitmap.width;
            if (canvas.height !== bitmap.height) canvas.height = bitmap.height;
            ctx.drawImage(bitmap, 0, 0);
            bitmap.close();

            if (frameQueue.length > 0) animationFrameId = requestAnimationFrame(renderLoop);
        };
        const scheduleRender = () => {
            if (animationFrameId === null) animationFrameId = requestAnimationFrame(renderLoop);
        };

        try {
            for await (const frame of stream) {
                try {
                    try {
                        if (generation !== this.mediaGeneration || !this.encryptionContext) break;

                        const decrypted = this.decryptMediaFrame(frame, 'video');
                        let dimensions: { width: number; height: number };
                        let blob: Blob;
                        try {
                            dimensions = this.validateJpegDimensions(decrypted);
                            blob = this.createJpegBlob(decrypted);
                        } finally {
                            SecureMemory.zeroBuffer(decrypted);
                        }
                        const bitmap = await createImageBitmap(blob);

                        if (bitmap.width !== dimensions.width || bitmap.height !== dimensions.height) {
                            bitmap.close();
                            throw new Error('Decoded media dimensions changed during decode');
                        }

                        if (generation !== this.mediaGeneration || !receiverActive) {
                            bitmap.close();
                            break;
                        }

                        while (frameQueue.length >= MAX_DECODED_FRAME_QUEUE) {
                            try { frameQueue.shift()!.close(); } catch { }
                        }
                        frameQueue.push(bitmap);
                        scheduleRender();
                    } catch { }
                } finally {
                    SecureMemory.zeroBuffer(frame);
                }
            }
        } finally {
            receiverActive = false;
            if (animationFrameId !== null) cancelAnimationFrame(animationFrameId);
            animationFrameId = null;
            while (frameQueue.length > 0) { try { frameQueue.shift()!.close(); } catch { } }
            try { videoTrack.stop(); } catch { }
            try { outputStream.removeTrack(videoTrack); } catch { }
            if (this.remoteStream === outputStream && outputStream.getTracks().length === 0) {
                this.remoteStream = null;
                this.notifyRemoteStream(null);
            }
        }
    }

    // Receive screen share stream
    private async receiveScreenStream(stream: SecureStream): Promise<void> {
        if (!this.encryptionContext || stream.id !== this.expectedRemoteScreenStreamId) {
            this.abortSecureStream(stream, 'Unexpected call screen stream');
            return;
        }
        if (this.incomingScreenStream === stream) return;

        const generation = this.mediaGeneration;
        if (this.incomingScreenStream && this.incomingScreenStream !== stream) {
            this.abortSecureStream(this.incomingScreenStream, 'Replaced by a newer screen stream');
        }
        this.incomingScreenStream = stream;

        const settings = await this.getMediaSettings();
        if (
            generation !== this.mediaGeneration ||
            !this.encryptionContext ||
            !this.currentCall ||
            stream.id !== this.expectedRemoteScreenStreamId
        ) {
            this.abortSecureStream(stream, 'Call ended before screen stream initialized');
            if (this.incomingScreenStream === stream) this.incomingScreenStream = null;
            return;
        }

        // Create canvas for screen rendering
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('Screen canvas is unavailable');
        const initialDimensions = this.initialRenderDimensions(settings);
        canvas.width = initialDimensions.width;
        canvas.height = initialDimensions.height;

        const canvasStream = canvas.captureStream(settings.frameRate);

        if (!this.remoteScreenStream) {
            this.remoteScreenStream = new MediaStream();
            this.notifyRemoteScreenStream(this.remoteScreenStream);
        }

        const videoTrack = canvasStream.getVideoTracks()[0];
        if (!videoTrack) throw new Error('Screen renderer did not provide a track');
        const outputStream = this.remoteScreenStream;
        outputStream.addTrack(videoTrack);

        const frameQueue: ImageBitmap[] = [];
        let receiverActive = true;
        let animationFrameId: number | null = null;

        const renderLoop = () => {
            animationFrameId = null;
            if (
                !receiverActive ||
                generation !== this.mediaGeneration ||
                this.incomingScreenStream !== stream
            ) {
                while (frameQueue.length > 0) { try { frameQueue.shift()!.close(); } catch { } }
                return;
            }
            if (frameQueue.length === 0) return;

            const bitmap = frameQueue.shift()!;
            if (canvas.width !== bitmap.width) canvas.width = bitmap.width;
            if (canvas.height !== bitmap.height) canvas.height = bitmap.height;
            ctx.drawImage(bitmap, 0, 0);
            bitmap.close();

            if (frameQueue.length > 0) animationFrameId = requestAnimationFrame(renderLoop);
        };
        const scheduleRender = () => {
            if (animationFrameId === null) animationFrameId = requestAnimationFrame(renderLoop);
        };

        try {
            for await (const frame of stream) {
                try {
                    try {
                        if (generation !== this.mediaGeneration || !this.encryptionContext) break;

                        const decrypted = this.decryptMediaFrame(frame, 'screen');
                        let dimensions: { width: number; height: number };
                        let blob: Blob;
                        try {
                            dimensions = this.validateJpegDimensions(decrypted);
                            blob = this.createJpegBlob(decrypted);
                        } finally {
                            SecureMemory.zeroBuffer(decrypted);
                        }
                        const bitmap = await createImageBitmap(blob);

                        if (bitmap.width !== dimensions.width || bitmap.height !== dimensions.height) {
                            bitmap.close();
                            throw new Error('Decoded media dimensions changed during decode');
                        }

                        if (
                            generation !== this.mediaGeneration ||
                            !receiverActive ||
                            this.incomingScreenStream !== stream
                        ) {
                            bitmap.close();
                            break;
                        }

                        while (frameQueue.length >= MAX_DECODED_FRAME_QUEUE) {
                            try { frameQueue.shift()!.close(); } catch { }
                        }
                        frameQueue.push(bitmap);
                        scheduleRender();
                    } catch { }
                } finally {
                    SecureMemory.zeroBuffer(frame);
                }
            }
        } finally {
            receiverActive = false;
            if (animationFrameId !== null) cancelAnimationFrame(animationFrameId);
            animationFrameId = null;
            while (frameQueue.length > 0) { try { frameQueue.shift()!.close(); } catch { } }
            try { videoTrack.stop(); } catch { }
            try { outputStream.removeTrack(videoTrack); } catch { }
            if (this.incomingScreenStream === stream) {
                this.cleanupRemoteScreenShare();
            }
        }
    }

    // Start periodic key rotation during call
    private startKeyRotation(): void {
        if (this.keyRotationTimer || !this.encryptionContext) return;

        this.keyRotationTimer = setInterval(() => {
            if (this.encryptionContext) {
                this.rotateMediaKeys();
            }
        }, CALL_KEY_ROTATION_INTERVAL);
    }

    // Rotate media encryption keys
    private rotateMediaKeys(): void {
        const ctx = this.encryptionContext;
        if (!ctx) return;

        const current: MediaKeyFamily = {
            audio: ctx.sendAudioKey,
            video: ctx.sendVideoKey,
            screen: ctx.sendScreenKey
        };
        const next = this.rotateMediaFamily(current);
        this.zeroMediaFamily(current);

        ctx.sendAudioKey = next.audio;
        ctx.sendVideoKey = next.video;
        ctx.sendScreenKey = next.screen;
        ctx.sendEpoch += 1;
    }

    private cancelPendingSignalSessionWaits(): void {
        for (const cancel of Array.from(this.pendingSignalSessionWaitCancels)) {
            try { cancel(); } catch { }
        }
        this.pendingSignalSessionWaitCancels.clear();
    }

    private isOutboundCallSignalCurrent(signal: CallSignal): boolean {
        if (this.destroyed) return false;
        if (signal.type === 'offer') {
            return this.currentCall?.id === signal.callId &&
                this.currentCall.peer === signal.to &&
                this.currentCall.direction === 'outgoing' &&
                this.currentCall.status === 'ringing';
        }
        if (signal.type === 'answer') {
            return this.currentCall?.id === signal.callId &&
                this.currentCall.peer === signal.to &&
                this.currentCall.direction === 'incoming' &&
                this.currentCall.status === 'connecting';
        }
        if (signal.type === 'screen-share-start') {
            return this.currentCall?.id === signal.callId &&
                this.currentCall.peer === signal.to &&
                this.currentCall.status === 'connected' &&
                this.screenShareStream?.id === signal.data?.streamId;
        }
        if (signal.type === 'screen-share-ready') {
            return this.currentCall?.id === signal.callId &&
                this.currentCall.peer === signal.to &&
                this.currentCall.status === 'connected' &&
                this.expectedRemoteScreenStreamId === signal.data?.streamId;
        }
        return true;
    }

    private async waitForSignalSession(peer: string, generation: number): Promise<void> {
        const isCurrent = () => generation === this.lifecycleGeneration && !this.destroyed;
        const hasSession = await signalApi.hasSession(this.localUsername, peer);
        if (!isCurrent()) throw new Error('Call signaling was cancelled');
        if (hasSession) return;
        if (this.pendingSignalSessionWaitCancels.size >= MAX_PENDING_SIGNAL_SESSION_WAITS) {
            throw new Error('Too many pending call signaling waits');
        }

        await new Promise<void>((resolve, reject) => {
            let settled = false;
            let timeoutId: ReturnType<typeof setTimeout> | null = null;
            let onSessionReady: ((event: Event) => void) | null = null;
            let cancel: (() => void) | null = null;

            const cleanup = () => {
                if (timeoutId) clearTimeout(timeoutId);
                timeoutId = null;
                if (onSessionReady) {
                    window.removeEventListener(
                        EventType.LIBSIGNAL_SESSION_READY,
                        onSessionReady as EventListener
                    );
                }
                if (cancel) this.pendingSignalSessionWaitCancels.delete(cancel);
            };
            const finish = (error?: Error) => {
                if (settled) return;
                settled = true;
                cleanup();
                if (error) reject(error);
                else resolve();
            };

            cancel = () => finish(new Error('Call signaling wait cancelled'));
            onSessionReady = (event: Event) => {
                const detail = (event as CustomEvent).detail;
                if (!isCurrent()) {
                    finish(new Error('Call signaling was cancelled'));
                    return;
                }
                if (
                    isPlainObject(detail) &&
                    !hasPrototypePollutionKeys(detail) &&
                    Object.keys(detail).sort().join(',') === 'account,peer' &&
                    detail.account === this.localUsername &&
                    detail.peer === peer
                ) {
                    finish();
                }
            };

            this.pendingSignalSessionWaitCancels.add(cancel);
            window.addEventListener(
                EventType.LIBSIGNAL_SESSION_READY,
                onSessionReady as EventListener
            );
            timeoutId = setTimeout(
                () => finish(new Error('Timeout waiting for session establishment')),
                10_000
            );
            
            void signalApi.hasSession(this.localUsername, peer).then(
                (ready) => {
                    if (!isCurrent()) finish(new Error('Call signaling was cancelled'));
                    else if (ready) finish();
                },
                () => finish(new Error('Signal session state unavailable'))
            );
        });
    }

    // Send a call signal to the peer
    private async sendCallSignal(callSig: CallSignal): Promise<void> {
        if (
            callSig.from !== this.localUsername ||
            !isValidCallId(callSig.callId) ||
            !isValidCallingUsername(callSig.to) ||
            callSig.to !== callSig.to.toLowerCase() ||
            callSig.to === this.localUsername ||
            !Number.isSafeInteger(callSig.timestamp) ||
            Math.abs(Date.now() - callSig.timestamp) > MAX_CALL_SIGNAL_CLOCK_SKEW_MS ||
            !this.isOutboundCallSignalCurrent(callSig)
        ) {
            throw new Error('Invalid or stale outbound call signal');
        }

        const generation = this.lifecycleGeneration;
        await this.waitForSignalSession(callSig.to, generation);
        for (let attempt = 0; attempt <= MAX_CALL_SIGNAL_ERROR_RETRIES; attempt += 1) {
            if (
                generation !== this.lifecycleGeneration ||
                this.destroyed ||
                this.securityQuarantined ||
                keyTransparencyClient.isSecurityIncidentActive() ||
                !blockingSystem.isEnforcementReady() ||
                blockingSystem.isBlockedSync(callSig.to) ||
                Math.abs(Date.now() - callSig.timestamp) > MAX_CALL_SIGNAL_CLOCK_SKEW_MS ||
                !this.isOutboundCallSignalCurrent(callSig)
            ) {
                throw new Error('Call signaling was cancelled');
            }

            let result: Awaited<ReturnType<typeof unifiedSignalTransport.send>>;
            try {
                result = await unifiedSignalTransport.send(
                    callSig.to,
                    { content: JSON.stringify(callSig) },
                    SignalType.CALL_SIGNAL
                );
            } catch (error: unknown) {
                result = {
                    success: false,
                    transport: 'server',
                    error: error instanceof Error ? error.message : 'Call signal send failed'
                };
            }

            if (result.success) return;

            const error = result.error || 'Call signal send failed';
            if (attempt >= MAX_CALL_SIGNAL_ERROR_RETRIES || !this.isRetryableCallSignalError(error)) {
                throw new Error(error);
            }

            console.warn('[CALL-SIGNAL] live send failed; retrying', {
                subtype: callSig.type,
                attempt: attempt + 2,
                maxAttempts: MAX_CALL_SIGNAL_ERROR_RETRIES + 1,
                transport: result.transport,
                error
            });
            await new Promise<void>((resolve) => {
                setTimeout(resolve, CALL_SIGNAL_RETRY_BASE_DELAY_MS * (2 ** attempt));
            });
        }
    }

    private isRetryableCallSignalError(error: string): boolean {
        const normalized = error.trim().toLowerCase();
        return ![
            'invalid-recipient',
            'recipient-blocked',
            'blocking-policy-unavailable',
            'recipient-policy-changed',
            'account-transition',
            'encryption provider not set',
            'invalid encrypted envelope'
        ].some((terminal) => normalized.includes(terminal));
    }

    private async sendCallSignalBestEffort(callSig: CallSignal): Promise<void> {
        try {
            await this.sendCallSignal(callSig);
        } catch { }
    }

    private allowIncomingOffer(from: string, now = Date.now()): boolean {
        if (now - this.incomingOfferGlobal.windowStart >= CALL_OFFER_RATE_WINDOW_MS) {
            this.incomingOfferGlobal = { windowStart: now, count: 0 };
        }
        const previous = this.incomingOfferRates.get(from);
        const peer = !previous || now - previous.windowStart >= CALL_OFFER_RATE_WINDOW_MS
            ? { windowStart: now, count: 0 }
            : previous;
        if (
            peer.count >= MAX_CALL_OFFERS_PER_PEER ||
            this.incomingOfferGlobal.count >= MAX_CALL_OFFERS_GLOBAL
        ) return false;

        if (!this.incomingOfferRates.has(from) && this.incomingOfferRates.size >= MAX_CALL_OFFER_RATE_PEERS) {
            const oldest = this.incomingOfferRates.keys().next().value;
            if (typeof oldest === 'string') this.incomingOfferRates.delete(oldest);
        }
        peer.count += 1;
        this.incomingOfferRates.delete(from);
        this.incomingOfferRates.set(from, peer);
        this.incomingOfferGlobal.count += 1;
        return true;
    }

    // Handle incoming call signal
    private async handleCallSignal(candidate: unknown): Promise<void> {
        if (this.securityQuarantined || keyTransparencyClient.isSecurityIncidentActive()) return;
        if (!isExactCallSignal(candidate)) return;
        const signal = candidate;
        if (
            signal.from === this.localUsername ||
            signal.to !== this.localUsername ||
            Math.abs(Date.now() - signal.timestamp) > MAX_CALL_SIGNAL_CLOCK_SKEW_MS ||
            !blockingSystem.isEnforcementReady() ||
            blockingSystem.isBlockedSync(signal.from)
        ) {
            return;
        }

        if (signal.type === 'offer') {
            if (!this.allowIncomingOffer(signal.from)) return;
        } else {
            if (
                !this.currentCall ||
                this.currentCall.id !== signal.callId ||
                this.currentCall.peer !== signal.from
            ) {
                return;
            }
            if (
                signal.type === 'answer' &&
                (this.currentCall.direction !== 'outgoing' || this.currentCall.status !== 'ringing')
            ) return;
            if (
                (
                    signal.type === 'screen-share-start' ||
                    signal.type === 'screen-share-ready' ||
                    signal.type === 'screen-share-stop'
                ) &&
                this.currentCall.status !== 'connected'
            ) return;
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

            case 'screen-share-start':
                if (this.expectedRemoteScreenStreamId === signal.data.streamId) break;
                if (
                    this.seenRemoteScreenStreamIds.has(signal.data.streamId) ||
                    this.seenRemoteScreenStreamIds.size >= MAX_REMOTE_SCREEN_SHARES_PER_CALL
                ) break;
                this.seenRemoteScreenStreamIds.add(signal.data.streamId);
                if (this.incomingScreenStream || this.remoteScreenStream || this.expectedRemoteScreenStreamId) {
                    this.cleanupRemoteScreenShare();
                }
                this.expectedRemoteScreenStreamId = signal.data.streamId;
                this.remoteScreenStream = new MediaStream();
                this.notifyRemoteScreenStream(this.remoteScreenStream);
                if (this.callConnection) {
                    const announcedStream = this.callConnection.getStreamById(this.expectedRemoteScreenStreamId);
                    if (announcedStream) this.receiveExpectedScreenStream(announcedStream, this.callConnection);
                }
                await this.sendCallSignalBestEffort({
                    type: 'screen-share-ready',
                    callId: signal.callId,
                    from: this.localUsername,
                    to: signal.from,
                    data: { streamId: signal.data.streamId },
                    timestamp: Date.now()
                });
                break;

            case 'screen-share-ready':
                this.acceptScreenShareReady(signal);
                break;

            case 'screen-share-stop':
                if (this.expectedRemoteScreenStreamId === signal.data.streamId) {
                    this.cleanupRemoteScreenShare();
                }
                break;
        }
    }

    // Handle incoming call offer
    private async handleCallOffer(signal: Extract<CallSignal, { type: 'offer' }>): Promise<void> {
        if (this.currentCall) {
            if (
                this.currentCall.direction === 'incoming' &&
                this.currentCall.id === signal.callId &&
                this.currentCall.peer === signal.from
            ) {
                return;
            }
            // Collision Detection
            if (this.currentCall.peer === signal.from && (this.currentCall.status === 'connecting' || this.currentCall.status === 'ringing')) {
                // Lexicographical Arbitration lower username stays as initiator
                if (this.localUsername < signal.from) {
                    await this.sendCallSignal({
                        type: 'decline-call',
                        callId: signal.callId,
                        from: this.localUsername,
                        to: signal.from,
                        timestamp: Date.now()
                    });
                    return;
                } else {
                    const supersededCall = this.currentCall;
                    supersededCall.status = 'declined';
                    supersededCall.endTime = Date.now();
                    supersededCall.endReason = 'declined';
                    supersededCall.duration = supersededCall.startTime
                        ? Math.max(0, supersededCall.endTime - supersededCall.startTime)
                        : 0;
                    this.notifyCallState(supersededCall);
                    this.cleanup();
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
            type: signal.data.callType,
            direction: 'incoming',
            status: 'ringing',
            peer: signal.from
        };

        this.ringStartAt = Date.now();
        this.notifyIncomingCall(this.currentCall);
        this.notifyCallState(this.currentCall);

        const activeCallId = signal.callId;
        const activePeer = signal.from;
        this.callTimeoutId = setTimeout(() => {
            if (
                this.currentCall?.id === activeCallId &&
                this.currentCall.peer === activePeer &&
                this.currentCall.status === 'ringing'
            ) {
                this.currentCall.status = 'missed';
                this.notifyCallState(this.currentCall);
                this.cleanup();
            }
        }, CALL_RING_TIMEOUT);
    }

    // Handle incoming call answer
    private async handleCallAnswer(signal: CallSignal): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== signal.callId) { return; }
        if (this.currentCall.direction !== 'outgoing') { return; }
        if (this.currentCall.status !== 'ringing') { return; }

        this.currentCall.status = 'connecting';
        this.notifyCallState(this.currentCall);

        try {
            await this.startMediaStreaming(signal.callId);
            this.markConnected(signal.callId);
        } catch (error) {
            if (this.currentCall?.id === signal.callId) {
                await this.endCall('failed');
            }
            throw error;
        }
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
        this.notifyCallState(this.currentCall);
        this.cleanup();
    }

    // Handle incoming call decline
    private async handleCallDecline(signal: CallSignal): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== signal.callId) return;

        this.currentCall.status = 'declined';
        this.currentCall.endTime = Date.now();
        this.notifyCallState(this.currentCall);

        this.cleanup();
    }

    // Generate a random call ID
    private generateCallId(): string {
        return PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
    }

    // Mark call as connected
    private markConnected(expectedCallId: string): void {
        if (this.currentCall?.id === expectedCallId && this.currentCall.status === 'connecting') {
            this.currentCall.status = 'connected';
            this.currentCall.startTime = Date.now();

            if (this.callTimeoutId) {
                clearTimeout(this.callTimeoutId);
                this.callTimeoutId = null;
            }

            this.notifyCallState(this.currentCall);
        }
    }

    // Cleanup call resources
    private cleanup(): void {
        this.mediaGeneration += 1;
        this.cameraSwitchGeneration += 1;
        this.microphoneSwitchGeneration += 1;
        this.cancelPendingSignalSessionWaits();
        this.unsubscribeCallStreams();
        this.teardownCallMediaElements();

        // Stop local media
        if (this.localStream) {
            const localStream = this.localStream;
            this.localStream = null;
            this.stopMediaStream(localStream);
            this.lastCaptureReleaseAt = Date.now();
        }

        this.teardownCallAudioNodes();
        for (const context of [this.sharedAudioContext, this.sharedReceiveAudioContext]) {
            if (context?.state === 'running') {
                try { void context.suspend().catch(() => { }); } catch { }
            }
        }

        this.cleanupScreenShareLocal();

        // Close streams
        for (const stream of [this.audioStream, this.videoStream]) this.closeSecureStream(stream);
        this.audioStream = null;
        this.videoStream = null;

        this.callConnection = null;

        this.clearEncryptionContext();

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

        this.stopMediaStream(this.remoteStream);
        this.remoteStream = null;
        this.cleanupRemoteScreenShare();
        this.seenRemoteScreenStreamIds.clear();
        this.ringStartAt = null;

        this.currentCall = null;
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
    async getAvailableScreenSources(): Promise<ScreenSource[]> {
        try {
            const candidates: unknown = await system.getScreenSources();
            if (!Array.isArray(candidates) || candidates.length > MAX_SCREEN_SOURCES) return [];

            const sources: ScreenSource[] = [];
            const seen = new Set<string>();
            for (const candidate of candidates) {
                if (
                    !isPlainObject(candidate) ||
                    hasPrototypePollutionKeys(candidate) ||
                    Object.keys(candidate).sort().join(',') !== 'id,name,source_type' ||
                    (candidate.source_type !== 'screen' && candidate.source_type !== 'window') ||
                    !isValidScreenSourceId(candidate.id, candidate.source_type) ||
                    typeof candidate.name !== 'string' ||
                    candidate.name.length === 0 ||
                    candidate.name.length > MAX_SCREEN_SOURCE_NAME_LENGTH ||
                    /[\x00-\x1f\x7f]/.test(candidate.name) ||
                    seen.has(candidate.id)
                ) {
                    continue;
                }
                seen.add(candidate.id);
                sources.push({
                    id: candidate.id,
                    name: candidate.name,
                    type: candidate.source_type
                });
            }
            sources.sort((left, right) => Number(left.type === 'window') - Number(right.type === 'window'));
            return sources;
        } catch {
            return [];
        }
    }

    // Destroy the calling service
    destroy(): void {
        if (this.destroyed) return;
        this.destroyed = true;
        this.lifecycleGeneration += 1;

        if (typeof window !== 'undefined') {
            window.removeEventListener('beforeunload', this.beforeUnloadHandler);
            window.removeEventListener(EventType.CALL_SIGNAL, this.callSignalHandler);
            window.removeEventListener(EventType.USER_BLOCKED, this.userBlockedHandler);
            window.removeEventListener(
                EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT,
                this.keyTransparencySecurityIncidentHandler
            );
        }
        this.initialized = false;
        this.cleanup();

        this.closeAudioContext(this.sharedAudioContext);
        this.closeAudioContext(this.sharedReceiveAudioContext);
        this.sharedAudioContext = null;
        this.sharedReceiveAudioContext = null;
        this.audioWorkletLoaded = false;
        this.receiveAudioWorkletLoaded = false;
        this.mediaSettingsUnsubscribe?.();
        this.mediaSettingsUnsubscribe = null;
        this.mediaSettings = null;
        this.incomingOfferRates.clear();
        this.incomingOfferGlobal = { windowStart: 0, count: 0 };

        this.onIncomingCallCallback = null;
        this.onCallStateChangeCallback = null;
        this.onRemoteStreamCallback = null;
        this.onRemoteScreenStreamCallback = null;
        this.onLocalStreamCallback = null;
    }
}
