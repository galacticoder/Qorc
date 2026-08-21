/**
 * Secure Calling Service
 */

import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SecureMemory } from '../cryptography/secure-memory';
import { P2PTransport, p2pTransport } from './p2p-transport';
import {
    ConnectionState,
    SecureConnection,
    SecureStream
} from './secure-transport';
import { screenSharingSettings } from '../database/screen-sharing-settings';
import { STORAGE_KEYS } from '../database/storage-keys';
import { encryptedStorage } from '../database/encrypted-storage';
import { unifiedSignalTransport } from './unified-signal-transport';
import {
    CALL_TIMEOUT,
    CALL_RING_TIMEOUT,
    CALL_DEVICE_SETTLE_MS,
    MAX_CALL_SIGNAL_CLOCK_SKEW_MS,
    P2P_CONNECTION_TIMEOUT_MS,
    TARGET_FPS,
    VISUAL_FRAME_SEND_DEADLINE_MAX_MS,
    VISUAL_FRAME_SEND_DEADLINE_MS,
} from '../constants';
import {
    audioCodec,
    nativeCamera,
    signal as signalApi,
    system,
    isTauri,
    requireNativeMediaAccess,
} from '../tauri-bindings';
import {
    isExactCallSignal,
    isValidCallId,
    isValidCallingUsername,
    isValidMediaDeviceId,
    releaseVisualCanvas,
} from '../utils/calling-utils';
import { hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import {
    CallState,
    CallSignal,
    LocalCallEndReason,
} from '../types/calling-types';
import { cloneScreenSharingSettings, type ScreenSharingSettings, type ScreenSource } from '../types/screen-sharing-types';
import { blockingSystem } from '../blocking/blocking-system';
import { keyTransparencyClient } from '../key-transparency/client';
import { CallTelemetry } from './call-telemetry';
import {
    RealtimeVisualDecoder,
    RealtimeVisualEncoder,
    NativeCameraCaptureSource,
    decodeVisualBatch,
    visualPlayoutAgeMs,
    type DecodedVisualFrame,
    type VisualFrameMetadata,
} from './call-video-codec';

export type { CallState, CallSignal };

type PendingAudioCapture = {
    pcm: Uint8Array;
    capturedAt: number;
    sequence: number;
};
type BufferedAudioPacket = {
    packet: Uint8Array;
    sequence: number;
    capturedAt: number;
    arrivedAt: number;
    discontinuity: boolean;
};
type PendingScreenShareReady = {
    callId: string;
    streamId: string;
    generation: number;
    timeoutId: ReturnType<typeof setTimeout>;
    finish: (ready: boolean) => void;
};

const OPUS_FRAME_SAMPLES = 960;
const OPUS_PCM_BYTES = OPUS_FRAME_SAMPLES * Float32Array.BYTES_PER_ELEMENT;
const OPUS_MAX_PACKET_BYTES = 1276;
const AUDIO_PACKET_HEADER_BYTES = 14;
const MAX_AUDIO_PLAINTEXT_BYTES = AUDIO_PACKET_HEADER_BYTES + OPUS_MAX_PACKET_BYTES;
const AUDIO_BATCH_VERSION = 2;
const AUDIO_BATCH_HEADER_BYTES = 4;
const AUDIO_BATCH_ENTRY_BYTES = 2;
const MAX_AUDIO_BATCH_PACKETS = 4;
const MAX_AUDIO_BATCH_BYTES = AUDIO_BATCH_HEADER_BYTES +
    MAX_AUDIO_BATCH_PACKETS * (AUDIO_BATCH_ENTRY_BYTES + MAX_AUDIO_PLAINTEXT_BYTES);
const MAX_AUDIO_QUEUE_PACKETS = 5;
const MIN_AUDIO_JITTER_PACKETS = 3;
const AUDIO_FRAME_DURATION_MS = 20;
const AUDIO_SEND_DEADLINE_MS = 160;
const AUDIO_SEND_DEADLINE_MAX_MS = 320;
const AUDIO_DTX_KEEPALIVE_FRAMES = 20;
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
const visualFrameSendDeadlineMs = (rttMs: number | null): number => (
    rttMs === null || !Number.isFinite(rttMs)
        ? VISUAL_FRAME_SEND_DEADLINE_MS
        : Math.min(
            VISUAL_FRAME_SEND_DEADLINE_MAX_MS,
            Math.max(VISUAL_FRAME_SEND_DEADLINE_MS, Math.round(250 + rttMs * 0.7))
        )
);
function createAudioPacket(
    packet: Uint8Array,
    sequence: number,
    capturedAt: number,
    discontinuity: boolean
): Uint8Array {
    if (packet.length === 0 || packet.length > OPUS_MAX_PACKET_BYTES) {
        throw new Error('Invalid Opus packet');
    }
    const output = new Uint8Array(AUDIO_PACKET_HEADER_BYTES + packet.length);
    const view = new DataView(output.buffer);
    view.setUint8(0, 1);
    view.setUint8(1, (packet.length === 1 ? 1 : 0) | (discontinuity ? 2 : 0));
    view.setUint32(2, sequence, false);
    view.setBigUint64(6, BigInt(Math.max(0, Math.trunc(capturedAt))), false);
    output.set(packet, AUDIO_PACKET_HEADER_BYTES);
    return output;
}

function parseAudioPacket(data: Uint8Array, arrivedAt: number): BufferedAudioPacket {
    if (
        data.length <= AUDIO_PACKET_HEADER_BYTES ||
        data.length > MAX_AUDIO_PLAINTEXT_BYTES
    ) {
        throw new Error('Invalid audio packet length');
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const flags = view.getUint8(1);
    if (view.getUint8(0) !== 1 || (flags & 0xfc) !== 0) {
        throw new Error('Invalid audio packet header');
    }
    const capturedAt = Number(view.getBigUint64(6, false));
    if (!Number.isSafeInteger(capturedAt) || capturedAt <= 0) {
        throw new Error('Invalid audio capture timestamp');
    }
    return {
        sequence: view.getUint32(2, false),
        capturedAt,
        arrivedAt,
        discontinuity: (flags & 2) !== 0,
        packet: data.slice(AUDIO_PACKET_HEADER_BYTES),
    };
}

export function encodeCallAudioBatch(packets: readonly Uint8Array[]): Uint8Array {
    if (packets.length < 1 || packets.length > MAX_AUDIO_BATCH_PACKETS) {
        throw new Error('Invalid audio batch count');
    }
    let byteLength = AUDIO_BATCH_HEADER_BYTES;
    for (const packet of packets) {
        if (packet.byteLength <= AUDIO_PACKET_HEADER_BYTES || packet.byteLength > MAX_AUDIO_PLAINTEXT_BYTES) {
            throw new Error('Invalid audio batch packet');
        }
        byteLength += AUDIO_BATCH_ENTRY_BYTES + packet.byteLength;
    }
    if (byteLength > MAX_AUDIO_BATCH_BYTES) throw new Error('Audio batch exceeds limit');
    const output = new Uint8Array(byteLength);
    const view = new DataView(output.buffer);
    output[0] = AUDIO_BATCH_VERSION;
    output[1] = packets.length;
    let offset = AUDIO_BATCH_HEADER_BYTES;
    for (const packet of packets) {
        view.setUint16(offset, packet.byteLength, false);
        offset += AUDIO_BATCH_ENTRY_BYTES;
        output.set(packet, offset);
        offset += packet.byteLength;
    }
    return output;
}

export function decodeCallAudioBatch(data: Uint8Array, arrivedAt: number): BufferedAudioPacket[] {
    if (
        data.byteLength <= AUDIO_BATCH_HEADER_BYTES ||
        data.byteLength > MAX_AUDIO_BATCH_BYTES ||
        data[0] !== AUDIO_BATCH_VERSION ||
        data[1] < 1 ||
        data[1] > MAX_AUDIO_BATCH_PACKETS ||
        data[2] !== 0 ||
        data[3] !== 0
    ) throw new Error('Invalid audio batch');
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const packets: BufferedAudioPacket[] = [];
    let offset = AUDIO_BATCH_HEADER_BYTES;
    try {
        for (let index = 0; index < data[1]; index += 1) {
            if (offset + AUDIO_BATCH_ENTRY_BYTES > data.byteLength) throw new Error('Invalid audio batch entry');
            const byteLength = view.getUint16(offset, false);
            offset += AUDIO_BATCH_ENTRY_BYTES;
            if (
                byteLength <= AUDIO_PACKET_HEADER_BYTES ||
                byteLength > MAX_AUDIO_PLAINTEXT_BYTES ||
                offset + byteLength > data.byteLength
            ) throw new Error('Invalid audio batch entry');
            const packetArrivalAt = arrivedAt - (data[1] - index - 1) * AUDIO_FRAME_DURATION_MS;
            packets.push(parseAudioPacket(data.subarray(offset, offset + byteLength), packetArrivalAt));
            offset += byteLength;
        }
        if (offset !== data.byteLength) throw new Error('Invalid audio batch trailing data');
        return packets;
    } catch (error) {
        for (const packet of packets) SecureMemory.zeroBuffer(packet.packet);
        throw error;
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
    private localVideoCanvas: HTMLCanvasElement | null = null;
    private remoteVideoCanvas: HTMLCanvasElement | null = null;
    private remoteScreenCanvas: HTMLCanvasElement | null = null;
    private screenStream: MediaStream | null = null;
    private currentCall: CallState | null = null;
    private isScreenSharing: boolean = false;
    private screenSharePending: boolean = false;
    private videoEnabled: boolean = false;
    private localUsername: string = '';
    private preferredCameraDeviceId: string | null = null;
    private cameraSessionId: string | null = null;

    // Transport
    private transport: P2PTransport;
    private callConnection: SecureConnection | null = null;
    private audioStream: SecureStream | null = null;
    private videoStream: SecureStream | null = null;
    private telemetryStream: SecureStream | null = null;
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
    private audioCodecSessionId: string | null = null;

    private screenCaptureVideoEl: HTMLVideoElement | null = null;
    private videoEncoder: RealtimeVisualEncoder | null = null;
    private screenEncoder: RealtimeVisualEncoder | null = null;
    private remoteVideoRenderId = 0;
    private lastCaptureReleaseAt = 0;

    private mediaGeneration = 0;
    private screenShareGeneration = 0;
    private cameraSwitchGeneration = 0;
    private microphoneSwitchGeneration = 0;
    private callStreamUnsubscribe: (() => void) | null = null;
    private callConnectionStateUnsubscribe: (() => void) | null = null;

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
    private onRemoteVideoCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onRemoteScreenCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onLocalVideoCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onLocalStreamCallback: ((stream: MediaStream) => void) | null = null;

    // Timers
    private callTimeoutId: ReturnType<typeof setTimeout> | null = null;
    private ringStartAt: number | null = null;
    private callTelemetry: CallTelemetry | null = null;

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

    private notifyRemoteVideoCanvas(canvas: HTMLCanvasElement | null): void {
        try {
            this.onRemoteVideoCanvasCallback?.(canvas);
        } catch (error) {
            console.error('[SecureCall] Remote video observer failed:', error);
        }
    }

    private notifyRemoteScreenCanvas(canvas: HTMLCanvasElement | null): void {
        try {
            this.onRemoteScreenCanvasCallback?.(canvas);
        } catch (error) {
            console.error('[SecureCall] Remote screen observer failed:', error);
        }
    }

    private notifyLocalVideoCanvas(canvas: HTMLCanvasElement | null): void {
        try {
            this.onLocalVideoCanvasCallback?.(canvas);
        } catch (error) {
            console.error('[SecureCall] Local video observer failed:', error);
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

    private unsubscribeCallConnectionState(): void {
        const unsubscribe = this.callConnectionStateUnsubscribe;
        this.callConnectionStateUnsubscribe = null;
        if (!unsubscribe) return;
        try { unsubscribe(); } catch { }
    }

    private handleCallConnectionState(
        connection: SecureConnection,
        expectedCallId: string,
        state: ConnectionState
    ): void {
        if (state !== 'disconnected' && state !== 'failed') return;
        if (this.callConnection !== connection || this.currentCall?.id !== expectedCallId) return;
        if (
            this.currentCall.status === 'ended' ||
            this.currentCall.status === 'declined' ||
            this.currentCall.status === 'missed'
        ) return;

        const call = this.currentCall;
        const endTime = Date.now();
        call.status = 'ended';
        call.endTime = endTime;
        call.duration = call.startTime ? Math.max(0, endTime - call.startTime) : 0;
        call.endReason = 'failed';
        this.notifyCallState(call);
        this.cleanup();
    }

    private bindCallConnectionState(connection: SecureConnection, expectedCallId: string): void {
        this.unsubscribeCallConnectionState();
        const unsubscribe = connection.onStateChange((state) => {
            this.handleCallConnectionState(connection, expectedCallId, state);
        });
        if (this.callConnection !== connection || this.currentCall?.id !== expectedCallId) {
            try { unsubscribe(); } catch { }
            return;
        }
        this.callConnectionStateUnsubscribe = unsubscribe;
        this.handleCallConnectionState(connection, expectedCallId, connection.state);
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

            try {
                await this.establishCallConnection(targetUser, callId);
            } catch (error) {
                if (!this.isRecoverableRouteFailure(error)) throw error;
            }
            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== targetUser) {
                throw new Error('Call was cancelled while connecting media');
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
                data: {
                    callType: this.currentCall.type
                },
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

            let answerSent = false;
            if (!this.callConnection || !this.audioStream) {
                try {
                    await this.establishCallConnection(peer, callId);
                } catch (error) {
                    if (!this.isRecoverableRouteFailure(error)) throw error;
                    await this.sendCallSignal({
                        type: 'answer',
                        callId,
                        from: this.localUsername,
                        to: peer,
                        timestamp: Date.now()
                    });
                    answerSent = true;
                    if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== peer) {
                        throw new Error('Call ended while the answer was being delivered');
                    }
                    await this.establishCallConnection(peer, callId);
                }
            }

            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== peer) {
                throw new Error('Call was cancelled');
            }

            if (!answerSent) {
                await this.sendCallSignal({
                    type: 'answer',
                    callId,
                    from: this.localUsername,
                    to: peer,
                    timestamp: Date.now()
                });
            }

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
        void this.sendCallSignalBestEffort(signal);
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
        const sessionId = this.cameraSessionId;
        if (!this.localStream || this.currentCall?.type !== 'video' || !this.videoStream || !sessionId) return false;
        const enabled = !this.videoEnabled;
        await nativeCamera.setEnabled(sessionId, enabled);
        if (this.cameraSessionId !== sessionId || this.currentCall?.id !== sessionId) return false;
        this.videoEnabled = enabled;
        return enabled;
    }

    // Switch camera device
    async switchCamera(deviceId?: string): Promise<void> {
        if (!this.localStream) throw new Error('No active local media stream');
        if (deviceId !== undefined && !isValidMediaDeviceId(deviceId)) {
            throw new Error('Invalid camera device identifier');
        }
        if (!deviceId) return;
        const activeCallId = this.currentCall?.id;
        if (!activeCallId || this.currentCall?.type !== 'video' || this.cameraSessionId !== activeCallId) {
            throw new Error('No active camera capture');
        }
        if (this.preferredCameraDeviceId === deviceId) {
            this.preferredCameraDeviceId = deviceId;
            return;
        }
        const previousDeviceId = this.preferredCameraDeviceId;
        const switchGeneration = ++this.cameraSwitchGeneration;
        const settings = await this.getMediaSettings();
        const profile = this.cameraProfile(settings.quality);
        try {
            await requireNativeMediaAccess('camera');
            await nativeCamera.start(activeCallId, deviceId, profile.width, profile.height, TARGET_FPS);
            if (
                switchGeneration !== this.cameraSwitchGeneration ||
                this.currentCall?.id !== activeCallId ||
                this.cameraSessionId !== activeCallId
            ) {
                throw new Error('Call changed while the camera was switching');
            }
            await nativeCamera.setEnabled(activeCallId, this.videoEnabled);
            await this.startVideoStreaming();
            if (
                switchGeneration !== this.cameraSwitchGeneration ||
                this.currentCall?.id !== activeCallId ||
                this.cameraSessionId !== activeCallId
            ) {
                throw new Error('Call changed while the camera was switching');
            }
            this.preferredCameraDeviceId = deviceId;
            const account = this.localUsername;
            try {
                await Promise.resolve().then(() => {
                    if (
                        this.destroyed ||
                        this.localUsername !== account ||
                        this.preferredCameraDeviceId !== deviceId
                    ) return;
                    return encryptedStorage.setItem(STORAGE_KEYS.PREFERRED_CAMERA, deviceId);
                });
            } catch { }
        } catch (error) {
            if (
                switchGeneration === this.cameraSwitchGeneration &&
                this.currentCall?.id === activeCallId &&
                this.cameraSessionId === activeCallId
            ) {
                try {
                    await nativeCamera.start(activeCallId, previousDeviceId, profile.width, profile.height, TARGET_FPS);
                    await nativeCamera.setEnabled(activeCallId, this.videoEnabled);
                } catch { }
                try { await this.startVideoStreaming(); } catch { }
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
            if (this.callAudioNode && this.audioStream) {
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
                        this.audioStream
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
            this.currentCall.status !== 'connected'
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
            this.callConnection === connection;

        try {
            await this.getMediaSettings();
            if (!shareIsCurrent()) {
                throw new Error('Call ended before screen capture');
            }

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
                        maxFrameRate: TARGET_FPS
                    };
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
                    frameRate: { ideal: TARGET_FPS, max: TARGET_FPS }
                };
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

    private cameraProfile(quality: ScreenSharingSettings['quality']): { width: number; height: number } {
        if (quality === 'low') return { width: 640, height: 360 };
        if (quality === 'high') return { width: 1280, height: 720 };
        return { width: 960, height: 540 };
    }

    // Set up local media capture
    private async setupLocalMedia(callType: 'audio' | 'video', expectedCallId: string): Promise<'audio' | 'video'> {
        this.teardownCallMediaElements();
        const previousCameraSessionId = this.cameraSessionId;
        this.cameraSessionId = null;
        if (previousCameraSessionId) {
            try { await nativeCamera.stop(previousCameraSessionId); } catch { }
        }
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
        await requireNativeMediaAccess(callType === 'video' ? 'audio-video' : 'audio');
        const acquiredStream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false,
        });

        if (!callIsCurrent()) {
            this.stopMediaStream(acquiredStream);
            throw new Error('Call was cancelled while media permission was pending');
        }

        try {
            if (callType === 'video') {
                const settings = await this.getMediaSettings();
                const profile = this.cameraProfile(settings.quality);
                await nativeCamera.start(
                    expectedCallId,
                    this.preferredCameraDeviceId,
                    profile.width,
                    profile.height,
                    TARGET_FPS,
                );
                if (!callIsCurrent()) {
                    await nativeCamera.stop(expectedCallId);
                    throw new Error('Call was cancelled while camera capture was starting');
                }
                this.cameraSessionId = expectedCallId;
            }
        } catch (error) {
            this.stopMediaStream(acquiredStream);
            throw error;
        }

        this.localStream = acquiredStream;
        this.videoEnabled = callType === 'video';
        this.notifyLocalStream(this.localStream);
        return callType;
    }

    // Establish call connection
    private async establishCallConnection(
        peer: string,
        expectedCallId: string
    ): Promise<void> {
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
        let telemetryStream: SecureStream | null = null;
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

            try {
                telemetryStream = await connection.createStream({
                    type: 'call-telemetry',
                    id: `call-telemetry:${expectedCallId}`,
                    lossy: true
                });
            } catch {
                telemetryStream = null;
            }
            if (!callIsCurrent()) throw new Error('Call was cancelled while opening telemetry');

            this.mediaGeneration += 1;
            this.callConnection = connection;
            this.audioStream = audioStream;
            this.videoStream = videoStream;
            this.telemetryStream = telemetryStream;
            this.callTelemetry = new CallTelemetry(
                expectedCallId,
                this.currentCall.direction,
                this.currentCall.type,
                connection,
                telemetryStream,
                kind => {
                    if (kind === 'video') this.videoEncoder?.requestKeyFrame();
                    else this.screenEncoder?.requestKeyFrame();
                }
            );
            this.bindCallConnectionState(connection, expectedCallId);
            if (!callIsCurrent() || this.callConnection !== connection) {
                throw new Error('Call connection closed during setup');
            }
        } catch (error) {
            if (audioStream && this.audioStream !== audioStream) this.closeSecureStream(audioStream);
            if (videoStream && this.videoStream !== videoStream) this.closeSecureStream(videoStream);
            if (telemetryStream && this.telemetryStream !== telemetryStream) this.closeSecureStream(telemetryStream);
            throw error;
        }
    }

    private isRecoverableRouteFailure(error: unknown): boolean {
        if ((error as { code?: unknown })?.code === 'P2P_ENDPOINT_MISSING') return true;
        const message = error instanceof Error ? error.message.toLowerCase() : '';
        return [
            'no p2p endpoint available',
            'onion dial failed',
            'host unreachable',
            'network is unreachable',
            'connection refused',
            'dial timeout',
        ].some(value => message.includes(value));
    }

    // Start streaming media frames
    private async startMediaStreaming(expectedCallId: string): Promise<void> {
        if (
            this.currentCall?.id !== expectedCallId ||
            this.currentCall.status !== 'connecting' ||
            !this.localStream ||
            !this.callConnection
        ) {
            throw new Error('Call media startup is stale or incomplete');
        }

        const generation = this.mediaGeneration;
        if (!isTauri()) throw new Error('Native Opus codec unavailable');
        if (this.audioCodecSessionId !== expectedCallId) {
            const previousSession = this.audioCodecSessionId;
            this.audioCodecSessionId = null;
            if (previousSession) {
                try { await audioCodec.stop(previousSession); } catch { }
            }
            await audioCodec.start(expectedCallId);
            this.audioCodecSessionId = expectedCallId;
        }
        const starters: Promise<void>[] = [];

        // Set up audio processing
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            starters.push(this.startAudioStreaming(audioTrack));
        }

        // Set up video processing
        if (this.currentCall.type === 'video' && this.videoStream) {
            starters.push(this.startVideoStreaming());
        }

        await Promise.all(starters);
        if (
            generation !== this.mediaGeneration ||
            this.currentCall?.id !== expectedCallId ||
            this.currentCall.status !== 'connecting' ||
            !this.callConnection
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
        const ctx = new AudioContext({ sampleRate: 48_000, latencyHint: 'interactive' });
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
        const ctx = new AudioContext({ sampleRate: 48_000, latencyHint: 'interactive' });
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

    private attachCaptureMediaElement(el: HTMLVideoElement): void {
        if (!document.body) throw new Error('Call capture surface is unavailable');
        el.autoplay = true;
        el.controls = false;
        el.disablePictureInPicture = true;
        el.tabIndex = -1;
        el.setAttribute('aria-hidden', 'true');
        Object.assign(el.style, {
            position: 'fixed',
            left: '0',
            bottom: '0',
            width: '2px',
            height: '2px',
            opacity: '0.01',
            pointerEvents: 'none',
            zIndex: '2147483647',
        });
        document.body.appendChild(el);
    }

    private teardownCallMediaElements(): void {
        this.remoteVideoRenderId += 1;
        if (this.localVideoCanvas) {
            this.localVideoCanvas = null;
            this.notifyLocalVideoCanvas(null);
        }
        this.videoEncoder?.stop();
        this.screenEncoder?.stop();
        this.videoEncoder = null;
        this.screenEncoder = null;
        this.detachMediaElement(this.screenCaptureVideoEl);
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
        this.screenEncoder?.stop();
        this.screenEncoder = null;
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

        releaseVisualCanvas(this.remoteScreenCanvas);
        this.remoteScreenCanvas = null;
        this.notifyRemoteScreenCanvas(null);
    }

    private receiveExpectedScreenStream(stream: SecureStream, connection: SecureConnection): void {
        if (
            stream.type !== 'call-screen' ||
            stream.id !== this.expectedRemoteScreenStreamId ||
            this.callConnection !== connection ||
            !this.currentCall ||
            this.currentCall.status !== 'connected'
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
        if (!this.audioStream || !this.audioCodecSessionId) return;

        const generation = this.mediaGeneration;
        const stream = this.audioStream;
        const codecSessionId = this.audioCodecSessionId;

        const audioContext = await this.getSharedAudioContext();
        if (!this.audioWorkletLoaded) {
            await this.loadAudioWorklet(audioContext);
            this.audioWorkletLoaded = true;
        }

        if (generation !== this.mediaGeneration || this.audioStream !== stream) return;

        const source = audioContext.createMediaStreamSource(new MediaStream([track]));
        let workletNode: AudioWorkletNode | null = null;

        try {
            workletNode = new AudioWorkletNode(audioContext, 'audio-sender-processor');
            const senderNode = workletNode;
            const pending: PendingAudioCapture[] = [];
            let nextCaptureSequence = 0;
            let dtxFrames = 0;
            let streamDiscontinuity = false;
            let lastAudioRoute: string | null = null;
            const currentAudioRoute = (): string => {
                const telemetry = this.callConnection?.getAudioLaneTelemetry();
                return telemetry?.selectedLane
                    ? `lane:${telemetry.selectedLane}`
                    : 'primary';
            };
            let draining = false;
            const isCurrent = () =>
                generation === this.mediaGeneration &&
                this.audioStream === stream &&
                this.callAudioNode === senderNode &&
                this.audioCodecSessionId === codecSessionId;
            const drain = async (): Promise<void> => {
                if (draining) return;
                draining = true;
                try {
                    while (isCurrent() && pending.length > 0) {
                        const captures = pending.splice(0, MAX_AUDIO_BATCH_PACKETS);
                        const packets: Array<{ packet: Uint8Array; capturedAt: number }> = [];
                        const measuredRttMs = this.callTelemetry?.getLatestRttMs();
                        const sendDeadlineMs = measuredRttMs === null || measuredRttMs === undefined
                            ? AUDIO_SEND_DEADLINE_MS
                            : Math.min(
                                AUDIO_SEND_DEADLINE_MAX_MS,
                                AUDIO_SEND_DEADLINE_MS + Math.round(measuredRttMs * 0.05)
                            );
                        for (const capture of captures) {
                            let opusPacket: Uint8Array | null = null;
                            let packet: Uint8Array | null = null;
                            try {
                                if (!isCurrent() || Date.now() - capture.capturedAt >= sendDeadlineMs) {
                                    streamDiscontinuity = true;
                                    this.callTelemetry?.noteCaptureDrop('audio');
                                    continue;
                                }
                                opusPacket = await audioCodec.encode(codecSessionId, capture.pcm);
                                if (!isCurrent() || Date.now() - capture.capturedAt >= sendDeadlineMs) {
                                    streamDiscontinuity = true;
                                    this.callTelemetry?.noteCaptureDrop('audio');
                                    continue;
                                }
                                if (opusPacket.byteLength === 1) {
                                    dtxFrames += 1;
                                    if ((dtxFrames - 1) % AUDIO_DTX_KEEPALIVE_FRAMES !== 0) {
                                        streamDiscontinuity = true;
                                        continue;
                                    }
                                } else {
                                    dtxFrames = 0;
                                }
                                packet = createAudioPacket(
                                    opusPacket,
                                    capture.sequence,
                                    capture.capturedAt,
                                    streamDiscontinuity
                                );
                                streamDiscontinuity = false;
                                packets.push({ packet, capturedAt: capture.capturedAt });
                                packet = null;
                            } catch {
                                streamDiscontinuity = true;
                                this.callTelemetry?.noteSendError('audio');
                            } finally {
                                SecureMemory.zeroBuffer(capture.pcm);
                                if (opusPacket) SecureMemory.zeroBuffer(opusPacket);
                                if (packet) SecureMemory.zeroBuffer(packet);
                            }
                        }
                        if (packets.length === 0) continue;
                        let batch: Uint8Array | null = null;
                        try {
                            batch = encodeCallAudioBatch(packets.map(item => item.packet));
                            const writeStartedAt = performance.now();
                            await stream.write(batch, {
                                deadline: packets[0].capturedAt + sendDeadlineMs,
                                priority: 'realtime',
                            });
                            const writeMs = performance.now() - writeStartedAt;
                            const audioRoute = currentAudioRoute();
                            streamDiscontinuity = lastAudioRoute !== null && audioRoute !== lastAudioRoute;
                            lastAudioRoute = audioRoute;
                            for (const item of packets) {
                                this.callTelemetry?.noteSend('audio', item.packet.byteLength, writeMs);
                            }
                        } catch {
                            streamDiscontinuity = true;
                            this.callTelemetry?.noteSendError('audio');
                        } finally {
                            if (batch) SecureMemory.zeroBuffer(batch);
                            for (const item of packets) SecureMemory.zeroBuffer(item.packet);
                        }
                    }
                } finally {
                    draining = false;
                    if (isCurrent() && pending.length > 0) void drain();
                    if (!isCurrent()) {
                        for (const capture of pending.splice(0)) {
                            SecureMemory.zeroBuffer(capture.pcm);
                        }
                    }
                }
            };
            senderNode.port.onmessage = (e) => {
                const inputData = e.data;
                if (!(inputData instanceof Float32Array)) return;
                const incomingBytes = new Uint8Array(
                    inputData.buffer,
                    inputData.byteOffset,
                    inputData.byteLength
                );
                if (inputData.length !== OPUS_FRAME_SAMPLES || inputData.byteLength !== OPUS_PCM_BYTES) {
                    SecureMemory.zeroBuffer(incomingBytes);
                    return;
                }
                if (!isCurrent()) {
                    SecureMemory.zeroBuffer(incomingBytes);
                    return;
                }
                if (pending.length >= MAX_AUDIO_QUEUE_PACKETS) {
                    const dropped = pending.shift();
                    if (dropped) SecureMemory.zeroBuffer(dropped.pcm);
                    streamDiscontinuity = true;
                    this.callTelemetry?.noteCaptureDrop('audio');
                }
                pending.push({
                    pcm: incomingBytes,
                    capturedAt: Date.now(),
                    sequence: nextCaptureSequence,
                });
                nextCaptureSequence = (nextCaptureSequence + 1) >>> 0;
                void drain();
            };

            source.connect(senderNode);
            senderNode.connect(audioContext.destination);
            if (
                generation !== this.mediaGeneration ||
                this.audioStream !== stream
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
    private async startVideoStreaming(): Promise<void> {
        if (!this.videoStream || !this.localStream) return;

        const generation = this.mediaGeneration;
        const captureGeneration = this.cameraSwitchGeneration;
        const sourceStream = this.localStream;
        const transportStream = this.videoStream;
        const cameraSessionId = this.cameraSessionId;
        if (!cameraSessionId || this.currentCall?.id !== cameraSessionId) {
            throw new Error('Native camera capture is unavailable');
        }
        await this.getMediaSettings();
        if (
            generation !== this.mediaGeneration ||
            captureGeneration !== this.cameraSwitchGeneration ||
            this.localStream !== sourceStream ||
            this.videoStream !== transportStream
        ) return;

        this.videoEncoder?.stop();
        this.videoEncoder = null;
        if (this.localVideoCanvas) {
            this.localVideoCanvas = null;
            this.notifyLocalVideoCanvas(null);
        }

        const isActive = () =>
            generation === this.mediaGeneration &&
            captureGeneration === this.cameraSwitchGeneration &&
            this.localStream === sourceStream &&
            this.cameraSessionId === cameraSessionId &&
            this.currentCall?.id === cameraSessionId &&
            this.videoStream === transportStream &&
            !transportStream.closed;

        const encoder = new RealtimeVisualEncoder('video', {
            isActive,
            isSourceEnabled: () => this.videoEnabled,
            getQuality: () => this.mediaSettings?.quality ?? 'medium',
            send: async (frame, frames) => {
                if (!isActive()) throw new Error('Video sender is stale');
                const startedAt = performance.now();
                const sendDeadlineMs = visualFrameSendDeadlineMs(this.callTelemetry?.getLatestRttMs() ?? null);
                await transportStream.write(frame, {
                    deadline: frames[0].metadata.capturedAt + sendDeadlineMs,
                    priority: 'visual',
                });
                const writeMs = performance.now() - startedAt;
                for (const item of frames) {
                    this.callTelemetry?.noteSend('video', item.bytes, writeMs);
                    this.callTelemetry?.noteFrameSent('video', item.metadata.capturedAt);
                }
                return writeMs;
            },
            onCaptureDrop: () => this.callTelemetry?.noteCaptureDrop('video'),
            onEncode: milliseconds => this.callTelemetry?.noteEncode('video', milliseconds),
            onSendError: () => this.callTelemetry?.noteSendError('video'),
            onAdaptation: state => this.callTelemetry?.noteVisualState('video', state),
        });
        try {
            this.videoEncoder = encoder;
            this.localVideoCanvas = encoder.getCanvas();
            this.notifyLocalVideoCanvas(this.localVideoCanvas);
            encoder.start(new NativeCameraCaptureSource(cameraSessionId));
        } catch (error) {
            encoder.stop();
            if (this.videoEncoder === encoder) this.videoEncoder = null;
            if (this.localVideoCanvas === encoder.getCanvas()) {
                this.localVideoCanvas = null;
                this.notifyLocalVideoCanvas(null);
            }
            throw error;
        }
    }

    // Stream screen frames
    private async startScreenStreaming(): Promise<void> {
        if (!this.screenStream || !this.screenShareStream) {
            throw new Error('Screen media startup is incomplete');
        }

        const generation = this.mediaGeneration;
        const sourceStream = this.screenStream;
        const transportStream = this.screenShareStream;
        await this.getMediaSettings();
        if (
            generation !== this.mediaGeneration ||
            this.screenStream !== sourceStream ||
            this.screenShareStream !== transportStream
        ) return;

        const track = this.screenStream.getVideoTracks()[0];
        if (!track) return;

        const video = document.createElement('video');
        video.muted = true;
        video.playsInline = true;
        video.srcObject = sourceStream;
        this.attachCaptureMediaElement(video);
        this.screenCaptureVideoEl = video;

        const isActive = () =>
            generation === this.mediaGeneration &&
            this.isScreenSharing &&
            this.screenStream === sourceStream &&
            this.screenShareStream === transportStream &&
            this.screenCaptureVideoEl === video &&
            !transportStream.closed;

        let started = false;
        const beginCapture = () => {
            if (started) return;
            started = true;
            this.screenEncoder?.stop();
            const encoder = new RealtimeVisualEncoder('screen', {
                isActive,
                isSourceEnabled: () => track.enabled && track.readyState === 'live',
                getQuality: () => this.mediaSettings?.quality ?? 'medium',
                send: async (frame, frames) => {
                    if (!isActive()) throw new Error('Screen sender is stale');
                    const startedAt = performance.now();
                    const sendDeadlineMs = visualFrameSendDeadlineMs(this.callTelemetry?.getLatestRttMs() ?? null);
                    await transportStream.write(frame, {
                        deadline: frames[0].metadata.capturedAt + sendDeadlineMs,
                        priority: 'visual',
                    });
                    const writeMs = performance.now() - startedAt;
                    for (const item of frames) {
                        this.callTelemetry?.noteSend('screen', item.bytes, writeMs);
                        this.callTelemetry?.noteFrameSent('screen', item.metadata.capturedAt);
                    }
                    return writeMs;
                },
                onCaptureDrop: () => this.callTelemetry?.noteCaptureDrop('screen'),
                onEncode: milliseconds => this.callTelemetry?.noteEncode('screen', milliseconds),
                onSendError: () => this.callTelemetry?.noteSendError('screen'),
                onAdaptation: state => this.callTelemetry?.noteVisualState('screen', state),
            });
            this.screenEncoder = encoder;
            encoder.start(video);
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
        if (!this.audioStream || !this.audioCodecSessionId) return;

        const generation = this.mediaGeneration;
        const stream = this.audioStream;
        const codecSessionId = this.audioCodecSessionId;

        const audioContext = await this.getSharedReceiveAudioContext();
        if (!this.receiveAudioWorkletLoaded) {
            await this.loadAudioWorklet(audioContext);
            this.receiveAudioWorkletLoaded = true;
        }

        if (generation !== this.mediaGeneration || this.audioStream !== stream) return;

        let workletNode: AudioWorkletNode | null = null;
        let playoutTimer: ReturnType<typeof setInterval> | null = null;
        const jitterBuffer = new Map<number, BufferedAudioPacket>();
        try {
            workletNode = new AudioWorkletNode(audioContext, 'audio-receiver-processor');
            this.callReceiveAudioNode = workletNode;
            workletNode.connect(audioContext.destination);

            let expectedSequence: number | null = null;
            let started = false;
            let playoutBusy = false;
            let consecutiveLosses = 0;
            let lastArrival: number | null = null;
            let lastCapture: number | null = null;
            let estimatedJitterMs = 0;
            let targetPackets = MIN_AUDIO_JITTER_PACKETS;
            const sortedSequences = () => Array.from(jitterBuffer.keys()).sort((left, right) => left - right);
            const discardPacket = (sequence: number): void => {
                const packet = jitterBuffer.get(sequence);
                if (!packet) return;
                jitterBuffer.delete(sequence);
                SecureMemory.zeroBuffer(packet.packet);
            };
            const postDecoded = (bytes: Uint8Array): void => {
                if (bytes.byteLength !== OPUS_PCM_BYTES) {
                    SecureMemory.zeroBuffer(bytes);
                    throw new Error('Invalid decoded Opus PCM length');
                }
                const audioData = new Float32Array(OPUS_FRAME_SAMPLES);
                new Uint8Array(audioData.buffer).set(bytes);
                SecureMemory.zeroBuffer(bytes);
                workletNode!.port.postMessage(audioData, [audioData.buffer]);
            };
            const playout = async (): Promise<void> => {
                if (
                    playoutBusy ||
                    generation !== this.mediaGeneration ||
                    this.audioStream !== stream ||
                    this.audioCodecSessionId !== codecSessionId
                ) return;
                if (!started) {
                    const sequences = sortedSequences();
                    if (sequences.length === 0) return;
                    const oldest = jitterBuffer.get(sequences[0]);
                    if (
                        sequences.length < targetPackets &&
                        oldest &&
                        Date.now() - oldest.arrivedAt < 100
                    ) return;
                    expectedSequence = sequences[0];
                    started = true;
                }
                if (expectedSequence === null) return;
                playoutBusy = true;
                const decodeStartedAt = performance.now();
                let decoded: Uint8Array | null = null;
                let advanceExpectedSequence = true;
                try {
                    const exact = jitterBuffer.get(expectedSequence);
                    if (exact) {
                        jitterBuffer.delete(expectedSequence);
                        try {
                            decoded = await audioCodec.decode(codecSessionId, exact.packet, false);
                        } finally {
                            SecureMemory.zeroBuffer(exact.packet);
                        }
                        consecutiveLosses = 0;
                    } else {
                        const nextSequence = (expectedSequence + 1) >>> 0;
                        const next = jitterBuffer.get(nextSequence);
                        if (next) {
                            try {
                                decoded = await audioCodec.decode(codecSessionId, next.packet, true);
                            } catch {
                                decoded = await audioCodec.decode(codecSessionId, new Uint8Array(0), false);
                            }
                        } else if (consecutiveLosses < MAX_AUDIO_QUEUE_PACKETS) {
                            decoded = await audioCodec.decode(codecSessionId, new Uint8Array(0), false);
                        } else {
                            decoded = new Uint8Array(OPUS_PCM_BYTES);
                            advanceExpectedSequence = false;
                        }
                        consecutiveLosses += 1;
                    }
                    if (
                        generation !== this.mediaGeneration ||
                        this.audioStream !== stream ||
                        this.audioCodecSessionId !== codecSessionId
                    ) {
                        if (decoded) SecureMemory.zeroBuffer(decoded);
                        return;
                    }
                    if (decoded) postDecoded(decoded);
                    this.callTelemetry?.noteDecode('audio', performance.now() - decodeStartedAt);
                    if (advanceExpectedSequence) {
                        expectedSequence = (expectedSequence + 1) >>> 0;
                    }
                    const sequences = sortedSequences();
                    if (
                        consecutiveLosses >= MAX_AUDIO_QUEUE_PACKETS &&
                        sequences.length > 0 &&
                        sequences[0] > expectedSequence
                    ) {
                        expectedSequence = sequences[0];
                        consecutiveLosses = 0;
                    }
                    while (jitterBuffer.size > targetPackets) {
                        const oldestSequence = sortedSequences()[0];
                        if (oldestSequence === undefined) break;
                        discardPacket(oldestSequence);
                        if (oldestSequence >= expectedSequence) {
                            expectedSequence = (oldestSequence + 1) >>> 0;
                        }
                        this.callTelemetry?.noteRenderDrop('audio');
                    }
                } catch {
                    if (decoded) SecureMemory.zeroBuffer(decoded);
                    this.callTelemetry?.noteReceiveError('audio');
                } finally {
                    playoutBusy = false;
                }
            };
            playoutTimer = setInterval(() => { void playout(); }, AUDIO_FRAME_DURATION_MS);

            for await (const data of stream) {
                try {
                    if (generation !== this.mediaGeneration || this.audioStream !== stream) break;
                    const arrivedAt = Date.now();
                    for (const packet of decodeCallAudioBatch(data, arrivedAt)) {
                        this.callTelemetry?.noteReceive(
                            'audio',
                            AUDIO_PACKET_HEADER_BYTES + packet.packet.byteLength,
                            packet.capturedAt
                        );
                        if (
                            packet.discontinuity &&
                            started &&
                            expectedSequence !== null &&
                            packet.sequence > expectedSequence
                        ) {
                            expectedSequence = packet.sequence;
                            consecutiveLosses = 0;
                            for (const sequence of sortedSequences()) {
                                if (sequence < expectedSequence) discardPacket(sequence);
                            }
                        }
                        if (started && expectedSequence !== null && packet.sequence < expectedSequence) {
                            SecureMemory.zeroBuffer(packet.packet);
                            this.callTelemetry?.noteRenderDrop('audio');
                            continue;
                        }
                        if (jitterBuffer.has(packet.sequence)) {
                            SecureMemory.zeroBuffer(packet.packet);
                            continue;
                        }
                        if (lastArrival !== null && lastCapture !== null) {
                            const variation = Math.abs(
                                (packet.arrivedAt - lastArrival) -
                                (packet.capturedAt - lastCapture)
                            );
                            estimatedJitterMs += (variation - estimatedJitterMs) / 16;
                            targetPackets = Math.max(
                                MIN_AUDIO_JITTER_PACKETS,
                                Math.min(
                                    MAX_AUDIO_QUEUE_PACKETS,
                                    Math.ceil((60 + Math.min(40, estimatedJitterMs * 4)) / AUDIO_FRAME_DURATION_MS)
                                )
                            );
                        }
                        lastArrival = packet.arrivedAt;
                        lastCapture = packet.capturedAt;
                        jitterBuffer.set(packet.sequence, packet);
                        while (jitterBuffer.size > MAX_AUDIO_QUEUE_PACKETS) {
                            const oldestSequence = sortedSequences()[0];
                            if (oldestSequence === undefined) break;
                            discardPacket(oldestSequence);
                            this.callTelemetry?.noteRenderDrop('audio');
                        }
                    }
                } catch {
                    this.callTelemetry?.noteReceiveError('audio');
                } finally {
                    SecureMemory.zeroBuffer(data);
                }
            }
        } catch { }
        finally {
            if (playoutTimer) clearInterval(playoutTimer);
            for (const packet of jitterBuffer.values()) SecureMemory.zeroBuffer(packet.packet);
            jitterBuffer.clear();
            if (workletNode && this.callReceiveAudioNode === workletNode) {
                this.destroyAudioWorkletNode(workletNode);
                this.callReceiveAudioNode = null;
            }
        }
    }

    private async receiveVideoStream(): Promise<void> {
        if (!this.videoStream) return;

        const generation = this.mediaGeneration;
        const stream = this.videoStream;
        if (!this.remoteVideoCanvas) {
            this.remoteVideoCanvas = document.createElement('canvas');
            this.remoteVideoCanvas.width = 2;
            this.remoteVideoCanvas.height = 2;
            this.notifyRemoteVideoCanvas(this.remoteVideoCanvas);
        }
        const outputCanvas = this.remoteVideoCanvas;
        const renderId = ++this.remoteVideoRenderId;
        try {
            await this.receiveEncodedVisualStream(
                'video',
                stream,
                outputCanvas,
                () => generation === this.mediaGeneration &&
                    this.videoStream === stream &&
                    this.remoteVideoRenderId === renderId,
            );
        } finally {
            if (this.remoteVideoCanvas === outputCanvas) {
                releaseVisualCanvas(outputCanvas);
                this.remoteVideoCanvas = null;
                this.notifyRemoteVideoCanvas(null);
            }
        }
    }

    private async receiveScreenStream(stream: SecureStream): Promise<void> {
        if (stream.id !== this.expectedRemoteScreenStreamId) {
            this.abortSecureStream(stream, 'Unexpected call screen stream');
            return;
        }
        if (this.incomingScreenStream === stream) return;

        const generation = this.mediaGeneration;
        if (this.incomingScreenStream && this.incomingScreenStream !== stream) {
            this.abortSecureStream(this.incomingScreenStream, 'Replaced by a newer screen stream');
        }
        this.incomingScreenStream = stream;

        if (
            generation !== this.mediaGeneration ||
            !this.currentCall ||
            stream.id !== this.expectedRemoteScreenStreamId
        ) {
            this.abortSecureStream(stream, 'Call ended before screen stream initialized');
            if (this.incomingScreenStream === stream) this.incomingScreenStream = null;
            return;
        }

        if (!this.remoteScreenCanvas) {
            this.remoteScreenCanvas = document.createElement('canvas');
            this.remoteScreenCanvas.width = 2;
            this.remoteScreenCanvas.height = 2;
            this.notifyRemoteScreenCanvas(this.remoteScreenCanvas);
        }
        const outputCanvas = this.remoteScreenCanvas;

        try {
            await this.receiveEncodedVisualStream(
                'screen',
                stream,
                outputCanvas,
                () => generation === this.mediaGeneration &&
                    this.incomingScreenStream === stream &&
                    stream.id === this.expectedRemoteScreenStreamId,
            );
        } finally {
            if (this.incomingScreenStream === stream) {
                this.cleanupRemoteScreenShare();
            }
        }
    }

    private async receiveEncodedVisualStream(
        kind: 'video' | 'screen',
        stream: SecureStream,
        canvas: HTMLCanvasElement,
        isActive: () => boolean,
    ): Promise<void> {
        const context = canvas.getContext('2d', { alpha: false });
        if (!context) throw new Error('Visual renderer canvas is unavailable');

        let latestFrame: DecodedVisualFrame | null = null;
        let latestMetadata: VisualFrameMetadata | null = null;
        let animationFrameId: number | null = null;
        let renderRateStartedAt = performance.now();
        let renderedInWindow = 0;
        let renderedFps = 0;
        const render = () => {
            animationFrameId = null;
            const frame = latestFrame;
            const metadata = latestMetadata;
            latestFrame = null;
            latestMetadata = null;
            if (!frame || !metadata) return;
            try {
                if (!isActive()) return;
                if (canvas.width !== frame.width) canvas.width = frame.width;
                if (canvas.height !== frame.height) canvas.height = frame.height;
                context.drawImage(frame.source, 0, 0, canvas.width, canvas.height);
                if (kind === 'video') {
                    const now = performance.now();
                    renderedInWindow += 1;
                    const elapsed = now - renderRateStartedAt;
                    if (elapsed >= 1_000) {
                        const measuredFps = renderedInWindow * 1000 / elapsed;
                        renderedFps = renderedFps === 0
                            ? measuredFps
                            : renderedFps * 0.7 + measuredFps * 0.3;
                        renderedInWindow = 0;
                        renderRateStartedAt = now;
                    }
                    const label = `RX ${renderedFps.toFixed(1)} FPS`;
                    const fontSize = Math.max(12, Math.min(20, Math.round(canvas.height * 0.06)));
                    context.save();
                    context.font = `bold ${fontSize}px sans-serif`;
                    context.textBaseline = 'top';
                    const width = Math.ceil(context.measureText(label).width) + 16;
                    const x = Math.max(8, canvas.width - width - 8);
                    context.fillStyle = 'rgba(0, 0, 0, 0.72)';
                    context.fillRect(x, 8, width, fontSize + 12);
                    context.fillStyle = '#ffffff';
                    context.fillText(label, x + 8, 14);
                    context.restore();
                }
                this.callTelemetry?.noteFrameRendered(kind, metadata.capturedAt);
            } finally {
                try { frame.close(); } catch { }
            }
        };
        const decoder = new RealtimeVisualDecoder({
            onArrival: (bytes, metadata) => this.callTelemetry?.noteReceive(kind, bytes, metadata.capturedAt),
            getFrameAgeMs: metadata => this.callTelemetry?.getRemoteFrameAgeMs(metadata.capturedAt) ?? null,
            getMaxFrameAgeMs: () => visualPlayoutAgeMs(this.callTelemetry?.getLatestRttMs() ?? null),
            onAdmitted: () => this.callTelemetry?.noteDecoderAdmitted(kind),
            onFrame: (frame, metadata, decodeMs) => {
                this.callTelemetry?.noteDecode(kind, decodeMs);
                this.callTelemetry?.noteDecoded(kind);
                if (!isActive()) {
                    try { frame.close(); } catch { }
                    return;
                }
                if (latestFrame) {
                    try { latestFrame.close(); } catch { }
                    this.callTelemetry?.noteRenderDrop(kind);
                }
                latestFrame = frame;
                latestMetadata = metadata;
                if (animationFrameId === null) animationFrameId = requestAnimationFrame(render);
            },
            onDrop: () => this.callTelemetry?.noteRenderDrop(kind),
            onDiscontinuity: () => this.callTelemetry?.requestKeyFrame(kind),
            onError: () => this.callTelemetry?.noteReceiveError(kind),
            onState: state => this.callTelemetry?.noteVisualDecoderState(kind, state),
        });

        try {
            for await (const frame of stream) {
                try {
                    if (!isActive()) break;
                    for (const visualFrame of decodeVisualBatch(frame)) decoder.push(visualFrame);
                } catch {
                    this.callTelemetry?.noteReceiveError(kind);
                } finally {
                    SecureMemory.zeroBuffer(frame);
                }
            }
        } finally {
            decoder.stop();
            if (animationFrameId !== null) cancelAnimationFrame(animationFrameId);
            if (latestFrame) {
                try { latestFrame.close(); } catch { }
            }
        }
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
                if (this.incomingScreenStream || this.remoteScreenCanvas || this.expectedRemoteScreenStreamId) {
                    this.cleanupRemoteScreenShare();
                }
                this.expectedRemoteScreenStreamId = signal.data.streamId;
                this.remoteScreenCanvas = document.createElement('canvas');
                this.remoteScreenCanvas.width = 2;
                this.remoteScreenCanvas.height = 2;
                this.notifyRemoteScreenCanvas(this.remoteScreenCanvas);
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

        const callType = signal.data.callType;
        this.currentCall = {
            id: signal.callId,
            type: callType,
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
    private async handleCallAnswer(signal: Extract<CallSignal, { type: 'answer' }>): Promise<void> {
        if (!this.currentCall || this.currentCall.id !== signal.callId) { return; }
        if (this.currentCall.direction !== 'outgoing') { return; }
        if (this.currentCall.status !== 'ringing') { return; }

        this.currentCall.status = 'connecting';
        this.notifyCallState(this.currentCall);

        try {
            if (!this.callConnection || !this.audioStream) {
                await this.establishCallConnection(signal.from, signal.callId);
            }
            if (
                !this.currentCall ||
                this.currentCall.id !== signal.callId ||
                this.currentCall.peer !== signal.from ||
                this.currentCall.direction !== 'outgoing' ||
                this.currentCall.status !== 'connecting'
            ) {
                throw new Error('Call was cancelled while connecting media');
            }
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

            this.callTelemetry?.start();
            this.notifyCallState(this.currentCall);
        }
    }

    // Cleanup call resources
    private cleanup(): void {
        this.mediaGeneration += 1;
        this.cameraSwitchGeneration += 1;
        this.microphoneSwitchGeneration += 1;
        this.videoEnabled = false;
        this.cancelPendingSignalSessionWaits();
        this.unsubscribeCallConnectionState();
        this.unsubscribeCallStreams();
        this.teardownCallMediaElements();

        const cameraSessionId = this.cameraSessionId;
        this.cameraSessionId = null;
        if (cameraSessionId) void nativeCamera.stop(cameraSessionId).catch(() => { });

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

        this.callTelemetry?.stop();
        this.callTelemetry = null;

        const codecSessionId = this.audioCodecSessionId;
        this.audioCodecSessionId = null;
        if (codecSessionId) void audioCodec.stop(codecSessionId).catch(() => { });

        // Close streams
        for (const stream of [this.audioStream, this.videoStream, this.telemetryStream]) this.closeSecureStream(stream);
        this.audioStream = null;
        this.videoStream = null;
        this.telemetryStream = null;

        this.callConnection = null;

        // Clear timeouts
        if (this.callTimeoutId) {
            clearTimeout(this.callTimeoutId);
            this.callTimeoutId = null;
        }

        releaseVisualCanvas(this.remoteVideoCanvas);
        this.remoteVideoCanvas = null;
        this.notifyRemoteVideoCanvas(null);
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

    onRemoteVideoCanvas(callback: (canvas: HTMLCanvasElement | null) => void): void {
        this.onRemoteVideoCanvasCallback = callback;
    }

    onRemoteScreenCanvas(callback: (canvas: HTMLCanvasElement | null) => void): void {
        this.onRemoteScreenCanvasCallback = callback;
    }

    onLocalVideoCanvas(callback: (canvas: HTMLCanvasElement | null) => void): void {
        this.onLocalVideoCanvasCallback = callback;
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
        this.onRemoteVideoCanvasCallback = null;
        this.onRemoteScreenCanvasCallback = null;
        this.onLocalVideoCanvasCallback = null;
        this.onLocalStreamCallback = null;
    }
}
