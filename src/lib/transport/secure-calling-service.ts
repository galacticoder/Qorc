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
import { readAppSettingsAsync, updateAppSettingsAsync } from '../ui/app-settings';
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
    nativeAudioPlayback,
    nativeCamera,
    nativeMicrophone,
    nativeScreen,
    signal as signalApi,
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

const CAMERA_CAPTURE_WIDTH = 1280;
const CAMERA_CAPTURE_HEIGHT = 720;
import { blockingSystem } from '../blocking/blocking-system';
import { keyTransparencyClient } from '../key-transparency/client';
import { CallTelemetry } from './call-telemetry';
import {
    RealtimeVisualDecoder,
    RealtimeVisualEncoder,
    NativeCameraCaptureSource,
    NativeScreenCaptureSource,
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
type PendingIncomingCall = {
    call: CallState;
    receivedAt: number;
    timeoutId: ReturnType<typeof setTimeout>;
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
const CALL_CONNECTION_ATTEMPTS = 3;
const CALL_CONNECTION_RETRY_BASE_DELAY_MS = 500;
const CALL_PASSIVE_CONNECTION_WAIT_MS = 10_000;
const CAMERA_RECOVERY_RETRY_DELAYS_MS = [2_000, 5_000, 15_000] as const;
const CALL_OFFER_RATE_WINDOW_MS = 60_000;
const MAX_CALL_OFFERS_PER_PEER = 4;
const MAX_CALL_OFFERS_GLOBAL = 16;
const MAX_CALL_OFFER_RATE_PEERS = 128;
const MAX_PENDING_INCOMING_CALLS = 6;
const SCREEN_CAPTURE_REQUEST_TIMEOUT_MS = 30_000;
const SCREEN_SHARE_READY_TIMEOUT_MS = 10_000;
const SCREEN_FIRST_FRAME_TIMEOUT_MS = 10_000;
const SCREEN_SHARE_ANNOUNCEMENT_TIMEOUT_MS = 10_000;
const MAX_VISUAL_RENDER_QUEUE_FRAMES = 3;
const visualFrameSendDeadlineMs = (rttMs: number | null): number => (
    rttMs === null || !Number.isFinite(rttMs)
        ? VISUAL_FRAME_SEND_DEADLINE_MAX_MS
        : Math.min(
            VISUAL_FRAME_SEND_DEADLINE_MAX_MS,
            Math.max(VISUAL_FRAME_SEND_DEADLINE_MS, Math.round(250 + rttMs * 0.7))
        )
);
const isRetryableCallConnectionError = (error: unknown): boolean => {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.trim().toLowerCase();
    return normalized.includes('bridge disconnected') ||
        normalized.includes('connection failed: disconnected') ||
        normalized.includes('p2p inbound adoption failed: disconnected') ||
        normalized.includes('connection closed') ||
        normalized.includes('not connected');
};
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

// Calling Service
export class SecureCallingService {
    private localMediaActive = false;
    private localVideoCanvas: HTMLCanvasElement | null = null;
    private localScreenCanvas: HTMLCanvasElement | null = null;
    private remoteVideoCanvas: HTMLCanvasElement | null = null;
    private remoteScreenCanvas: HTMLCanvasElement | null = null;
    private screenStream: MediaStream | null = null;
    private screenCaptureVideoEl: HTMLVideoElement | null = null;
    private screenCaptureSessionId: string | null = null;
    private currentCall: CallState | null = null;
    private pendingIncomingCalls = new Map<string, PendingIncomingCall>();
    private isScreenSharing: boolean = false;
    private screenSharePending: boolean = false;
    private videoEnabled: boolean = false;
    private localUsername: string = '';
    private preferredCameraDeviceId: string | null = null;
    private preferredMicrophoneDeviceId: string | null = null;
    private preferredSpeakerDeviceId: string | null = null;
    private cameraSessionId: string | null = null;
    private microphoneSessionId: string | null = null;
    private microphoneEnabled = true;

    // Transport
    private transport: P2PTransport;
    private callConnection: SecureConnection | null = null;
    private audioStream: SecureStream | null = null;
    private videoStream: SecureStream | null = null;
    private telemetryStream: SecureStream | null = null;
    private screenShareStream: SecureStream | null = null;
    private incomingScreenStream: SecureStream | null = null;
    private pendingIncomingScreenStream: SecureStream | null = null;
    private pendingIncomingScreenStreamTimeoutId: ReturnType<typeof setTimeout> | null = null;
    private expectedRemoteScreenStreamId: string | null = null;
    private pendingScreenShareReady: PendingScreenShareReady | null = null;
    private seenRemoteScreenStreamIds = new Set<string>();
    private audioCodecSessionId: string | null = null;
    private audioPlaybackSessionId: string | null = null;

    private videoEncoder: RealtimeVisualEncoder | null = null;
    private screenEncoder: RealtimeVisualEncoder | null = null;
    private remoteVideoRenderId = 0;
    private lastCaptureReleaseAt = 0;
    private cameraRecoveryAttempts = 0;
    private cameraRecoveryInFlight = false;
    private cameraRecoveryTimer: ReturnType<typeof setTimeout> | null = null;

    private mediaGeneration = 0;
    private screenShareGeneration = 0;
    private cameraSwitchGeneration = 0;
    private microphoneSwitchGeneration = 0;
    private nextAudioCaptureSequence = 0;
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
    private securityQuarantined = keyTransparencyClient.isSecurityIncidentActive();

    // Callbacks
    private onIncomingCallCallback: ((call: CallState) => void) | null = null;
    private onCallStateChangeCallback: ((call: CallState, isActive: boolean) => void) | null = null;
    private onRemoteVideoCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onRemoteScreenCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onLocalVideoCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onLocalScreenCanvasCallback: ((canvas: HTMLCanvasElement | null) => void) | null = null;
    private onLocalMediaChangeCallback: ((active: boolean) => void) | null = null;
    private onScreenSharingChangeCallback: ((sharing: boolean) => void) | null = null;

    // Timers
    private callTimeoutId: ReturnType<typeof setTimeout> | null = null;
    private ringStartAt: number | null = null;
    private callTelemetry: CallTelemetry | null = null;

    private readonly beforeUnloadHandler = (): void => {
        if (this.currentCall && this.currentCall.status !== 'ended') {
            void this.endCall('shutdown');
        }
        this.clearPendingIncomingCalls('shutdown');
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
            detail.username !== detail.username.trim().toLowerCase()
        ) return;
        if (this.currentCall?.peer === detail.username) {
            void this.endCall('blocked');
        }
        for (const [callId, pending] of Array.from(this.pendingIncomingCalls.entries())) {
            if (pending.call.peer !== detail.username) continue;
            const call = this.finishPendingIncomingCall(callId, 'ended', 'blocked');
            if (!call) continue;
            void this.sendCallSignalBestEffort({
                type: 'end-call',
                callId: call.id,
                from: this.localUsername,
                to: call.peer,
                timestamp: Date.now()
            });
        }
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

        this.clearPendingIncomingCalls('shutdown');

        this.cleanup();
    };

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
            this.onCallStateChangeCallback?.({ ...call }, this.currentCall?.id === call.id);
        } catch (error) {
            console.error('[SecureCall] Call state observer failed:', error);
        }
    }

    getCallState(callId: string): CallState | null {
        if (this.currentCall?.id === callId) return { ...this.currentCall };
        const pending = this.pendingIncomingCalls.get(callId);
        return pending ? { ...pending.call } : null;
    }

    private takePendingIncomingCall(callId: string): PendingIncomingCall | null {
        const pending = this.pendingIncomingCalls.get(callId);
        if (!pending) return null;
        clearTimeout(pending.timeoutId);
        this.pendingIncomingCalls.delete(callId);
        return pending;
    }

    private finishPendingIncomingCall(
        callId: string,
        status: 'ended' | 'missed',
        endReason: CallState['endReason']
    ): CallState | null {
        const pending = this.takePendingIncomingCall(callId);
        if (!pending) return null;
        const endTime = Date.now();
        pending.call.status = status;
        pending.call.endTime = endTime;
        pending.call.duration = Math.max(0, endTime - pending.receivedAt);
        pending.call.endReason = endReason;
        this.notifyCallState(pending.call);
        return pending.call;
    }

    private clearPendingIncomingCalls(endReason: CallState['endReason']): void {
        for (const callId of Array.from(this.pendingIncomingCalls.keys())) {
            this.finishPendingIncomingCall(callId, 'ended', endReason);
        }
    }

    private queueIncomingCall(signal: Extract<CallSignal, { type: 'offer' }>): boolean {
        if (this.pendingIncomingCalls.has(signal.callId)) return true;
        if (this.pendingIncomingCalls.size >= MAX_PENDING_INCOMING_CALLS) return false;

        const receivedAt = Date.now();
        const call: CallState = {
            id: signal.callId,
            type: signal.data.callType,
            direction: 'incoming',
            status: 'ringing',
            peer: signal.from
        };
        const timeoutId = setTimeout(() => {
            this.finishPendingIncomingCall(signal.callId, 'missed', 'timeout');
        }, CALL_RING_TIMEOUT);
        this.pendingIncomingCalls.set(signal.callId, { call, receivedAt, timeoutId });
        this.notifyIncomingCall(call);
        this.notifyCallState(call);
        return true;
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

    private notifyLocalScreenCanvas(canvas: HTMLCanvasElement | null): void {
        try {
            this.onLocalScreenCanvasCallback?.(canvas);
        } catch (error) {
            console.error('[SecureCall] Local screen observer failed:', error);
        }
    }

    private notifyLocalMediaChange(active: boolean): void {
        try {
            this.onLocalMediaChangeCallback?.(active);
        } catch (error) {
            console.error('[SecureCall] Local media observer failed:', error);
        }
    }

    private notifyScreenSharing(sharing: boolean): void {
        try {
            this.onScreenSharingChangeCallback?.(sharing);
        } catch (error) {
            console.error('[SecureCall] Screen sharing observer failed:', error);
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

    private detachMediaElement(element: HTMLMediaElement | null): void {
        if (!element) return;
        try { element.pause(); } catch { }
        try { element.srcObject = null; } catch { }
        try { element.removeAttribute('src'); } catch { }
        try { element.remove(); } catch { }
    }

    private attachCaptureMediaElement(
        element: HTMLVideoElement,
        stream: MediaStream
    ): void {
        element.autoplay = true;
        element.muted = true;
        element.playsInline = true;
        element.preload = 'auto';
        element.disablePictureInPicture = true;
        element.style.position = 'fixed';
        element.style.left = '0';
        element.style.top = '0';
        element.style.width = '2px';
        element.style.height = '2px';
        element.style.opacity = '0.001';
        element.style.pointerEvents = 'none';
        element.style.zIndex = '0';
        document.body.appendChild(element);
        element.srcObject = stream;
        try {
            void element.play().catch(error => {
                console.error('[CALL-DIAG]', {
                    phase: 'screen.capture-playback-rejected',
                    errorName: error instanceof DOMException ? error.name : error instanceof Error ? error.name : 'Error',
                    errorMessage: error instanceof Error ? error.message : String(error)
                });
            });
        } catch (error) {
            this.detachMediaElement(element);
            throw error;
        }
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
        const storedSettings = await readAppSettingsAsync();
        this.preferredCameraDeviceId = storedSettings.preferredCameraId || null;
        this.preferredMicrophoneDeviceId = storedSettings.preferredCallMicId || null;
        this.preferredSpeakerDeviceId = storedSettings.preferredSpeakerId || null;

        if (this.destroyed) {
            throw new Error('Calling service was destroyed during initialization');
        }

        window.addEventListener('beforeunload', this.beforeUnloadHandler);
        window.addEventListener(EventType.CALL_SIGNAL, this.callSignalHandler);
        window.addEventListener(EventType.USER_BLOCKED, this.userBlockedHandler);
        window.addEventListener(
            EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT,
            this.keyTransparencySecurityIncidentHandler
        );
        this.initialized = true;
    }

    // Start a call to peer
    async startCall(targetUser: string, callType: 'audio' | 'video' = 'audio'): Promise<string> {
        const startedAt = performance.now();
        console.info('[CALL-DIAG]', { phase: 'service.start-enter', callType });
        console.info('[CALL-DIAG]', { phase: 'service.initialize-before', callType });
        await this.initialize();
        console.info('[CALL-DIAG]', {
            phase: 'service.initialize-after',
            callType,
            elapsedMs: Math.round(performance.now() - startedAt),
        });
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
        console.info('[CALL-DIAG]', { phase: 'service.notify-connecting-before', callType });
        this.notifyCallState(this.currentCall);
        console.info('[CALL-DIAG]', {
            phase: 'service.notify-connecting-after',
            callType,
            elapsedMs: Math.round(performance.now() - startedAt),
        });

        try {
            const signalingGeneration = this.lifecycleGeneration;
            console.info('[CALL-DIAG]', { phase: 'service.signal-session-before', callType });
            await this.waitForSignalSession(targetUser, signalingGeneration);
            console.info('[CALL-DIAG]', {
                phase: 'service.signal-session-after',
                callType,
                elapsedMs: Math.round(performance.now() - startedAt),
            });
            if (
                signalingGeneration !== this.lifecycleGeneration ||
                !this.currentCall ||
                this.currentCall.id !== callId ||
                this.currentCall.peer !== targetUser
            ) {
                throw new Error('Call was cancelled while preparing secure signaling');
            }

            // Set up local media
            console.info('[CALL-DIAG]', { phase: 'service.local-media-before', callType });
            const actualCallType = await this.setupLocalMedia(callType, callId);
            console.info('[CALL-DIAG]', {
                phase: 'service.local-media-after',
                callType: actualCallType,
                elapsedMs: Math.round(performance.now() - startedAt),
            });
            if (!this.currentCall || this.currentCall.id !== callId) { throw new Error('Call was cancelled'); }
            this.currentCall.type = actualCallType;

            const activeCallId = this.currentCall.id;
            this.currentCall.status = 'ringing';
            console.info('[CALL-DIAG]', { phase: 'service.notify-ringing-before', callType: actualCallType });
            this.notifyCallState(this.currentCall);
            console.info('[CALL-DIAG]', { phase: 'service.notify-ringing-after', callType: actualCallType });

            this.callTimeoutId = setTimeout(() => {
                if (this.currentCall?.id === activeCallId && this.currentCall.status === 'ringing') {
                    void this.endCall('timeout');
                }
            }, CALL_TIMEOUT);

            console.info('[CALL-DIAG]', { phase: 'service.offer-before', callType: actualCallType });
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
            console.info('[CALL-DIAG]', {
                phase: 'service.offer-after',
                callType: actualCallType,
                elapsedMs: Math.round(performance.now() - startedAt),
            });

            if (!this.currentCall || this.currentCall.id !== activeCallId || this.currentCall.peer !== targetUser) {
                throw new Error('Call ended while the offer was being delivered');
            }

            return activeCallId;

        } catch (error: unknown) {
            console.error('[CALL-DIAG]', {
                phase: 'service.start-failed',
                callType,
                elapsedMs: Math.round(performance.now() - startedAt),
                errorName: error instanceof Error ? error.name : 'UnknownError',
                errorMessage: error instanceof Error ? error.message : String(error),
            });
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
        const queuedCall = this.pendingIncomingCalls.get(callId);
        if (!queuedCall || queuedCall.call.status !== 'ringing') {
            throw new Error('No matching incoming call found');
        }

        if (this.currentCall) {
            await this.endCall('user');
        }

        const selected = this.takePendingIncomingCall(callId);
        if (!selected || selected.call.status !== 'ringing') {
            throw new Error('Incoming call ended before it could be answered');
        }
        this.currentCall = selected.call;
        this.ringStartAt = selected.receivedAt;

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

            if (!this.callConnection || !this.audioStream) {
                await this.establishCallConnection(peer, callId, true);
            }

            if (!this.currentCall || this.currentCall.id !== callId || this.currentCall.peer !== peer) {
                throw new Error('Call was cancelled');
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
        const queued = this.pendingIncomingCalls.get(callId);
        if (!queued || queued.call.status !== 'ringing') return;
        const call = this.finishPendingIncomingCall(callId, 'missed', 'timeout');
        if (!call) return;
        const signal: CallSignal = {
            type: 'end-call',
            callId,
            from: this.localUsername,
            to: call.peer,
            timestamp: Date.now()
        };

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
    async toggleMute(): Promise<boolean> {
        const sessionId = this.microphoneSessionId;
        if (!this.localMediaActive || !sessionId) return false;
        const enabled = !this.microphoneEnabled;
        await nativeMicrophone.setEnabled(sessionId, enabled);
        if (this.microphoneSessionId !== sessionId) return !this.microphoneEnabled;
        this.microphoneEnabled = enabled;
        return !enabled;
    }

    // Toggle video state
    async toggleVideo(): Promise<boolean> {
        const sessionId = this.cameraSessionId;
        if (!this.localMediaActive || this.currentCall?.type !== 'video' || !this.videoStream || !sessionId) return false;
        const enabled = !this.videoEnabled;
        await nativeCamera.setEnabled(sessionId, enabled);
        if (this.cameraSessionId !== sessionId || this.currentCall?.id !== sessionId) return false;
        this.videoEnabled = enabled;
        return enabled;
    }

    // Switch camera device
    async switchCamera(deviceId?: string): Promise<void> {
        if (!this.localMediaActive) throw new Error('No active local media capture');
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
        this.clearCameraRecoveryTimer();
        this.cameraRecoveryAttempts = 0;
        const switchGeneration = ++this.cameraSwitchGeneration;
        this.cameraRecoveryInFlight = true;
        try {
            await requireNativeMediaAccess('camera');
            await nativeCamera.start(activeCallId, deviceId, CAMERA_CAPTURE_WIDTH, CAMERA_CAPTURE_HEIGHT, TARGET_FPS);
            if (
                switchGeneration !== this.cameraSwitchGeneration ||
                this.currentCall?.id !== activeCallId ||
                this.cameraSessionId !== activeCallId
            ) {
                if (
                    this.currentCall?.id !== activeCallId ||
                    this.cameraSessionId !== activeCallId
                ) {
                    await nativeCamera.stop(activeCallId).catch(() => { });
                }
                throw new Error('Call changed while the camera was switching');
            }
            await nativeCamera.setEnabled(activeCallId, this.videoEnabled);
            await this.startVideoStreaming();
            if (
                switchGeneration !== this.cameraSwitchGeneration ||
                this.currentCall?.id !== activeCallId ||
                this.cameraSessionId !== activeCallId
            ) {
                if (
                    this.currentCall?.id !== activeCallId ||
                    this.cameraSessionId !== activeCallId
                ) {
                    await nativeCamera.stop(activeCallId).catch(() => { });
                }
                throw new Error('Call changed while the camera was switching');
            }
            this.preferredCameraDeviceId = deviceId;
            const account = this.localUsername;
            if (
                this.destroyed ||
                this.localUsername !== account ||
                this.preferredCameraDeviceId !== deviceId
            ) {
                throw new Error('Call changed before camera preference was persisted');
            }
            await updateAppSettingsAsync({ preferredCameraId: deviceId });
        } catch (error) {
            if (
                switchGeneration !== this.cameraSwitchGeneration &&
                (this.currentCall?.id !== activeCallId || this.cameraSessionId !== activeCallId)
            ) {
                await nativeCamera.stop(activeCallId).catch(() => { });
            }
            if (
                switchGeneration === this.cameraSwitchGeneration &&
                this.currentCall?.id === activeCallId &&
                this.cameraSessionId === activeCallId
            ) {
                try {
                    await nativeCamera.start(activeCallId, previousDeviceId, CAMERA_CAPTURE_WIDTH, CAMERA_CAPTURE_HEIGHT, TARGET_FPS);
                    await nativeCamera.setEnabled(activeCallId, this.videoEnabled);
                } catch { }
                try { await this.startVideoStreaming(); } catch { }
            }
            throw error;
        } finally {
            if (switchGeneration === this.cameraSwitchGeneration) {
                this.cameraRecoveryInFlight = false;
            }
        }
    }

    // Switch microphone device
    async switchMicrophone(deviceId: string): Promise<void> {
        if (!this.localMediaActive) throw new Error('No active local media capture');
        if (!isValidMediaDeviceId(deviceId)) throw new Error('Invalid microphone device identifier');
        const activeCallId = this.currentCall?.id;
        if (!activeCallId || this.microphoneSessionId !== activeCallId) {
            throw new Error('No active microphone capture');
        }
        if (this.preferredMicrophoneDeviceId === deviceId) return;
        const previousDeviceId = this.preferredMicrophoneDeviceId;
        const switchGeneration = ++this.microphoneSwitchGeneration;
        try {
            await requireNativeMediaAccess('microphone');
            await nativeMicrophone.start(activeCallId, deviceId);
            if (
                switchGeneration !== this.microphoneSwitchGeneration ||
                this.currentCall?.id !== activeCallId ||
                this.microphoneSessionId !== activeCallId
            ) {
                throw new Error('Call changed while the microphone was switching');
            }
            await nativeMicrophone.setEnabled(activeCallId, this.microphoneEnabled);
            await this.startAudioStreaming();
            if (
                switchGeneration !== this.microphoneSwitchGeneration ||
                this.currentCall?.id !== activeCallId ||
                this.microphoneSessionId !== activeCallId
            ) {
                throw new Error('Call changed while the microphone was switching');
            }
            this.preferredMicrophoneDeviceId = deviceId;
        } catch (error) {
            if (
                switchGeneration === this.microphoneSwitchGeneration &&
                this.currentCall?.id === activeCallId &&
                this.microphoneSessionId === activeCallId
            ) {
                try {
                    await nativeMicrophone.start(activeCallId, previousDeviceId);
                    await nativeMicrophone.setEnabled(activeCallId, this.microphoneEnabled);
                    await this.startAudioStreaming();
                } catch { }
            }
            throw error;
        }
    }

    async switchSpeaker(deviceId: string): Promise<void> {
        if (!isValidMediaDeviceId(deviceId)) throw new Error('Invalid speaker device identifier');
        const activeCallId = this.currentCall?.id;
        if (
            !activeCallId ||
            this.audioCodecSessionId !== activeCallId ||
            this.audioPlaybackSessionId !== activeCallId
        ) {
            throw new Error('Native call audio output is unavailable');
        }
        if (this.preferredSpeakerDeviceId === deviceId) return;
        const previousDeviceId = this.preferredSpeakerDeviceId;
        try {
            await nativeAudioPlayback.start(activeCallId, deviceId);
            if (
                this.currentCall?.id !== activeCallId ||
                this.audioCodecSessionId !== activeCallId
            ) {
                await nativeAudioPlayback.stop(activeCallId).catch(() => { });
                throw new Error('Call changed while the speaker was switching');
            }
            this.audioPlaybackSessionId = activeCallId;
            this.preferredSpeakerDeviceId = deviceId;
            await updateAppSettingsAsync({ preferredSpeakerId: deviceId });
        } catch (error) {
            try {
                await nativeAudioPlayback.start(activeCallId, previousDeviceId);
                if (this.currentCall?.id === activeCallId) {
                    this.audioPlaybackSessionId = activeCallId;
                }
            } catch {
                this.audioPlaybackSessionId = null;
            }
            throw error;
        }
    }

    // Start screen sharing
    async startScreenShare(): Promise<void> {
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
        const callId = this.currentCall.id;
        const peer = this.currentCall.peer;
        const connection = this.callConnection;
        const generation = ++this.screenShareGeneration;
        const startedAt = performance.now();
        this.screenSharePending = true;
        let acquiredStream: MediaStream | null = null;
        let acquiredNativeSessionId: string | null = null;
        let transportStream: SecureStream | null = null;
        const useNativeCapture = /\bLinux\b/i.test(navigator.userAgent);
        const shareIsCurrent = () =>
            generation === this.screenShareGeneration &&
            this.currentCall?.id === callId &&
            this.currentCall.status === 'connected' &&
            this.callConnection === connection;

        try {
            if (!shareIsCurrent()) {
                throw new Error('Call ended before screen capture');
            }
            console.info('[CALL-DIAG]', {
                phase: 'screen.capture-request-before',
                callId,
                generation,
                capturePath: useNativeCapture ? 'native-portal' : 'webview'
            });
            if (useNativeCapture) {
                acquiredNativeSessionId = callId;
                this.screenCaptureSessionId = acquiredNativeSessionId;
                await nativeScreen.start(acquiredNativeSessionId);
                if (!shareIsCurrent()) {
                    throw new Error('Call ended while screen capture was starting');
                }
                console.info('[CALL-DIAG]', {
                    phase: 'screen.capture-request-after',
                    callId,
                    generation,
                    elapsedMs: Math.round(performance.now() - startedAt),
                    capturePath: 'native-portal'
                });
            } else {
                if (!navigator.mediaDevices?.getDisplayMedia) {
                    throw new Error('Screen sharing is not supported by this runtime');
                }
                const screenStream = await this.requestDisplayCapture(callId, generation);
                acquiredStream = screenStream;
                const screenTrack = screenStream.getVideoTracks()[0];
                console.info('[CALL-DIAG]', {
                    phase: 'screen.capture-request-after',
                    callId,
                    generation,
                    elapsedMs: Math.round(performance.now() - startedAt),
                    capturePath: 'webview',
                    trackCount: screenStream.getVideoTracks().length,
                    trackState: screenTrack?.readyState ?? null,
                    settings: screenTrack?.getSettings() ?? null
                });
                if (!shareIsCurrent()) {
                    throw new Error('Call ended while screen capture was starting');
                }
                if (!screenTrack) {
                    throw new Error('Screen capture did not provide a video track');
                }
                try { screenTrack.contentHint = 'detail'; } catch { }
                this.screenStream = screenStream;
                screenTrack.onended = () => {
                    void this.stopScreenShare();
                };
                if (screenTrack.readyState !== 'live') {
                    throw new Error('Screen capture ended before sharing started');
                }
            }

            transportStream = await connection.createStream({
                type: 'call-screen',
                lossy: true
            });
            console.info('[CALL-DIAG]', {
                phase: 'screen.transport-created',
                callId,
                generation,
                streamId: transportStream.id,
                elapsedMs: Math.round(performance.now() - startedAt)
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
            console.info('[CALL-DIAG]', {
                phase: 'screen.announcement-sent',
                callId,
                generation,
                streamId: transportStream.id,
                elapsedMs: Math.round(performance.now() - startedAt)
            });
            if (
                generation !== this.screenShareGeneration ||
                this.screenShareStream !== transportStream ||
                !shareIsCurrent()
            ) {
                throw new Error('Call ended while screen sharing was being announced');
            }
            if (
                (useNativeCapture
                    ? this.screenCaptureSessionId !== acquiredNativeSessionId
                    : this.screenStream !== acquiredStream)
            ) {
                throw new Error('Screen capture changed while sharing was being announced');
            }
            await this.startScreenStreaming();
            console.info('[CALL-DIAG]', {
                phase: 'screen.encoder-started',
                callId,
                generation,
                streamId: transportStream.id,
                elapsedMs: Math.round(performance.now() - startedAt)
            });
            if (!await readyPromise || !shareIsCurrent() || this.screenShareStream !== transportStream) {
                throw new Error('Peer did not confirm the screen share');
            }
            console.info('[CALL-DIAG]', {
                phase: 'screen.peer-ready',
                callId,
                generation,
                streamId: transportStream.id,
                elapsedMs: Math.round(performance.now() - startedAt)
            });
            if (
                generation !== this.screenShareGeneration ||
                (useNativeCapture
                    ? this.screenCaptureSessionId !== acquiredNativeSessionId
                    : this.screenStream !== acquiredStream) ||
                this.screenShareStream !== transportStream ||
                !shareIsCurrent()
            ) {
                throw new Error('Call ended while screen sharing was starting');
            }
            this.isScreenSharing = true;
            console.info('[CALL-DIAG]', {
                phase: 'screen.ready',
                callId,
                generation,
                streamId: transportStream.id,
                elapsedMs: Math.round(performance.now() - startedAt)
            });
            this.notifyScreenSharing(true);

        } catch (error) {
            console.error('[CALL-DIAG]', {
                phase: 'screen.start-failed',
                callId,
                generation,
                elapsedMs: Math.round(performance.now() - startedAt),
                errorName: error instanceof DOMException ? error.name : error instanceof Error ? error.name : 'Error',
                errorMessage: error instanceof Error ? error.message : String(error)
            });
            if (acquiredStream && this.screenStream !== acquiredStream) {
                this.stopMediaStream(acquiredStream, true);
            }
            if (
                acquiredNativeSessionId &&
                this.screenCaptureSessionId !== acquiredNativeSessionId
            ) {
                void nativeScreen.stop(acquiredNativeSessionId).catch(() => { });
            }
            if (transportStream && this.screenShareStream !== transportStream) {
                this.closeSecureStream(transportStream);
            }
            if (generation === this.screenShareGeneration) {
                this.cleanupScreenShareLocal();
            }
            if (transportStream && this.currentCall?.id === callId && this.currentCall.peer === peer) {
                void this.sendCallSignalBestEffort({
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
        const startedAt = performance.now();
        console.info('[CALL-DIAG]', { phase: 'media.setup-enter', callType });
        console.info('[CALL-DIAG]', { phase: 'media.teardown-elements-before', callType });
        this.teardownCallMediaElements();
        console.info('[CALL-DIAG]', { phase: 'media.teardown-elements-after', callType });
        const previousCameraSessionId = this.cameraSessionId;
        this.cameraSessionId = null;
        if (previousCameraSessionId) {
            console.info('[CALL-DIAG]', { phase: 'media.previous-camera-stop-before', callType });
            try {
                await nativeCamera.stop(previousCameraSessionId);
                console.info('[CALL-DIAG]', { phase: 'media.previous-camera-stop-after', callType });
            } catch (error) {
                console.error('[CALL-DIAG]', {
                    phase: 'media.previous-camera-stop-failed',
                    errorName: error instanceof Error ? error.name : 'UnknownError',
                    errorMessage: error instanceof Error ? error.message : String(error),
                });
            }
        }
        const previousMicrophoneSessionId = this.microphoneSessionId;
        this.microphoneSessionId = null;
        if (previousMicrophoneSessionId) {
            console.info('[CALL-DIAG]', { phase: 'media.previous-microphone-stop-before', callType });
            try {
                await nativeMicrophone.stop(previousMicrophoneSessionId);
                console.info('[CALL-DIAG]', { phase: 'media.previous-microphone-stop-after', callType });
            } catch (error) {
                console.error('[CALL-DIAG]', {
                    phase: 'media.previous-microphone-stop-failed',
                    errorName: error instanceof Error ? error.name : 'UnknownError',
                    errorMessage: error instanceof Error ? error.message : String(error),
                });
            }
        }
        if (this.localMediaActive) {
            this.localMediaActive = false;
            this.notifyLocalMediaChange(false);
        }
        if (previousCameraSessionId || previousMicrophoneSessionId) {
            this.lastCaptureReleaseAt = Date.now();
        }

        const sinceRelease = Date.now() - this.lastCaptureReleaseAt;
        if (this.lastCaptureReleaseAt > 0 && sinceRelease < CALL_DEVICE_SETTLE_MS) {
            console.info('[CALL-DIAG]', {
                phase: 'media.device-settle-before',
                waitMs: CALL_DEVICE_SETTLE_MS - sinceRelease,
            });
            await new Promise(resolve => setTimeout(resolve, CALL_DEVICE_SETTLE_MS - sinceRelease));
            console.info('[CALL-DIAG]', { phase: 'media.device-settle-after' });
        }
        const callIsCurrent = () => this.currentCall?.id === expectedCallId;
        if (!callIsCurrent()) {
            throw new Error('Call was cancelled before media capture');
        }
        console.info('[CALL-DIAG]', { phase: 'media.native-permission-before', callType });
        await requireNativeMediaAccess(callType === 'video' ? 'microphone-camera' : 'microphone');
        console.info('[CALL-DIAG]', {
            phase: 'media.native-permission-after',
            callType,
            elapsedMs: Math.round(performance.now() - startedAt),
        });
        const storedSettings = await readAppSettingsAsync();
        this.preferredMicrophoneDeviceId = storedSettings.preferredCallMicId || null;
        this.preferredSpeakerDeviceId = storedSettings.preferredSpeakerId || null;
        this.preferredCameraDeviceId = storedSettings.preferredCameraId || null;
        console.info('[CALL-DIAG]', {
            phase: 'media.native-microphone-before',
            callType,
            preferredDevice: this.preferredMicrophoneDeviceId !== null,
        });
        await nativeMicrophone.start(expectedCallId, this.preferredMicrophoneDeviceId);
        this.microphoneSessionId = expectedCallId;
        this.microphoneEnabled = true;
        console.info('[CALL-DIAG]', {
            phase: 'media.native-microphone-after',
            callType,
            elapsedMs: Math.round(performance.now() - startedAt),
        });

        if (!callIsCurrent()) {
            this.microphoneSessionId = null;
            await nativeMicrophone.stop(expectedCallId);
            throw new Error('Call was cancelled while media permission was pending');
        }

        try {
            if (callType === 'video') {
                console.info('[CALL-DIAG]', {
                    phase: 'media.native-camera-before',
                    callType,
                    preferredDevice: this.preferredCameraDeviceId !== null,
                    width: CAMERA_CAPTURE_WIDTH,
                    height: CAMERA_CAPTURE_HEIGHT,
                    frameRate: TARGET_FPS,
                });
                await nativeCamera.start(
                    expectedCallId,
                    this.preferredCameraDeviceId,
                    CAMERA_CAPTURE_WIDTH,
                    CAMERA_CAPTURE_HEIGHT,
                    TARGET_FPS,
                );
                console.info('[CALL-DIAG]', {
                    phase: 'media.native-camera-after',
                    callType,
                    elapsedMs: Math.round(performance.now() - startedAt),
                });
                if (!callIsCurrent()) {
                    await nativeCamera.stop(expectedCallId);
                    throw new Error('Call was cancelled while camera capture was starting');
                }
                this.cameraSessionId = expectedCallId;
            }
        } catch (error) {
            this.microphoneSessionId = null;
            await nativeMicrophone.stop(expectedCallId).catch(() => { });
            throw error;
        }

        this.localMediaActive = true;
        this.videoEnabled = callType === 'video';
        console.info('[CALL-DIAG]', { phase: 'media.notify-local-capture-before', callType });
        this.notifyLocalMediaChange(true);
        console.info('[CALL-DIAG]', {
            phase: 'media.notify-local-capture-after',
            callType,
            elapsedMs: Math.round(performance.now() - startedAt),
        });
        return callType;
    }

    // Establish call connection
    private async establishCallConnection(
        peer: string,
        expectedCallId: string,
        passiveFirst = false,
    ): Promise<void> {
        const callIsCurrent = () =>
            this.currentCall?.id === expectedCallId &&
            this.currentCall.peer === peer &&
            this.currentCall.status === 'connecting';

        if (passiveFirst) {
            const passiveStartedAt = performance.now();
            console.info('[CALL-DIAG]', {
                phase: 'connection.passive-wait-before',
                callId: expectedCallId.slice(0, 12),
            });
            const connection = await this.waitForConnectedPeer(
                peer,
                callIsCurrent,
                CALL_PASSIVE_CONNECTION_WAIT_MS,
            );
            console.info('[CALL-DIAG]', {
                phase: connection ? 'connection.passive-wait-connected' : 'connection.passive-wait-expired',
                callId: expectedCallId.slice(0, 12),
                elapsedMs: Math.round(performance.now() - passiveStartedAt),
            });
            if (!callIsCurrent()) throw new Error('Call was cancelled while connecting');
        }

        let lastError: unknown = new Error('Call connection failed');
        for (let attempt = 0; attempt < CALL_CONNECTION_ATTEMPTS; attempt++) {
            if (!callIsCurrent()) throw new Error('Call was cancelled while connecting');

            let audioStream: SecureStream | null = null;
            let videoStream: SecureStream | null = null;
            let telemetryStream: SecureStream | null = null;
            try {
                const existingConnection = this.transport.getConnection(peer);
                const connection = existingConnection && existingConnection.state === 'connected'
                    ? existingConnection
                    : await this.transport.connect(peer, {
                        timeout: P2P_CONNECTION_TIMEOUT_MS
                    });
                if (!callIsCurrent()) throw new Error('Call was cancelled while connecting');

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

                telemetryStream = await connection.createStream({
                    type: 'call-telemetry',
                    id: `call-telemetry:${expectedCallId}`,
                    lossy: true
                });
                if (!callIsCurrent()) throw new Error('Call was cancelled while opening telemetry');
                if (connection.state !== 'connected') {
                    throw new Error('Call connection closed during setup');
                }

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
                if (attempt > 0) {
                    console.info('[CALL-DIAG]', {
                        phase: 'connection.retry-recovered',
                        callId: expectedCallId.slice(0, 12),
                        attempt: attempt + 1
                    });
                }
                return;
            } catch (error) {
                if (audioStream && this.audioStream !== audioStream) this.closeSecureStream(audioStream);
                if (videoStream && this.videoStream !== videoStream) this.closeSecureStream(videoStream);
                if (telemetryStream && this.telemetryStream !== telemetryStream) this.closeSecureStream(telemetryStream);
                lastError = error;

                if (!callIsCurrent()) throw new Error('Call was cancelled while connecting');
                if (
                    attempt + 1 >= CALL_CONNECTION_ATTEMPTS ||
                    !isRetryableCallConnectionError(error)
                ) {
                    throw error;
                }

                const delayMs = CALL_CONNECTION_RETRY_BASE_DELAY_MS * (2 ** attempt);
                console.warn('[CALL-DIAG]', {
                    phase: 'connection.retry',
                    callId: expectedCallId.slice(0, 12),
                    attempt: attempt + 2,
                    maxAttempts: CALL_CONNECTION_ATTEMPTS,
                    delayMs,
                    errorName: error instanceof Error ? error.name : 'UnknownError',
                    errorMessage: error instanceof Error ? error.message : String(error)
                });
                await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
            }
        }
        throw lastError;
    }

    private waitForConnectedPeer(
        peer: string,
        isCurrent: () => boolean,
        timeoutMs: number,
    ): Promise<SecureConnection | null> {
        const existing = this.transport.getConnection(peer);
        if (existing?.state === 'connected') return Promise.resolve(existing);
        return new Promise(resolve => {
            let settled = false;
            let timeoutId: ReturnType<typeof setTimeout> | null = null;
            let pollId: ReturnType<typeof setInterval> | null = null;
            let unsubscribe = () => { };
            const finish = (connection: SecureConnection | null) => {
                if (settled) return;
                settled = true;
                if (timeoutId) clearTimeout(timeoutId);
                if (pollId) clearInterval(pollId);
                unsubscribe();
                resolve(connection);
            };
            const inspect = () => {
                if (!isCurrent()) {
                    finish(null);
                    return;
                }
                const connection = this.transport.getConnection(peer);
                if (connection?.state === 'connected') finish(connection);
            };
            unsubscribe = this.transport.onPeerConnected(() => inspect());
            pollId = setInterval(inspect, 100);
            timeoutId = setTimeout(() => finish(null), timeoutMs);
            inspect();
        });
    }

    // Start streaming media frames
    private async startMediaStreaming(expectedCallId: string): Promise<void> {
        if (
            this.currentCall?.id !== expectedCallId ||
            this.currentCall.status !== 'connecting' ||
            !this.localMediaActive ||
            this.microphoneSessionId !== expectedCallId ||
            !this.callConnection
        ) {
            throw new Error('Call media startup is stale or incomplete');
        }

        const generation = this.mediaGeneration;
        if (this.audioCodecSessionId !== expectedCallId) {
            const previousSession = this.audioCodecSessionId;
            this.audioCodecSessionId = null;
            if (previousSession) {
                try { await audioCodec.stop(previousSession); } catch { }
            }
            await audioCodec.start(expectedCallId);
            this.audioCodecSessionId = expectedCallId;
        }
        if (this.audioPlaybackSessionId !== expectedCallId) {
            const previousSession = this.audioPlaybackSessionId;
            this.audioPlaybackSessionId = null;
            if (previousSession) {
                try { await nativeAudioPlayback.stop(previousSession); } catch { }
            }
            await nativeAudioPlayback.start(expectedCallId, this.preferredSpeakerDeviceId);
            this.audioPlaybackSessionId = expectedCallId;
        }
        const starters: Promise<void>[] = [];

        starters.push(this.startAudioStreaming());

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
        if (this.localScreenCanvas) {
            this.localScreenCanvas = null;
            this.notifyLocalScreenCanvas(null);
        }
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

    private requestDisplayCapture(callId: string, generation: number): Promise<MediaStream> {
        return new Promise<MediaStream>((resolve, reject) => {
            let settled = false;
            const startedAt = performance.now();
            const timeoutId = setTimeout(() => {
                if (settled) return;
                settled = true;
                console.error('[CALL-DIAG]', {
                    phase: 'screen.capture-request-timeout',
                    callId,
                    generation,
                    elapsedMs: Math.round(performance.now() - startedAt)
                });
                reject(new DOMException('Screen capture request timed out', 'TimeoutError'));
            }, SCREEN_CAPTURE_REQUEST_TIMEOUT_MS);

            let request: Promise<MediaStream>;
            try {
                request = navigator.mediaDevices.getDisplayMedia({
                    video: true,
                    audio: false
                });
            } catch (error) {
                clearTimeout(timeoutId);
                settled = true;
                reject(error);
                return;
            }

            void request.then(
                stream => {
                    if (settled) {
                        this.stopMediaStream(stream, true);
                        return;
                    }
                    if (generation !== this.screenShareGeneration) {
                        settled = true;
                        clearTimeout(timeoutId);
                        this.stopMediaStream(stream, true);
                        reject(new Error('Call ended while screen capture was starting'));
                        return;
                    }
                    settled = true;
                    clearTimeout(timeoutId);
                    resolve(stream);
                },
                error => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timeoutId);
                    reject(error);
                }
            );
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
        if (this.localScreenCanvas) {
            this.localScreenCanvas = null;
            this.notifyLocalScreenCanvas(null);
        }
        this.screenSharePending = false;
        const stream = this.screenStream;
        this.screenStream = null;
        const nativeSessionId = this.screenCaptureSessionId;
        this.screenCaptureSessionId = null;
        const wasScreenSharing = this.isScreenSharing;
        this.isScreenSharing = false;
        this.stopMediaStream(stream, true);
        if (nativeSessionId) void nativeScreen.stop(nativeSessionId).catch(() => { });
        this.detachMediaElement(this.screenCaptureVideoEl);
        this.screenCaptureVideoEl = null;

        const transportStream = this.screenShareStream;
        this.screenShareStream = null;
        this.closeSecureStream(transportStream);

        if (wasScreenSharing) this.notifyScreenSharing(false);
    }

    private cleanupRemoteScreenShare(preservePendingStreamId: string | null = null): void {
        const preservedPending = this.pendingIncomingScreenStream?.id === preservePendingStreamId
            ? this.pendingIncomingScreenStream
            : null;
        this.clearPendingIncomingScreenStream(preservedPending);
        this.expectedRemoteScreenStreamId = null;
        const incoming = this.incomingScreenStream;
        this.incomingScreenStream = null;
        this.abortSecureStream(incoming, 'Screen sharing stopped');

        releaseVisualCanvas(this.remoteScreenCanvas);
        this.remoteScreenCanvas = null;
        this.notifyRemoteScreenCanvas(null);
    }

    private clearPendingIncomingScreenStream(keep: SecureStream | null = null): void {
        if (this.pendingIncomingScreenStreamTimeoutId) {
            clearTimeout(this.pendingIncomingScreenStreamTimeoutId);
            this.pendingIncomingScreenStreamTimeoutId = null;
        }
        const pending = this.pendingIncomingScreenStream;
        this.pendingIncomingScreenStream = null;
        if (pending && pending !== keep) {
            this.abortSecureStream(pending, 'Screen share was not announced');
        }
    }

    private receiveExpectedScreenStream(stream: SecureStream, connection: SecureConnection): void {
        if (
            stream.type !== 'call-screen' ||
            this.callConnection !== connection ||
            !this.currentCall ||
            this.currentCall.status !== 'connected'
        ) {
            this.abortSecureStream(stream, 'Unannounced call screen stream');
            return;
        }
        if (!this.expectedRemoteScreenStreamId) {
            this.clearPendingIncomingScreenStream(stream);
            this.pendingIncomingScreenStream = stream;
            this.pendingIncomingScreenStreamTimeoutId = setTimeout(() => {
                if (this.pendingIncomingScreenStream !== stream) return;
                this.pendingIncomingScreenStream = null;
                this.pendingIncomingScreenStreamTimeoutId = null;
                this.abortSecureStream(stream, 'Screen share announcement timed out');
            }, SCREEN_SHARE_ANNOUNCEMENT_TIMEOUT_MS);
            return;
        }
        if (stream.id !== this.expectedRemoteScreenStreamId) {
            this.abortSecureStream(stream, 'Unexpected call screen stream');
            return;
        }
        this.clearPendingIncomingScreenStream(stream);
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
    private async startAudioStreaming(): Promise<void> {
        if (!this.audioStream || !this.audioCodecSessionId || !this.microphoneSessionId) return;

        const generation = this.mediaGeneration;
        const captureGeneration = this.microphoneSwitchGeneration;
        const stream = this.audioStream;
        const codecSessionId = this.audioCodecSessionId;
        const microphoneSessionId = this.microphoneSessionId;
        const pending: PendingAudioCapture[] = [];
        let nativeSequence = 0;
        let dtxFrames = 0;
        let streamDiscontinuity = false;
        let lastAudioRoute: string | null = null;
        let draining = false;
        const isCurrent = () =>
            generation === this.mediaGeneration &&
            captureGeneration === this.microphoneSwitchGeneration &&
            this.audioStream === stream &&
            this.audioCodecSessionId === codecSessionId &&
            this.microphoneSessionId === microphoneSessionId;
        const currentAudioRoute = (): string => {
            const telemetry = this.callConnection?.getAudioLaneTelemetry();
            return telemetry?.selectedLane
                ? `lane:${telemetry.selectedLane}`
                : 'primary';
        };
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
                            transferOwnership: true,
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
        void (async () => {
            while (isCurrent()) {
                try {
                    const frame = await nativeMicrophone.pull(microphoneSessionId, nativeSequence);
                    if (!isCurrent()) {
                        if (frame) SecureMemory.zeroBuffer(frame.pcm);
                        break;
                    }
                    if (!frame) continue;
                    if (
                        nativeSequence !== 0 &&
                        frame.sequence !== ((nativeSequence + 1) >>> 0)
                    ) {
                        streamDiscontinuity = true;
                        this.callTelemetry?.noteCaptureDrop('audio');
                    }
                    nativeSequence = frame.sequence;
                    if (frame.pcm.byteLength !== OPUS_PCM_BYTES) {
                        SecureMemory.zeroBuffer(frame.pcm);
                        streamDiscontinuity = true;
                        this.callTelemetry?.noteCaptureDrop('audio');
                        continue;
                    }
                    if (pending.length >= MAX_AUDIO_QUEUE_PACKETS) {
                        const dropped = pending.shift();
                        if (dropped) SecureMemory.zeroBuffer(dropped.pcm);
                        streamDiscontinuity = true;
                        this.callTelemetry?.noteCaptureDrop('audio');
                    }
                    pending.push({
                        pcm: frame.pcm,
                        capturedAt: frame.capturedAt,
                        sequence: this.nextAudioCaptureSequence,
                    });
                    this.nextAudioCaptureSequence = (this.nextAudioCaptureSequence + 1) >>> 0;
                    void drain();
                } catch (error) {
                    if (isCurrent()) {
                        console.error('[CALL-DIAG]', {
                            phase: 'media.native-microphone-pull-failed',
                            errorName: error instanceof Error ? error.name : 'UnknownError',
                            errorMessage: error instanceof Error ? error.message : String(error),
                        });
                        this.callTelemetry?.noteSendError('audio');
                    }
                    break;
                }
            }
        })();
    }

    // Stream video frames
    private async startVideoStreaming(): Promise<void> {
        if (!this.videoStream || !this.localMediaActive) return;

        const generation = this.mediaGeneration;
        const captureGeneration = this.cameraSwitchGeneration;
        const transportStream = this.videoStream;
        const cameraSessionId = this.cameraSessionId;
        if (!cameraSessionId || this.currentCall?.id !== cameraSessionId) {
            throw new Error('Native camera capture is unavailable');
        }
        if (
            generation !== this.mediaGeneration ||
            captureGeneration !== this.cameraSwitchGeneration ||
            !this.localMediaActive ||
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
            this.localMediaActive &&
            this.cameraSessionId === cameraSessionId &&
            this.currentCall?.id === cameraSessionId &&
            this.videoStream === transportStream &&
            !transportStream.closed;

        let localPreviewAnnounced = false;
        const encoder = new RealtimeVisualEncoder('video', {
            isActive,
            isSourceEnabled: () => this.videoEnabled,
            send: async (frame, frames) => {
                if (!isActive()) throw new Error('Video sender is stale');
                const startedAt = performance.now();
                const sendDeadlineMs = visualFrameSendDeadlineMs(this.callTelemetry?.getLatestRttMs() ?? null);
                await transportStream.write(frame, {
                    deadline: frames[0].metadata.capturedAt + sendDeadlineMs,
                    priority: 'visual',
                    transferOwnership: true,
                });
                const writeMs = performance.now() - startedAt;
                for (const item of frames) {
                    this.callTelemetry?.noteSend('video', item.bytes, writeMs);
                    this.callTelemetry?.noteFrameSent('video', item.metadata.capturedAt);
                }
                return writeMs;
            },
            onCaptureDrop: () => this.callTelemetry?.noteCaptureDrop('video'),
            onSourceFrame: () => this.callTelemetry?.noteSourceFrame('video'),
            onSourceDrop: count => this.callTelemetry?.noteSourceDrop('video', count),
            onSourceError: reason => {
                console.error('[CALL-DIAG]', {
                    phase: 'media.native-camera-source-failed',
                    callId: cameraSessionId.slice(0, 12),
                    reason,
                });
                if (this.videoEncoder === encoder) {
                    void this.recoverNativeCamera(cameraSessionId, encoder);
                }
            },
            onCaptureTiming: (stage, milliseconds) =>
                this.callTelemetry?.noteCaptureTiming('video', stage, milliseconds),
            onEncode: milliseconds => this.callTelemetry?.noteEncode('video', milliseconds),
            onSendError: () => this.callTelemetry?.noteSendError('video'),
            onAdaptation: state => {
                this.callTelemetry?.noteVisualState('video', state);
                if (
                    !localPreviewAnnounced &&
                    this.videoEncoder === encoder &&
                    this.localVideoCanvas === encoder.getCanvas()
                ) {
                    localPreviewAnnounced = true;
                    this.notifyLocalVideoCanvas(encoder.getCanvas());
                }
            },
            onState: state => this.callTelemetry?.noteVisualEncoderState('video', state),
            onDiagnostic: event => this.callTelemetry?.noteVisualPipelineEvent('video', 'sender', event),
        });
        try {
            this.videoEncoder = encoder;
            this.localVideoCanvas = encoder.getCanvas();
            encoder.start(new NativeCameraCaptureSource(cameraSessionId));
            this.clearCameraRecoveryTimer();
            this.cameraRecoveryAttempts = 0;
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

    private async recoverNativeCamera(
        expectedCallId: string,
        failedEncoder: RealtimeVisualEncoder,
    ): Promise<void> {
        const call = this.currentCall;
        if (
            this.videoEncoder !== failedEncoder ||
            call?.id !== expectedCallId ||
            call.type !== 'video' ||
            (call.status !== 'connecting' && call.status !== 'connected') ||
            this.cameraSessionId !== expectedCallId
        ) return;
        if (this.cameraRecoveryInFlight || this.cameraRecoveryTimer) return;
        this.cameraRecoveryInFlight = true;
        this.cameraRecoveryAttempts += 1;
        const recoveryAttempt = this.cameraRecoveryAttempts;
        const recoveryGeneration = ++this.cameraSwitchGeneration;
        let nativeCaptureStarted = false;
        console.info('[CALL-DIAG]', {
            phase: 'media.native-camera-recovery-before',
            callId: expectedCallId.slice(0, 12),
            attempt: recoveryAttempt,
        });
        try {
            await nativeCamera.start(
                expectedCallId,
                this.preferredCameraDeviceId,
                CAMERA_CAPTURE_WIDTH,
                CAMERA_CAPTURE_HEIGHT,
                TARGET_FPS,
            );
            nativeCaptureStarted = true;
            if (!this.isCameraRecoveryCurrent(
                expectedCallId,
                failedEncoder,
                recoveryGeneration,
            )) {
                if (
                    this.currentCall?.id !== expectedCallId ||
                    this.cameraSessionId !== expectedCallId
                ) {
                    await nativeCamera.stop(expectedCallId).catch(() => { });
                }
                return;
            }
            await nativeCamera.setEnabled(expectedCallId, this.videoEnabled);
            if (!this.isCameraRecoveryCurrent(
                expectedCallId,
                failedEncoder,
                recoveryGeneration,
            )) {
                if (
                    this.currentCall?.id !== expectedCallId ||
                    this.cameraSessionId !== expectedCallId
                ) {
                    await nativeCamera.stop(expectedCallId).catch(() => { });
                }
                return;
            }
            await this.startVideoStreaming();
            console.info('[CALL-DIAG]', {
                phase: 'media.native-camera-recovery-after',
                callId: expectedCallId.slice(0, 12),
                attempt: recoveryAttempt,
            });
        } catch (error) {
            const call = this.currentCall;
            const recoveryOwnsCall = recoveryGeneration === this.cameraSwitchGeneration &&
                call?.id === expectedCallId &&
                call.type === 'video' &&
                (call.status === 'connecting' || call.status === 'connected') &&
                this.cameraSessionId === expectedCallId;
            if (!recoveryOwnsCall) {
                if (
                    nativeCaptureStarted &&
                    (call?.id !== expectedCallId || this.cameraSessionId !== expectedCallId)
                ) {
                    await nativeCamera.stop(expectedCallId).catch(() => { });
                }
                return;
            }
            console.error('[CALL-DIAG]', {
                phase: 'media.native-camera-recovery-failed',
                callId: expectedCallId.slice(0, 12),
                attempt: recoveryAttempt,
                errorName: error instanceof Error ? error.name : 'UnknownError',
                errorMessage: error instanceof Error ? error.message : String(error),
            });
            if (nativeCaptureStarted) {
                await nativeCamera.stop(expectedCallId).catch(() => { });
            }
            const retryDelay = CAMERA_RECOVERY_RETRY_DELAYS_MS[recoveryAttempt - 1];
            if (retryDelay !== undefined && this.videoEncoder === failedEncoder) {
                this.scheduleCameraRecovery(expectedCallId, failedEncoder, retryDelay);
            } else if (this.videoEncoder === failedEncoder) {
                failedEncoder.stop();
                this.videoEncoder = null;
                if (this.localVideoCanvas === failedEncoder.getCanvas()) {
                    this.localVideoCanvas = null;
                    this.notifyLocalVideoCanvas(null);
                }
            }
        } finally {
            if (recoveryGeneration === this.cameraSwitchGeneration) {
                this.cameraRecoveryInFlight = false;
            }
        }
    }

    private isCameraRecoveryCurrent(
        expectedCallId: string,
        failedEncoder: RealtimeVisualEncoder,
        recoveryGeneration: number,
    ): boolean {
        const call = this.currentCall;
        return recoveryGeneration === this.cameraSwitchGeneration &&
            this.videoEncoder === failedEncoder &&
            call?.id === expectedCallId &&
            call.type === 'video' &&
            (call.status === 'connecting' || call.status === 'connected') &&
            this.cameraSessionId === expectedCallId;
    }

    private scheduleCameraRecovery(
        expectedCallId: string,
        failedEncoder: RealtimeVisualEncoder,
        delayMs: number,
    ): void {
        if (this.cameraRecoveryTimer || this.videoEncoder !== failedEncoder) return;
        console.info('[CALL-DIAG]', {
            phase: 'media.native-camera-recovery-scheduled',
            callId: expectedCallId.slice(0, 12),
            attempt: this.cameraRecoveryAttempts + 1,
            delayMs,
        });
        this.cameraRecoveryTimer = setTimeout(() => {
            this.cameraRecoveryTimer = null;
            void this.recoverNativeCamera(expectedCallId, failedEncoder);
        }, delayMs);
    }

    private clearCameraRecoveryTimer(): void {
        if (this.cameraRecoveryTimer) clearTimeout(this.cameraRecoveryTimer);
        this.cameraRecoveryTimer = null;
    }

    // Stream screen frames
    private async startScreenStreaming(): Promise<void> {
        if ((!this.screenStream && !this.screenCaptureSessionId) || !this.screenShareStream) {
            throw new Error('Screen media startup is incomplete');
        }

        const generation = this.mediaGeneration;
        const captureStream = this.screenStream;
        const captureSessionId = this.screenCaptureSessionId;
        const transportStream = this.screenShareStream;
        const captureTrack = captureStream?.getVideoTracks()[0] ?? null;
        if (!captureSessionId && (!captureTrack || captureTrack.readyState !== 'live')) {
            throw new Error('Screen capture video track is unavailable');
        }
        if (
            generation !== this.mediaGeneration ||
            this.screenStream !== captureStream ||
            this.screenCaptureSessionId !== captureSessionId ||
            this.screenShareStream !== transportStream
        ) {
            throw new Error('Screen sharing changed before capture playback started');
        }

        let captureVideo: HTMLVideoElement | null = null;
        const captureSource = captureSessionId
            ? new NativeScreenCaptureSource(captureSessionId)
            : (() => {
                const element = document.createElement('video');
                console.info('[CALL-DIAG]', {
                    phase: 'screen.capture-element-before',
                    callId: this.currentCall?.id ?? null,
                    streamId: transportStream.id,
                    trackState: captureTrack?.readyState ?? null
                });
                this.attachCaptureMediaElement(element, captureStream!);
                console.info('[CALL-DIAG]', {
                    phase: 'screen.capture-element-after',
                    callId: this.currentCall?.id ?? null,
                    streamId: transportStream.id,
                    readyState: element.readyState,
                    videoWidth: element.videoWidth,
                    videoHeight: element.videoHeight,
                    trackState: captureTrack?.readyState ?? null
                });
                captureVideo = element;
                return element;
            })();
        if (
            generation !== this.mediaGeneration ||
            this.screenStream !== captureStream ||
            this.screenCaptureSessionId !== captureSessionId ||
            this.screenShareStream !== transportStream ||
            (!captureSessionId && captureTrack?.readyState !== 'live')
        ) {
            this.detachMediaElement(captureVideo);
            throw new Error('Screen sharing changed while capture playback was starting');
        }

        const isActive = () =>
            generation === this.mediaGeneration &&
            (this.isScreenSharing || this.screenSharePending) &&
            this.screenStream === captureStream &&
            this.screenCaptureSessionId === captureSessionId &&
            this.screenShareStream === transportStream &&
            (captureSessionId !== null || captureTrack?.readyState === 'live') &&
            !transportStream.closed;

        this.screenEncoder?.stop();
        this.detachMediaElement(this.screenCaptureVideoEl);
        this.screenCaptureVideoEl = captureVideo;
        let localPreviewAnnounced = false;
        let resolveFirstFrame = () => { };
        let rejectFirstFrame = (_error: Error) => { };
        let firstFrameTimeoutId: ReturnType<typeof setTimeout> | null = null;
        const firstFramePromise = new Promise<void>((resolve, reject) => {
            resolveFirstFrame = resolve;
            rejectFirstFrame = reject;
            firstFrameTimeoutId = setTimeout(
                () => reject(new Error('Screen capture did not produce a frame')),
                SCREEN_FIRST_FRAME_TIMEOUT_MS
            );
        });
        const encoder = new RealtimeVisualEncoder('screen', {
            isActive,
            isSourceEnabled: () => true,
            send: async (frame, frames) => {
                if (!isActive()) throw new Error('Screen sender is stale');
                const startedAt = performance.now();
                const sendDeadlineMs = visualFrameSendDeadlineMs(this.callTelemetry?.getLatestRttMs() ?? null);
                await transportStream.write(frame, {
                    deadline: frames[0].metadata.capturedAt + sendDeadlineMs,
                    priority: 'visual',
                    transferOwnership: true,
                });
                const writeMs = performance.now() - startedAt;
                for (const item of frames) {
                    this.callTelemetry?.noteSend('screen', item.bytes, writeMs);
                    this.callTelemetry?.noteFrameSent('screen', item.metadata.capturedAt);
                }
                return writeMs;
            },
            onCaptureDrop: () => this.callTelemetry?.noteCaptureDrop('screen'),
            onSourceFrame: () => this.callTelemetry?.noteSourceFrame('screen'),
            onSourceDrop: count => this.callTelemetry?.noteSourceDrop('screen', count),
            onSourceError: reason => {
                console.error('[CALL-DIAG]', {
                    phase: 'screen.native-source-failed',
                    callId: this.currentCall?.id ?? null,
                    streamId: transportStream.id,
                    reason,
                });
                if (!localPreviewAnnounced) {
                    rejectFirstFrame(new Error(reason));
                } else if (this.screenEncoder === encoder) {
                    void this.stopScreenShare();
                }
            },
            onCaptureTiming: (stage, milliseconds) =>
                this.callTelemetry?.noteCaptureTiming('screen', stage, milliseconds),
            onEncode: milliseconds => this.callTelemetry?.noteEncode('screen', milliseconds),
            onSendError: () => this.callTelemetry?.noteSendError('screen'),
            onAdaptation: state => {
                this.callTelemetry?.noteVisualState('screen', state);
                if (
                    !localPreviewAnnounced &&
                    this.screenEncoder === encoder &&
                    this.localScreenCanvas === encoder.getCanvas()
                ) {
                    localPreviewAnnounced = true;
                    console.info('[CALL-DIAG]', {
                        phase: 'screen.local-first-frame',
                        callId: this.currentCall?.id ?? null,
                        streamId: transportStream.id,
                        width: state.width,
                        height: state.height,
                        targetFps: state.targetFps
                    });
                    this.notifyLocalScreenCanvas(encoder.getCanvas());
                    if (firstFrameTimeoutId) clearTimeout(firstFrameTimeoutId);
                    firstFrameTimeoutId = null;
                    resolveFirstFrame();
                }
            },
            onState: state => this.callTelemetry?.noteVisualEncoderState('screen', state),
            onDiagnostic: event => this.callTelemetry?.noteVisualPipelineEvent('screen', 'sender', event),
        });
        try {
            this.screenEncoder = encoder;
            this.localScreenCanvas = encoder.getCanvas();
            encoder.start(captureSource);
            await firstFramePromise;
        } catch (error) {
            if (firstFrameTimeoutId) clearTimeout(firstFrameTimeoutId);
            firstFrameTimeoutId = null;
            encoder.stop();
            if (this.screenEncoder === encoder) this.screenEncoder = null;
            if (this.localScreenCanvas === encoder.getCanvas()) {
                this.localScreenCanvas = null;
                this.notifyLocalScreenCanvas(null);
            }
            if (captureVideo && this.screenCaptureVideoEl === captureVideo) {
                this.screenCaptureVideoEl = null;
                this.detachMediaElement(captureVideo);
            }
            throw error;
        }
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
        if (this.audioPlaybackSessionId !== codecSessionId) {
            throw new Error('Native audio playback is unavailable');
        }

        if (generation !== this.mediaGeneration || this.audioStream !== stream) return;

        let playoutTimer: ReturnType<typeof setInterval> | null = null;
        const jitterBuffer = new Map<number, BufferedAudioPacket>();
        try {
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
            const decodeFrame = async (packet: Uint8Array, fec: boolean): Promise<void> => {
                await audioCodec.decodeToPlayback(codecSessionId, packet, fec);
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
                let advanceExpectedSequence = true;
                try {
                    const exact = jitterBuffer.get(expectedSequence);
                    if (exact) {
                        jitterBuffer.delete(expectedSequence);
                        try {
                            await decodeFrame(exact.packet, false);
                        } finally {
                            SecureMemory.zeroBuffer(exact.packet);
                        }
                        consecutiveLosses = 0;
                    } else {
                        const nextSequence = (expectedSequence + 1) >>> 0;
                        const next = jitterBuffer.get(nextSequence);
                        if (next) {
                            try {
                                await decodeFrame(next.packet, true);
                            } catch {
                                await decodeFrame(new Uint8Array(0), false);
                            }
                        } else if (consecutiveLosses < MAX_AUDIO_QUEUE_PACKETS) {
                            await decodeFrame(new Uint8Array(0), false);
                        } else {
                            await decodeFrame(new Uint8Array(0), false);
                            advanceExpectedSequence = false;
                        }
                        consecutiveLosses += 1;
                    }
                    if (
                        generation !== this.mediaGeneration ||
                        this.audioStream !== stream ||
                        this.audioCodecSessionId !== codecSessionId
                    ) {
                        return;
                    }
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

        const renderQueue: Array<{
            frame: DecodedVisualFrame;
            metadata: VisualFrameMetadata;
        }> = [];
        let renderTimer: ReturnType<typeof setTimeout> | null = null;
        let renderScheduled = false;
        let lastFrameQueuedAt = 0;
        let lastAnimationCallbackAt = 0;
        let replacedFrames = 0;
        let outputAnnounced = false;
        let buffering = false;
        let sourceIntervalMs = 0;
        let lastSourceTimestamp = 0;
        let lastSourceSequence = 0;
        let scheduledDelayMs = 0;
        let render = () => { };
        const reportRendererState = () => this.callTelemetry?.noteVisualRendererState(kind, {
            animationFramePending: renderScheduled,
            framePending: renderQueue.length > 0,
            queuedFrames: renderQueue.length,
            buffering,
            sourceIntervalMs,
            scheduledDelayMs,
            lastFrameQueuedAt,
            lastAnimationCallbackAt,
            replacedFrames,
            canvasWidth: canvas.width,
            canvasHeight: canvas.height,
        });
        const scheduleRender = () => {
            if (renderTimer || renderQueue.length === 0 || !isActive()) return;
            const now = performance.now();
            scheduledDelayMs = lastAnimationCallbackAt === 0
                ? 0
                : renderQueue.length > 1
                    ? 0
                    : Math.max(0, lastAnimationCallbackAt + sourceIntervalMs - now);
            renderScheduled = true;
            renderTimer = setTimeout(render, scheduledDelayMs);
        };
        render = () => {
            renderTimer = null;
            renderScheduled = false;
            scheduledDelayMs = 0;
            lastAnimationCallbackAt = performance.now();
            let queued = renderQueue.shift();
            while (queued) {
                const remoteAgeMs = this.callTelemetry?.getRemoteFrameAgeMs(
                    queued.metadata.capturedAt,
                ) ?? null;
                if (
                    remoteAgeMs === null ||
                    remoteAgeMs <= visualPlayoutAgeMs(this.callTelemetry?.getLatestRttMs() ?? null)
                ) break;
                try { queued.frame.close(); } catch { }
                this.callTelemetry?.noteRenderDrop(kind);
                replacedFrames += 1;
                queued = renderQueue.shift();
            }
            if (!queued) {
                buffering = true;
                reportRendererState();
                return;
            }
            const { frame, metadata } = queued;
            try {
                if (!isActive()) return;
                if (canvas.width !== frame.width) canvas.width = frame.width;
                if (canvas.height !== frame.height) canvas.height = frame.height;
                context.drawImage(frame.source, 0, 0, canvas.width, canvas.height);
                if (!outputAnnounced) {
                    outputAnnounced = true;
                    if (kind === 'screen' && this.remoteScreenCanvas === canvas) {
                        console.info('[CALL-DIAG]', {
                            phase: 'screen.remote-first-frame',
                            callId: this.currentCall?.id ?? null,
                            streamId: stream.id,
                            width: frame.width,
                            height: frame.height
                        });
                        this.notifyRemoteScreenCanvas(canvas);
                    } else if (kind === 'video' && this.remoteVideoCanvas === canvas) {
                        this.notifyRemoteVideoCanvas(canvas);
                    }
                }
                this.callTelemetry?.noteFrameRendered(kind, metadata.capturedAt);
            } finally {
                try { frame.close(); } catch { }
                buffering = renderQueue.length === 0;
                if (renderQueue.length > 0) scheduleRender();
                reportRendererState();
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
                if (lastSourceTimestamp > 0 && lastSourceSequence > 0) {
                    const sequenceDistance = (metadata.sequence - lastSourceSequence) >>> 0;
                    const timestampDistance = metadata.timestamp - lastSourceTimestamp;
                    if (
                        sequenceDistance > 0 &&
                        sequenceDistance < 120 &&
                        timestampDistance > 0 &&
                        timestampDistance < 2_000_000
                    ) {
                        const interval = timestampDistance / 1_000 / sequenceDistance;
                        if (interval >= 8 && interval <= 200) {
                            sourceIntervalMs = sourceIntervalMs > 0
                                ? sourceIntervalMs * 0.85 + interval * 0.15
                                : interval;
                        }
                    }
                }
                lastSourceTimestamp = metadata.timestamp;
                lastSourceSequence = metadata.sequence;
                if (sourceIntervalMs === 0) sourceIntervalMs = 1_000 / 30;
                renderQueue.push({ frame, metadata });
                while (renderQueue.length > MAX_VISUAL_RENDER_QUEUE_FRAMES) {
                    const dropped = renderQueue.shift();
                    try { dropped?.frame.close(); } catch { }
                    this.callTelemetry?.noteRenderDrop(kind);
                    replacedFrames += 1;
                }
                lastFrameQueuedAt = performance.now();
                scheduleRender();
                reportRendererState();
            },
            onDrop: () => this.callTelemetry?.noteRenderDrop(kind),
            onDiscontinuity: () => this.callTelemetry?.requestKeyFrame(kind),
            onError: () => this.callTelemetry?.noteReceiveError(kind),
            onState: state => this.callTelemetry?.noteVisualDecoderState(kind, state),
            onDiagnostic: event => this.callTelemetry?.noteVisualPipelineEvent(kind, 'receiver', event),
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
            if (renderTimer) clearTimeout(renderTimer);
            renderTimer = null;
            for (const queued of renderQueue) {
                try { queued.frame.close(); } catch { }
            }
            renderQueue.length = 0;
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
            const matchesCurrent = Boolean(
                this.currentCall
                && this.currentCall.id === signal.callId
                && this.currentCall.peer === signal.from
            );
            const pending = this.pendingIncomingCalls.get(signal.callId);
            const matchesPendingEnd = Boolean(
                signal.type === 'end-call'
                && pending
                && pending.call.peer === signal.from
            );
            if (!matchesCurrent && !matchesPendingEnd) {
                return;
            }
            if (
                signal.type === 'answer' &&
                (
                    !this.currentCall
                    || this.currentCall.direction !== 'outgoing'
                    || this.currentCall.status !== 'ringing'
                )
            ) return;
            if (
                (
                    signal.type === 'screen-share-start' ||
                    signal.type === 'screen-share-ready' ||
                    signal.type === 'screen-share-stop'
                ) &&
                (!this.currentCall || this.currentCall.status !== 'connected')
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
                    this.cleanupRemoteScreenShare(signal.data.streamId);
                }
                this.expectedRemoteScreenStreamId = signal.data.streamId;
                console.info('[CALL-DIAG]', {
                    phase: 'screen.remote-announcement-received',
                    callId: signal.callId,
                    streamId: signal.data.streamId
                });
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
        if (this.pendingIncomingCalls.has(signal.callId)) return;
        if (this.currentCall) {
            // Collision Detection
            if (
                this.currentCall.direction === 'outgoing' &&
                this.currentCall.peer === signal.from &&
                (this.currentCall.status === 'connecting' || this.currentCall.status === 'ringing')
            ) {
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
            }
        }

        if (this.queueIncomingCall(signal)) return;
        await this.sendCallSignalBestEffort({
            type: 'end-call',
            callId: signal.callId,
            from: this.localUsername,
            to: signal.from,
            timestamp: Date.now()
        });
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
        const pending = this.pendingIncomingCalls.get(signal.callId);
        if (pending && pending.call.peer === signal.from) {
            this.finishPendingIncomingCall(signal.callId, 'ended', 'remote');
            return;
        }
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
        this.clearCameraRecoveryTimer();
        this.cameraRecoveryAttempts = 0;
        this.cameraRecoveryInFlight = false;
        this.microphoneSwitchGeneration += 1;
        this.videoEnabled = false;
        this.cancelPendingSignalSessionWaits();
        this.unsubscribeCallConnectionState();
        this.unsubscribeCallStreams();
        this.teardownCallMediaElements();

        const cameraSessionId = this.cameraSessionId;
        this.cameraSessionId = null;
        if (cameraSessionId) void nativeCamera.stop(cameraSessionId).catch(() => { });

        const microphoneSessionId = this.microphoneSessionId;
        this.microphoneSessionId = null;
        this.microphoneEnabled = true;
        this.nextAudioCaptureSequence = 0;
        if (microphoneSessionId) void nativeMicrophone.stop(microphoneSessionId).catch(() => { });

        if (this.localMediaActive) {
            this.localMediaActive = false;
            this.notifyLocalMediaChange(false);
        }
        if (cameraSessionId || microphoneSessionId) {
            this.lastCaptureReleaseAt = Date.now();
        }

        this.cleanupScreenShareLocal();

        this.callTelemetry?.stop();
        this.callTelemetry = null;

        const playbackSessionId = this.audioPlaybackSessionId;
        this.audioPlaybackSessionId = null;
        if (playbackSessionId) void nativeAudioPlayback.stop(playbackSessionId).catch(() => { });

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
    onCallStateChange(callback: (call: CallState, isActive: boolean) => void): void {
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

    onLocalScreenCanvas(callback: (canvas: HTMLCanvasElement | null) => void): void {
        this.onLocalScreenCanvasCallback = callback;
    }

    onLocalMediaChange(callback: (active: boolean) => void): void {
        this.onLocalMediaChangeCallback = callback;
    }

    onScreenSharingChange(callback: (sharing: boolean) => void): void {
        this.onScreenSharingChangeCallback = callback;
    }

    // Get screen sharing status
    getScreenSharingStatus(): boolean {
        return this.isScreenSharing;
    }

    // Destroy the calling service
    destroy(): void {
        if (this.destroyed) return;
        this.destroyed = true;
        this.lifecycleGeneration += 1;

        window.removeEventListener('beforeunload', this.beforeUnloadHandler);
        window.removeEventListener(EventType.CALL_SIGNAL, this.callSignalHandler);
        window.removeEventListener(EventType.USER_BLOCKED, this.userBlockedHandler);
        window.removeEventListener(
            EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT,
            this.keyTransparencySecurityIncidentHandler
        );
        this.initialized = false;
        this.clearPendingIncomingCalls('shutdown');
        this.cleanup();

        this.incomingOfferRates.clear();
        this.incomingOfferGlobal = { windowStart: 0, count: 0 };
        this.onIncomingCallCallback = null;
        this.onCallStateChangeCallback = null;
        this.onRemoteVideoCanvasCallback = null;
        this.onRemoteScreenCanvasCallback = null;
        this.onLocalVideoCanvasCallback = null;
        this.onLocalScreenCanvasCallback = null;
        this.onLocalMediaChangeCallback = null;
        this.onScreenSharingChangeCallback = null;
    }
}
