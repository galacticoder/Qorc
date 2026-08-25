import { TARGET_FPS } from '../constants';
import { SecureMemory } from '../cryptography/secure-memory';
import { nativeCamera, nativeScreen, type NativeCameraFrame } from '../tauri-bindings';
import { MAX_CALL_FRAME_SIZE, NOISE_FRAME_OVERHEAD } from './secure-transport';

export type VisualMediaKind = 'video' | 'screen';

export interface VisualFrameMetadata {
    sequence: number;
    capturedAt: number;
    timestamp: number;
    width: number;
    height: number;
    keyFrame: boolean;
}

export interface VisualAdaptationState {
    level: number;
    width: number;
    height: number;
    bitrate: number;
    targetFps: number;
}

export interface VisualEncoderState {
    source: 'native' | 'element' | 'none';
    codecState: 'configured' | 'unconfigured' | 'closed' | 'missing';
    codecQueueSize: number;
    pendingEncodes: number;
    oldestPendingEncodeMs: number;
    sendQueueFrames: number;
    sendInFlightFrames: number;
    sendPending: boolean;
    capturePending: boolean;
    keyFrameRequested: boolean;
    discardUntilKeyFrame: boolean;
    restartRequested: boolean;
    retryInMs: number;
    targetFps: number;
    adaptationLevel: number;
    configuredBitrate: number;
    observedEncodedKbps: number;
    adaptationHealth: 'warmup' | 'stressed' | 'healthy' | 'neutral';
    adaptationCaptureLossRatio: number;
    adaptationSendFailureRatio: number;
    adaptationAverageEncodeMs: number;
    adaptationAverageWriteMs: number;
    adaptationStableForMs: number;
    adaptationRecoveryInMs: number;
    adaptationRecoveryWindowMs: number;
    lastCaptureAgoMs: number | null;
    lastEncodedAgoMs: number | null;
    lastSendSuccessAgoMs: number | null;
    lastSendFailureAgoMs: number | null;
    encodedKeyFrames: number;
    deliveryInvalidations: number;
    encoderFailures: number;
    sendFailures: number;
    retiredEncoderOutputs: number;
}

export interface VisualDecoderState {
    codecState: 'configured' | 'unconfigured' | 'closed';
    codecQueueSize: number;
    queuedFrames: number;
    pendingDecodes: number;
    oldestPendingDecodeMs: number;
    bufferedSeconds: number;
    playbackLagMs: number;
    playbackRate: number;
    playbackRecoveries: number;
    pipelineResets: number;
    bufferStalls: number;
    waitingForKeyFrame: boolean;
    resetOnNextKeyFrame: boolean;
    recoveryRequested: boolean;
    lastArrivalAgoMs: number | null;
    lastOutputAgoMs: number | null;
    lastAcceptedOutputAgoMs: number | null;
    lastKeyFrameAgoMs: number | null;
    staleArrivalDrops: number;
    staleDrainDrops: number;
    staleOutputDrops: number;
    sequenceGapRecoveries: number;
    outOfOrderDrops: number;
    waitingForKeyFrameDrops: number;
    capacityRecoveries: number;
    dimensionDrops: number;
    unmatchedOutputs: number;
    decoderErrors: number;
    watchdogResets: number;
}

export type VisualPipelineEventReason =
    | 'encoder-failure'
    | 'encoder-output-invalid'
    | 'send-failure'
    | 'send-capacity'
    | 'stale-arrival'
    | 'sequence-gap'
    | 'decode-capacity'
    | 'invalid-frame'
    | 'stale-drain'
    | 'decoder-submit'
    | 'unmatched-output'
    | 'dimension-mismatch'
    | 'stale-output'
    | 'decoder-failure'
    | 'decoder-watchdog'
    | 'key-frame-resumed';

export interface VisualPipelineEvent {
    reason: VisualPipelineEventReason;
    sequence: number | null;
    keyFrame: boolean | null;
    frameAgeMs: number | null;
    maxFrameAgeMs: number | null;
    queueFrames: number;
    inFlightFrames: number;
    codecQueueSize: number;
    waitingForKeyFrame: boolean;
    detail?: string;
}

interface EncoderCallbacks {
    isActive: () => boolean;
    isSourceEnabled: () => boolean;
    send: (
        frame: Uint8Array,
        frames: readonly VisualSendDescriptor[],
    ) => Promise<number>;
    onCaptureDrop: () => void;
    onSourceFrame?: () => void;
    onSourceDrop?: (count: number) => void;
    onSourceError?: (reason: string) => void;
    onCaptureTiming?: (stage: 'pull' | 'sourceAge' | 'decode' | 'prepare', milliseconds: number) => void;
    onEncode: (milliseconds: number) => void;
    onSendError: (reason: string) => void;
    onAdaptation: (state: VisualAdaptationState) => void;
    onState: (state: VisualEncoderState) => void;
    onDiagnostic: (event: VisualPipelineEvent) => void;
}

interface DecoderCallbacks {
    onArrival: (bytes: number, metadata: VisualFrameMetadata) => void;
    getFrameAgeMs: (metadata: VisualFrameMetadata) => number | null;
    getMaxFrameAgeMs: () => number;
    onAdmitted: () => void;
    onFrame: (frame: DecodedVisualFrame, metadata: VisualFrameMetadata, decodeMs: number) => void;
    onDrop: () => void;
    onDiscontinuity: () => void;
    onError: () => void;
    onState: (state: VisualDecoderState) => void;
    onDiagnostic: (event: VisualPipelineEvent) => void;
}

export interface VisualSendDescriptor {
    bytes: number;
    metadata: VisualFrameMetadata;
}

export interface DecodedVisualFrame {
    source: CanvasImageSource;
    width: number;
    height: number;
    close: () => void;
}

type EncoderProfile = { width: number; height: number; bitrate: number };
type QueuedDecode = { payload: Uint8Array; metadata: VisualFrameMetadata };
type QueuedSend = { frame: Uint8Array; metadata: VisualFrameMetadata };
type PendingEncode = {
    capturedAt: number;
    width: number;
    height: number;
    startedAt: number;
};
type PendingDecode = {
    metadata: VisualFrameMetadata;
    startedAt: number;
};
export interface NativeVisualCaptureSource {
    read: () => Promise<NativeCameraFrame | null>;
    stop: () => void;
}

type VisualCaptureSource = HTMLVideoElement | NativeVisualCaptureSource;

export class NativeCameraCaptureSource implements NativeVisualCaptureSource {
    private sequence = 0;
    private stopped = false;

    constructor(readonly sessionId: string) { }

    async read(): Promise<NativeCameraFrame | null> {
        if (this.stopped) return null;
        const frame = await nativeCamera.pull(this.sessionId, this.sequence);
        if (frame) this.sequence = frame.sequence;
        return frame;
    }

    stop(): void {
        this.stopped = true;
    }
}

export class NativeScreenCaptureSource implements NativeVisualCaptureSource {
    private sequence = 0;
    private stopped = false;

    constructor(readonly sessionId: string) { }

    async read(): Promise<NativeCameraFrame | null> {
        if (this.stopped) return null;
        const frame = await nativeScreen.pull(this.sessionId, this.sequence);
        if (frame) this.sequence = frame.sequence;
        return frame;
    }

    stop(): void {
        this.stopped = true;
    }
}

const isVideoElement = (source: VisualCaptureSource): source is HTMLVideoElement =>
    source instanceof HTMLVideoElement;

const errorDetail = (error: unknown): string => {
    const value = error instanceof Error ? error.message : String(error);
    return value.replace(/\s+/g, ' ').slice(0, 200);
};

const elapsedSince = (now: number, then: number): number | null =>
    then > 0 ? Math.max(0, Math.round(now - then)) : null;

const DEFAULT_FRAME_DURATION_US = Math.round(1_000_000 / TARGET_FPS);
const VIDEO_CODEC = 'vp8';
const VISUAL_FRAME_VERSION = 4;
const VISUAL_FRAME_HEADER_BYTES = 32;
const VISUAL_BATCH_VERSION = 1;
const VISUAL_BATCH_HEADER_BYTES = 4;
const VISUAL_BATCH_ENTRY_BYTES = 4;
const MAX_VISUAL_BATCH_FRAMES = 2;
const MAX_VISUAL_BATCH_BYTES = MAX_CALL_FRAME_SIZE - NOISE_FRAME_OVERHEAD;
const VP8_CODEC_ID = 3;
const MAX_VISUAL_ENCODED_BYTES = 1024 * 1024;
const MAX_VISUAL_DIMENSION = 1280;
const MAX_VISUAL_PIXELS = 1280 * 720;
const MAX_FRAME_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_ADAPTATION_LEVEL = 5;
const MAX_PENDING_DECODES = 8;
const MAX_CODEC_QUEUE_FRAMES = 3;
const MAX_PENDING_CODEC_METADATA = 12;
const MAX_PENDING_SENDS = 4;
const MAX_ENCODER_PIPELINE_FRAMES = 3;
const KEY_FRAME_INTERVAL_US = 2_000_000;
const ENCODE_STRESS_MS = 30;
const ENCODE_RECOVERY_MS = 24;
const WRITE_STRESS_MS = 140;
const WRITE_RECOVERY_MS = 90;
const ADAPTATION_WINDOW_MS = 2_000;
const ADAPTATION_STRESS_WINDOWS = 2;
const ADAPTATION_RECOVERY_MS = 15_000;
const ADAPTATION_MAX_RECOVERY_MS = 60_000;
const ADAPTATION_FAILED_UPGRADE_MS = 30_000;
const ADAPTATION_WARMUP_MS = 1_500;
const CAPTURE_STRESS_RATIO = 0.12;
const CAPTURE_RECOVERY_RATIO = 0.08;
const MIN_VISUAL_PLAYOUT_AGE_MS = 900;
const MAX_VISUAL_PLAYOUT_AGE_MS = 2_000;
const KEY_FRAME_REQUEST_RETRY_MS = 2_000;
const ENCODER_STATE_REPORT_INTERVAL_MS = 1_000;
const DECODER_STATE_REPORT_INTERVAL_MS = 1_000;
const DECODER_STALL_TIMEOUT_MS = 750;
const MAX_NATIVE_PULL_RETRIES = 3;
const MIN_NATIVE_SOURCE_STALL_MS = 4_000;
const MAX_NATIVE_SOURCE_STALL_MS = 10_000;

const TARGET_PROFILE: EncoderProfile = { width: 1280, height: 720, bitrate: 2_500_000 };
const LEVEL_SCALES = [1, 0.75, 0.55, 0.4, 0.3, 0.23] as const;
const BITRATE_SCALES = [1, 0.72, 0.5, 0.32, 0.2, 0.12] as const;

const fitDimensions = (
    sourceWidth: number,
    sourceHeight: number,
    profile: EncoderProfile,
    level: number,
): { width: number; height: number; bitrate: number } => {
    const scale = LEVEL_SCALES[level];
    const widthLimit = Math.max(2, Math.floor(Math.min(profile.width, sourceWidth) * scale));
    const heightLimit = Math.max(2, Math.floor(Math.min(profile.height, sourceHeight) * scale));
    const ratio = Math.min(1, widthLimit / sourceWidth, heightLimit / sourceHeight);
    return {
        width: Math.max(2, Math.floor(sourceWidth * ratio / 2) * 2),
        height: Math.max(2, Math.floor(sourceHeight * ratio / 2) * 2),
        bitrate: Math.max(180_000, Math.round(profile.bitrate * BITRATE_SCALES[level])),
    };
};

const isVp8Chunk = (
    payload: Uint8Array,
    keyFrame: boolean,
    width?: number,
    height?: number,
): boolean => {
    if (
        !(payload instanceof Uint8Array) ||
        payload.byteLength < (keyFrame ? 10 : 3) ||
        payload.byteLength > MAX_VISUAL_ENCODED_BYTES ||
        (payload[0] & 1) !== (keyFrame ? 0 : 1)
    ) return false;
    if (!keyFrame) return true;
    if (payload[3] !== 0x9d || payload[4] !== 0x01 || payload[5] !== 0x2a) return false;
    if (width === undefined || height === undefined) return true;
    const codedWidth = (payload[6] | (payload[7] << 8)) & 0x3fff;
    const codedHeight = (payload[8] | (payload[9] << 8)) & 0x3fff;
    return codedWidth === width && codedHeight === height;
};

export function visualPlayoutAgeMs(rttMs: number | null): number {
    if (rttMs === null || !Number.isFinite(rttMs) || rttMs < 0) {
        return MIN_VISUAL_PLAYOUT_AGE_MS;
    }
    return Math.min(
        MAX_VISUAL_PLAYOUT_AGE_MS,
        Math.max(MIN_VISUAL_PLAYOUT_AGE_MS, Math.round(rttMs + 450)),
    );
}

export function encodeVisualFrame(payload: Uint8Array, metadata: VisualFrameMetadata): Uint8Array {
    if (
        typeof metadata.keyFrame !== 'boolean' ||
        !Number.isSafeInteger(metadata.sequence) || metadata.sequence <= 0 || metadata.sequence > 0xffff_ffff ||
        !Number.isSafeInteger(metadata.capturedAt) || metadata.capturedAt <= 0 ||
        !Number.isSafeInteger(metadata.timestamp) || metadata.timestamp <= 0 ||
        !Number.isInteger(metadata.width) || !Number.isInteger(metadata.height) ||
        metadata.width < 2 || metadata.height < 2 ||
        metadata.width > MAX_VISUAL_DIMENSION || metadata.height > MAX_VISUAL_DIMENSION ||
        metadata.width * metadata.height > MAX_VISUAL_PIXELS ||
        !isVp8Chunk(payload, metadata.keyFrame, metadata.width, metadata.height)
    ) throw new Error('Invalid encoded visual frame');
    const output = new Uint8Array(VISUAL_FRAME_HEADER_BYTES + payload.byteLength);
    const view = new DataView(output.buffer);
    view.setUint8(0, VISUAL_FRAME_VERSION);
    view.setUint8(1, VP8_CODEC_ID);
    view.setUint8(2, metadata.keyFrame ? 1 : 0);
    view.setUint8(3, 0);
    view.setUint32(4, metadata.sequence, false);
    view.setBigUint64(8, BigInt(metadata.capturedAt), false);
    view.setBigUint64(16, BigInt(metadata.timestamp), false);
    view.setUint16(24, metadata.width, false);
    view.setUint16(26, metadata.height, false);
    view.setUint32(28, payload.byteLength, false);
    output.set(payload, VISUAL_FRAME_HEADER_BYTES);
    return output;
}

export function decodeVisualFrame(frame: Uint8Array): { payload: Uint8Array; metadata: VisualFrameMetadata } {
    if (!(frame instanceof Uint8Array) || frame.byteLength <= VISUAL_FRAME_HEADER_BYTES || frame.byteLength > VISUAL_FRAME_HEADER_BYTES + MAX_VISUAL_ENCODED_BYTES) {
        throw new Error('Invalid visual frame length');
    }
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const sequence = view.getUint32(4, false);
    const capturedAt = Number(view.getBigUint64(8, false));
    const timestamp = Number(view.getBigUint64(16, false));
    const width = view.getUint16(24, false);
    const height = view.getUint16(26, false);
    const payloadLength = view.getUint32(28, false);
    const payload = frame.subarray(VISUAL_FRAME_HEADER_BYTES);
    const keyFrameByte = view.getUint8(2);
    const keyFrame = keyFrameByte === 1;
    if (
        view.getUint8(0) !== VISUAL_FRAME_VERSION || view.getUint8(1) !== VP8_CODEC_ID ||
        keyFrameByte > 1 || view.getUint8(3) !== 0 || sequence === 0 ||
        !Number.isSafeInteger(capturedAt) || capturedAt <= 0 || Math.abs(Date.now() - capturedAt) > MAX_FRAME_CLOCK_SKEW_MS ||
        !Number.isSafeInteger(timestamp) || timestamp <= 0 ||
        width < 2 || height < 2 || width > MAX_VISUAL_DIMENSION || height > MAX_VISUAL_DIMENSION ||
        width * height > MAX_VISUAL_PIXELS || payloadLength !== payload.byteLength ||
        !isVp8Chunk(payload, keyFrame, width, height)
    ) throw new Error('Invalid visual frame header');
    return {
        payload,
        metadata: { sequence, capturedAt, timestamp, width, height, keyFrame },
    };
}

export function encodeVisualBatch(frames: readonly Uint8Array[]): Uint8Array {
    if (frames.length < 1 || frames.length > MAX_VISUAL_BATCH_FRAMES) {
        throw new Error('Invalid visual batch count');
    }
    let byteLength = VISUAL_BATCH_HEADER_BYTES;
    for (const frame of frames) {
        decodeVisualFrame(frame);
        byteLength += VISUAL_BATCH_ENTRY_BYTES + frame.byteLength;
    }
    if (byteLength > MAX_VISUAL_BATCH_BYTES) throw new Error('Visual batch exceeds transport limit');
    const output = new Uint8Array(byteLength);
    const view = new DataView(output.buffer);
    output[0] = VISUAL_BATCH_VERSION;
    output[1] = frames.length;
    let offset = VISUAL_BATCH_HEADER_BYTES;
    for (const frame of frames) {
        view.setUint32(offset, frame.byteLength, false);
        offset += VISUAL_BATCH_ENTRY_BYTES;
        output.set(frame, offset);
        offset += frame.byteLength;
    }
    return output;
}

export function decodeVisualBatch(batch: Uint8Array): Uint8Array[] {
    if (!(batch instanceof Uint8Array) || batch.byteLength <= VISUAL_BATCH_HEADER_BYTES || batch.byteLength > MAX_VISUAL_BATCH_BYTES) {
        throw new Error('Invalid visual batch length');
    }
    const count = batch[1];
    if (batch[0] !== VISUAL_BATCH_VERSION || count < 1 || count > MAX_VISUAL_BATCH_FRAMES || batch[2] !== 0 || batch[3] !== 0) {
        throw new Error('Invalid visual batch header');
    }
    const view = new DataView(batch.buffer, batch.byteOffset, batch.byteLength);
    const frames: Uint8Array[] = [];
    let offset = VISUAL_BATCH_HEADER_BYTES;
    for (let index = 0; index < count; index += 1) {
        if (offset + VISUAL_BATCH_ENTRY_BYTES > batch.byteLength) throw new Error('Invalid visual batch entry');
        const byteLength = view.getUint32(offset, false);
        offset += VISUAL_BATCH_ENTRY_BYTES;
        if (byteLength <= VISUAL_FRAME_HEADER_BYTES || offset + byteLength > batch.byteLength) {
            throw new Error('Invalid visual batch entry');
        }
        const frame = batch.subarray(offset, offset + byteLength);
        decodeVisualFrame(frame);
        frames.push(frame);
        offset += byteLength;
    }
    if (offset !== batch.byteLength) throw new Error('Invalid visual batch trailing data');
    return frames;
}

export class RealtimeVisualEncoder {
    private readonly canvas = document.createElement('canvas');
    private readonly context: CanvasRenderingContext2D;
    private timer: ReturnType<typeof setTimeout> | null = null;
    private videoFrameCallbackId: number | null = null;
    private video: HTMLVideoElement | null = null;
    private nativeSource: NativeVisualCaptureSource | null = null;
    private encoder: VideoEncoder | null = null;
    private encoderGeneration = 0;
    private encoderSignature = '';
    private restartRequested = true;
    private keyFrameRequested = true;
    private discardUntilKeyFrame = true;
    private lastKeyFrameTimestamp = 0;
    private pendingEncode = new Map<number, PendingEncode>();
    private stopped = false;
    private capturePending = false;
    private pendingMediaTime: number | undefined;
    private sendPending = false;
    private sendInFlightFrames = 0;
    private sendQueue: QueuedSend[] = [];
    private sequence = 0;
    private timestamp = 0;
    private adaptationLevel: number;
    private stableSince = 0;
    private retryAfter = 0;
    private adaptationSignature = '';
    private nextCaptureAt = 0;
    private lastMediaTime = -1;
    private adaptationWindowStartedAt = 0;
    private adaptationSendSuccesses = 0;
    private adaptationSendFailures = 0;
    private adaptationEncodeTotalMs = 0;
    private adaptationEncodeSamples = 0;
    private adaptationEncodedBytes = 0;
    private adaptationWriteTotalMs = 0;
    private adaptationWriteSamples = 0;
    private adaptationSourceFrames = 0;
    private adaptationSourceDrops = 0;
    private adaptationCaptureDrops = 0;
    private adaptationRemoteDiscontinuities = 0;
    private adaptationStressWindows = 0;
    private adaptationWarmupUntil = 0;
    private adaptationRecoveryAllowedAt = 0;
    private adaptationRecoveryMs = ADAPTATION_RECOVERY_MS;
    private lastAdaptationUpgradeAt = 0;
    private sourceCapturedAt = 0;
    private nativeSequence = 0;
    private targetFps = TARGET_FPS;
    private configuredBitrate = TARGET_PROFILE.bitrate;
    private observedEncodedKbps = 0;
    private adaptationHealth: VisualEncoderState['adaptationHealth'] = 'warmup';
    private adaptationCaptureLossRatio = 0;
    private adaptationSendFailureRatio = 0;
    private adaptationAverageEncodeMs = 0;
    private adaptationAverageWriteMs = 0;
    private sourceKind: VisualEncoderState['source'] = 'none';
    private stateTimer: ReturnType<typeof setInterval> | null = null;
    private lastEncoderStateReportAt = 0;
    private lastCaptureAt = 0;
    private lastEncodedAt = 0;
    private lastSendSuccessAt = 0;
    private lastSendFailureAt = 0;
    private encodedKeyFrames = 0;
    private deliveryInvalidations = 0;
    private encoderFailures = 0;
    private sendFailures = 0;
    private retiredEncoderOutputs = 0;

    constructor(private readonly kind: VisualMediaKind, private readonly callbacks: EncoderCallbacks) {
        const context = this.canvas.getContext('2d', { alpha: false });
        if (!context) throw new Error('Visual encoder canvas is unavailable');
        this.context = context;
        this.adaptationLevel = kind === 'screen' ? 2 : 3;
    }

    start(source: VisualCaptureSource): void {
        if (this.stopped) throw new Error('Visual encoder is stopped');
        this.sourceKind = isVideoElement(source) ? 'element' : 'native';
        this.stateTimer = setInterval(
            () => this.reportState(performance.now(), true),
            ENCODER_STATE_REPORT_INTERVAL_MS,
        );
        if (isVideoElement(source)) {
            this.video = source;
            const sourceFrameRate = source.srcObject instanceof MediaStream
                ? source.srcObject.getVideoTracks()[0]?.getSettings().frameRate
                : undefined;
            if (typeof sourceFrameRate === 'number' && Number.isFinite(sourceFrameRate) && sourceFrameRate > 0) {
                this.targetFps = Math.max(1, Math.min(TARGET_FPS, Math.round(sourceFrameRate)));
            }
            this.beginCaptureSchedule();
        } else {
            this.video = null;
            this.nativeSource = source;
            this.initializeCaptureClock();
            void this.consumeNativeFrames();
        }
        this.reportState(performance.now(), true);
    }

    getCanvas(): HTMLCanvasElement {
        return this.canvas;
    }

    requestKeyFrame(): void {
        if (this.stopped) return;
        this.adaptationRemoteDiscontinuities += 1;
        this.evaluateAdaptation(performance.now());
        this.invalidateDelivery();
    }

    stop(): void {
        if (this.stopped) return;
        this.stopped = true;
        if (this.stateTimer) clearInterval(this.stateTimer);
        this.stateTimer = null;
        if (this.timer) clearTimeout(this.timer);
        this.timer = null;
        if (this.video && this.videoFrameCallbackId !== null) {
            try { this.video.cancelVideoFrameCallback(this.videoFrameCallbackId); } catch { }
        }
        this.videoFrameCallbackId = null;
        this.nativeSource?.stop();
        this.nativeSource = null;
        this.video = null;
        this.sourceKind = 'none';
        this.capturePending = false;
        this.pendingMediaTime = undefined;
        this.closeEncoder();
        for (const item of this.sendQueue) SecureMemory.zeroBuffer(item.frame);
        this.sendQueue = [];
        this.canvas.width = 1;
        this.canvas.height = 1;
    }

    private beginCaptureSchedule(): void {
        this.initializeCaptureClock();
        this.schedule(0);
    }

    private initializeCaptureClock(): void {
        this.nextCaptureAt = performance.now();
        this.adaptationWindowStartedAt = this.nextCaptureAt;
        this.adaptationWarmupUntil = this.nextCaptureAt + ADAPTATION_WARMUP_MS;
    }

    private get frameIntervalMs(): number {
        return 1000 / this.targetFps;
    }

    private get frameDurationUs(): number {
        return Math.round(1_000_000 / this.targetFps);
    }

    private schedule(delay = 0): void {
        if (this.stopped || this.timer || this.videoFrameCallbackId !== null) return;
        const video = this.video;
        if (video && this.kind === 'screen') {
            this.timer = setTimeout(() => {
                this.timer = null;
                const now = performance.now();
                this.offerCapture(now / 1000, now);
                this.schedule(this.frameIntervalMs);
            }, Math.max(1, delay));
            return;
        }
        if (delay > 1) {
            this.timer = setTimeout(() => {
                this.timer = null;
                this.schedule();
            }, delay);
            return;
        }
        if (video && typeof video.requestVideoFrameCallback === 'function') {
            this.videoFrameCallbackId = video.requestVideoFrameCallback((_now, metadata) => {
                this.videoFrameCallbackId = null;
                this.schedule();
                this.offerCapture(metadata.mediaTime, performance.now());
            });
            return;
        }
        if (video) {
            this.timer = setTimeout(() => {
                this.timer = null;
                const now = performance.now();
                this.schedule(this.frameIntervalMs);
                this.offerCapture(now / 1000, now);
            }, Math.max(1, delay));
            return;
        }
        throw new Error('Video capture source is unavailable');
    }

    private offerCapture(mediaTime: number | undefined, now: number, pending = false): void {
        if (this.stopped || !this.callbacks.isActive()) return;
        if (!pending) {
            if (now + 1 < this.nextCaptureAt) return;
            const elapsed = Math.max(0, now - this.nextCaptureAt);
            this.nextCaptureAt += (Math.floor(elapsed / this.frameIntervalMs) + 1) * this.frameIntervalMs;
        }
        if (this.capturePending) {
            this.pendingMediaTime = mediaTime;
            this.noteCaptureDrop(now);
            return;
        }
        if (now < this.retryAfter) {
            this.noteBackoffDrop();
            return;
        }
        this.capturePending = true;
        void this.capture(mediaTime);
    }

    private get encoderPipelineFrames(): number {
        return this.sendQueue.length +
            this.sendInFlightFrames +
            Math.max(this.pendingEncode.size, this.encoder?.encodeQueueSize ?? 0);
    }

    private capture(mediaTime?: number): void {
        try {
            if (this.stopped || !this.callbacks.isActive()) return;
            const now = performance.now();
            const video = this.video;
            const sourceEnabled = this.callbacks.isSourceEnabled();
            let source: CanvasImageSource | null = null;
            let sourceWidth: number;
            let sourceHeight: number;
            if (!video || video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA || video.videoWidth < 2 || video.videoHeight < 2) {
                this.noteCaptureDrop();
                return;
            } else if (!sourceEnabled) {
                sourceWidth = video.videoWidth;
                sourceHeight = video.videoHeight;
            } else {
                source = video;
                sourceWidth = video.videoWidth;
                sourceHeight = video.videoHeight;
                const currentMediaTime = Number.isFinite(mediaTime) ? mediaTime as number : video.currentTime;
                if (!Number.isFinite(currentMediaTime) || currentMediaTime <= this.lastMediaTime) {
                    return;
                }
                this.lastMediaTime = currentMediaTime;
                this.callbacks.onSourceFrame?.();
                this.adaptationSourceFrames += 1;
            }
            if (this.encoderPipelineFrames >= MAX_ENCODER_PIPELINE_FRAMES) {
                this.drawCapturedSource(source, sourceWidth, sourceHeight, sourceEnabled);
                this.noteCaptureDrop(now);
                return;
            }
            this.processCapturedSource(source, sourceWidth, sourceHeight, sourceEnabled);
        } catch (error) {
            if (!this.stopped) {
                this.handleEncoderFailure(this.encoderGeneration, errorDetail(error));
            }
        } finally {
            this.capturePending = false;
            if (!this.stopped && this.callbacks.isActive() && this.pendingMediaTime !== undefined) {
                const pendingMediaTime = this.pendingMediaTime;
                this.pendingMediaTime = undefined;
                queueMicrotask(() => this.offerCapture(pendingMediaTime, performance.now(), true));
            }
        }
    }

    private async consumeNativeFrames(): Promise<void> {
        const source = this.nativeSource;
        if (!source) return;
        const beginRead = (): Promise<{
            frame: NativeCameraFrame | null;
            pullMs: number;
            error?: unknown;
        }> => {
            const startedAt = performance.now();
            return source.read().then(
                frame => ({ frame, pullMs: performance.now() - startedAt }),
                error => ({ frame: null, pullMs: performance.now() - startedAt, error }),
            );
        };
        let pendingRead = beginRead();
        try {
            let consecutiveReadFailures = 0;
            let lastNativeFrameAt = performance.now();
            while (!this.stopped && this.callbacks.isActive() && this.nativeSource === source) {
                const { frame, pullMs, error } = await pendingRead;
                this.callbacks.onCaptureTiming?.('pull', pullMs);
                if (this.stopped || !this.callbacks.isActive() || this.nativeSource !== source) {
                    if (frame) SecureMemory.zeroBuffer(frame.jpeg);
                    break;
                }
                if (error) {
                    consecutiveReadFailures += 1;
                    if (consecutiveReadFailures > MAX_NATIVE_PULL_RETRIES) throw error;
                    await new Promise(resolve => setTimeout(
                        resolve,
                        50 * (2 ** (consecutiveReadFailures - 1)),
                    ));
                    pendingRead = beginRead();
                    continue;
                }
                consecutiveReadFailures = 0;
                pendingRead = beginRead();
                if (!frame) {
                    const now = performance.now();
                    if (!this.callbacks.isSourceEnabled()) {
                        lastNativeFrameAt = now;
                        continue;
                    }
                    const stallTimeoutMs = this.kind === 'screen'
                        ? MAX_NATIVE_SOURCE_STALL_MS
                        : Math.max(
                            MIN_NATIVE_SOURCE_STALL_MS,
                            Math.min(MAX_NATIVE_SOURCE_STALL_MS, 6_000 / this.targetFps),
                        );
                    if (now - lastNativeFrameAt >= stallTimeoutMs) {
                        throw new Error(`${this.kind} capture stopped producing frames`);
                    }
                    continue;
                }
                const sourceNow = performance.now();
                lastNativeFrameAt = sourceNow;
                this.observeNativeFrame(frame, sourceNow);
                let image: ImageBitmap | null = null;
                try {
                    const now = sourceNow;
                    if (now < this.retryAfter) {
                        this.noteBackoffDrop();
                        continue;
                    }
                    const decodeStartedAt = performance.now();
                    image = await createImageBitmap(new Blob([frame.jpeg], { type: 'image/jpeg' }));
                    this.callbacks.onCaptureTiming?.('decode', performance.now() - decodeStartedAt);
                    if (this.stopped || !this.callbacks.isActive() || this.nativeSource !== source) break;
                    this.sourceCapturedAt = frame.capturedAt;
                    const sourceEnabled = this.callbacks.isSourceEnabled() && frame.enabled;
                    const prepareStartedAt = performance.now();
                    if (this.encoderPipelineFrames >= MAX_ENCODER_PIPELINE_FRAMES) {
                        this.drawCapturedSource(
                            sourceEnabled ? image : null,
                            frame.width,
                            frame.height,
                            sourceEnabled,
                        );
                        this.noteCaptureDrop(now);
                    } else {
                        this.processCapturedSource(
                            sourceEnabled ? image : null,
                            frame.width,
                            frame.height,
                            sourceEnabled,
                        );
                    }
                    this.callbacks.onCaptureTiming?.('prepare', performance.now() - prepareStartedAt);
                } catch (error) {
                    if (!this.stopped) {
                        this.handleEncoderFailure(this.encoderGeneration, errorDetail(error));
                    }
                } finally {
                    SecureMemory.zeroBuffer(frame.jpeg);
                    try { image?.close(); } catch { }
                }
            }
        } catch (error) {
            if (!this.stopped && this.callbacks.isActive()) {
                this.noteCaptureDrop();
                this.callbacks.onSourceError?.(errorDetail(error));
            }
        } finally {
            try {
                const { frame } = await pendingRead;
                if (frame) SecureMemory.zeroBuffer(frame.jpeg);
            } catch { }
            if (this.nativeSource === source) this.nativeSource = null;
        }
    }

    private observeNativeFrame(frame: NativeCameraFrame, now: number): void {
        this.callbacks.onSourceFrame?.();
        this.callbacks.onCaptureTiming?.('sourceAge', Math.max(0, Date.now() - frame.capturedAt));
        this.adaptationSourceFrames += 1;
        if (this.nativeSequence > 0 && frame.sequence > this.nativeSequence + 1) {
            const skipped = frame.sequence - this.nativeSequence - 1;
            this.callbacks.onSourceDrop?.(skipped);
            this.adaptationSourceDrops += skipped;
        }
        this.nativeSequence = frame.sequence;
        const frameRate = Math.max(1, Math.min(TARGET_FPS, Math.round(frame.frameRate)));
        if (frameRate !== this.targetFps) {
            this.targetFps = frameRate;
            this.nextCaptureAt = now;
            this.restartRequested = true;
            this.adaptationSignature = '';
            this.adaptationWarmupUntil = now + ADAPTATION_WARMUP_MS;
        }
    }

    private processCapturedSource(
        source: CanvasImageSource | null,
        sourceWidth: number,
        sourceHeight: number,
        sourceEnabled: boolean,
    ): void {
        const now = performance.now();
        const { dimensions, resized } = this.drawCapturedSource(
            source,
            sourceWidth,
            sourceHeight,
            sourceEnabled,
        );
        const signature = `${this.adaptationLevel}:${dimensions.width}:${dimensions.height}:${dimensions.bitrate}:${this.targetFps}`;
        if (signature !== this.adaptationSignature) {
            this.adaptationSignature = signature;
            this.callbacks.onAdaptation({ level: this.adaptationLevel, width: dimensions.width, height: dimensions.height, bitrate: dimensions.bitrate, targetFps: this.targetFps });
        }
        if (resized || this.restartRequested || this.encoderSignature !== signature || !this.encoder) {
            this.startEncoder(signature, dimensions);
        }
        this.encodeCanvas(dimensions, now);
        this.evaluateAdaptation(now);
        this.reportState(now);
    }

    private drawCapturedSource(
        source: CanvasImageSource | null,
        sourceWidth: number,
        sourceHeight: number,
        sourceEnabled: boolean,
    ): {
        dimensions: { width: number; height: number; bitrate: number };
        resized: boolean;
    } {
        this.lastCaptureAt = performance.now();
        const dimensions = fitDimensions(sourceWidth, sourceHeight, TARGET_PROFILE, this.adaptationLevel);
        this.configuredBitrate = dimensions.bitrate;
        const resized = this.canvas.width !== dimensions.width || this.canvas.height !== dimensions.height;
        if (this.canvas.width !== dimensions.width) this.canvas.width = dimensions.width;
        if (this.canvas.height !== dimensions.height) this.canvas.height = dimensions.height;
        if (sourceEnabled && source) {
            this.context.drawImage(source, 0, 0, dimensions.width, dimensions.height);
        } else {
            this.context.fillStyle = '#000000';
            this.context.fillRect(0, 0, dimensions.width, dimensions.height);
        }
        return { dimensions, resized };
    }

    private startEncoder(
        signature: string,
        dimensions: { width: number; height: number; bitrate: number },
    ): void {
        if (typeof VideoEncoder !== 'function' || typeof VideoFrame !== 'function') {
            throw new Error('Persistent VP8 WebCodecs encoding is unavailable');
        }
        this.closeEncoder();
        const generation = ++this.encoderGeneration;
        const encoder = new VideoEncoder({
            output: chunk => this.handleEncodedChunk(chunk, generation),
            error: error => this.handleEncoderFailure(generation, errorDetail(error)),
        });
        try {
            encoder.configure({
                codec: VIDEO_CODEC,
                width: dimensions.width,
                height: dimensions.height,
                bitrate: dimensions.bitrate,
                bitrateMode: 'constant',
                framerate: this.targetFps,
                latencyMode: 'realtime',
                hardwareAcceleration: 'no-preference',
            });
        } catch (error) {
            try { encoder.close(); } catch { }
            throw error;
        }
        this.encoder = encoder;
        this.encoderSignature = signature;
        this.keyFrameRequested = true;
        this.discardUntilKeyFrame = true;
        this.lastKeyFrameTimestamp = 0;
        this.restartRequested = false;
    }

    private closeEncoder(): void {
        this.encoderGeneration += 1;
        const encoder = this.encoder;
        this.encoder = null;
        if (encoder && encoder.state !== 'closed') {
            try { encoder.close(); } catch { }
        }
        this.pendingEncode.clear();
        this.encoderSignature = '';
    }

    private invalidateDelivery(): void {
        for (const item of this.sendQueue) SecureMemory.zeroBuffer(item.frame);
        this.sendQueue = [];
        this.keyFrameRequested = true;
        this.discardUntilKeyFrame = true;
        this.deliveryInvalidations += 1;
    }

    private handleEncoderFailure(generation: number, detail: string): void {
        if (this.stopped || generation !== this.encoderGeneration) return;
        this.encoderFailures += 1;
        this.callbacks.onSendError(detail);
        this.emitDiagnostic('encoder-failure', detail);
        this.noteCaptureDrop();
        this.invalidateDelivery();
        this.closeEncoder();
        this.restartRequested = true;
        this.reportState(performance.now(), true);
    }

    private encodeCanvas(
        dimensions: { width: number; height: number },
        now: number,
    ): void {
        const encoder = this.encoder;
        if (!encoder || encoder.state !== 'configured') return;
        if (this.pendingEncode.size >= MAX_PENDING_CODEC_METADATA) {
            this.handleEncoderFailure(this.encoderGeneration, 'pending encoder metadata capacity');
            return;
        }
        if (encoder.encodeQueueSize >= MAX_CODEC_QUEUE_FRAMES) {
            this.noteCaptureDrop(now);
            return;
        }
        this.timestamp = Math.max(this.timestamp + 1, Math.round(now * 1_000));
        const timestamp = this.timestamp;
        const keyFrame =
            this.keyFrameRequested ||
            this.lastKeyFrameTimestamp === 0 ||
            timestamp - this.lastKeyFrameTimestamp >= KEY_FRAME_INTERVAL_US;
        const frame = new VideoFrame(this.canvas, {
            timestamp,
            duration: this.frameDurationUs,
            alpha: 'discard',
        });
        this.pendingEncode.set(timestamp, {
            capturedAt: this.sourceCapturedAt || Date.now(),
            width: dimensions.width,
            height: dimensions.height,
            startedAt: now,
        });
        try {
            encoder.encode(frame, { keyFrame });
            if (keyFrame) {
                this.keyFrameRequested = false;
                this.lastKeyFrameTimestamp = timestamp;
            }
        } catch (error) {
            this.pendingEncode.delete(timestamp);
            this.keyFrameRequested = true;
            throw error;
        } finally {
            frame.close();
        }
    }

    private handleEncodedChunk(
        chunk: EncodedVideoChunk,
        generation: number,
    ): void {
        if (this.stopped || generation !== this.encoderGeneration) return;
        const pending = this.pendingEncode.get(chunk.timestamp);
        let retired = 0;
        for (const timestamp of this.pendingEncode.keys()) {
            if (timestamp >= chunk.timestamp) break;
            this.pendingEncode.delete(timestamp);
            retired += 1;
        }
        this.pendingEncode.delete(chunk.timestamp);
        if (retired > 0) {
            this.retiredEncoderOutputs += retired;
            this.adaptationCaptureDrops += retired;
            for (let index = 0; index < retired; index += 1) this.callbacks.onCaptureDrop();
        }
        if (chunk.byteLength === 0) return;
        this.lastEncodedAt = performance.now();
        this.adaptationEncodedBytes += chunk.byteLength;
        if (!pending) return;
        const keyFrame = chunk.type === 'key';
        if (keyFrame) this.encodedKeyFrames += 1;
        if (this.discardUntilKeyFrame && !keyFrame) {
            this.noteCaptureDrop();
            return;
        }
        if (this.sendQueue.length + this.sendInFlightFrames >= MAX_PENDING_SENDS) {
            this.noteCaptureDrop();
            this.emitDiagnostic('send-capacity', undefined, {
                sequence: this.sequence || null,
                keyFrame,
            });
            this.keyFrameRequested = true;
            this.discardUntilKeyFrame = true;
            return;
        }
        const payload = new Uint8Array(chunk.byteLength);
        try {
            chunk.copyTo(payload);
            if (!isVp8Chunk(payload, keyFrame)) throw new Error('Invalid VP8 WebCodecs output');
            if (keyFrame) this.discardUntilKeyFrame = false;
            const encodeMs = Math.max(0, performance.now() - pending.startedAt);
            this.adaptationEncodeTotalMs += encodeMs;
            this.adaptationEncodeSamples += 1;
            this.callbacks.onEncode(encodeMs);
            this.sequence = (this.sequence + 1) >>> 0;
            if (this.sequence === 0) this.sequence = 1;
            const metadata: VisualFrameMetadata = {
                sequence: this.sequence,
                capturedAt: pending.capturedAt,
                timestamp: chunk.timestamp,
                width: pending.width,
                height: pending.height,
                keyFrame,
            };
            const frame = encodeVisualFrame(payload, metadata);
            this.sendQueue.push({ frame, metadata });
            void this.drainSendQueue();
        } catch (error) {
            if (!this.stopped && generation === this.encoderGeneration) {
                this.noteCaptureDrop();
                this.emitDiagnostic('encoder-output-invalid', errorDetail(error), {
                    sequence: this.sequence || null,
                    keyFrame,
                });
                this.invalidateDelivery();
            }
        } finally {
            SecureMemory.zeroBuffer(payload);
        }
    }

    private async drainSendQueue(): Promise<void> {
        if (this.sendPending || this.stopped) return;
        this.sendPending = true;
        try {
            while (!this.stopped && this.callbacks.isActive() && this.sendQueue.length > 0) {
                if (this.stopped || !this.callbacks.isActive() || this.sendQueue.length === 0) break;
                const items = [this.sendQueue.shift()!];
                const second = this.sendQueue[0];
                if (
                    second &&
                    VISUAL_BATCH_HEADER_BYTES +
                    VISUAL_BATCH_ENTRY_BYTES * 2 +
                    items[0].frame.byteLength +
                    second.frame.byteLength <= MAX_VISUAL_BATCH_BYTES
                ) {
                    items.push(this.sendQueue.shift()!);
                }
                this.sendInFlightFrames = items.length;
                let batch: Uint8Array | null = null;
                try {
                    batch = encodeVisualBatch(items.map(item => item.frame));
                    const writeMs = await this.callbacks.send(batch, items.map(item => ({
                        bytes: item.frame.byteLength,
                        metadata: item.metadata,
                    })));
                    this.lastSendSuccessAt = performance.now();
                    this.observeDelivery(writeMs, true);
                } catch (error) {
                    const detail = errorDetail(error);
                    const now = performance.now();
                    const warmingUp = detail === 'Visual transport warming up';
                    if (warmingUp) {
                        this.retryAfter = now + 500;
                        this.stableSince = 0;
                    } else {
                        this.lastSendFailureAt = now;
                        this.sendFailures += 1;
                        this.callbacks.onSendError(detail);
                        this.emitDiagnostic('send-failure', detail, {
                            sequence: items[0]?.metadata.sequence ?? null,
                            keyFrame: items.some(item => item.metadata.keyFrame),
                        });
                        this.observeDelivery(0, false);
                    }
                    this.invalidateDelivery();
                } finally {
                    if (batch) SecureMemory.zeroBuffer(batch);
                    for (const item of items) SecureMemory.zeroBuffer(item.frame);
                    this.sendInFlightFrames = 0;
                    this.reportState(performance.now());
                }
            }
        } finally {
            this.sendPending = false;
            if (this.stopped || !this.callbacks.isActive()) {
                for (const item of this.sendQueue) SecureMemory.zeroBuffer(item.frame);
                this.sendQueue = [];
            } else if (this.sendQueue.length > 0) void this.drainSendQueue();
        }
    }

    private emitDiagnostic(
        reason: VisualPipelineEventReason,
        detail?: string,
        frame: { sequence: number | null; keyFrame: boolean | null } = {
            sequence: null,
            keyFrame: null,
        },
    ): void {
        this.callbacks.onDiagnostic({
            reason,
            sequence: frame.sequence,
            keyFrame: frame.keyFrame,
            frameAgeMs: null,
            maxFrameAgeMs: null,
            queueFrames: this.sendQueue.length,
            inFlightFrames: this.sendInFlightFrames,
            codecQueueSize: this.encoder?.encodeQueueSize ?? 0,
            waitingForKeyFrame: this.discardUntilKeyFrame,
            ...(detail ? { detail } : {}),
        });
    }

    private reportState(now: number, force = false): void {
        if (!force && now - this.lastEncoderStateReportAt < ENCODER_STATE_REPORT_INTERVAL_MS) return;
        this.lastEncoderStateReportAt = now;
        let oldestPendingEncodeMs = 0;
        for (const pending of this.pendingEncode.values()) {
            oldestPendingEncodeMs = Math.max(oldestPendingEncodeMs, now - pending.startedAt);
        }
        this.callbacks.onState({
            source: this.sourceKind,
            codecState: this.encoder?.state ?? 'missing',
            codecQueueSize: this.encoder?.encodeQueueSize ?? 0,
            pendingEncodes: this.pendingEncode.size,
            oldestPendingEncodeMs: Math.max(0, Math.round(oldestPendingEncodeMs)),
            sendQueueFrames: this.sendQueue.length,
            sendInFlightFrames: this.sendInFlightFrames,
            sendPending: this.sendPending,
            capturePending: this.capturePending,
            keyFrameRequested: this.keyFrameRequested,
            discardUntilKeyFrame: this.discardUntilKeyFrame,
            restartRequested: this.restartRequested,
            retryInMs: Math.max(0, Math.round(this.retryAfter - now)),
            targetFps: this.targetFps,
            adaptationLevel: this.adaptationLevel,
            configuredBitrate: this.configuredBitrate,
            observedEncodedKbps: Math.round(this.observedEncodedKbps),
            adaptationHealth: this.adaptationHealth,
            adaptationCaptureLossRatio: this.adaptationCaptureLossRatio,
            adaptationSendFailureRatio: this.adaptationSendFailureRatio,
            adaptationAverageEncodeMs: this.adaptationAverageEncodeMs,
            adaptationAverageWriteMs: this.adaptationAverageWriteMs,
            adaptationStableForMs: this.stableSince > 0 ? Math.max(0, Math.round(now - this.stableSince)) : 0,
            adaptationRecoveryInMs: this.adaptationLevel > 0
                ? Math.max(0, Math.round(Math.max(
                    this.adaptationRecoveryAllowedAt - now,
                    this.stableSince > 0 ? this.adaptationRecoveryMs - (now - this.stableSince) : this.adaptationRecoveryMs,
                )))
                : 0,
            adaptationRecoveryWindowMs: this.adaptationRecoveryMs,
            lastCaptureAgoMs: elapsedSince(now, this.lastCaptureAt),
            lastEncodedAgoMs: elapsedSince(now, this.lastEncodedAt),
            lastSendSuccessAgoMs: elapsedSince(now, this.lastSendSuccessAt),
            lastSendFailureAgoMs: elapsedSince(now, this.lastSendFailureAt),
            encodedKeyFrames: this.encodedKeyFrames,
            deliveryInvalidations: this.deliveryInvalidations,
            encoderFailures: this.encoderFailures,
            sendFailures: this.sendFailures,
            retiredEncoderOutputs: this.retiredEncoderOutputs,
        });
    }

    private observeDelivery(writeMs: number, success: boolean): void {
        const now = performance.now();
        if (success && Number.isFinite(writeMs) && writeMs >= 0) {
            this.adaptationSendSuccesses += 1;
            this.adaptationWriteTotalMs += writeMs;
            this.adaptationWriteSamples += 1;
        } else {
            this.adaptationSendFailures += 1;
        }
        this.evaluateAdaptation(now);
    }

    private noteCaptureDrop(now = performance.now()): void {
        this.adaptationCaptureDrops += 1;
        this.callbacks.onCaptureDrop();
        this.evaluateAdaptation(now);
    }

    private noteBackoffDrop(): void {
        this.callbacks.onCaptureDrop();
    }

    private evaluateAdaptation(now: number): void {
        if (this.adaptationWindowStartedAt === 0) this.adaptationWindowStartedAt = now;
        const windowMs = now - this.adaptationWindowStartedAt;
        if (windowMs < ADAPTATION_WINDOW_MS) return;
        const encodedBitsPerSecond = this.adaptationEncodedBytes * 8_000 / Math.max(1, windowMs);
        this.observedEncodedKbps = encodedBitsPerSecond / 1_000;
        if (now < this.adaptationWarmupUntil) {
            this.adaptationHealth = 'warmup';
            this.resetAdaptationWindow(now);
            return;
        }
        const sendFailureRatio = this.adaptationSendFailures /
            Math.max(1, this.adaptationSendSuccesses + this.adaptationSendFailures);
        const averageEncodeMs = this.adaptationEncodeTotalMs / Math.max(1, this.adaptationEncodeSamples);
        const averageWriteMs = this.adaptationWriteTotalMs / Math.max(1, this.adaptationWriteSamples);
        const captureDrops = this.adaptationSourceDrops + this.adaptationCaptureDrops;
        const captureLossRatio = captureDrops /
            Math.max(1, this.adaptationSourceFrames + captureDrops);
        this.adaptationCaptureLossRatio = captureLossRatio;
        this.adaptationSendFailureRatio = sendFailureRatio;
        this.adaptationAverageEncodeMs = averageEncodeMs;
        this.adaptationAverageWriteMs = averageWriteMs;
        const frameBudgetMs = 1000 / this.targetFps;
        const encodeStressMs = Math.min(ENCODE_STRESS_MS, frameBudgetMs * 0.9);
        const encodeRecoveryMs = Math.min(ENCODE_RECOVERY_MS, frameBudgetMs * 0.7);
        const stressed =
            sendFailureRatio > 0.12 ||
            captureLossRatio > CAPTURE_STRESS_RATIO ||
            this.adaptationRemoteDiscontinuities > 0 ||
            averageEncodeMs > encodeStressMs ||
            averageWriteMs > WRITE_STRESS_MS;
        const healthy =
            this.adaptationEncodeSamples > 0 &&
            this.adaptationWriteSamples > 0 &&
            sendFailureRatio < 0.03 &&
            captureLossRatio < CAPTURE_RECOVERY_RATIO &&
            averageEncodeMs < encodeRecoveryMs &&
            averageWriteMs < WRITE_RECOVERY_MS &&
            this.adaptationRemoteDiscontinuities === 0;
        this.adaptationHealth = stressed ? 'stressed' : healthy ? 'healthy' : 'neutral';
        if (stressed) {
            this.adaptationStressWindows += 1;
            this.stableSince = 0;
            if (this.adaptationStressWindows >= ADAPTATION_STRESS_WINDOWS) this.degrade(now);
        } else if (healthy) {
            this.adaptationStressWindows = 0;
            if (this.stableSince === 0) this.stableSince = now;
            if (
                this.adaptationLevel > 0 &&
                now >= this.adaptationRecoveryAllowedAt &&
                now - this.stableSince >= this.adaptationRecoveryMs
            ) {
                if (
                    this.lastAdaptationUpgradeAt > 0 &&
                    now - this.lastAdaptationUpgradeAt >= ADAPTATION_FAILED_UPGRADE_MS
                ) {
                    this.adaptationRecoveryMs = Math.max(
                        ADAPTATION_RECOVERY_MS,
                        Math.floor(this.adaptationRecoveryMs / 2),
                    );
                }
                this.adaptationLevel -= 1;
                this.stableSince = now;
                this.restartRequested = true;
                this.lastAdaptationUpgradeAt = now;
                this.adaptationWarmupUntil = now + ADAPTATION_WARMUP_MS;
            }
        } else {
            this.adaptationStressWindows = 0;
            this.stableSince = 0;
        }
        this.resetAdaptationWindow(now);
    }

    private resetAdaptationWindow(now: number): void {
        this.adaptationWindowStartedAt = now;
        this.adaptationSendSuccesses = 0;
        this.adaptationSendFailures = 0;
        this.adaptationEncodeTotalMs = 0;
        this.adaptationEncodeSamples = 0;
        this.adaptationEncodedBytes = 0;
        this.adaptationWriteTotalMs = 0;
        this.adaptationWriteSamples = 0;
        this.adaptationSourceFrames = 0;
        this.adaptationSourceDrops = 0;
        this.adaptationCaptureDrops = 0;
        this.adaptationRemoteDiscontinuities = 0;
    }

    private degrade(now: number): void {
        this.adaptationStressWindows = 0;
        this.stableSince = 0;
        if (this.adaptationLevel < MAX_ADAPTATION_LEVEL) {
            if (
                this.lastAdaptationUpgradeAt > 0 &&
                now - this.lastAdaptationUpgradeAt < ADAPTATION_FAILED_UPGRADE_MS
            ) {
                this.adaptationRecoveryMs = Math.min(
                    ADAPTATION_MAX_RECOVERY_MS,
                    this.adaptationRecoveryMs * 2,
                );
            }
            this.adaptationLevel += 1;
            this.restartRequested = true;
            this.adaptationRecoveryAllowedAt = now + this.adaptationRecoveryMs;
            this.adaptationWarmupUntil = now + ADAPTATION_WARMUP_MS;
        }
    }
}

export class RealtimeVisualDecoder {
    private decoder: VideoDecoder;
    private stopped = false;
    private drainScheduled = false;
    private queue: QueuedDecode[] = [];
    private pendingDecode = new Map<number, PendingDecode>();
    private lastSequence = 0;
    private generation = 0;
    private waitingForKeyFrame = true;
    private resetOnNextKeyFrame = false;
    private recoveryRequested = false;
    private lastKeyFrameRequestAt = 0;
    private latestMetadata: VisualFrameMetadata | null = null;
    private totalPlaybackRecoveries = 0;
    private lastStateReportAt = 0;
    private pipelineResets = 0;
    private bufferStalls = 0;
    private decodeStallTimer: ReturnType<typeof setTimeout> | null = null;
    private stateTimer: ReturnType<typeof setInterval> | null = null;
    private lastArrivalAt = 0;
    private lastOutputAt = 0;
    private lastAcceptedOutputAt = 0;
    private lastKeyFrameAt = 0;
    private decoderWidth = 0;
    private decoderHeight = 0;
    private staleArrivalDrops = 0;
    private staleDrainDrops = 0;
    private staleOutputDrops = 0;
    private sequenceGapRecoveries = 0;
    private outOfOrderDrops = 0;
    private waitingForKeyFrameDrops = 0;
    private capacityRecoveries = 0;
    private dimensionDrops = 0;
    private unmatchedOutputs = 0;
    private decoderErrors = 0;
    private watchdogResets = 0;

    constructor(private readonly callbacks: DecoderCallbacks) {
        if (typeof VideoDecoder !== 'function' || typeof EncodedVideoChunk !== 'function') {
            throw new Error('Persistent VP8 WebCodecs decoding is unavailable');
        }
        this.decoder = this.createDecoder();
        this.stateTimer = setInterval(
            () => this.reportState(performance.now(), true),
            DECODER_STATE_REPORT_INTERVAL_MS,
        );
        this.reportState(performance.now(), true);
    }

    push(frame: Uint8Array): VisualFrameMetadata | null {
        if (this.stopped) return null;
        try {
            const decoded = decodeVisualFrame(frame);
            const now = performance.now();
            this.lastArrivalAt = now;
            this.callbacks.onArrival(frame.byteLength, decoded.metadata);
            const frameAgeMs = this.callbacks.getFrameAgeMs(decoded.metadata);
            if (frameAgeMs !== null && frameAgeMs > this.callbacks.getMaxFrameAgeMs()) {
                this.lastSequence = decoded.metadata.sequence;
                this.staleArrivalDrops += 1;
                this.callbacks.onDrop();
                this.recoverFromStaleFrames('stale-arrival', decoded.metadata, frameAgeMs);
                return null;
            }
            if (this.lastSequence !== 0) {
                const expected = this.lastSequence === 0xffff_ffff ? 1 : this.lastSequence + 1;
                if (decoded.metadata.sequence !== expected) {
                    const distance = (decoded.metadata.sequence - this.lastSequence) >>> 0;
                    if (distance === 0 || distance >= 0x8000_0000) {
                        this.outOfOrderDrops += 1;
                        this.callbacks.onDrop();
                        return null;
                    }
                    if (!this.waitingForKeyFrame) {
                        this.sequenceGapRecoveries += 1;
                        this.totalPlaybackRecoveries += 1;
                        this.clearQueue();
                        this.waitingForKeyFrame = true;
                        this.resetOnNextKeyFrame = true;
                        if (!decoded.metadata.keyFrame) this.requireKeyFrame();
                        this.emitDiagnostic('sequence-gap', decoded.metadata, frameAgeMs);
                        this.reportState(now, true);
                    }
                }
            }
            this.lastSequence = decoded.metadata.sequence;
            if (this.waitingForKeyFrame && !decoded.metadata.keyFrame) {
                this.waitingForKeyFrameDrops += 1;
                this.requireKeyFrame();
                this.callbacks.onDrop();
                return null;
            }
            if (decoded.metadata.keyFrame) {
                const wasWaiting = this.waitingForKeyFrame;
                const dimensionsChanged =
                    this.decoderWidth > 0 &&
                    (decoded.metadata.width !== this.decoderWidth ||
                        decoded.metadata.height !== this.decoderHeight);
                if (this.resetOnNextKeyFrame || dimensionsChanged) this.resetDecoder();
                this.decoderWidth = decoded.metadata.width;
                this.decoderHeight = decoded.metadata.height;
                this.resetOnNextKeyFrame = false;
                this.waitingForKeyFrame = false;
                this.recoveryRequested = false;
                this.lastKeyFrameRequestAt = 0;
                this.lastKeyFrameAt = now;
                if (wasWaiting) this.emitDiagnostic('key-frame-resumed', decoded.metadata, frameAgeMs);
            }
            const item: QueuedDecode = {
                payload: Uint8Array.from(decoded.payload),
                metadata: decoded.metadata,
            };
            if (this.queue.length + this.pendingDecode.size >= MAX_PENDING_DECODES) {
                this.lastSequence = decoded.metadata.sequence;
                this.bufferStalls += 1;
                this.capacityRecoveries += 1;
                this.totalPlaybackRecoveries += 1;
                this.emitDiagnostic('decode-capacity', decoded.metadata, frameAgeMs);
                this.resetDecoder();
                if (!decoded.metadata.keyFrame) {
                    SecureMemory.zeroBuffer(item.payload);
                    this.requireKeyFrame(true);
                    this.callbacks.onDrop();
                    this.reportState(performance.now(), true);
                    return null;
                }
            }
            this.lastSequence = decoded.metadata.sequence;
            this.queue.push(item);
            this.callbacks.onAdmitted();
            this.scheduleDrain();
            return decoded.metadata;
        } catch (error) {
            this.decoderErrors += 1;
            this.callbacks.onError();
            this.totalPlaybackRecoveries += 1;
            this.emitDiagnostic('invalid-frame', null, null, errorDetail(error));
            this.resetDecoder();
            this.waitingForKeyFrame = true;
            this.requireKeyFrame();
            return null;
        }
    }

    stop(): void {
        if (this.stopped) return;
        this.stopped = true;
        if (this.stateTimer) clearInterval(this.stateTimer);
        this.stateTimer = null;
        this.generation += 1;
        this.drainScheduled = false;
        this.clearDecodeStallTimer();
        this.clearQueue();
        this.pendingDecode.clear();
        if (this.decoder.state !== 'closed') {
            try { this.decoder.close(); } catch { }
        }
    }

    private createDecoder(): VideoDecoder {
        const generation = ++this.generation;
        let decoder: VideoDecoder;
        decoder = new VideoDecoder({
            output: frame => this.handleDecodedFrame(frame, decoder, generation),
            error: () => this.handleDecoderFailure(decoder, generation),
        });
        decoder.addEventListener('dequeue', () => {
            if (this.stopped || generation !== this.generation || this.decoder !== decoder) return;
            this.scheduleDrain();
            this.scheduleDecodeStallCheck();
            this.reportState(performance.now());
        });
        decoder.configure({
            codec: VIDEO_CODEC,
            optimizeForLatency: true,
            hardwareAcceleration: 'no-preference',
        });
        this.pipelineResets += 1;
        return decoder;
    }

    private resetDecoder(): void {
        this.clearDecodeStallTimer();
        this.clearQueue();
        this.pendingDecode.clear();
        this.resetOnNextKeyFrame = false;
        const previous = this.decoder;
        if (previous && previous.state !== 'closed') {
            try { previous.close(); } catch { }
        }
        if (!this.stopped) this.decoder = this.createDecoder();
    }

    private clearQueue(): void {
        for (const item of this.queue) SecureMemory.zeroBuffer(item.payload);
        this.queue = [];
    }

    private requireKeyFrame(force = false): void {
        this.waitingForKeyFrame = true;
        const now = performance.now();
        if (
            this.recoveryRequested &&
            !force &&
            now - this.lastKeyFrameRequestAt < KEY_FRAME_REQUEST_RETRY_MS
        ) return;
        this.recoveryRequested = true;
        this.lastKeyFrameRequestAt = now;
        this.callbacks.onDiscontinuity();
    }

    private scheduleDrain(): void {
        if (this.drainScheduled || this.stopped) return;
        this.drainScheduled = true;
        queueMicrotask(() => {
            this.drainScheduled = false;
            if (!this.stopped) this.drain();
        });
    }

    private drain(): void {
        const decoder = this.decoder;
        const generation = this.generation;
        while (
            !this.stopped &&
            decoder === this.decoder &&
            generation === this.generation &&
            decoder.state === 'configured' &&
            decoder.decodeQueueSize < MAX_CODEC_QUEUE_FRAMES &&
            this.queue.length > 0
        ) {
            const item = this.queue.shift()!;
            try {
                const frameAgeMs = this.callbacks.getFrameAgeMs(item.metadata);
                if (frameAgeMs !== null && frameAgeMs > this.callbacks.getMaxFrameAgeMs()) {
                    this.staleDrainDrops += 1;
                    this.callbacks.onDrop();
                    this.recoverFromStaleFrames('stale-drain', item.metadata, frameAgeMs);
                    return;
                }
                const chunk = new EncodedVideoChunk({
                    type: item.metadata.keyFrame ? 'key' : 'delta',
                    timestamp: item.metadata.timestamp,
                    duration: DEFAULT_FRAME_DURATION_US,
                    data: item.payload,
                });
                this.pendingDecode.set(item.metadata.timestamp, {
                    metadata: item.metadata,
                    startedAt: performance.now(),
                });
                decoder.decode(chunk);
                this.scheduleDecodeStallCheck();
            } catch (error) {
                this.pendingDecode.delete(item.metadata.timestamp);
                this.decoderErrors += 1;
                this.callbacks.onError();
                this.totalPlaybackRecoveries += 1;
                this.emitDiagnostic('decoder-submit', item.metadata, null, errorDetail(error));
                this.resetDecoder();
                this.waitingForKeyFrame = true;
                this.requireKeyFrame();
                return;
            } finally {
                SecureMemory.zeroBuffer(item.payload);
            }
        }
        this.reportState(performance.now());
    }

    private handleDecodedFrame(
        frame: VideoFrame,
        decoder: VideoDecoder,
        generation: number,
    ): void {
        if (this.stopped || generation !== this.generation || decoder !== this.decoder) {
            frame.close();
            return;
        }
        const now = performance.now();
        this.lastOutputAt = now;
        const pending = this.pendingDecode.get(frame.timestamp);
        this.pendingDecode.delete(frame.timestamp);
        this.scheduleDecodeStallCheck();
        if (!pending) {
            this.unmatchedOutputs += 1;
            this.emitDiagnostic('unmatched-output');
            frame.close();
            return;
        }
        const metadata = pending.metadata;
        const width = frame.displayWidth || frame.codedWidth;
        const height = frame.displayHeight || frame.codedHeight;
        const frameAgeMs = this.callbacks.getFrameAgeMs(metadata);
        if (width !== metadata.width || height !== metadata.height) {
            this.dimensionDrops += 1;
            frame.close();
            this.callbacks.onDrop();
            this.emitDiagnostic(
                'dimension-mismatch',
                metadata,
                frameAgeMs,
                `${width}x${height}!=${metadata.width}x${metadata.height}`,
            );
            this.totalPlaybackRecoveries += 1;
            this.resetDecoder();
            this.waitingForKeyFrame = true;
            this.requireKeyFrame(true);
            this.reportState(performance.now(), true);
            return;
        }
        if (frameAgeMs !== null && frameAgeMs > this.callbacks.getMaxFrameAgeMs()) {
            this.staleOutputDrops += 1;
            frame.close();
            this.callbacks.onDrop();
            this.recoverFromStaleFrames('stale-output', metadata, frameAgeMs);
            this.scheduleDrain();
            return;
        }
        this.latestMetadata = metadata;
        this.lastAcceptedOutputAt = now;
        const decodeMs = Math.max(0, now - pending.startedAt);
        let closed = false;
        const decodedFrame: DecodedVisualFrame = {
            source: frame,
            width,
            height,
            close: () => {
                if (closed) return;
                closed = true;
                frame.close();
            },
        };
        try {
            this.callbacks.onFrame(decodedFrame, metadata, decodeMs);
        } catch (error) {
            decodedFrame.close();
            this.decoderErrors += 1;
            this.callbacks.onError();
            this.emitDiagnostic('decoder-failure', metadata, frameAgeMs, errorDetail(error));
        }
        this.reportState(performance.now());
        this.scheduleDrain();
    }

    private handleDecoderFailure(decoder: VideoDecoder, generation: number): void {
        if (this.stopped || generation !== this.generation || decoder !== this.decoder) return;
        this.callbacks.onError();
        this.bufferStalls += 1;
        this.decoderErrors += 1;
        this.totalPlaybackRecoveries += 1;
        this.emitDiagnostic('decoder-failure');
        this.resetDecoder();
        this.waitingForKeyFrame = true;
        this.requireKeyFrame(true);
        this.reportState(performance.now(), true);
    }

    private recoverFromStaleFrames(
        reason: 'stale-arrival' | 'stale-drain' | 'stale-output',
        metadata: VisualFrameMetadata,
        frameAgeMs: number,
    ): void {
        const startedRecovery = !this.waitingForKeyFrame;
        if (startedRecovery) {
            this.totalPlaybackRecoveries += 1;
            this.clearQueue();
            this.resetOnNextKeyFrame = true;
        }
        this.requireKeyFrame();
        if (startedRecovery) this.emitDiagnostic(reason, metadata, frameAgeMs);
    }

    private clearDecodeStallTimer(): void {
        if (this.decodeStallTimer !== null) clearTimeout(this.decodeStallTimer);
        this.decodeStallTimer = null;
    }

    private scheduleDecodeStallCheck(): void {
        if (this.stopped) return;
        if (this.pendingDecode.size === 0) {
            this.clearDecodeStallTimer();
            return;
        }
        if (this.decodeStallTimer !== null) return;
        let oldestStartedAt = Number.POSITIVE_INFINITY;
        for (const pending of this.pendingDecode.values()) {
            oldestStartedAt = Math.min(oldestStartedAt, pending.startedAt);
        }
        const delay = Math.max(0, DECODER_STALL_TIMEOUT_MS - (performance.now() - oldestStartedAt));
        this.decodeStallTimer = setTimeout(() => {
            this.decodeStallTimer = null;
            if (this.stopped || this.pendingDecode.size === 0) return;
            let oldest = Number.POSITIVE_INFINITY;
            for (const pending of this.pendingDecode.values()) {
                oldest = Math.min(oldest, pending.startedAt);
            }
            if (performance.now() - oldest < DECODER_STALL_TIMEOUT_MS) {
                this.scheduleDecodeStallCheck();
                return;
            }
            this.bufferStalls += 1;
            this.watchdogResets += 1;
            this.totalPlaybackRecoveries += 1;
            this.emitDiagnostic('decoder-watchdog');
            this.resetDecoder();
            this.waitingForKeyFrame = true;
            this.requireKeyFrame(true);
            this.reportState(performance.now(), true);
        }, delay);
    }

    private reportState(now: number, force = false): void {
        if (!force && now - this.lastStateReportAt < DECODER_STATE_REPORT_INTERVAL_MS) return;
        this.lastStateReportAt = now;
        const bufferedFrames = this.queue.length + this.pendingDecode.size;
        const frameAgeMs = this.latestMetadata
            ? this.callbacks.getFrameAgeMs(this.latestMetadata)
            : null;
        let oldestPendingDecodeMs = 0;
        for (const pending of this.pendingDecode.values()) {
            oldestPendingDecodeMs = Math.max(oldestPendingDecodeMs, now - pending.startedAt);
        }
        this.callbacks.onState({
            codecState: this.decoder.state,
            codecQueueSize: this.decoder.decodeQueueSize,
            queuedFrames: this.queue.length,
            pendingDecodes: this.pendingDecode.size,
            oldestPendingDecodeMs: Math.max(0, Math.round(oldestPendingDecodeMs)),
            bufferedSeconds: Math.round(bufferedFrames / TARGET_FPS * 10) / 10,
            playbackLagMs: frameAgeMs === null ? 0 : Math.max(0, Math.round(frameAgeMs)),
            playbackRate: 1,
            playbackRecoveries: this.totalPlaybackRecoveries,
            pipelineResets: this.pipelineResets,
            bufferStalls: this.bufferStalls,
            waitingForKeyFrame: this.waitingForKeyFrame,
            resetOnNextKeyFrame: this.resetOnNextKeyFrame,
            recoveryRequested: this.recoveryRequested,
            lastArrivalAgoMs: elapsedSince(now, this.lastArrivalAt),
            lastOutputAgoMs: elapsedSince(now, this.lastOutputAt),
            lastAcceptedOutputAgoMs: elapsedSince(now, this.lastAcceptedOutputAt),
            lastKeyFrameAgoMs: elapsedSince(now, this.lastKeyFrameAt),
            staleArrivalDrops: this.staleArrivalDrops,
            staleDrainDrops: this.staleDrainDrops,
            staleOutputDrops: this.staleOutputDrops,
            sequenceGapRecoveries: this.sequenceGapRecoveries,
            outOfOrderDrops: this.outOfOrderDrops,
            waitingForKeyFrameDrops: this.waitingForKeyFrameDrops,
            capacityRecoveries: this.capacityRecoveries,
            dimensionDrops: this.dimensionDrops,
            unmatchedOutputs: this.unmatchedOutputs,
            decoderErrors: this.decoderErrors,
            watchdogResets: this.watchdogResets,
        });
    }

    private emitDiagnostic(
        reason: VisualPipelineEventReason,
        metadata: VisualFrameMetadata | null = null,
        frameAgeMs: number | null = null,
        detail?: string,
    ): void {
        this.callbacks.onDiagnostic({
            reason,
            sequence: metadata?.sequence ?? null,
            keyFrame: metadata?.keyFrame ?? null,
            frameAgeMs: frameAgeMs === null ? null : Math.max(0, Math.round(frameAgeMs)),
            maxFrameAgeMs: Math.round(this.callbacks.getMaxFrameAgeMs()),
            queueFrames: this.queue.length,
            inFlightFrames: this.pendingDecode.size,
            codecQueueSize: this.decoder?.decodeQueueSize ?? 0,
            waitingForKeyFrame: this.waitingForKeyFrame,
            ...(detail ? { detail } : {}),
        });
    }
}
