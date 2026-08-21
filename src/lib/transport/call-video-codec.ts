import { TARGET_FPS, type QualityOption } from '../constants';
import { SecureMemory } from '../cryptography/secure-memory';
import { nativeCamera, type NativeCameraFrame } from '../tauri-bindings';
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

export interface VisualDecoderState {
    bufferedSeconds: number;
    playbackLagMs: number;
    playbackRate: number;
    playbackRecoveries: number;
    pipelineResets: number;
    bufferStalls: number;
}

interface EncoderCallbacks {
    isActive: () => boolean;
    isSourceEnabled: () => boolean;
    getQuality: () => QualityOption;
    send: (frame: Uint8Array, frames: readonly VisualSendDescriptor[]) => Promise<number>;
    onCaptureDrop: () => void;
    onEncode: (milliseconds: number) => void;
    onSendError: () => void;
    onAdaptation: (state: VisualAdaptationState) => void;
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
type QueuedSend = { frame: Uint8Array; metadata: VisualFrameMetadata; queuedAt: number };
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

const isVideoElement = (source: VisualCaptureSource): source is HTMLVideoElement =>
    source instanceof HTMLVideoElement;

const FRAME_INTERVAL_MS = 1000 / TARGET_FPS;
const FRAME_DURATION_US = Math.round(1_000_000 / TARGET_FPS);
const VIDEO_CODEC = 'vp8';
const VISUAL_FRAME_VERSION = 4;
const VISUAL_FRAME_HEADER_BYTES = 32;
const VISUAL_BATCH_VERSION = 1;
const VISUAL_BATCH_HEADER_BYTES = 4;
const VISUAL_BATCH_ENTRY_BYTES = 4;
const MAX_VISUAL_BATCH_FRAMES = 2;
const MAX_VISUAL_BATCH_BYTES = MAX_CALL_FRAME_SIZE - NOISE_FRAME_OVERHEAD;
const VISUAL_BATCH_COALESCE_MS = 18;
const VP8_CODEC_ID = 3;
const MAX_VISUAL_ENCODED_BYTES = 1024 * 1024;
const MAX_VISUAL_DIMENSION = 1280;
const MAX_VISUAL_PIXELS = 1280 * 720;
const MAX_FRAME_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_ADAPTATION_LEVEL = 3;
const MAX_PENDING_DECODES = 8;
const MAX_CODEC_QUEUE_FRAMES = 3;
const MAX_PENDING_CODEC_METADATA = 12;
const MAX_PENDING_SENDS = 4;
const KEY_FRAME_INTERVAL_US = 2_000_000;
const ENCODE_STRESS_MS = 40;
const ENCODE_RECOVERY_MS = 35;
const WRITE_STRESS_MS = 140;
const WRITE_RECOVERY_MS = 90;
const ADAPTATION_WINDOW_MS = 2_000;
const ADAPTATION_RECOVERY_MS = 10_000;
const ADAPTATION_WARMUP_MS = 10_000;
const MIN_VISUAL_PLAYOUT_AGE_MS = 1_200;
const MAX_VISUAL_PLAYOUT_AGE_MS = 2_000;
const KEY_FRAME_REQUEST_RETRY_MS = 2_000;
const DECODER_STATE_REPORT_INTERVAL_MS = 1_000;

const QUALITY_PROFILES: Record<QualityOption, EncoderProfile> = {
    low: { width: 640, height: 360, bitrate: 900_000 },
    medium: { width: 960, height: 540, bitrate: 1_500_000 },
    high: { width: 1280, height: 720, bitrate: 2_500_000 },
};
const LEVEL_SCALES = [1, 0.85, 0.7, 0.55] as const;
const BITRATE_SCALES = [1, 0.9, 0.8, 0.7] as const;

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
        bitrate: Math.max(500_000, Math.round(profile.bitrate * BITRATE_SCALES[level])),
    };
};

const isVp8Chunk = (payload: Uint8Array, keyFrame: boolean): boolean =>
    payload instanceof Uint8Array &&
    payload.byteLength >= (keyFrame ? 10 : 3) &&
    payload.byteLength <= MAX_VISUAL_ENCODED_BYTES &&
    (payload[0] & 1) === (keyFrame ? 0 : 1) &&
    (!keyFrame || (payload[3] === 0x9d && payload[4] === 0x01 && payload[5] === 0x2a));

export function visualPlayoutAgeMs(rttMs: number | null): number {
    if (rttMs === null || !Number.isFinite(rttMs) || rttMs < 0) return 1_500;
    return Math.min(MAX_VISUAL_PLAYOUT_AGE_MS, Math.max(MIN_VISUAL_PLAYOUT_AGE_MS, rttMs + 500));
}

export function encodeVisualFrame(payload: Uint8Array, metadata: VisualFrameMetadata): Uint8Array {
    if (
        typeof metadata.keyFrame !== 'boolean' ||
        !isVp8Chunk(payload, metadata.keyFrame) ||
        !Number.isSafeInteger(metadata.sequence) || metadata.sequence <= 0 || metadata.sequence > 0xffff_ffff ||
        !Number.isSafeInteger(metadata.capturedAt) || metadata.capturedAt <= 0 ||
        !Number.isSafeInteger(metadata.timestamp) || metadata.timestamp <= 0 ||
        !Number.isInteger(metadata.width) || !Number.isInteger(metadata.height) ||
        metadata.width < 2 || metadata.height < 2 ||
        metadata.width > MAX_VISUAL_DIMENSION || metadata.height > MAX_VISUAL_DIMENSION ||
        metadata.width * metadata.height > MAX_VISUAL_PIXELS
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
        width * height > MAX_VISUAL_PIXELS || payloadLength !== payload.byteLength || !isVp8Chunk(payload, keyFrame)
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
    private adaptationLevel = 0;
    private stableSince = 0;
    private retryAfter = 0;
    private activeQuality: QualityOption | null = null;
    private adaptationSignature = '';
    private nextCaptureAt = 0;
    private lastMediaTime = -1;
    private adaptationWindowStartedAt = 0;
    private adaptationSendSuccesses = 0;
    private adaptationSendFailures = 0;
    private adaptationEncodeTotalMs = 0;
    private adaptationEncodeSamples = 0;
    private adaptationWriteTotalMs = 0;
    private adaptationWriteSamples = 0;
    private adaptationStressWindows = 0;
    private adaptationWarmupUntil = 0;
    private sourceCapturedAt = 0;

    constructor(_kind: VisualMediaKind, private readonly callbacks: EncoderCallbacks) {
        const context = this.canvas.getContext('2d', { alpha: false });
        if (!context) throw new Error('Visual encoder canvas is unavailable');
        this.context = context;
    }

    start(source: VisualCaptureSource): void {
        if (this.stopped) throw new Error('Visual encoder is stopped');
        if (isVideoElement(source)) {
            this.video = source;
            this.beginCaptureSchedule();
        } else {
            this.video = null;
            this.nativeSource = source;
            this.initializeCaptureClock();
            void this.consumeNativeFrames();
        }
    }

    getCanvas(): HTMLCanvasElement {
        return this.canvas;
    }

    requestKeyFrame(): void {
        if (this.stopped) return;
        this.invalidateDelivery();
    }

    stop(): void {
        if (this.stopped) return;
        this.stopped = true;
        if (this.timer) clearTimeout(this.timer);
        this.timer = null;
        if (this.video && this.videoFrameCallbackId !== null) {
            try { this.video.cancelVideoFrameCallback(this.videoFrameCallbackId); } catch { }
        }
        this.videoFrameCallbackId = null;
        this.nativeSource?.stop();
        this.nativeSource = null;
        this.video = null;
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

    private schedule(delay = 0): void {
        if (this.stopped || this.timer || this.videoFrameCallbackId !== null) return;
        const video = this.video;
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
        throw new Error('Video frame scheduling is unavailable');
    }

    private offerCapture(mediaTime: number | undefined, now: number, pending = false): void {
        if (this.stopped || !this.callbacks.isActive()) return;
        if (!pending) {
            if (now + 1 < this.nextCaptureAt) return;
            const elapsed = Math.max(0, now - this.nextCaptureAt);
            this.nextCaptureAt += (Math.floor(elapsed / FRAME_INTERVAL_MS) + 1) * FRAME_INTERVAL_MS;
        }
        if (this.capturePending) {
            this.pendingMediaTime = mediaTime;
            this.noteCaptureDrop(now);
            return;
        }
        if (now < this.retryAfter) {
            this.noteCaptureDrop(now);
            return;
        }
        this.capturePending = true;
        void this.capture(mediaTime);
    }

    private capture(mediaTime?: number): void {
        try {
            if (this.stopped || !this.callbacks.isActive()) return;
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
                    this.noteCaptureDrop();
                    return;
                }
                this.lastMediaTime = currentMediaTime;
            }
            this.processCapturedSource(source, sourceWidth, sourceHeight, sourceEnabled);
        } catch {
            if (!this.stopped) {
                this.handleEncoderFailure(this.encoderGeneration);
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
        try {
            while (!this.stopped && this.callbacks.isActive() && this.nativeSource === source) {
                const frame = await source.read();
                if (!frame) continue;
                let image: ImageBitmap | null = null;
                try {
                    const now = performance.now();
                    if (now + 1 < this.nextCaptureAt || now < this.retryAfter) {
                        this.noteCaptureDrop(now);
                        continue;
                    }
                    const elapsed = Math.max(0, now - this.nextCaptureAt);
                    this.nextCaptureAt += (Math.floor(elapsed / FRAME_INTERVAL_MS) + 1) * FRAME_INTERVAL_MS;
                    image = await createImageBitmap(new Blob([Uint8Array.from(frame.jpeg).buffer], { type: 'image/jpeg' }));
                    if (this.stopped || !this.callbacks.isActive() || this.nativeSource !== source) break;
                    this.sourceCapturedAt = frame.capturedAt;
                    const sourceEnabled = this.callbacks.isSourceEnabled() && frame.enabled;
                    this.processCapturedSource(sourceEnabled ? image : null, frame.width, frame.height, sourceEnabled);
                } catch {
                    if (!this.stopped) {
                        this.handleEncoderFailure(this.encoderGeneration);
                    }
                } finally {
                    SecureMemory.zeroBuffer(frame.jpeg);
                    try { image?.close(); } catch { }
                }
            }
        } catch {
            if (!this.stopped && this.callbacks.isActive()) this.noteCaptureDrop();
        } finally {
            if (this.nativeSource === source) this.nativeSource = null;
        }
    }

    private processCapturedSource(
        source: CanvasImageSource | null,
        sourceWidth: number,
        sourceHeight: number,
        sourceEnabled: boolean,
    ): void {
        const quality = this.callbacks.getQuality();
        if (quality !== this.activeQuality) {
            this.activeQuality = quality;
            this.adaptationLevel = 0;
            this.stableSince = 0;
            this.adaptationStressWindows = 0;
            this.resetAdaptationWindow(performance.now());
            this.adaptationSignature = '';
            this.restartRequested = true;
        }
        const dimensions = fitDimensions(sourceWidth, sourceHeight, QUALITY_PROFILES[quality], this.adaptationLevel);
        const resized = this.canvas.width !== dimensions.width || this.canvas.height !== dimensions.height;
        if (this.canvas.width !== dimensions.width) this.canvas.width = dimensions.width;
        if (this.canvas.height !== dimensions.height) this.canvas.height = dimensions.height;
        if (sourceEnabled && source) this.context.drawImage(source, 0, 0, dimensions.width, dimensions.height);
        else {
            this.context.fillStyle = '#000000';
            this.context.fillRect(0, 0, dimensions.width, dimensions.height);
        }
        const signature = `${this.adaptationLevel}:${dimensions.width}:${dimensions.height}:${dimensions.bitrate}`;
        if (signature !== this.adaptationSignature) {
            this.adaptationSignature = signature;
            this.callbacks.onAdaptation({ level: this.adaptationLevel, width: dimensions.width, height: dimensions.height, bitrate: dimensions.bitrate, targetFps: TARGET_FPS });
        }
        const now = performance.now();
        if (resized || this.restartRequested || this.encoderSignature !== signature || !this.encoder) {
            this.startEncoder(signature, dimensions);
        }
        this.encodeCanvas(dimensions, now);
        this.evaluateAdaptation(now);
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
            error: () => this.handleEncoderFailure(generation),
        });
        try {
            encoder.configure({
                codec: VIDEO_CODEC,
                width: dimensions.width,
                height: dimensions.height,
                bitrate: dimensions.bitrate,
                framerate: TARGET_FPS,
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
    }

    private handleEncoderFailure(generation: number): void {
        if (this.stopped || generation !== this.encoderGeneration) return;
        this.callbacks.onSendError();
        this.noteCaptureDrop();
        this.invalidateDelivery();
        this.closeEncoder();
        this.restartRequested = true;
    }

    private encodeCanvas(
        dimensions: { width: number; height: number },
        now: number,
    ): void {
        const encoder = this.encoder;
        if (!encoder || encoder.state !== 'configured') return;
        if (this.pendingEncode.size >= MAX_PENDING_CODEC_METADATA) {
            this.handleEncoderFailure(this.encoderGeneration);
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
            duration: FRAME_DURATION_US,
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
        this.pendingEncode.delete(chunk.timestamp);
        if (!pending || chunk.byteLength === 0) return;
        const keyFrame = chunk.type === 'key';
        if (this.discardUntilKeyFrame && !keyFrame) {
            this.noteCaptureDrop();
            return;
        }
        if (this.sendQueue.length + this.sendInFlightFrames >= MAX_PENDING_SENDS) {
            this.noteCaptureDrop();
            this.invalidateDelivery();
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
            this.sendQueue.push({ frame, metadata, queuedAt: performance.now() });
            void this.drainSendQueue();
        } catch {
            if (!this.stopped && generation === this.encoderGeneration) {
                this.noteCaptureDrop();
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
                const first = this.sendQueue[0];
                if (this.sendQueue.length === 1) {
                    const remaining = VISUAL_BATCH_COALESCE_MS - (performance.now() - first.queuedAt);
                    if (remaining > 0) await new Promise<void>(resolve => setTimeout(resolve, remaining));
                }
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
                    this.observeDelivery(writeMs, true);
                } catch (error) {
                    this.callbacks.onSendError();
                    if (error instanceof Error && error.message.includes('Dedicated visual lane unavailable')) {
                        this.retryAfter = performance.now() + 250;
                        this.stableSince = 0;
                    }
                    this.observeDelivery(0, false);
                    this.invalidateDelivery();
                } finally {
                    if (batch) SecureMemory.zeroBuffer(batch);
                    for (const item of items) SecureMemory.zeroBuffer(item.frame);
                    this.sendInFlightFrames = 0;
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
        this.callbacks.onCaptureDrop();
        this.evaluateAdaptation(now);
    }

    private evaluateAdaptation(now: number): void {
        if (this.adaptationWindowStartedAt === 0) this.adaptationWindowStartedAt = now;
        if (now - this.adaptationWindowStartedAt < ADAPTATION_WINDOW_MS) return;
        if (now < this.adaptationWarmupUntil) {
            this.resetAdaptationWindow(now);
            return;
        }
        const sendFailureRatio = this.adaptationSendFailures /
            Math.max(1, this.adaptationSendSuccesses + this.adaptationSendFailures);
        const averageEncodeMs = this.adaptationEncodeTotalMs / Math.max(1, this.adaptationEncodeSamples);
        const averageWriteMs = this.adaptationWriteTotalMs / Math.max(1, this.adaptationWriteSamples);
        const stressed =
            sendFailureRatio > 0.12 ||
            averageEncodeMs > ENCODE_STRESS_MS ||
            averageWriteMs > WRITE_STRESS_MS;
        const healthy =
            this.adaptationEncodeSamples > 0 &&
            this.adaptationWriteSamples > 0 &&
            sendFailureRatio < 0.03 &&
            averageEncodeMs < ENCODE_RECOVERY_MS &&
            averageWriteMs < WRITE_RECOVERY_MS;
        if (stressed) {
            this.adaptationStressWindows += 1;
            this.stableSince = 0;
            if (this.adaptationStressWindows >= 2) this.degrade();
        } else if (healthy) {
            this.adaptationStressWindows = 0;
            if (this.stableSince === 0) this.stableSince = now;
            if (this.adaptationLevel > 0 && now - this.stableSince >= ADAPTATION_RECOVERY_MS) {
                this.adaptationLevel -= 1;
                this.stableSince = now;
                this.restartRequested = true;
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
        this.adaptationWriteTotalMs = 0;
        this.adaptationWriteSamples = 0;
    }

    private degrade(): void {
        this.adaptationStressWindows = 0;
        this.stableSince = 0;
        if (this.adaptationLevel < MAX_ADAPTATION_LEVEL) {
            this.adaptationLevel += 1;
            this.restartRequested = true;
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
    private recoveryRequested = false;
    private lastKeyFrameRequestAt = 0;
    private latestMetadata: VisualFrameMetadata | null = null;
    private totalPlaybackRecoveries = 0;
    private lastStateReportAt = 0;
    private pipelineResets = 0;
    private bufferStalls = 0;

    constructor(private readonly callbacks: DecoderCallbacks) {
        if (typeof VideoDecoder !== 'function' || typeof EncodedVideoChunk !== 'function') {
            throw new Error('Persistent VP8 WebCodecs decoding is unavailable');
        }
        this.decoder = this.createDecoder();
    }

    push(frame: Uint8Array): VisualFrameMetadata | null {
        if (this.stopped) return null;
        try {
            const decoded = decodeVisualFrame(frame);
            this.callbacks.onArrival(frame.byteLength, decoded.metadata);
            const frameAgeMs = this.callbacks.getFrameAgeMs(decoded.metadata);
            if (frameAgeMs !== null && frameAgeMs > this.callbacks.getMaxFrameAgeMs()) {
                this.lastSequence = decoded.metadata.sequence;
                this.callbacks.onDrop();
                this.totalPlaybackRecoveries += 1;
                this.resetDecoder();
                this.requireKeyFrame();
                return null;
            }
            if (this.lastSequence !== 0) {
                const expected = this.lastSequence === 0xffff_ffff ? 1 : this.lastSequence + 1;
                if (decoded.metadata.sequence !== expected) {
                    const distance = (decoded.metadata.sequence - this.lastSequence) >>> 0;
                    if (distance === 0 || distance >= 0x8000_0000) {
                        this.callbacks.onDrop();
                        return null;
                    }
                    if (!this.waitingForKeyFrame) {
                        this.totalPlaybackRecoveries += 1;
                        this.resetDecoder();
                        this.waitingForKeyFrame = true;
                    }
                }
            }
            if (this.waitingForKeyFrame && !decoded.metadata.keyFrame) {
                this.requireKeyFrame();
                this.callbacks.onDrop();
                return null;
            }
            if (decoded.metadata.keyFrame) {
                this.waitingForKeyFrame = false;
                this.recoveryRequested = false;
                this.lastKeyFrameRequestAt = 0;
            }
            const item: QueuedDecode = {
                payload: Uint8Array.from(decoded.payload),
                metadata: decoded.metadata,
            };
            if (this.queue.length + this.pendingDecode.size >= MAX_PENDING_DECODES) {
                SecureMemory.zeroBuffer(item.payload);
                this.lastSequence = decoded.metadata.sequence;
                this.bufferStalls += 1;
                this.totalPlaybackRecoveries += 1;
                this.resetDecoder();
                this.requireKeyFrame(true);
                this.callbacks.onDrop();
                this.reportState(performance.now(), true);
                return null;
            }
            this.lastSequence = decoded.metadata.sequence;
            this.queue.push(item);
            this.callbacks.onAdmitted();
            this.scheduleDrain();
            return decoded.metadata;
        } catch {
            this.callbacks.onError();
            this.totalPlaybackRecoveries += 1;
            this.resetDecoder();
            this.waitingForKeyFrame = true;
            this.requireKeyFrame();
            return null;
        }
    }

    stop(): void {
        if (this.stopped) return;
        this.stopped = true;
        this.generation += 1;
        this.drainScheduled = false;
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
        this.clearQueue();
        this.pendingDecode.clear();
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
                    this.callbacks.onDrop();
                    this.totalPlaybackRecoveries += 1;
                    this.resetDecoder();
                    this.requireKeyFrame();
                    return;
                }
                const chunk = new EncodedVideoChunk({
                    type: item.metadata.keyFrame ? 'key' : 'delta',
                    timestamp: item.metadata.timestamp,
                    duration: FRAME_DURATION_US,
                    data: item.payload,
                });
                this.pendingDecode.set(item.metadata.timestamp, {
                    metadata: item.metadata,
                    startedAt: performance.now(),
                });
                decoder.decode(chunk);
            } catch {
                this.pendingDecode.delete(item.metadata.timestamp);
                this.callbacks.onError();
                this.totalPlaybackRecoveries += 1;
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
        const pending = this.pendingDecode.get(frame.timestamp);
        this.pendingDecode.delete(frame.timestamp);
        if (!pending) {
            frame.close();
            return;
        }
        const metadata = pending.metadata;
        const width = frame.displayWidth || frame.codedWidth;
        const height = frame.displayHeight || frame.codedHeight;
        const frameAgeMs = this.callbacks.getFrameAgeMs(metadata);
        if (
            width !== metadata.width ||
            height !== metadata.height ||
            frameAgeMs !== null && frameAgeMs > this.callbacks.getMaxFrameAgeMs()
        ) {
            frame.close();
            this.callbacks.onDrop();
            this.scheduleDrain();
            return;
        }
        this.latestMetadata = metadata;
        const decodeMs = Math.max(0, performance.now() - pending.startedAt);
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
        } catch {
            decodedFrame.close();
            this.callbacks.onError();
        }
        this.reportState(performance.now());
        this.scheduleDrain();
    }

    private handleDecoderFailure(decoder: VideoDecoder, generation: number): void {
        if (this.stopped || generation !== this.generation || decoder !== this.decoder) return;
        this.callbacks.onError();
        this.bufferStalls += 1;
        this.totalPlaybackRecoveries += 1;
        this.resetDecoder();
        this.waitingForKeyFrame = true;
        this.requireKeyFrame(true);
        this.reportState(performance.now(), true);
    }

    private reportState(now: number, force = false): void {
        if (!force && now - this.lastStateReportAt < DECODER_STATE_REPORT_INTERVAL_MS) return;
        this.lastStateReportAt = now;
        const bufferedFrames = this.queue.length + this.pendingDecode.size;
        const frameAgeMs = this.latestMetadata
            ? this.callbacks.getFrameAgeMs(this.latestMetadata)
            : null;
        this.callbacks.onState({
            bufferedSeconds: Math.round(bufferedFrames / TARGET_FPS * 10) / 10,
            playbackLagMs: frameAgeMs === null ? 0 : Math.max(0, Math.round(frameAgeMs)),
            playbackRate: 1,
            playbackRecoveries: this.totalPlaybackRecoveries,
            pipelineResets: this.pipelineResets,
            bufferStalls: this.bufferStalls,
        });
    }
}
