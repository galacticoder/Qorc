import { PostQuantumRandom } from '../cryptography/random';
import type { CallState } from '../types/calling-types';
import type { SecureConnection, SecureStream } from './secure-transport';
import type { VisualAdaptationState, VisualDecoderState } from './call-video-codec';

export type CallTelemetryMediaKind = 'audio' | 'video' | 'screen';

const PROBE_REQUEST = 1;
const PROBE_RESPONSE = 2;
const KEY_FRAME_REQUEST = 3;
const PROBE_ID_BYTES = 8;
const PROBE_REQUEST_BYTES = 17;
const PROBE_RESPONSE_BYTES = 33;
const PROBE_INTERVAL_MS = 2_000;
const PROBE_TIMEOUT_MS = 8_000;
const LOG_INTERVAL_MS = 5_000;

type ProbeRequest = {
    type: 'request';
    id: string;
    sentAt: number;
};

type ProbeResponse = {
    type: 'response';
    id: string;
    sentAt: number;
    receivedAt: number;
    repliedAt: number;
};

type KeyFrameRequest = {
    type: 'key-frame-request';
    kind: 'video' | 'screen';
};

export type CallTelemetryProbe = ProbeRequest | ProbeResponse | KeyFrameRequest;

type SampleSummary = {
    latest: number | null;
    average: number | null;
    p95: number | null;
    maximum: number | null;
};

type MediaInterval = {
    txFrames: number;
    txBytes: number;
    rxFrames: number;
    rxBytes: number;
    admittedFrames: number;
    decodedFrames: number;
    renderedFrames: number;
    discontinuities: number;
    keyFrameRequests: number;
    keyFrameRequestsReceived: number;
    captureDrops: number;
    sendErrors: number;
    receiveErrors: number;
    renderDrops: number;
    writeMs: number[];
    encodeMs: number[];
    sendAgeMs: number[];
    renderAgeMs: number[];
    decodeMs: number[];
    arrivalGapMs: number[];
    arrivalJitterMs: number[];
};

type MediaTotals = {
    txFrames: number;
    txBytes: number;
    rxFrames: number;
    rxBytes: number;
    admittedFrames: number;
    decodedFrames: number;
    renderedFrames: number;
    discontinuities: number;
    keyFrameRequests: number;
    keyFrameRequestsReceived: number;
    captureDrops: number;
    sendErrors: number;
    receiveErrors: number;
    renderDrops: number;
};

type PendingProbe = {
    id: string;
    sentAt: number;
    startedAt: number;
    timeoutId: ReturnType<typeof setTimeout>;
};

const mediaKinds: CallTelemetryMediaKind[] = ['audio', 'video', 'screen'];

function monotonicNow(): number {
    return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

function round(value: number): number {
    return Math.round(value * 10) / 10;
}

function summarize(samples: number[]): SampleSummary {
    if (samples.length === 0) {
        return { latest: null, average: null, p95: null, maximum: null };
    }
    const sorted = samples.slice().sort((left, right) => left - right);
    const sum = samples.reduce((total, sample) => total + sample, 0);
    const p95Index = Math.max(0, Math.ceil(sorted.length * 0.95) - 1);
    return {
        latest: round(samples[samples.length - 1]),
        average: round(sum / samples.length),
        p95: round(sorted[p95Index]),
        maximum: round(sorted[sorted.length - 1])
    };
}

function createMediaInterval(): MediaInterval {
    return {
        txFrames: 0,
        txBytes: 0,
        rxFrames: 0,
        rxBytes: 0,
        admittedFrames: 0,
        decodedFrames: 0,
        renderedFrames: 0,
        discontinuities: 0,
        keyFrameRequests: 0,
        keyFrameRequestsReceived: 0,
        captureDrops: 0,
        sendErrors: 0,
        receiveErrors: 0,
        renderDrops: 0,
        writeMs: [],
        encodeMs: [],
        sendAgeMs: [],
        renderAgeMs: [],
        decodeMs: [],
        arrivalGapMs: [],
        arrivalJitterMs: []
    };
}

function createMediaTotals(): MediaTotals {
    return {
        txFrames: 0,
        txBytes: 0,
        rxFrames: 0,
        rxBytes: 0,
        admittedFrames: 0,
        decodedFrames: 0,
        renderedFrames: 0,
        discontinuities: 0,
        keyFrameRequests: 0,
        keyFrameRequestsReceived: 0,
        captureDrops: 0,
        sendErrors: 0,
        receiveErrors: 0,
        renderDrops: 0
    };
}

function idBytesToHex(bytes: Uint8Array): string {
    let value = '';
    for (const byte of bytes) value += byte.toString(16).padStart(2, '0');
    return value;
}

function writeProbeId(target: Uint8Array, id: string): void {
    if (!/^[a-f0-9]{16}$/.test(id)) throw new Error('Invalid call telemetry probe ID');
    for (let index = 0; index < PROBE_ID_BYTES; index += 1) {
        target[1 + index] = Number.parseInt(id.slice(index * 2, index * 2 + 2), 16);
    }
}

function readTimestamp(view: DataView, offset: number): number {
    const value = Number(view.getBigUint64(offset, false));
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error('Invalid call telemetry timestamp');
    }
    return value;
}

function writeTimestamp(view: DataView, offset: number, value: number): void {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error('Invalid call telemetry timestamp');
    }
    view.setBigUint64(offset, BigInt(value), false);
}

export function encodeCallTelemetryProbe(probe: CallTelemetryProbe): Uint8Array {
    if (probe.type === 'key-frame-request') {
        return Uint8Array.of(KEY_FRAME_REQUEST, probe.kind === 'video' ? 1 : 2);
    }
    const response = probe.type === 'response';
    const frame = new Uint8Array(response ? PROBE_RESPONSE_BYTES : PROBE_REQUEST_BYTES);
    const view = new DataView(frame.buffer);
    frame[0] = response ? PROBE_RESPONSE : PROBE_REQUEST;
    writeProbeId(frame, probe.id);
    writeTimestamp(view, 9, probe.sentAt);
    if (response) {
        if (probe.repliedAt < probe.receivedAt) {
            throw new Error('Invalid call telemetry response timing');
        }
        writeTimestamp(view, 17, probe.receivedAt);
        writeTimestamp(view, 25, probe.repliedAt);
    }
    return frame;
}

export function decodeCallTelemetryProbe(frame: Uint8Array): CallTelemetryProbe {
    if (!(frame instanceof Uint8Array)) throw new Error('Invalid call telemetry probe');
    if (frame[0] === KEY_FRAME_REQUEST) {
        if (frame.byteLength !== 2 || (frame[1] !== 1 && frame[1] !== 2)) {
            throw new Error('Invalid call telemetry key-frame request');
        }
        return { type: 'key-frame-request', kind: frame[1] === 1 ? 'video' : 'screen' };
    }
    const response = frame[0] === PROBE_RESPONSE;
    if (
        (frame[0] !== PROBE_REQUEST && !response) ||
        frame.byteLength !== (response ? PROBE_RESPONSE_BYTES : PROBE_REQUEST_BYTES)
    ) {
        throw new Error('Invalid call telemetry probe');
    }
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const id = idBytesToHex(frame.subarray(1, 1 + PROBE_ID_BYTES));
    const sentAt = readTimestamp(view, 9);
    if (!response) return { type: 'request', id, sentAt };
    const receivedAt = readTimestamp(view, 17);
    const repliedAt = readTimestamp(view, 25);
    if (repliedAt < receivedAt) throw new Error('Invalid call telemetry response timing');
    return { type: 'response', id, sentAt, receivedAt, repliedAt };
}

export class CallTelemetry {
    private readonly startedAt = monotonicNow();
    private intervalStartedAt = this.startedAt;
    private readonly interval = new Map<CallTelemetryMediaKind, MediaInterval>();
    private readonly totals = new Map<CallTelemetryMediaKind, MediaTotals>();
    private readonly lastArrivalAt = new Map<CallTelemetryMediaKind, number>();
    private readonly lastCaptureAt = new Map<CallTelemetryMediaKind, number>();
    private readonly lastArrivalGap = new Map<CallTelemetryMediaKind, number>();
    private readonly arrivalJitter = new Map<CallTelemetryMediaKind, number>();
    private readonly visualState = new Map<'video' | 'screen', VisualAdaptationState>();
    private readonly visualDecoderState = new Map<'video' | 'screen', VisualDecoderState>();
    private readonly lastKeyFrameRequestAt = new Map<'video' | 'screen', number>();
    private readonly rttSamples: number[] = [];
    private latestRttMs: number | null = null;
    private remoteClockOffsetMs: number | null = null;
    private lifetimeRttMinMs: number | null = null;
    private lifetimeRttMaxMs: number | null = null;
    private probeFailures = 0;
    private totalProbeFailures = 0;
    private protocolErrors = 0;
    private pendingProbe: PendingProbe | null = null;
    private probeTimer: ReturnType<typeof setInterval> | null = null;
    private logTimer: ReturnType<typeof setInterval> | null = null;
    private reporting = false;
    private stopped = false;

    constructor(
        private readonly callId: string,
        private readonly direction: CallState['direction'],
        private readonly callType: CallState['type'],
        private readonly connection: SecureConnection,
        private readonly stream: SecureStream | null,
        private readonly onKeyFrameRequest?: (kind: 'video' | 'screen') => void
    ) {
        for (const kind of mediaKinds) {
            this.interval.set(kind, createMediaInterval());
            this.totals.set(kind, createMediaTotals());
        }
        if (stream) void this.receiveLoop();
    }

    start(): void {
        if (this.reporting || this.stopped) return;
        this.reporting = true;
        void this.sendProbe();
        if (this.stream) {
            this.probeTimer = setInterval(() => { void this.sendProbe(); }, PROBE_INTERVAL_MS);
        }
        this.logTimer = setInterval(() => this.emit(false), LOG_INTERVAL_MS);
    }

    stop(): void {
        if (this.stopped) return;
        this.stopped = true;
        if (this.probeTimer) clearInterval(this.probeTimer);
        if (this.logTimer) clearInterval(this.logTimer);
        this.probeTimer = null;
        this.logTimer = null;
        this.clearPendingProbe(false);
        if (this.reporting) this.emit(true);
    }

    noteSend(kind: CallTelemetryMediaKind, bytes: number, writeMs: number): void {
        const interval = this.interval.get(kind)!;
        const totals = this.totals.get(kind)!;
        interval.txFrames += 1;
        interval.txBytes += Math.max(0, bytes);
        totals.txFrames += 1;
        totals.txBytes += Math.max(0, bytes);
        if (Number.isFinite(writeMs) && writeMs >= 0) interval.writeMs.push(writeMs);
    }

    noteCaptureDrop(kind: CallTelemetryMediaKind): void {
        this.interval.get(kind)!.captureDrops += 1;
        this.totals.get(kind)!.captureDrops += 1;
    }

    noteEncode(kind: 'video' | 'screen', encodeMs: number): void {
        if (Number.isFinite(encodeMs) && encodeMs >= 0) {
            this.interval.get(kind)!.encodeMs.push(encodeMs);
        }
    }

    noteFrameSent(kind: 'video' | 'screen', capturedAt: number): void {
        const age = Date.now() - capturedAt;
        if (Number.isFinite(age) && age >= 0 && age <= 300_000) {
            this.interval.get(kind)!.sendAgeMs.push(age);
        }
    }

    noteFrameRendered(kind: 'video' | 'screen', capturedAt: number): void {
        this.interval.get(kind)!.renderedFrames += 1;
        this.totals.get(kind)!.renderedFrames += 1;
        const age = Date.now() - capturedAt + (this.remoteClockOffsetMs ?? 0);
        if (Number.isFinite(age) && age >= 0 && age <= 300_000) {
            this.interval.get(kind)!.renderAgeMs.push(age);
        }
    }

    noteVisualState(kind: 'video' | 'screen', state: VisualAdaptationState): void {
        this.visualState.set(kind, { ...state });
    }

    noteVisualDecoderState(kind: 'video' | 'screen', state: VisualDecoderState): void {
        this.visualDecoderState.set(kind, { ...state });
    }

    noteSendError(kind: CallTelemetryMediaKind): void {
        this.interval.get(kind)!.sendErrors += 1;
        this.totals.get(kind)!.sendErrors += 1;
    }

    noteReceive(kind: CallTelemetryMediaKind, bytes: number, capturedAt?: number): void {
        const interval = this.interval.get(kind)!;
        const totals = this.totals.get(kind)!;
        interval.rxFrames += 1;
        interval.rxBytes += Math.max(0, bytes);
        totals.rxFrames += 1;
        totals.rxBytes += Math.max(0, bytes);

        const now = monotonicNow();
        const previousArrival = this.lastArrivalAt.get(kind);
        if (previousArrival !== undefined) {
            const gap = Math.max(0, now - previousArrival);
            interval.arrivalGapMs.push(gap);
            const previousGap = this.lastArrivalGap.get(kind);
            const previousCapture = this.lastCaptureAt.get(kind);
            const hasCaptureTimestamp = typeof capturedAt === 'number' && Number.isFinite(capturedAt);
            const captureGap = hasCaptureTimestamp && previousCapture !== undefined
                ? Math.max(0, capturedAt - previousCapture)
                : undefined;
            if (captureGap !== undefined || previousGap !== undefined) {
                const variation = Math.abs(gap - (captureGap ?? previousGap!));
                const currentJitter = this.arrivalJitter.get(kind) ?? 0;
                const nextJitter = currentJitter + (variation - currentJitter) / 16;
                this.arrivalJitter.set(kind, nextJitter);
                interval.arrivalJitterMs.push(nextJitter);
            }
            this.lastArrivalGap.set(kind, gap);
        }
        this.lastArrivalAt.set(kind, now);
        if (typeof capturedAt === 'number' && Number.isFinite(capturedAt)) {
            this.lastCaptureAt.set(kind, capturedAt);
        }
    }

    noteDecode(kind: CallTelemetryMediaKind, decodeMs: number): void {
        if (Number.isFinite(decodeMs) && decodeMs >= 0) {
            this.interval.get(kind)!.decodeMs.push(decodeMs);
        }
    }

    noteDecoderAdmitted(kind: 'video' | 'screen'): void {
        this.interval.get(kind)!.admittedFrames += 1;
        this.totals.get(kind)!.admittedFrames += 1;
    }

    noteDecoded(kind: 'video' | 'screen'): void {
        this.interval.get(kind)!.decodedFrames += 1;
        this.totals.get(kind)!.decodedFrames += 1;
    }

    noteDiscontinuity(kind: 'video' | 'screen'): void {
        this.interval.get(kind)!.discontinuities += 1;
        this.totals.get(kind)!.discontinuities += 1;
    }

    requestKeyFrame(kind: 'video' | 'screen'): void {
        this.noteDiscontinuity(kind);
        if (!this.stream || !this.stream.writable || this.stopped) return;
        const now = monotonicNow();
        const previous = this.lastKeyFrameRequestAt.get(kind);
        if (previous !== undefined && now - previous < 2_000) return;
        this.lastKeyFrameRequestAt.set(kind, now);
        this.interval.get(kind)!.keyFrameRequests += 1;
        this.totals.get(kind)!.keyFrameRequests += 1;
        const frame = encodeCallTelemetryProbe({ type: 'key-frame-request', kind });
        void this.stream.write(frame).catch(() => { }).finally(() => frame.fill(0));
    }

    noteReceiveError(kind: CallTelemetryMediaKind): void {
        this.interval.get(kind)!.receiveErrors += 1;
        this.totals.get(kind)!.receiveErrors += 1;
    }

    noteRenderDrop(kind: CallTelemetryMediaKind): void {
        this.interval.get(kind)!.renderDrops += 1;
        this.totals.get(kind)!.renderDrops += 1;
    }

    snapshot(final = false): Record<string, unknown> {
        const now = monotonicNow();
        const windowMs = Math.max(1, now - this.intervalStartedAt);
        const windowSeconds = windowMs / 1_000;
        const media: Record<string, unknown> = {};

        for (const kind of mediaKinds) {
            const current = this.interval.get(kind)!;
            const total = this.totals.get(kind)!;
            media[kind] = {
                txFps: round(current.txFrames / windowSeconds),
                txKbps: round((current.txBytes * 8) / 1_000 / windowSeconds),
                rxFps: round(current.rxFrames / windowSeconds),
                rxKbps: round((current.rxBytes * 8) / 1_000 / windowSeconds),
                admittedFps: round(current.admittedFrames / windowSeconds),
                decodedFps: round(current.decodedFrames / windowSeconds),
                renderedFps: round(current.renderedFrames / windowSeconds),
                writeMs: summarize(current.writeMs),
                encodeMs: summarize(current.encodeMs),
                sendAgeMs: summarize(current.sendAgeMs),
                renderAgeMs: summarize(current.renderAgeMs),
                decodeMs: summarize(current.decodeMs),
                arrivalGapMs: summarize(current.arrivalGapMs),
                arrivalJitterMs: summarize(current.arrivalJitterMs),
                captureDrops: current.captureDrops,
                sendErrors: current.sendErrors,
                receiveErrors: current.receiveErrors,
                renderDrops: current.renderDrops,
                discontinuities: current.discontinuities,
                keyFrameRequests: current.keyFrameRequests,
                keyFrameRequestsReceived: current.keyFrameRequestsReceived,
                visualState: kind === 'audio'
                    ? null
                    : this.visualState.get(kind) ?? null,
                decoderState: kind === 'audio'
                    ? null
                    : this.visualDecoderState.get(kind) ?? null,
                totals: { ...total }
            };
        }

        const rtt = summarize(this.rttSamples);
        const estimatedOneWayMs = this.latestRttMs === null ? null : round(this.latestRttMs / 2);
        const result = {
            phase: final ? 'final' : 'sample',
            callId: this.callId.slice(0, 12),
            direction: this.direction,
            callType: this.callType,
            elapsedMs: Math.round(now - this.startedAt),
            sampleWindowMs: Math.round(windowMs),
            transport: {
                state: this.connection.state,
                telemetryStreamAvailable: Boolean(this.stream),
                rttMs: {
                    ...rtt,
                    latest: this.latestRttMs === null ? null : round(this.latestRttMs),
                    lifetimeMinimum: this.lifetimeRttMinMs === null ? null : round(this.lifetimeRttMinMs),
                    lifetimeMaximum: this.lifetimeRttMaxMs === null ? null : round(this.lifetimeRttMaxMs)
                },
                estimatedOneWayMs,
                remoteClockOffsetMs: this.remoteClockOffsetMs === null
                    ? null
                    : round(this.remoteClockOffsetMs),
                probeFailures: this.probeFailures,
                totalProbeFailures: this.totalProbeFailures,
                telemetryProtocolErrors: this.protocolErrors,
                audioLanes: this.connection.getAudioLaneTelemetry?.() ?? null,
                connectionAgeMs: this.connection.connectedAt === null
                    ? null
                    : Math.max(0, Date.now() - this.connection.connectedAt),
                lastActivityAgoMs: this.connection.lastActivity > 0
                    ? Math.max(0, Date.now() - this.connection.lastActivity)
                    : null
            },
            media
        };

        this.resetInterval(now);
        return result;
    }

    private emit(final: boolean): void {
        console.log(`[CALL-TELEMETRY] ${JSON.stringify(this.snapshot(final))}`);
    }

    private resetInterval(now: number): void {
        this.intervalStartedAt = now;
        for (const kind of mediaKinds) this.interval.set(kind, createMediaInterval());
        this.rttSamples.length = 0;
        this.probeFailures = 0;
    }

    private async receiveLoop(): Promise<void> {
        if (!this.stream) return;
        try {
            for await (const frame of this.stream) {
                try {
                    if (this.stopped) break;
                    const probe = decodeCallTelemetryProbe(frame);
                    if (probe.type === 'key-frame-request') {
                        this.interval.get(probe.kind)!.keyFrameRequestsReceived += 1;
                        this.totals.get(probe.kind)!.keyFrameRequestsReceived += 1;
                        this.onKeyFrameRequest?.(probe.kind);
                    } else if (probe.type === 'request') {
                        const receivedAt = Date.now();
                        const response = encodeCallTelemetryProbe({
                            type: 'response',
                            id: probe.id,
                            sentAt: probe.sentAt,
                            receivedAt,
                            repliedAt: Date.now()
                        });
                        try {
                            await this.stream.write(response);
                        } finally {
                            response.fill(0);
                        }
                    } else {
                        this.acceptProbeResponse(probe);
                    }
                } catch {
                    this.protocolErrors += 1;
                } finally {
                    frame.fill(0);
                }
            }
        } catch {
            if (!this.stopped) this.noteProbeFailure();
        }
    }

    private async sendProbe(): Promise<void> {
        if (!this.reporting || this.stopped || !this.stream || this.stream.closed) return;
        if (this.pendingProbe) return;

        const randomId = PostQuantumRandom.randomBytes(PROBE_ID_BYTES);
        const id = idBytesToHex(randomId);
        randomId.fill(0);
        const sentAt = Date.now();
        const request = encodeCallTelemetryProbe({ type: 'request', id, sentAt });
        const timeoutId = setTimeout(() => {
            if (this.pendingProbe?.id !== id) return;
            this.clearPendingProbe(true);
        }, PROBE_TIMEOUT_MS);
        this.pendingProbe = { id, sentAt, startedAt: monotonicNow(), timeoutId };

        try {
            await this.stream.write(request);
        } catch {
            if (this.pendingProbe?.id === id) this.clearPendingProbe(true);
        } finally {
            request.fill(0);
        }
    }

    private acceptProbeResponse(response: ProbeResponse): void {
        const pending = this.pendingProbe;
        if (!pending || response.id !== pending.id || response.sentAt !== pending.sentAt) return;
        const elapsed = Math.max(0, monotonicNow() - pending.startedAt);
        const remoteProcessing = Math.max(0, response.repliedAt - response.receivedAt);
        if (remoteProcessing > elapsed + 1_000) {
            this.clearPendingProbe(true);
            return;
        }
        const rttMs = Math.max(0, elapsed - Math.min(elapsed, remoteProcessing));
        const responseArrivedAt = Date.now();
        const clockOffsetMs = (
            (response.receivedAt - response.sentAt) +
            (response.repliedAt - responseArrivedAt)
        ) / 2;
        if (Number.isFinite(clockOffsetMs) && Math.abs(clockOffsetMs) <= 300_000) {
            this.remoteClockOffsetMs = this.remoteClockOffsetMs === null
                ? clockOffsetMs
                : (this.remoteClockOffsetMs * 7 + clockOffsetMs) / 8;
        }
        this.latestRttMs = rttMs;
        this.connection.updatePrimaryPathRtt(rttMs);
        this.lifetimeRttMinMs = this.lifetimeRttMinMs === null
            ? rttMs
            : Math.min(this.lifetimeRttMinMs, rttMs);
        this.lifetimeRttMaxMs = this.lifetimeRttMaxMs === null
            ? rttMs
            : Math.max(this.lifetimeRttMaxMs, rttMs);
        this.rttSamples.push(rttMs);
        this.clearPendingProbe(false);
    }

    getLatestRttMs(): number | null {
        return this.latestRttMs;
    }

    getRemoteFrameAgeMs(capturedAt: number): number | null {
        if (
            this.remoteClockOffsetMs === null ||
            !Number.isSafeInteger(capturedAt) ||
            capturedAt <= 0
        ) return null;
        const age = Date.now() - capturedAt + this.remoteClockOffsetMs;
        return Number.isFinite(age) ? Math.max(0, age) : null;
    }

    private clearPendingProbe(failed: boolean): void {
        if (!this.pendingProbe) return;
        clearTimeout(this.pendingProbe.timeoutId);
        this.pendingProbe = null;
        if (failed) this.noteProbeFailure();
    }

    private noteProbeFailure(): void {
        this.probeFailures += 1;
        this.totalProbeFailures += 1;
    }
}
