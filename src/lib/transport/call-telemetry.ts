import {
  CALL_TELEMETRY_PROBE_INTERVAL_MS,
  CALL_TELEMETRY_PROBE_TIMEOUT_MS,
  CALL_TELEMETRY_PROBE_ID_BYTES,
  CALL_TELEMETRY_CAMERA_STATE,
  CALL_TELEMETRY_KEY_FRAME_REQUEST,
  CALL_TELEMETRY_PROBE_RESPONSE_BYTES,
  CALL_TELEMETRY_PROBE_REQUEST_BYTES,
  CALL_TELEMETRY_PROBE_RESPONSE,
  CALL_TELEMETRY_PROBE_REQUEST,
  CALL_KEY_FRAME_REQUEST_COOLDOWN_MS,
  CALL_TELEMETRY_MAX_CLOCK_OFFSET_MS,
} from '../constants';
import { PostQuantumRandom } from '../cryptography/random';
import type { CallState } from '../types/calling-types';
import type { SecureConnection, SecureStream } from './secure-transport';

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

type CameraState = {
    type: 'camera-state';
    enabled: boolean;
};

export type CallTelemetryProbe = ProbeRequest | ProbeResponse | KeyFrameRequest | CameraState;

type PendingProbe = {
    id: string;
    sentAt: number;
    startedAt: number;
    timeoutId: ReturnType<typeof setTimeout>;
};

function idBytesToHex(bytes: Uint8Array): string {
    let value = '';
    for (const byte of bytes) value += byte.toString(16).padStart(2, '0');
    return value;
}

function writeProbeId(target: Uint8Array, id: string): void {
    if (!/^[a-f0-9]{16}$/.test(id)) throw new Error('Invalid call telemetry probe ID');
    for (let index = 0; index < CALL_TELEMETRY_PROBE_ID_BYTES; index += 1) {
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
    if (probe.type === 'camera-state') {
        if (typeof probe.enabled !== 'boolean') throw new Error('Invalid call camera state');
        return Uint8Array.of(CALL_TELEMETRY_CAMERA_STATE, probe.enabled ? 1 : 0);
    }
    if (probe.type === 'key-frame-request') {
        return Uint8Array.of(CALL_TELEMETRY_KEY_FRAME_REQUEST, probe.kind === 'video' ? 1 : 2);
    }
    const response = probe.type === 'response';
    const frame = new Uint8Array(response ? CALL_TELEMETRY_PROBE_RESPONSE_BYTES : CALL_TELEMETRY_PROBE_REQUEST_BYTES);
    const view = new DataView(frame.buffer);
    frame[0] = response ? CALL_TELEMETRY_PROBE_RESPONSE : CALL_TELEMETRY_PROBE_REQUEST;
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
    if (frame[0] === CALL_TELEMETRY_CAMERA_STATE) {
        if (frame.byteLength !== 2 || (frame[1] !== 0 && frame[1] !== 1)) {
            throw new Error('Invalid call camera state');
        }
        return { type: 'camera-state', enabled: frame[1] === 1 };
    }
    if (frame[0] === CALL_TELEMETRY_KEY_FRAME_REQUEST) {
        if (frame.byteLength !== 2 || (frame[1] !== 1 && frame[1] !== 2)) {
            throw new Error('Invalid call telemetry key-frame request');
        }
        return { type: 'key-frame-request', kind: frame[1] === 1 ? 'video' : 'screen' };
    }
    const response = frame[0] === CALL_TELEMETRY_PROBE_RESPONSE;
    if (
        (frame[0] !== CALL_TELEMETRY_PROBE_REQUEST && !response) ||
        frame.byteLength !== (response ? CALL_TELEMETRY_PROBE_RESPONSE_BYTES : CALL_TELEMETRY_PROBE_REQUEST_BYTES)
    ) {
        throw new Error('Invalid call telemetry probe');
    }
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const id = idBytesToHex(frame.subarray(1, 1 + CALL_TELEMETRY_PROBE_ID_BYTES));
    const sentAt = readTimestamp(view, 9);
    if (!response) return { type: 'request', id, sentAt };
    const receivedAt = readTimestamp(view, 17);
    const repliedAt = readTimestamp(view, 25);
    if (repliedAt < receivedAt) throw new Error('Invalid call telemetry response timing');
    return { type: 'response', id, sentAt, receivedAt, repliedAt };
}

export class CallTelemetry {
    private readonly lastKeyFrameRequestAt = new Map<'video' | 'screen', number>();
    private latestRttMs: number | null = null;
    private remoteClockOffsetMs: number | null = null;
    private pendingProbe: PendingProbe | null = null;
    private probeTimer: ReturnType<typeof setInterval> | null = null;
    private started = false;
    private stopped = false;

    constructor(
        private readonly callType: CallState['type'],
        private readonly connection: SecureConnection,
        private readonly stream: SecureStream,
        private readonly onKeyFrameRequest: (kind: 'video' | 'screen') => void,
        private readonly onCameraState: (enabled: boolean) => void,
        private readonly isCameraEnabled: () => boolean
    ) {
        void this.receiveLoop();
    }

    start(): void {
        if (this.started || this.stopped) return;
        this.started = true;
        void this.sendProbe();
        void this.sendCameraState();
        this.probeTimer = setInterval(() => {
            void this.sendProbe();
            void this.sendCameraState();
        }, CALL_TELEMETRY_PROBE_INTERVAL_MS);
    }

    stop(): void {
        if (this.stopped) return;
        this.stopped = true;
        if (this.probeTimer) clearInterval(this.probeTimer);
        this.probeTimer = null;
        this.clearPendingProbe();
    }

    async sendCameraState(): Promise<void> {
        if (this.stopped || this.stream.closed || this.callType !== 'video') return;
        const frame = encodeCallTelemetryProbe({ type: 'camera-state', enabled: this.isCameraEnabled() });
        try {
            await this.stream.write(frame);
        } catch { } finally {
            frame.fill(0);
        }
    }

    requestKeyFrame(kind: 'video' | 'screen'): void {
        if (!this.stream.writable || this.stopped) return;
        const now = performance.now();
        const previous = this.lastKeyFrameRequestAt.get(kind);
        if (previous !== undefined && now - previous < CALL_KEY_FRAME_REQUEST_COOLDOWN_MS) return;
        this.lastKeyFrameRequestAt.set(kind, now);
        const frame = encodeCallTelemetryProbe({ type: 'key-frame-request', kind });
        void this.stream.write(frame).catch(() => { }).finally(() => frame.fill(0));
    }

    private async receiveLoop(): Promise<void> {
        try {
            for await (const frame of this.stream) {
                try {
                    if (this.stopped) break;
                    const probe = decodeCallTelemetryProbe(frame);
                    if (probe.type === 'camera-state') {
                        if (this.callType !== 'video') throw new Error('Camera state on an audio call');
                        this.onCameraState(probe.enabled);
                    } else if (probe.type === 'key-frame-request') {
                        this.onKeyFrameRequest(probe.kind);
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
                } finally {
                    frame.fill(0);
                }
            }
        } catch { }
    }

    private async sendProbe(): Promise<void> {
        if (!this.started || this.stopped || this.stream.closed) return;
        if (this.pendingProbe) return;

        const randomId = PostQuantumRandom.randomBytes(CALL_TELEMETRY_PROBE_ID_BYTES);
        const id = idBytesToHex(randomId);
        randomId.fill(0);
        const sentAt = Date.now();
        const request = encodeCallTelemetryProbe({ type: 'request', id, sentAt });
        const timeoutId = setTimeout(() => {
            if (this.pendingProbe?.id !== id) return;
            this.clearPendingProbe();
        }, CALL_TELEMETRY_PROBE_TIMEOUT_MS);
        this.pendingProbe = { id, sentAt, startedAt: performance.now(), timeoutId };

        try {
            await this.stream.write(request);
        } catch {
            if (this.pendingProbe?.id === id) this.clearPendingProbe();
        } finally {
            request.fill(0);
        }
    }

    private acceptProbeResponse(response: ProbeResponse): void {
        const pending = this.pendingProbe;
        if (!pending || response.id !== pending.id || response.sentAt !== pending.sentAt) return;
        const elapsed = Math.max(0, performance.now() - pending.startedAt);
        const remoteProcessing = Math.max(0, response.repliedAt - response.receivedAt);
        if (remoteProcessing > elapsed + 1_000) {
            this.clearPendingProbe();
            return;
        }
        const rttMs = Math.max(0, elapsed - Math.min(elapsed, remoteProcessing));
        const responseArrivedAt = Date.now();
        const clockOffsetMs = (
            (response.receivedAt - response.sentAt) +
            (response.repliedAt - responseArrivedAt)
        ) / 2;
        if (Number.isFinite(clockOffsetMs) && Math.abs(clockOffsetMs) <= CALL_TELEMETRY_MAX_CLOCK_OFFSET_MS) {
            this.remoteClockOffsetMs = this.remoteClockOffsetMs === null
                ? clockOffsetMs
                : (this.remoteClockOffsetMs * 7 + clockOffsetMs) / 8;
        }
        this.latestRttMs = rttMs;
        this.connection.updatePrimaryPathRtt(rttMs);
        this.clearPendingProbe();
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

    private clearPendingProbe(): void {
        if (!this.pendingProbe) return;
        clearTimeout(this.pendingProbe.timeoutId);
        this.pendingProbe = null;
    }
}
