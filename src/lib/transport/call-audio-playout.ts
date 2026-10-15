import { SecureMemory } from '../cryptography/secure-memory';

export const AUDIO_FRAME_DURATION_MS = 20;
const INITIAL_BUFFER_MS = 200;
const MIN_BUFFER_MS = 120;
const MAX_BUFFER_MS = 600;
const MAX_BUFFER_PACKETS = 60;
const MAX_CONCEALMENT_FRAMES = 3;

export interface BufferedAudioPacket {
    packet: Uint8Array;
    sequence: number;
    capturedAt: number;
    arrivedAt: number;
    discontinuity: boolean;
}

export interface AudioPlayoutFrame {
    packet: Uint8Array;
    fec: boolean;
}

export class CallAudioPlayout {
    private readonly packets = new Map<number, BufferedAudioPacket>();
    private expected: number | null = null;
    private buffering = true;
    private lastArrival: number | null = null;
    private lastCapture: number | null = null;
    private jitterMs = 0;
    private peakVariationMs = 0;
    private targetMs = INITIAL_BUFFER_MS;
    private losses = 0;
    private rebuffers = 0;
    private concealments = 0;
    private lateDrops = 0;
    private overflowDrops = 0;

    private sequences(): number[] {
        return Array.from(this.packets.keys()).sort((a, b) => (a - b) | 0);
    }

    private discard(sequence: number): void {
        const packet = this.packets.get(sequence);
        if (!packet) return;
        this.packets.delete(sequence);
        SecureMemory.zeroBuffer(packet.packet);
    }

    push(packet: BufferedAudioPacket): boolean {
        if (this.expected !== null && ((packet.sequence - this.expected) | 0) < 0) {
            SecureMemory.zeroBuffer(packet.packet);
            this.lateDrops++;
            return false;
        }
        if (this.packets.has(packet.sequence)) {
            SecureMemory.zeroBuffer(packet.packet);
            return false;
        }
        if (this.lastArrival !== null && this.lastCapture !== null) {
            const captureGap = packet.capturedAt - this.lastCapture;
            if (captureGap > 0 && captureGap < 10_000) {
                const variation = Math.abs(packet.arrivedAt - this.lastArrival - captureGap);
                this.jitterMs += (variation - this.jitterMs) / 16;
                this.peakVariationMs = Math.max(this.peakVariationMs * 0.99, Math.min(MAX_BUFFER_MS, variation));
                this.targetMs = Math.min(MAX_BUFFER_MS, Math.max(
                    MIN_BUFFER_MS,
                    AUDIO_FRAME_DURATION_MS * 3 + this.jitterMs * 4,
                    this.peakVariationMs + AUDIO_FRAME_DURATION_MS * 2,
                ));
            }
        }
        if (this.lastCapture === null || packet.capturedAt > this.lastCapture) {
            this.lastArrival = packet.arrivedAt;
            this.lastCapture = packet.capturedAt;
        }
        this.packets.set(packet.sequence, packet);
        while (this.packets.size > MAX_BUFFER_PACKETS) {
            const oldest = this.sequences()[0];
            this.discard(oldest);
            this.overflowDrops++;
            this.expected = (oldest + 1) >>> 0;
            this.buffering = true;
        }
        return true;
    }

    next(now: number): AudioPlayoutFrame | null {
        const sequences = this.sequences();
        if (sequences.length === 0) {
            if (!this.buffering) {
                this.rebuffers++;
                this.targetMs = Math.min(MAX_BUFFER_MS, this.targetMs + AUDIO_FRAME_DURATION_MS * 2);
            }
            this.buffering = true;
            return null;
        }
        const first = this.packets.get(sequences[0])!;
        if (this.buffering) {
            const bufferedMs = sequences.length * AUDIO_FRAME_DURATION_MS;
            if (bufferedMs < this.targetMs && now - first.arrivedAt < this.targetMs) return null;
            if (this.expected === null) this.expected = first.sequence;
            this.buffering = false;
        }
        let packet = this.packets.get(this.expected!);
        if (!packet && (first.discontinuity || this.losses >= MAX_CONCEALMENT_FRAMES)) {
            this.expected = first.sequence;
            packet = first;
            this.losses = 0;
        }
        if (packet) {
            this.packets.delete(packet.sequence);
            this.expected = (packet.sequence + 1) >>> 0;
            this.losses = 0;
            return { packet: packet.packet, fec: false };
        }
        if (now - first.arrivedAt < Math.min(80, this.targetMs / 2)) return null;
        const next = this.packets.get((this.expected! + 1) >>> 0);
        this.expected = (this.expected! + 1) >>> 0;
        this.losses++;
        this.concealments++;
        return {
            packet: next ? next.packet.slice() : new Uint8Array(0),
            fec: Boolean(next),
        };
    }

    snapshot() {
        return {
            targetMs: Math.round(this.targetMs),
            bufferedMs: this.packets.size * AUDIO_FRAME_DURATION_MS,
            buffering: this.buffering,
            rebufferCount: this.rebuffers,
            concealedFrames: this.concealments,
            lateDrops: this.lateDrops,
            overflowDrops: this.overflowDrops,
        };
    }

    clear(): void {
        for (const sequence of this.packets.keys()) this.discard(sequence);
    }
}
