type Phase = 'context' | 'discovery-queue' | 'bulk-queue' | 'key-exchange' |
  'admission-pow' | 'request-encryption' | 'connecting-upload-waiting-headers' |
  'body-download' | 'response-authentication' | 'response-decryption' | 'response-parse';

let nextId = 0;

export class DiscoveryTransferDiagnostics {
  readonly id = ++nextId;
  private readonly started = performance.now();
  private phaseStarted = this.started;
  private currentPhase: Phase = 'context';
  private readonly phases: Partial<Record<Phase, number>> = {};
  private bodyStarted: number | undefined;
  private bodyFinished: number | undefined;
  private firstByteMs: number | undefined;
  private lastByteAt: number | undefined;
  private receivedBytes = 0;
  private maxNoProgressMs = 0;
  private lastSampleAt = this.started;
  private lastTickAt = this.started;
  private lastSampleBytes = 0;
  private maxTimerDelayMs = 0;
  private finished = false;
  private readonly timer: ReturnType<typeof setInterval>;

  constructor(private readonly expectedBytes: number, private readonly kind: 'bucket' | 'key-transparency' = 'bucket') {
    console.info('[DISCOVERY-PERF]', JSON.stringify({ event: 'start', transfer: this.id, kind, expectedBytes }));
    this.timer = setInterval(() => this.sample(), 15_000);
  }

  phase(phase: Phase) {
    if (this.finished || phase === this.currentPhase) return;
    const now = performance.now();
    this.phases[this.currentPhase] = (this.phases[this.currentPhase] ?? 0) + now - this.phaseStarted;
    this.currentPhase = phase;
    this.phaseStarted = now;
  }

  progress(bytes: number) {
    if (this.finished || bytes < this.receivedBytes || bytes > this.expectedBytes) return;
    const now = performance.now();
    if (this.bodyStarted === undefined) {
      this.bodyStarted = now;
      this.lastByteAt = now;
      this.lastSampleAt = now;
      this.lastSampleBytes = 0;
      this.phase('body-download');
    }
    if (bytes > this.receivedBytes) {
      this.maxNoProgressMs = Math.max(this.maxNoProgressMs, now - this.lastByteAt!);
      this.firstByteMs ??= now - this.bodyStarted;
      this.lastByteAt = now;
      this.receivedBytes = bytes;
      if (bytes === this.expectedBytes) this.bodyFinished = now;
    }
  }

  private stats(now: number) {
    const bodyMs = this.bodyStarted === undefined ? 0 : (this.bodyFinished ?? now) - this.bodyStarted;
    const idleMs = this.lastByteAt === undefined || this.bodyFinished !== undefined ? 0 : now - this.lastByteAt;
    return {
      receivedBytes: this.receivedBytes,
      expectedBytes: this.expectedBytes,
      bodyMs: Math.round(bodyMs),
      averageKiBps: bodyMs > 0 ? Math.round(this.receivedBytes / bodyMs * 1000 / 1024 * 10) / 10 : null,
      firstBodyByteMs: this.firstByteMs === undefined ? null : Math.round(this.firstByteMs),
      noProgressMs: Math.round(idleMs),
      maxNoProgressMs: Math.round(Math.max(this.maxNoProgressMs, idleMs)),
    };
  }

  private sample() {
    if (this.finished) return;
    const now = performance.now();
    const interval = now - this.lastSampleAt;
    this.maxTimerDelayMs = Math.max(this.maxTimerDelayMs, now - this.lastTickAt - 15_000);
    this.lastTickAt = now;
    const delta = this.receivedBytes - this.lastSampleBytes;
    const rate = interval > 0 ? delta / interval * 1000 : 0;
    console.info('[DISCOVERY-PERF]', JSON.stringify({
      event: 'progress', transfer: this.id, phase: this.currentPhase,
      elapsedMs: Math.round(now - this.started), ...this.stats(now),
      windowKiBps: Math.round(rate / 1024 * 10) / 10,
      estimatedRemainingSeconds: this.receivedBytes === this.expectedBytes ? 0 : rate > 0
        ? Math.ceil((this.expectedBytes - this.receivedBytes) / rate) : null,
      maxTimerDelayMs: Math.round(this.maxTimerDelayMs),
    }));
    this.lastSampleAt = now;
    this.lastSampleBytes = this.receivedBytes;
  }

  finish(outcome: 'success' | 'cancelled' | 'error') {
    if (this.finished) return;
    this.finished = true;
    clearInterval(this.timer);
    const now = performance.now();
    this.maxTimerDelayMs = Math.max(this.maxTimerDelayMs, now - this.lastTickAt - 15_000);
    this.phases[this.currentPhase] = (this.phases[this.currentPhase] ?? 0) + now - this.phaseStarted;
    const phasesMs = Object.fromEntries(Object.entries(this.phases).map(([phase, ms]) => [phase, Math.round(ms)]));
    const groups = {
      queue: (this.phases['discovery-queue'] ?? 0) + (this.phases['bulk-queue'] ?? 0),
      clientPreparation: (this.phases.context ?? 0) + (this.phases['key-exchange'] ?? 0) +
        (this.phases['admission-pow'] ?? 0) + (this.phases['request-encryption'] ?? 0),
      beforeHeaders: this.phases['connecting-upload-waiting-headers'] ?? 0,
      download: this.phases['body-download'] ?? 0,
      clientVerification: (this.phases['response-authentication'] ?? 0) +
        (this.phases['response-decryption'] ?? 0) + (this.phases['response-parse'] ?? 0),
    };
    const dominantStage = Object.entries(groups).sort((a, b) => b[1] - a[1])[0][0];
    const nextCheck = {
      queue: 'Client request-lane contention; compare queue time with concurrent transfers before increasing concurrency.',
      clientPreparation: 'Client CPU/crypto/PoW; phasesMs identifies the expensive step.',
      beforeHeaders: 'Compare native Tor-ready and headers timings. Connect, TLS, upload, and server processing cannot be separated by this client trace.',
      download: 'Compare native body speed/stalls with this trace. If both are slow, inspect the Tor/server delivery path; if native is fast, inspect client event-loop/IPC delay.',
      clientVerification: 'Client response authentication/decryption/parsing; phasesMs identifies the expensive step.',
    }[dominantStage];
    console.info('[DISCOVERY-PERF]', JSON.stringify({
      event: 'summary', transfer: this.id, kind: this.kind, outcome, lastPhase: this.currentPhase,
      elapsedMs: Math.round(now - this.started), phasesMs, ...this.stats(now),
      maxTimerDelayMs: Math.round(this.maxTimerDelayMs), dominantStage, nextCheck,
    }));
  }
}
