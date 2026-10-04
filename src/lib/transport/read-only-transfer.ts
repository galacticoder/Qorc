import { anonymousBodyTimeoutMs } from '../../../shared/anonymous-transfer-policy.js';

const RATE_CHECK_INTERVAL_MS = 5_000;
const RATE_WINDOW_MS = 30_000;

export async function transferAnonymousRead<T>(
  responseBytes: number,
  request: (signal: AbortSignal, progress: (bytes: number) => void) => Promise<T>,
  signal: AbortSignal,
  onProgress: (bytes: number) => void,
  onRetry?: () => void,
): Promise<T> {
  const transferBudgetMs = anonymousBodyTimeoutMs(responseBytes);
  for (let attempt = 0; attempt < 3; attempt++) {
    signal.throwIfAborted();
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    let startedAt: number | undefined;
    let receivedBytes = 0;
    let lastByteAt = 0;
    const samples: Array<{ at: number; bytes: number }> = [];
    let slowTransfer: Error | undefined;
    const timer = setInterval(() => {
      if (controller.signal.aborted || startedAt === undefined || receivedBytes === responseBytes) return;
      const now = performance.now();
      const elapsed = now - startedAt;
      samples.push({ at: now, bytes: receivedBytes });
      while (samples.length > 1 && samples[1].at <= now - RATE_WINDOW_MS) samples.shift();
      if (elapsed < RATE_WINDOW_MS) return;
      const baseline = samples[0];
      let recent = baseline;
      for (const sample of samples) {
        if (sample.at <= now - 10_000) recent = sample;
      }
      const remainingMs = Math.max(1, transferBudgetMs - elapsed);
      const requiredRate = (responseBytes - receivedBytes) / remainingMs;
      const windowRate = (receivedBytes - baseline.bytes) / Math.max(1, now - baseline.at);
      const recentRate = (receivedBytes - recent.bytes) / Math.max(1, now - recent.at);
      const idle = now - lastByteAt >= RATE_WINDOW_MS;
      if (idle || (windowRate < requiredRate && recentRate < requiredRate)) {
        slowTransfer = new Error(`Anonymous download ${idle ? 'stalled' : 'too slow'}: received ${receivedBytes}/${responseBytes} bytes after ${Math.round(elapsed)} ms`);
        controller.abort();
      }
    }, RATE_CHECK_INTERVAL_MS);
    try {
      const result = await request(controller.signal, (bytes) => {
        if (!Number.isSafeInteger(bytes) || bytes < receivedBytes || bytes > responseBytes) return;
        const now = performance.now();
        if (startedAt === undefined) {
          startedAt = now;
          lastByteAt = now;
          samples.push({ at: now, bytes: 0 });
        }
        if (bytes > receivedBytes) lastByteAt = now;
        receivedBytes = bytes;
        onProgress(bytes);
      });
      signal.throwIfAborted();
      controller.signal.throwIfAborted();
      return result;
    } catch (error) {
      signal.throwIfAborted();
      const message = error instanceof Error ? error.message : String(error);
      const transferFailed = /^anonymous response (transfer deadline|read idle timeout|read failed)/.test(message);
      if (attempt === 2 || (!slowTransfer && !transferFailed)) throw slowTransfer ?? error;
      console.warn('[ANON-READ] retrying incomplete download on a new isolated request', {
        attempt: attempt + 2, responseBytes, reason: slowTransfer?.message ?? message,
      });
      onRetry?.();
    } finally {
      clearInterval(timer);
      signal.removeEventListener('abort', abort);
    }
  }
  throw new Error('Anonymous read transfer exhausted');
}
