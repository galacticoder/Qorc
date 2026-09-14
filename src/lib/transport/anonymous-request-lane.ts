export class AnonymousRequestLane {
  private active = 0;
  private waiters: Array<{
    grant: () => void;
  }> = [];

  constructor(
    private readonly maxActive: number,
    private readonly maxQueued: number,
    private readonly queueTimeoutMs: number,
  ) {}

  async acquire(signal?: AbortSignal): Promise<() => void> {
    signal?.throwIfAborted();
    if (this.active < this.maxActive) {
      this.active += 1;
    } else {
      if (this.waiters.length >= this.maxQueued) throw new Error('Anonymous transport queue is full');
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const finish = (error?: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          const index = this.waiters.indexOf(waiter);
          if (index >= 0) this.waiters.splice(index, 1);
          if (error) reject(error);
          else resolve();
        };
        const waiter = { grant: () => finish() };
        const abort = () => finish(new DOMException('Anonymous request cancelled', 'AbortError'));
        const timer = setTimeout(() => finish(new Error('Anonymous transport queue timed out')), this.queueTimeoutMs);
        this.waiters.push(waiter);
        signal?.addEventListener('abort', abort, { once: true });
      });
    }
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      const waiter = this.waiters.shift();
      if (waiter) waiter.grant();
      else this.active -= 1;
    };
    if (signal?.aborted) {
      release();
      signal.throwIfAborted();
    }
    return release;
  }
}

export async function runAnonymousRequestBatch<T>(
  operations: Array<(signal: AbortSignal) => Promise<T>>,
  signal?: AbortSignal,
): Promise<T[]> {
  signal?.throwIfAborted();
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  const requests = operations.map((operation) => Promise.resolve().then(() => {
    controller.signal.throwIfAborted();
    return operation(controller.signal);
  }));
  try {
    return await Promise.all(requests);
  } catch (error) {
    controller.abort();
    await Promise.allSettled(requests);
    throw error;
  } finally {
    signal?.removeEventListener('abort', abort);
  }
}
