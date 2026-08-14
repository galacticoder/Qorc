export function createAbortableAdmissionGate({
  maxConcurrent,
  maxQueued,
  queueTimeoutMs,
  abortedError,
  fullError,
  timeoutError
}) {
  let active = 0;
  const waiters = [];

  const createRelease = () => {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      active = Math.max(0, active - 1);
      while (waiters.length > 0) {
        const waiter = waiters.shift();
        if (!waiter || waiter.settled) continue;
        waiter.settled = true;
        clearTimeout(waiter.timer);
        waiter.signal?.removeEventListener('abort', waiter.onAbort);
        if (waiter.signal?.aborted) {
          waiter.reject(abortedError());
          continue;
        }
        active += 1;
        waiter.resolve(createRelease());
        break;
      }
    };
  };

  const acquire = (signal) => {
    if (signal?.aborted) return Promise.reject(abortedError());
    if (active < maxConcurrent) {
      active += 1;
      return Promise.resolve(createRelease());
    }
    if (waiters.length >= maxQueued) return Promise.reject(fullError());
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, signal, settled: false, timer: null, onAbort: null };
      const removeWaiter = () => {
        const index = waiters.indexOf(waiter);
        if (index >= 0) waiters.splice(index, 1);
      };
      waiter.onAbort = () => {
        if (waiter.settled) return;
        waiter.settled = true;
        clearTimeout(waiter.timer);
        removeWaiter();
        reject(abortedError());
      };
      waiter.timer = setTimeout(() => {
        if (waiter.settled) return;
        waiter.settled = true;
        signal?.removeEventListener('abort', waiter.onAbort);
        removeWaiter();
        reject(timeoutError());
      }, queueTimeoutMs);
      waiters.push(waiter);
      signal?.addEventListener('abort', waiter.onAbort, { once: true });
      if (signal?.aborted) waiter.onAbort();
    });
  };

  return Object.freeze({ acquire });
}
