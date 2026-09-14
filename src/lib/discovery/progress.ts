export interface DiscoveryProgress {
  phase: 'preparing' | 'downloading' | 'verifying';
  receivedBytes: number;
  totalBytes: number;
}

export type DiscoveryProgressObserver = (progress: DiscoveryProgress) => void;

export interface DiscoveryLookupOptions {
  forceRefresh?: boolean;
  monitorContact?: boolean;
  onProgress?: DiscoveryProgressObserver;
}

export class DiscoveryProgressStream {
  private latest: DiscoveryProgress = { phase: 'preparing', receivedBytes: 0, totalBytes: 0 };
  private observers = new Set<DiscoveryProgressObserver>();

  report = (progress: DiscoveryProgress): void => {
    this.latest = progress;
    for (const observer of this.observers) observer(progress);
  };

  subscribe(observer: DiscoveryProgressObserver): () => void {
    this.observers.add(observer);
    observer(this.latest);
    return () => { this.observers.delete(observer); };
  }
}

const lookupProgress = new WeakMap<Promise<unknown>, DiscoveryProgressStream>();

export function trackDiscoveryProgress<T>(operation: Promise<T>, progress: DiscoveryProgressStream): void {
  lookupProgress.set(operation, progress);
}

export function observeDiscoveryProgress<T>(operation: Promise<T>, observer?: DiscoveryProgressObserver): Promise<T> {
  const unsubscribe = observer && lookupProgress.get(operation)?.subscribe(observer);
  return unsubscribe ? operation.finally(unsubscribe) : operation;
}

export function createBucketProgress(count: number, responseBytes: number, report?: DiscoveryProgressObserver) {
  const received = Array<number>(count).fill(0);
  const totalBytes = count * responseBytes;
  report?.({ phase: 'preparing', receivedBytes: 0, totalBytes });
  return (index: number, bytes: number): void => {
    if (!Number.isInteger(index) || index < 0 || index >= count ||
      !Number.isSafeInteger(bytes) || bytes < received[index] || bytes > responseBytes) return;
    received[index] = bytes;
    const receivedBytes = received.reduce((sum, value) => sum + value, 0);
    report?.({ phase: receivedBytes === totalBytes ? 'verifying' : 'downloading', receivedBytes, totalBytes });
  };
}
