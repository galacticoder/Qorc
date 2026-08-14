export class StaleAuthOperationError extends Error {
  constructor() {
    super('Authentication operation is no longer current');
    this.name = 'StaleAuthOperationError';
  }
}

export interface AuthOperationSnapshot {
  readonly generation: number;
  readonly account: string;
  readonly requestId: string;
  readonly signal: AbortSignal;
}

export interface AuthLifecycle {
  begin: (account?: string, requestId?: string) => AuthOperationSnapshot;
  capture: () => AuthOperationSnapshot;
  invalidate: () => void;
  isCurrent: (operation: AuthOperationSnapshot) => boolean;
  assertCurrent: (operation: AuthOperationSnapshot) => void;
}

export const isStaleAuthOperation = (error: unknown): boolean =>
  error instanceof StaleAuthOperationError ||
  (error instanceof Error && error.name === 'AbortError');

export function wipeStaleAuthResult(value: unknown): void {
  const pending: unknown[] = [value];
  const seen = new Set<object>();
  let visited = 0;
  const maxVisited = 16_384;

  while (pending.length > 0 && visited < maxVisited) {
    const current = pending.pop();
    visited += 1;
    if (current instanceof Uint8Array) {
      try { current.fill(0); } catch { }
      continue;
    }
    if (current instanceof ArrayBuffer) {
      try { new Uint8Array(current).fill(0); } catch { }
      continue;
    }
    if (!current || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);

    if (Array.isArray(current)) {
      for (let index = 0; index < current.length && pending.length < maxVisited; index += 1) {
        pending.push(current[index]);
      }
      continue;
    }
    if (Object.getPrototypeOf(current) === Object.prototype) {
      for (const child of Object.values(current)) {
        if (pending.length >= maxVisited) break;
        pending.push(child);
      }
    }
  }
}
