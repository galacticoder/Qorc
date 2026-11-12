export interface ByteCallbackChunk {
  readonly offset: number;
  readonly data: string;
}

const MAX_CHUNK_BYTES = 5 * 1024;
const MAX_CHUNK_BASE64 = 4 * Math.ceil(MAX_CHUNK_BYTES / 3);

export function receiveCallbackBytes(
  read: (onChunk: (chunk: unknown) => void) => Promise<number>,
  maxBytes: number,
  exactLength = true,
  signal?: AbortSignal,
): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const parts: Uint8Array[] = [];
    let received = 0;
    let acknowledged: number | null = null;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const finish = (error?: unknown) => {
      if (settled) return;
      if (error === undefined && (acknowledged === null || acknowledged !== received)) return;
      let result: Uint8Array<ArrayBuffer> | null = null;
      if (error === undefined) {
        try {
          result = new Uint8Array(received);
          let offset = 0;
          for (const part of parts) { result.set(part, offset); offset += part.length; }
        } catch (allocationError) { error = allocationError ?? new Error('Native binary allocation failed'); }
      }
      settled = true;
      if (timer !== null) clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      for (const part of parts) part.fill(0);
      parts.length = 0;
      if (error !== undefined) reject(error);
      else resolve(result!.buffer);
    };
    const abort = () => finish(signal?.reason ?? new DOMException('Native binary receive cancelled', 'AbortError'));
    const deliveryDeadline = () => {
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(() => finish(new Error('Native binary callback delivery timed out')), 10_000);
    };
    const onChunk = (value: unknown) => {
      if (settled) return;
      try {
        if (!value || typeof value !== 'object' || Array.isArray(value) ||
            ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
            Object.keys(value).sort().join(',') !== 'data,offset') throw new Error('Invalid native binary chunk');
        const chunk = value as ByteCallbackChunk;
        if (!Number.isSafeInteger(chunk.offset) || chunk.offset !== received ||
            typeof chunk.data !== 'string' || chunk.data.length === 0 ||
            chunk.data.length > MAX_CHUNK_BASE64) throw new Error('Invalid native binary chunk');
        const decoded = atob(chunk.data);
        if (decoded.length === 0 || decoded.length > MAX_CHUNK_BYTES ||
            btoa(decoded) !== chunk.data || received + decoded.length > maxBytes) throw new Error('Invalid native binary chunk');
        const part = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) part[i] = decoded.charCodeAt(i);
        parts.push(part);
        received += part.length;
        finish();
        if (!settled) deliveryDeadline();
      } catch (error) { finish(error ?? new Error('Native binary callback failed')); }
    };
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > 16 * 1024 * 1024) {
      finish(new Error('Invalid native binary frame size'));
      return;
    }
    if (signal?.aborted) { abort(); return; }
    signal?.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => settled ? undefined : read(onChunk)).then(length => {
      if (settled) return;
      if (!Number.isSafeInteger(length) || length < received || length > maxBytes ||
          (exactLength && length !== 0 && length !== maxBytes)) {
        finish(new Error('Invalid native binary frame length'));
        return;
      }
      acknowledged = length;
      finish();
      if (!settled) deliveryDeadline();
    }, error => finish(error ?? new Error('Native binary receive failed')));
  });
}

export async function receiveCallbackJson<T>(
  read: (onChunk: (chunk: unknown) => void) => Promise<number>,
): Promise<T> {
  const bytes = await receiveCallbackBytes(read, 16 * 1024 * 1024, false);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as T; }
  finally { new Uint8Array(bytes).fill(0); }
}
