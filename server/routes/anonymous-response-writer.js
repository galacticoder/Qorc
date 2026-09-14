import {
  ANONYMOUS_IDLE_TIMEOUT_MS,
  anonymousBodyTimeoutMs,
} from '../../shared/anonymous-transfer-policy.js';

export async function writeAnonymousResponse(res, body, options = {}) {
  if (res.destroyed || res.writableEnded) return false;
  const idleTimeoutMs = options.idleTimeoutMs ?? ANONYMOUS_IDLE_TIMEOUT_MS;
  const totalTimeoutMs = options.totalTimeoutMs ?? anonymousBodyTimeoutMs(body.length);
  res.setTimeout(idleTimeoutMs);
  const startedAt = Date.now();
  let written = 0;
  let failed = false;
  const fail = (reason) => {
    if (failed) return;
    failed = true;
    console.warn('[PQ-ANONYMOUS-HTTP] Response delivery failed', {
      reason, writtenBytes: written, expectedBytes: body.length, elapsedMs: Date.now() - startedAt,
    });
    res.destroy();
  };
  const totalTimer = setTimeout(() => fail('transfer-deadline'), totalTimeoutMs);
  totalTimer.unref?.();
  try {
    const write = (chunk) => new Promise((resolve) => {
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(idleTimer);
        res.off('close', onClose);
        res.off('error', onError);
        if (error) fail(error);
        resolve(!failed);
      };
      const onClose = () => finish(res.writableFinished ? undefined : 'connection-closed');
      const onError = () => finish('write-error');
      const idleTimer = setTimeout(() => finish('write-idle-timeout'), idleTimeoutMs);
      idleTimer.unref?.();
      res.once('close', onClose);
      res.once('error', onError);
      if (failed || res.destroyed) {
        finish('connection-closed');
        return;
      }
      try {
        if (chunk) res.write(chunk, (error) => finish(error ? 'write-error' : undefined));
        else res.end(() => finish());
      } catch {
        finish('write-error');
      }
    });
    for (let offset = 0; offset < body.length; offset += 16 * 1024) {
      const chunk = body.subarray(offset, Math.min(body.length, offset + 16 * 1024));
      if (!await write(chunk)) return false;
      written += chunk.length;
    }
    return await write();
  } finally {
    clearTimeout(totalTimer);
  }
}
