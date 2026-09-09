'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { setTimeout: delay } = require('node:timers/promises');

const retryableCodes = new Set([
  'ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ETIMEDOUT', 'EAI_AGAIN',
  'ENETUNREACH', 'EHOSTUNREACH', 'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT'
]);
const retryableStatuses = new Set([408, 425, 429, 500, 502, 503, 504]);

function errorChain(error, seen = new Set()) {
  if (!error || seen.has(error)) return [];
  seen.add(error);
  return [error, ...errorChain(error.cause, seen),
    ...(Array.isArray(error.errors) ? error.errors.flatMap(item => errorChain(item, seen)) : [])];
}

function describeError(error) {
  return errorChain(error).map(item => [item.code, item.message].filter(Boolean).join(': '))
    .filter(Boolean).join(' -> ');
}

async function downloadRuntimePackage({ url, destination, validate }, {
  fetch = globalThis.fetch,
  wait = delay,
  log = console.warn
} = {}) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const temporaryPath = `${destination}.${process.pid}.tmp`;
  const attempts = 3;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    fs.rmSync(temporaryPath, { force: true });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(
      new DOMException('Package download exceeded 180 seconds', 'TimeoutError')
    ), 180_000);
    timer.unref();
    let failure;
    try {
      const response = await fetch(url, { redirect: 'follow', signal: controller.signal });
      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}`);
        error.status = response.status;
        throw error;
      }
      if (!response.body) throw new Error('Package response has no body');
      await pipeline(response.body, fs.createWriteStream(temporaryPath, { mode: 0o644 }));
      if (!validate(temporaryPath)) throw new Error('Downloaded package failed checksum or metadata validation');
      fs.renameSync(temporaryPath, destination);
      return;
    } catch (error) {
      fs.rmSync(temporaryPath, { force: true });
      failure = error;
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
    const retryable = errorChain(failure).some(error =>
      retryableCodes.has(error.code) || retryableStatuses.has(error.status) || error.name === 'TimeoutError'
    );
    const detail = describeError(failure);
    if (!retryable || attempt === attempts) {
      throw new Error(`Download failed for ${url} after ${attempt} attempt(s): ${detail}`, { cause: failure });
    }
    const waitMs = attempt * 1000;
    log(`[webkitgtk] ${detail}; retrying ${url} in ${waitMs / 1000}s (${attempt + 1}/${attempts})`);
    await wait(waitMs);
  }
}

module.exports = { downloadRuntimePackage };
