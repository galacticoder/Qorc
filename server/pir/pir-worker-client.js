/**
 * Boundary for an isolated reviewed hintless-SimplePIR worker
 */

import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

const SCHEME_ID = 'hintless-simplepir';
const DEFAULT_PARAMETER_ID = 'hintless-simplepir-rlwe64-v1';
const DEFAULT_WORKER_SOURCE_COMMIT = '49434e086ec56d19546ca6e97353671b690ba19b';
const PIR_WORKER_MAX_RESPONSE_BODY_BYTES = envInt(
  'PIR_WORKER_MAX_RESPONSE_BODY_BYTES',
  64 * 1024 * 1024,
  1024 * 1024,
  256 * 1024 * 1024
);
const PIR_WORKER_MAX_UPLOAD_BODY_BYTES = envInt(
  'PIR_WORKER_MAX_UPLOAD_BODY_BYTES',
  envInt('PIR_WORKER_MAX_REQUEST_BYTES', 192 * 1024 * 1024, 16 * 1024 * 1024, 1024 * 1024 * 1024),
  16 * 1024 * 1024,
  1024 * 1024 * 1024
);
const PIR_WORKER_REQUEST_RETRIES = envInt('PIR_WORKER_REQUEST_RETRIES', 3, 0, 8);
const PIR_WORKER_RETRY_BASE_MS = envInt('PIR_WORKER_RETRY_BASE_MS', 250, 50, 10_000);
const PIR_WORKER_RETRY_MAX_MS = envInt('PIR_WORKER_RETRY_MAX_MS', 5_000, 100, 60_000);
const RETRYABLE_FETCH_CODES = new Set([
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'ECONNRESET',
  'ECONNREFUSED',
  'EPIPE',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EAI_AGAIN'
]);
const RETRYABLE_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function byteSizeClass(bytes) {
  const n = Math.max(0, Number(bytes) || 0);
  if (n <= 1024 * 1024) return 'lte-1m';
  if (n <= 4 * 1024 * 1024) return 'lte-4m';
  if (n <= 8 * 1024 * 1024) return 'lte-8m';
  if (n <= 16 * 1024 * 1024) return 'lte-16m';
  if (n <= 64 * 1024 * 1024) return 'lte-64m';
  return 'gt-64m';
}

function countClass(count) {
  const n = Math.max(0, Number(count) || 0);
  if (n === 0) return 'none';
  if (n === 1) return 'single';
  if (n <= 32) return 'lte-32';
  if (n <= 1024) return 'lte-1k';
  if (n <= 16384) return 'lte-16k';
  if (n <= 65536) return 'lte-64k';
  return 'gt-64k';
}

function base64Length(byteLength) {
  return Math.ceil(Math.max(0, Number(byteLength) || 0) / 3) * 4;
}

function estimateUploadBodyBytes(workerManifest, records) {
  let bytes = Buffer.byteLength('{"manifest":,"records":[]}', 'utf8') +
    Buffer.byteLength(JSON.stringify(workerManifest), 'utf8');
  for (const record of records) {
    bytes += base64Length(record?.length || 0) + 3;
  }
  return bytes;
}

function workerResponseTooLarge(sizeBytes) {
  return {
    ok: false,
    error: 'pir_worker_response_too_large',
    body: {
      error: 'pir_response_too_large',
      responseSizeClass: byteSizeClass(sizeBytes),
      limitClass: byteSizeClass(PIR_WORKER_MAX_RESPONSE_BODY_BYTES)
    }
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelayMs(attempt) {
  const exponential = PIR_WORKER_RETRY_BASE_MS * (2 ** Math.max(0, attempt));
  const capped = Math.min(PIR_WORKER_RETRY_MAX_MS, exponential);
  const jitter = Math.floor(Math.random() * Math.max(1, Math.floor(capped / 3)));
  return capped + jitter;
}

function errorCode(error) {
  if (typeof error?.cause?.code === 'string') return error.cause.code;
  if (typeof error?.code === 'string') return error.code;
  return '';
}

function fetchFailure(error, fallback = 'pir_worker_error') {
  const code = errorCode(error);
  const isAbort = error?.name === 'AbortError';
  const retryable = !isAbort && code && RETRYABLE_FETCH_CODES.has(code);
  return {
    ok: false,
    error: isAbort
      ? 'pir_worker_timeout'
      : code
        ? `pir_worker_fetch_${code}`
        : fallback,
    detail: error?.message,
    retryable
  };
}

function isRetryableWorkerResult(result) {
  if (!result || result.ok) return false;
  if (result.retryable === true) return true;
  if (RETRYABLE_HTTP_STATUSES.has(Number(result.status))) return true;
  const match = typeof result.error === 'string'
    ? result.error.match(/^pir_worker_fetch_(.+)$/)
    : null;
  return !!(match && RETRYABLE_FETCH_CODES.has(match[1]));
}

function getWorkerUrl() {
  const raw = (process.env.PIR_WORKER_URL || 'http://127.0.0.1:8787').trim();
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return parsed.toString().replace(/\/+$/, '');
  } catch {
    return null;
  }
}

function envBool(name, fallback = false) {
  const raw = (process.env[name] || '').trim().toLowerCase();
  if (!raw) return fallback;
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

export function getPirWorkerConfig() {
  const url = getWorkerUrl();
  return {
    configured: !!url,
    required: envBool('PIR_REQUIRE_WORKER', true),
    url,
    schemeId: SCHEME_ID,
    parameterId: process.env.PIR_WORKER_PARAMETER_ID || DEFAULT_PARAMETER_ID,
    expectedSourceCommit: process.env.PIR_WORKER_SOURCE_COMMIT || DEFAULT_WORKER_SOURCE_COMMIT,
    timeoutMs: envInt('PIR_WORKER_TIMEOUT_MS', 300_000, 1000, 600_000),
    token: process.env.PIR_WORKER_TOKEN || ''
  };
}

export function isPirWorkerConfigured() {
  return getPirWorkerConfig().configured;
}

async function requestJsonOnce({ method, path, bodyText, config, maxResponseBodyBytes }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const headers = { 'content-type': 'application/json' };
    if (config.token) {
      headers.authorization = `Bearer ${config.token}`;
    }

    const response = await fetch(`${config.url}${path}`, {
      method,
      headers,
      body: bodyText,
      signal: controller.signal
    });

    const contentLength = Number.parseInt(response.headers.get('content-length') || '', 10);
    if (Number.isFinite(contentLength) && contentLength > maxResponseBodyBytes) {
      try {
        await response.body?.cancel?.();
      } catch { }
      return workerResponseTooLarge(contentLength);
    }

    let responseText;
    try {
      responseText = await response.text();
    } catch (error) {
      return fetchFailure(error, 'pir_worker_invalid_json');
    }

    const responseBytes = Buffer.byteLength(responseText, 'utf8');
    if (responseBytes > maxResponseBodyBytes) {
      return workerResponseTooLarge(responseBytes);
    }

    let parsed;
    try {
      parsed = responseText.length > 0 ? JSON.parse(responseText) : {};
    } catch (error) {
      return {
        ok: false,
        error: error?.name === 'AbortError' ? 'pir_worker_timeout' : 'pir_worker_invalid_json',
        detail: error?.message
      };
    }

    if (!response.ok) {
      const parsedError = parsed && typeof parsed === 'object' ? parsed : undefined;
      const workerError = typeof parsedError?.error === 'string' ? parsedError.error : '';
      return {
        ok: false,
        error: workerError ? `pir_worker_http_${response.status}:${workerError}` : `pir_worker_http_${response.status}`,
        status: response.status,
        body: parsedError,
        retryable: RETRYABLE_HTTP_STATUSES.has(response.status)
      };
    }
    return { ok: true, body: parsed };
  } catch (error) {
    return fetchFailure(error);
  } finally {
    clearTimeout(timeout);
  }
}

async function requestJson(method, path, body = undefined, options = {}) {
  const config = getPirWorkerConfig();
  if (!config.configured) {
    return { ok: false, error: 'pir_worker_unavailable' };
  }
  const maxResponseBodyBytes = Number.isFinite(options.maxResponseBodyBytes)
    ? options.maxResponseBodyBytes
    : Number.POSITIVE_INFINITY;
  const retries = Number.isFinite(options.retries)
    ? Math.max(0, Math.trunc(options.retries))
    : PIR_WORKER_REQUEST_RETRIES;
  const bodyText = body === undefined ? undefined : JSON.stringify(body);

  let lastResult = null;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const result = await requestJsonOnce({ method, path, bodyText, config, maxResponseBodyBytes });
    result.attempts = attempt + 1;
    lastResult = result;
    if (!isRetryableWorkerResult(result) || attempt >= retries) {
      return result;
    }

    const delayMs = retryDelayMs(attempt);
    cryptoLogger.info('[PIR] Worker request transient failure; retrying', {
      method,
      path,
      error: result.error,
      statusClass: result.status ? `http-${result.status}` : undefined,
      attempt: attempt + 1,
      maxAttempts: retries + 1,
      retryDelayMs: delayMs
    });
    await sleep(delayMs);
  }

  return lastResult || { ok: false, error: 'pir_worker_error', attempts: 0 };
}

async function postJson(path, body, options) {
  return requestJson('POST', path, body, options);
}

async function getJson(path) {
  return requestJson('GET', path);
}

export async function checkPirWorkerHealth() {
  const config = getPirWorkerConfig();
  if (!config.configured) {
    return { ok: false, error: 'pir_worker_unavailable' };
  }

  const result = await getJson('/health');
  if (!result.ok) return result;

  const body = result.body || {};
  if (body.scheme && body.scheme !== config.schemeId) {
    return { ok: false, error: 'pir_worker_scheme_mismatch' };
  }
  if (body.parameterId && body.parameterId !== config.parameterId) {
    return { ok: false, error: 'pir_worker_parameter_mismatch' };
  }
  if (body.sourceCommit && body.sourceCommit !== config.expectedSourceCommit) {
    return { ok: false, error: 'pir_worker_source_commit_mismatch' };
  }

  return { ok: true, health: body };
}

export async function assertPirWorkerReadyForRequiredMode() {
  const config = getPirWorkerConfig();
  if (!config.required) {
    return { required: false, ready: config.configured };
  }
  if (!config.configured) {
    throw new Error('PIR_REQUIRE_WORKER is true but PIR_WORKER_URL is not configured');
  }
  const health = await checkPirWorkerHealth();
  if (!health.ok) {
    throw new Error(`PIR worker required but not ready: ${health.error}`);
  }
  return { required: true, ready: true, health: health.health };
}

function parsePublicParams(body, manifest) {
  const publicParams = typeof body?.publicParams === 'string' ? body.publicParams : '';
  if (!publicParams) return null;
  return {
    publicParams,
    parameterId: typeof body?.parameterId === 'string' ? body.parameterId : manifest?.parameterId,
    recordCount: Number.isSafeInteger(Number(body?.recordCount)) ? Number(body.recordCount) : manifest?.recordCount,
    recordSize: Number.isSafeInteger(Number(body?.recordSize)) ? Number(body.recordSize) : manifest?.recordSize,
    dbRows: Number.isSafeInteger(Number(body?.dbRows)) ? Number(body.dbRows) : undefined,
    dbCols: Number.isSafeInteger(Number(body?.dbCols)) ? Number(body.dbCols) : undefined
  };
}

export async function uploadPirDatabase(database) {
  const config = getPirWorkerConfig();
  if (!config.configured) {
    return { uploaded: false, error: 'pir_worker_unavailable' };
  }

  const manifest = database?.manifest;
  const records = Array.isArray(database?.records) ? database.records : [];
  if (!manifest || records.length !== manifest.recordCount) {
    return { uploaded: false, error: 'invalid_pir_database' };
  }

  const workerManifest = {
    version: manifest.version,
    kind: manifest.kind,
    epochId: manifest.epochId,
    schemeId: manifest.schemeId,
    parameterId: manifest.parameterId,
    recordSize: manifest.recordSize,
    recordCount: manifest.recordCount,
    databaseDigest: manifest.databaseDigest
  };

  const uploadBodyBytes = estimateUploadBodyBytes(workerManifest, records);
  const rawDatabaseBytes = Number(manifest.recordCount || 0) * Number(manifest.recordSize || 0);
  if (uploadBodyBytes > PIR_WORKER_MAX_UPLOAD_BODY_BYTES) {
    cryptoLogger.warn('[PIR] Worker database upload refused before send', {
      kind: manifest.kind,
      epochId: manifest.epochId,
      error: 'pir_worker_upload_too_large',
      recordCountClass: countClass(manifest.recordCount),
      rawDatabaseSizeClass: byteSizeClass(rawDatabaseBytes),
      uploadBodySizeClass: byteSizeClass(uploadBodyBytes),
      uploadLimitClass: byteSizeClass(PIR_WORKER_MAX_UPLOAD_BODY_BYTES)
    });
    return { uploaded: false, error: 'pir_worker_upload_too_large' };
  }

  const result = await postJson('/v1/databases', {
    manifest: workerManifest,
    records: records.map((record) => Buffer.from(record).toString('base64'))
  });

  if (!result.ok) {
    cryptoLogger.warn('[PIR] Worker database upload failed', {
      kind: manifest.kind,
      epochId: manifest.epochId,
      error: result.error,
      retryable: result.retryable === true,
      attempts: result.attempts,
      recordCountClass: countClass(manifest.recordCount),
      rawDatabaseSizeClass: byteSizeClass(rawDatabaseBytes),
      uploadBodySizeClass: byteSizeClass(uploadBodyBytes),
      statusClass: result.status ? `http-${result.status}` : undefined
    });
    return { uploaded: false, error: result.error, retryable: result.retryable === true, attempts: result.attempts };
  }

  const accepted = result.body?.accepted === true &&
    result.body?.epochId === manifest.epochId &&
    result.body?.databaseDigest === manifest.databaseDigest;

  if (!accepted) {
    cryptoLogger.warn('[PIR] Worker database upload rejected manifest', {
      kind: manifest.kind,
      epochId: manifest.epochId
    });
    return { uploaded: false, error: 'pir_worker_manifest_mismatch' };
  }
  if (result.body?.parameterId && result.body.parameterId !== config.parameterId) {
    return { uploaded: false, error: 'pir_worker_parameter_mismatch' };
  }

  const publicParams = parsePublicParams(result.body, manifest);
  if (!publicParams) {
    return { uploaded: false, error: 'pir_worker_public_params_missing' };
  }

  return { uploaded: true, publicParams };
}

export async function fetchPirWorkerPublicParams({ kind, epochId }) {
  const config = getPirWorkerConfig();
  if (!config.configured) {
    return { success: false, error: 'pir_worker_unavailable' };
  }

  const result = await postJson('/v1/public-params', { kind, epochId });
  if (!result.ok) {
    return { success: false, error: result.error };
  }
  const body = result.body || {};
  if (body.success !== true || typeof body.publicParams !== 'string') {
    return { success: false, error: body.error || 'pir_worker_public_params_invalid' };
  }
  return {
    success: true,
    kind: body.kind,
    epochId: body.epochId,
    publicParams: parsePublicParams(body, { parameterId: config.parameterId })
  };
}

export async function queryPirWorker({ kind, epochId, query, maxResponseChars }) {
  const config = getPirWorkerConfig();
  if (!config.configured) {
    return { success: false, error: 'pir_worker_unavailable' };
  }
  if (!query || typeof query !== 'string') {
    return { success: false, error: 'invalid_pir_query' };
  }

  const request = { kind, epochId, query };
  if (Number.isSafeInteger(maxResponseChars) && maxResponseChars > 0) {
    request.maxResponseChars = maxResponseChars;
  }

  const result = await postJson('/v1/query', request, {
    maxResponseBodyBytes: PIR_WORKER_MAX_RESPONSE_BODY_BYTES
  });
  if (!result.ok) {
    return {
      success: false,
      error: result.body?.error || result.error,
      status: result.status,
      responseSizeClass: result.body?.responseSizeClass,
      limitClass: result.body?.limitClass
    };
  }

  const response = result.body?.response;
  if (typeof response !== 'string' || response.length === 0) {
    return { success: false, error: 'pir_worker_invalid_response' };
  }

  return { success: true, response };
}
