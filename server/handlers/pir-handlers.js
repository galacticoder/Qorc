/**
 * PIR retrieval handlers
 */

import { SignalType, sendSecureMessage, cryptoLogger, hasAccountAuthentication } from './core.js';
import {
  getPirDatabase,
  publicManifest,
  forcePirWorkerReupload
} from '../pir/pir-databases.js';
import { queryPirWorker } from '../pir/pir-worker-client.js';
import { OPAQUE_PIR_DATABASE_KIND, DISCOVERY_PIR_DATABASE_KIND, isPirDatabaseKind } from '../pir/page-layout.js';
import {
  encryptedResponseSizeClass,
  getEncryptedResponsePlaintextBudgetBytes,
  getMaxEncryptedResponseBytes
} from '../messaging/pq-envelope-handler.js';

const PIR_MAX_QUERY_CHARS = Math.min(
  Math.max(Number.parseInt(process.env.PIR_MAX_QUERY_CHARS || String(8 * 1024 * 1024), 10) || (8 * 1024 * 1024), 1024),
  64 * 1024 * 1024
);
const PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES = getEncryptedResponsePlaintextBudgetBytes();
const PIR_WORKER_RESPONSE_CHAR_BUDGET = Math.max(
  1024,
  Math.floor(PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES * 0.9)
);

function requiresAuthenticatedSession(kind) {
  return kind === OPAQUE_PIR_DATABASE_KIND || kind === DISCOVERY_PIR_DATABASE_KIND;
}

// Resolve the requested PIR database kind
function resolveKind(parsed) {
  const requested = typeof parsed?.kind === 'string' ? parsed.kind : '';
  return isPirDatabaseKind(requested) ? requested : DISCOVERY_PIR_DATABASE_KIND;
}

function isAuthorizedForKind(kind, ws, state) {
  if (!requiresAuthenticatedSession(kind)) return true;
  return hasAccountAuthentication(ws, state) || !!ws?._unlinkedSession;
}

function serializedPayloadBytes(payload) {
  try {
    return Buffer.byteLength(JSON.stringify(payload), 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function responseStringSizeClass(response) {
  return typeof response === 'string'
    ? encryptedResponseSizeClass(Buffer.byteLength(response, 'utf8'))
    : undefined;
}

function sendPirResponseTooLarge({ ws, requestId, kind, epochId, manifest, source, payloadBytes, responseSizeClass, limitClass }) {
  const payloadSizeClass = encryptedResponseSizeClass(payloadBytes);
  const payloadBudgetClass = encryptedResponseSizeClass(PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES);
  const encryptedLimitClass = encryptedResponseSizeClass(getMaxEncryptedResponseBytes());

  cryptoLogger.warn('[PIR] Response too large for secure transport', {
    kind,
    epochId,
    source,
    responseSizeClass,
    payloadSizeClass,
    payloadBudgetClass,
    encryptedLimitClass
  });

  return sendSecureMessage(ws, {
    type: SignalType.PIR_RESPONSE,
    requestId,
    success: false,
    kind,
    epochId,
    manifestDigest: manifest?.databaseDigest,
    error: 'pir_response_too_large',
    responseSizeClass: responseSizeClass || payloadSizeClass,
    limitClass: limitClass || payloadBudgetClass
  });
}

export async function handlePirManifestRequest({ ws, parsed, state }) {
  const kind = resolveKind(parsed);
  const requestId = typeof parsed?.requestId === 'string' ? parsed.requestId.slice(0, 128) : undefined;

  if (!isAuthorizedForKind(kind, ws, state)) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_MANIFEST,
      requestId,
      success: false,
      error: 'authentication_required'
    });
  }

  const result = await getPirDatabase(kind, { ensureWorker: parsed?.prepareWorker === true });
  if (!result.success) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_MANIFEST,
      requestId,
      success: false,
      kind,
      error: result.error
    });
  }

  const manifest = publicManifest(result.database);
  const payload = {
    type: SignalType.PIR_MANIFEST,
    requestId,
    success: true,
    manifest,
    workerUpload: result.database.workerUpload
      ? { uploaded: !!result.database.workerUpload.uploaded, error: result.database.workerUpload.error }
      : undefined
  };
  const payloadBytes = serializedPayloadBytes(payload);
  if (payloadBytes > PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES) {
    cryptoLogger.warn('[PIR] Manifest too large for secure transport', {
      kind,
      payloadSizeClass: encryptedResponseSizeClass(payloadBytes),
      payloadBudgetClass: encryptedResponseSizeClass(PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES),
      recordDigestTransport: manifest.recordDigestTransport || 'unknown',
      payloadDigestTransport: manifest.payloadDigestTransport || 'unknown'
    });
    return sendSecureMessage(ws, {
      type: SignalType.PIR_MANIFEST,
      requestId,
      success: false,
      kind,
      error: 'pir_manifest_too_large'
    });
  }

  await sendSecureMessage(ws, payload);
}

export async function handlePirQuery({ ws, parsed, state }) {
  const kind = resolveKind(parsed);
  const requestId = typeof parsed?.requestId === 'string' ? parsed.requestId.slice(0, 128) : undefined;
  const epochId = typeof parsed?.epochId === 'string' ? parsed.epochId.slice(0, 128) : '';
  const query = typeof parsed?.query === 'string' ? parsed.query : '';

  if (!isAuthorizedForKind(kind, ws, state)) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_RESPONSE,
      requestId,
      success: false,
      error: 'authentication_required'
    });
  }

  if (!query || query.length > PIR_MAX_QUERY_CHARS) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_RESPONSE,
      requestId,
      success: false,
      kind,
      epochId,
      error: 'invalid_pir_query'
    });
  }

  const databaseResult = await getPirDatabase(kind, { epochId, ensureWorker: true });
  if (!databaseResult.success) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_RESPONSE,
      requestId,
      success: false,
      kind,
      epochId,
      error: databaseResult.error
    });
  }

  const manifest = databaseResult.database.manifest;
  if (manifest.epochId !== epochId) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_RESPONSE,
      requestId,
      success: false,
      kind,
      epochId,
      error: 'pir_epoch_mismatch'
    });
  }

  if (!databaseResult.database.workerUpload?.uploaded) {
    return sendSecureMessage(ws, {
      type: SignalType.PIR_RESPONSE,
      requestId,
      success: false,
      kind,
      epochId,
      manifest: publicManifest(databaseResult.database),
      error: databaseResult.database.workerUpload?.error || 'pir_worker_unavailable'
    });
  }

  let response = await queryPirWorker({
    kind,
    epochId,
    query,
    maxResponseChars: PIR_WORKER_RESPONSE_CHAR_BUDGET
  });
  
  // Self heal a worker desync
  if (!response.success && response.error === 'pir_epoch_not_loaded') {
    const reup = await forcePirWorkerReupload(databaseResult.database);
    if (reup?.uploaded) {
      response = await queryPirWorker({ kind, epochId, query, maxResponseChars: PIR_WORKER_RESPONSE_CHAR_BUDGET });
    }
  }
  if (!response.success) {
    if (response.error === 'pir_response_too_large' || String(response.error || '').includes('pir_response_too_large')) {
      return sendPirResponseTooLarge({
        ws,
        requestId,
        kind,
        epochId,
        manifest,
        source: 'worker-response-budget',
        payloadBytes: PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES + 1,
        responseSizeClass: response.responseSizeClass,
        limitClass: response.limitClass
      });
    }

    cryptoLogger.warn('[PIR] Worker query failed', { kind, epochId, error: response.error });
    return sendSecureMessage(ws, {
      type: SignalType.PIR_RESPONSE,
      requestId,
      success: false,
      kind,
      epochId,
      manifest: publicManifest(databaseResult.database),
      error: response.error
    });
  }

  const payload = {
    type: SignalType.PIR_RESPONSE,
    requestId,
    success: true,
    kind,
    epochId,
    manifestDigest: manifest.databaseDigest,
    response: response.response,
    proof: response.proof,
    recordDigest: response.recordDigest
  };

  const payloadBytes = serializedPayloadBytes(payload);
  if (payloadBytes > PIR_SECURE_RESPONSE_PAYLOAD_BUDGET_BYTES) {
    return sendPirResponseTooLarge({
      ws,
      requestId,
      kind,
      epochId,
      manifest,
      source: 'server-payload-budget',
      payloadBytes,
      responseSizeClass: responseStringSizeClass(response.response)
    });
  }

  await sendSecureMessage(ws, payload);
}
