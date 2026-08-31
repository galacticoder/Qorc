import crypto from 'crypto';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { PostQuantumHash } from '../crypto/post-quantum-hash.js';
import { privateLookupId } from '../database/core.js';

import { verifyPowSolution } from '../security/auth-throttle.js';
import { withRedisClient } from '../session/redis-client.js';
import {
  AVATAR_BLOB_GET_AUDIENCE,
  AVATAR_BLOB_PUT_AUDIENCE,
  AVATAR_POOL_AUDIENCE,
  DISCOVERY_MANIFEST_AUDIENCE,
  KEY_TRANSPARENCY_APPEND_AUDIENCE,
  KEY_TRANSPARENCY_SYNC_AUDIENCE
} from '../config/audiences.js';
import { ANONYMOUS_OPERATION_FAILED } from '../config/error-codes.js';
import { envInt } from '../utils/env.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { setNoStoreHeaders } from '../utils/http.js';
import { createTokenBucketRateLimiter } from '../utils/rate-limit.js';
import {
  hasExactPlainObjectKeys as exactPlainObject,
  isSafeJsonTree
} from '../utils/validation.js';
import { computeHybridPublicKeyFingerprint } from '../crypto/hybrid-key-fingerprint.js';
import {
  ML_DSA_87_SIGNATURE_BYTES as ML_DSA_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES as ML_KEM_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES as ML_KEM_PUBLIC_KEY_BYTES
} from '../../shared/crypto-sizes.js';
import { DISCOVERY_BUCKET_QUERY_COUNT } from '../../shared/discovery-constants.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import {
  HASH_OUTPUT_BYTES,
  POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES,
  POST_QUANTUM_AEAD_KEY_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES as AEAD_NONCE_BYTES,
  POST_QUANTUM_AEAD_TAG_BYTES as AEAD_TAG_BYTES,
  POW_SEED_BYTES,
  POW_SOLUTION_BYTES
} from '../utils/crypto-consts.js';

const PROTOCOL_VERSION = PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_PROTOCOL;
const WIRE_VERSION = 1;
const REQUEST_MAGIC = Buffer.from('QORCAH01', 'ascii');
const RESPONSE_MAGIC = Buffer.from('QORCAR01', 'ascii');
const REQUEST_AAD_DOMAIN = Buffer.from(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_AAD, 'utf8');
const RESPONSE_AAD_DOMAIN = Buffer.from(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_AAD, 'utf8');
const RESPONSE_SIGNATURE_DOMAIN = Buffer.from(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_SIGNATURE, 'utf8');
const REQUEST_POW_DOMAIN = Buffer.from(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_ADMISSION_POW, 'utf8');

const REQUEST_SMALL_BYTES = 64 * 1024;
const REQUEST_LARGE_BYTES = 512 * 1024;
const REQUEST_PIR_BYTES = 2 * 1024 * 1024;
export const PQ_ANONYMOUS_HTTP_MAX_REQUEST_BYTES = REQUEST_PIR_BYTES;
const REQUEST_CLASS_BYTES = new Map([
  [1, REQUEST_SMALL_BYTES],
  [2, REQUEST_LARGE_BYTES],
  [3, REQUEST_PIR_BYTES],
]);

const RESPONSE_SMALL_BYTES = 64 * 1024;
const RESPONSE_KEY_TRANSPARENCY_BYTES = 512 * 1024;
const RESPONSE_PIR_BYTES = 1024 * 1024;
const RESPONSE_AVATAR_BYTES = 4 * 1024 * 1024;
const RESPONSE_DISCOVERY_BYTES = 8912896;

const AEAD_CIPHERTEXT_OVERHEAD = POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES;
const REQUEST_POW_NONCE_OFFSET = 3252;
const REQUEST_POW_SOLUTION_OFFSET = REQUEST_POW_NONCE_OFFSET + POW_SEED_BYTES;
const REQUEST_PREFIX_BYTES = REQUEST_POW_SOLUTION_OFFSET + POW_SOLUTION_BYTES;
const REQUEST_NONCE_OFFSET = REQUEST_PREFIX_BYTES;
const REQUEST_TAG_OFFSET = REQUEST_NONCE_OFFSET + AEAD_NONCE_BYTES;
const REQUEST_CIPHERTEXT_OFFSET = REQUEST_TAG_OFFSET + AEAD_TAG_BYTES;
const RESPONSE_PREFIX_BYTES = 1652;
const RESPONSE_NONCE_OFFSET = RESPONSE_PREFIX_BYTES;
const RESPONSE_TAG_OFFSET = RESPONSE_NONCE_OFFSET + AEAD_NONCE_BYTES;
const RESPONSE_SIGNATURE_OFFSET = RESPONSE_TAG_OFFSET + AEAD_TAG_BYTES;
const RESPONSE_CIPHERTEXT_OFFSET = RESPONSE_SIGNATURE_OFFSET + ML_DSA_SIGNATURE_BYTES;

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const REQUEST_POW_DIFFICULTY = 12;
const REPLAY_TTL_SECONDS = 10 * 60;
const LOCAL_REPLAY_MAX = 20_000;
const REQUEST_BODY_PARSE_TYPES = new Set([
  'encoding.unsupported',
  'entity.too.large',
  'entity.parse.failed',
  'request.aborted',
  'request.size.invalid',
  'stream.encoding.set',
  'stream.not.readable',
]);

const OPERATION_POLICY = Object.freeze({
  [AVATAR_BLOB_GET_AUDIENCE]: Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 2, responseBytes: RESPONSE_AVATAR_BYTES }),
  [AVATAR_BLOB_PUT_AUDIENCE]: Object.freeze({ requestClass: 2, requestBytes: REQUEST_LARGE_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES }),
  [AVATAR_POOL_AUDIENCE]: Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES }),
  'discovery/bucket': Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 4, responseBytes: RESPONSE_DISCOVERY_BYTES }),
  [DISCOVERY_MANIFEST_AUDIENCE]: Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES }),
  [KEY_TRANSPARENCY_SYNC_AUDIENCE]: Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 3, responseBytes: RESPONSE_KEY_TRANSPARENCY_BYTES }),
  [KEY_TRANSPARENCY_APPEND_AUDIENCE]: Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES }),
  'oprf/evaluate': Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES }),
  'spool/tag-index': Object.freeze({ requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 3, responseBytes: RESPONSE_KEY_TRANSPARENCY_BYTES }),
  'spool/pir': Object.freeze({ requestClass: 3, requestBytes: REQUEST_PIR_BYTES, responseClass: 5, responseBytes: RESPONSE_PIR_BYTES })
});

const MAX_INFLIGHT = envInt(
  'PQ_ANONYMOUS_HTTP_MAX_INFLIGHT',
  2 * DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_BUCKET_QUERY_COUNT + 1,
  16
);
const MAX_REQUESTS_PER_SECOND = envInt('PQ_ANONYMOUS_HTTP_MAX_RPS', 100, 1, 2_000);
const MAX_FAILURE_INFLIGHT = envInt('PQ_ANONYMOUS_HTTP_MAX_FAILURE_INFLIGHT', 16, 1, 64);
const MAX_FAILURES_PER_SECOND = envInt('PQ_ANONYMOUS_HTTP_MAX_FAILURE_RPS', 200, 1, 4_000);
const RESPONSE_WRITE_TIMEOUT_MS = envInt(
  'PQ_ANONYMOUS_HTTP_WRITE_TIMEOUT_MS',
  180_000,
  5_000,
  300_000
);

function responseSignatureDigest(body) {
  return PostQuantumHash.digestParts([
    RESPONSE_SIGNATURE_DOMAIN,
    body.subarray(0, RESPONSE_SIGNATURE_OFFSET),
    body.subarray(RESPONSE_CIPHERTEXT_OFFSET)
  ], HASH_OUTPUT_BYTES);
}

function requestPowSeed(body) {
  return PostQuantumHash.digestParts([
    REQUEST_POW_DOMAIN,
    body.subarray(0, REQUEST_POW_SOLUTION_OFFSET)
  ], POW_SEED_BYTES);
}

function randomFill(buffer) {
  return new Promise((resolve, reject) => {
    crypto.randomFill(buffer, (error) => error ? reject(error) : resolve());
  });
}

async function sendBinaryResponse(res, body) {
  res.status(200);
  setNoStoreHeaders(res);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Encoding', 'identity');
  res.setHeader('Content-Length', String(body.length));
  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      res.off?.('finish', finish);
      res.off?.('close', finish);
      res.off?.('error', finish);
      resolve();
    };
    const timer = setTimeout(() => {
      try { res.destroy?.(); } catch { }
      finish();
    }, RESPONSE_WRITE_TIMEOUT_MS);
    timer.unref?.();
    res.once?.('finish', finish);
    res.once?.('close', finish);
    res.once?.('error', finish);
    try {
      res.end(body, finish);
    } catch {
      finish();
    }
  });
}

const allowOpaqueFailure = createTokenBucketRateLimiter(MAX_FAILURES_PER_SECOND);
let opaqueFailureInflight = 0;

// Rejects a request
async function reject(res, reason) {
  console.warn('[PQ-ANONYMOUS-HTTP] rejected anonymous request', { reason });
  return sendOpaqueFailure(res);
}

async function sendOpaqueFailure(res) {
  if (!allowOpaqueFailure() || opaqueFailureInflight >= MAX_FAILURE_INFLIGHT) {
    try { res.destroy?.(); } catch { }
    return false;
  }
  opaqueFailureInflight += 1;
  const body = Buffer.allocUnsafe(RESPONSE_SMALL_BYTES);
  try {
    await randomFill(body);
    await sendBinaryResponse(res, body);
    return true;
  } finally {
    body.fill(0);
    opaqueFailureInflight = Math.max(0, opaqueFailureInflight - 1);
  }
}

export async function handlePqAnonymousHttpParseError(error, _req, res, _next) {
  if (res.headersSent || res.writableEnded) {
    try { res.destroy?.(); } catch { }
    return;
  }
  try {
    const parseType = typeof error?.type === 'string' && REQUEST_BODY_PARSE_TYPES.has(error.type)
      ? error.type
      : 'unknown';
    console.warn('[PQ-ANONYMOUS-HTTP] rejected anonymous request', {
      reason: 'request-body-parse',
      parseType
    });
    await sendOpaqueFailure(res);
  } catch {
    try { res.destroy?.(); } catch { }
  }
}

function parsePaddedRequest(plaintext) {
  if (plaintext.length < 5) return null;
  const jsonLength = plaintext.readUInt32BE(0);
  if (jsonLength < 2 || jsonLength > plaintext.length - 4) return null;
  let parsed;
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
      plaintext.subarray(4, 4 + jsonLength)
    );
    parsed = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (
    !exactPlainObject(parsed, ['body', 'operation', 'version']) ||
    parsed.version !== PROTOCOL_VERSION ||
    typeof parsed.operation !== 'string' ||
    !exactPlainObject(parsed.body, Object.keys(parsed.body || {})) ||
    !isSafeJsonTree(parsed.body)
  ) return null;
  return parsed;
}

function scrubRequestTree(root) {
  if (!root || typeof root !== 'object') return;
  const stack = [root];
  const seen = new Set();
  while (stack.length > 0) {
    const value = stack.pop();
    if (!value || typeof value !== 'object' || seen.has(value)) continue;
    seen.add(value);
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (value[index] && typeof value[index] === 'object') stack.push(value[index]);
        else value[index] = null;
      }
      continue;
    }
    for (const key of Object.keys(value)) {
      if (value[key] && typeof value[key] === 'object') stack.push(value[key]);
      else value[key] = null;
    }
  }
}

async function claimReplayId(replayId) {
  try {
    const result = await withRedisClient((client) => client.set(
      `${PROTOCOL_KEYS.ANONYMOUS_HTTP_REPLAY_PREFIX}${replayId}`,
      '1',
      'EX',
      REPLAY_TTL_SECONDS,
      'NX'
    ));
    return result === 'OK' ? 'claimed' : 'replayed';
  } catch {
    return 'unavailable';
  }
}

function rememberLocalReplay(localReplayIds, replayId) {
  localReplayIds.delete(replayId);
  while (localReplayIds.size >= LOCAL_REPLAY_MAX) {
    const oldest = localReplayIds.keys().next().value;
    if (typeof oldest !== 'string') break;
    localReplayIds.delete(oldest);
  }
  const expiresAt = Date.now() + REPLAY_TTL_SECONDS * 1000;
  localReplayIds.set(replayId, expiresAt);
}

async function encodeResponse({
  policy,
  payload,
  requestId,
  fingerprintBytes,
  requestKey,
  clientKemPublicKey,
  serverHybridKeyPair
}) {
  const response = Buffer.allocUnsafe(policy.responseBytes);
  const responsePlaintextBytes = policy.responseBytes - RESPONSE_CIPHERTEXT_OFFSET - AEAD_CIPHERTEXT_OVERHEAD;
  let responsePlaintext = null;
  let responseKemCiphertext = null;
  let responseSharedSecret = null;
  let responseCombinedSecret = null;
  let responseAad = null;
  let responseSalt = null;
  let responseKey = null;
  let encrypted = null;
  let signatureDigest = null;
  let signature = null;
  try {
    const responseEncapsulation = await CryptoUtils.Kyber.encapsulate(clientKemPublicKey);
    responseKemCiphertext = responseEncapsulation.ciphertext;
    responseSharedSecret = responseEncapsulation.sharedSecret;

    response.set(RESPONSE_MAGIC, 0);
    response[8] = WIRE_VERSION;
    response[9] = policy.responseClass;
    response[10] = 0;
    response[11] = 0;
    response.writeBigUInt64BE(BigInt(Date.now()), 44);
    response.set(requestId, 12);
    response.set(fingerprintBytes, 52);
    response.set(responseKemCiphertext, 84);

    responseAad = Buffer.concat([
      RESPONSE_AAD_DOMAIN,
      response.subarray(0, RESPONSE_PREFIX_BYTES)
    ]);
    responseSalt = PostQuantumHash.blake3(responseAad);
    responseCombinedSecret = new Uint8Array(requestKey.length + responseSharedSecret.length);
    responseCombinedSecret.set(requestKey, 0);
    responseCombinedSecret.set(responseSharedSecret, requestKey.length);
    responseKey = PostQuantumHash.deriveKey(
      responseCombinedSecret,
      responseSalt,
      PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_KDF,
      POST_QUANTUM_AEAD_KEY_BYTES
    );

    let encodedPayload = UTF8_ENCODER.encode(JSON.stringify({
      version: PROTOCOL_VERSION,
      payload
    }));
    if (encodedPayload.length > responsePlaintextBytes - 4) {
      encodedPayload.fill(0);
      encodedPayload = UTF8_ENCODER.encode(JSON.stringify({
        version: PROTOCOL_VERSION,
        payload: { ok: false, error: 'anonymous_response_too_large' }
      }));
    }
    try {
      responsePlaintext = Buffer.allocUnsafe(responsePlaintextBytes);
      await randomFill(responsePlaintext);
      responsePlaintext.writeUInt32BE(encodedPayload.length, 0);
      responsePlaintext.set(encodedPayload, 4);
    } finally {
      encodedPayload.fill(0);
    }

    encrypted = CryptoUtils.PostQuantumAEAD.encrypt(
      responsePlaintext,
      responseKey,
      responseAad
    );
    if (encrypted.ciphertext.length !== policy.responseBytes - RESPONSE_CIPHERTEXT_OFFSET) {
      throw new Error('anonymous response encryption length mismatch');
    }
    response.set(encrypted.nonce, RESPONSE_NONCE_OFFSET);
    response.set(encrypted.tag, RESPONSE_TAG_OFFSET);
    response.set(encrypted.ciphertext, RESPONSE_CIPHERTEXT_OFFSET);

    signatureDigest = responseSignatureDigest(response);
    signature = await CryptoUtils.Dilithium.sign(
      signatureDigest,
      serverHybridKeyPair.dilithium.secretKey
    );
    response.set(signature, RESPONSE_SIGNATURE_OFFSET);
    return response;
  } catch (error) {
    response.fill(0);
    throw error;
  } finally {
    responsePlaintext?.fill(0);
    responseKemCiphertext?.fill(0);
    responseSharedSecret?.fill(0);
    responseCombinedSecret?.fill(0);
    responseAad?.fill(0);
    responseSalt?.fill(0);
    responseKey?.fill(0);
    encrypted?.ciphertext?.fill(0);
    encrypted?.nonce?.fill(0);
    encrypted?.tag?.fill(0);
    signatureDigest?.fill(0);
    signature?.fill(0);
  }
}

export function createPqAnonymousHttpHandler({
  serverHybridKeyPair,
  dispatchOperation,
  claimReplay = claimReplayId
}) {
  if (
    !serverHybridKeyPair?.kyber?.secretKey ||
    !serverHybridKeyPair?.dilithium?.secretKey ||
    !serverHybridKeyPair?.x25519?.secretKey ||
    typeof dispatchOperation !== 'function' ||
    typeof claimReplay !== 'function'
  ) {
    throw new Error('PQ anonymous HTTP transport requires complete server key material');
  }

  const fingerprint = computeHybridPublicKeyFingerprint(serverHybridKeyPair);
  const fingerprintBytes = Buffer.from(fingerprint, 'hex');
  const localReplayIds = new Map();
  const allowRequest = createTokenBucketRateLimiter(MAX_REQUESTS_PER_SECOND);
  let inflight = 0;

  return async function pqAnonymousHttpHandler(req, res) {
    const requestBody = Buffer.isBuffer(req.body) ? req.body : null;
    let admitted = false;
    let requestKemCiphertext = null;
    let requestKemSecret = null;
    let clientKemPublicKey = null;
    let clientX25519PublicKey = null;
    let x25519Secret = null;
    let combinedSecret = null;
    let requestAad = null;
    let requestSalt = null;
    let requestKey = null;
    let powSeed = null;
    let plaintext = null;
    let parsedRequest = null;
    let responseBody = null;
    try {
      if (
        !requestBody ||
        !REQUEST_CLASS_BYTES.has(requestBody[9]) ||
        REQUEST_CLASS_BYTES.get(requestBody[9]) !== requestBody.length
      ) {
        await reject(res, 'request-size-class');
        return;
      }

      powSeed = requestPowSeed(requestBody);
      if (!verifyPowSolution(
        Buffer.from(powSeed).toString('base64'),
        REQUEST_POW_DIFFICULTY,
        requestBody.subarray(REQUEST_POW_SOLUTION_OFFSET, REQUEST_PREFIX_BYTES).toString('base64')
      )) {
        await reject(res, 'admission-work');
        return;
      }

      if (
        !crypto.timingSafeEqual(requestBody.subarray(0, 8), REQUEST_MAGIC) ||
        requestBody[8] !== WIRE_VERSION ||
        requestBody[10] !== 0 ||
        requestBody[11] !== 0
      ) {
        await reject(res, 'request-magic-or-wire-version');
        return;
      }

      const requestTimestampBig = requestBody.readBigUInt64BE(12);
      if (
        requestTimestampBig > BigInt(Number.MAX_SAFE_INTEGER) ||
        Math.abs(Number(requestTimestampBig) - Date.now()) > MAX_CLOCK_SKEW_MS ||
        !crypto.timingSafeEqual(requestBody.subarray(52, 84), fingerprintBytes)
      ) {
        await reject(res, 'clock-skew-or-server-fingerprint');
        return;
      }

      const requestId = requestBody.subarray(20, 52);
      const replayId = privateLookupId(
        PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REPLAY,
        requestId.toString('hex')
      );
      if ((localReplayIds.get(replayId) || 0) > Date.now()) {
        await reject(res, 'replay-local');
        return;
      }
      if (!allowRequest() || inflight >= MAX_INFLIGHT) {
        await reject(res, 'rate-limit-or-inflight-cap');
        return;
      }
      inflight += 1;
      admitted = true;

      const replayClaim = await claimReplay(replayId);
      if (replayClaim !== 'claimed') {
        await reject(res, `replay-claim-${replayClaim}`);
        return;
      }
      rememberLocalReplay(localReplayIds, replayId);

      requestKemCiphertext = new Uint8Array(requestBody.subarray(84, 84 + ML_KEM_CIPHERTEXT_BYTES));
      requestKemSecret = await CryptoUtils.Kyber.decapsulate(
        requestKemCiphertext,
        serverHybridKeyPair.kyber.secretKey
      );
      clientKemPublicKey = new Uint8Array(requestBody.subarray(
        84 + ML_KEM_CIPHERTEXT_BYTES,
        84 + ML_KEM_CIPHERTEXT_BYTES + ML_KEM_PUBLIC_KEY_BYTES
      ));
      clientX25519PublicKey = new Uint8Array(requestBody.subarray(
        84 + ML_KEM_CIPHERTEXT_BYTES + ML_KEM_PUBLIC_KEY_BYTES,
        REQUEST_POW_NONCE_OFFSET
      ));
      x25519Secret = CryptoUtils.Hybrid.computeClassicalSharedSecret(
        serverHybridKeyPair.x25519.secretKey,
        clientX25519PublicKey
      );
      requestAad = Buffer.concat([
        REQUEST_AAD_DOMAIN,
        requestBody.subarray(0, REQUEST_PREFIX_BYTES)
      ]);
      requestSalt = PostQuantumHash.blake3(requestAad);
      combinedSecret = new Uint8Array(requestKemSecret.length + x25519Secret.length);
      combinedSecret.set(requestKemSecret, 0);
      combinedSecret.set(x25519Secret, requestKemSecret.length);
      requestKey = PostQuantumHash.deriveKey(
        combinedSecret,
        requestSalt,
        PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_KDF,
        POST_QUANTUM_AEAD_KEY_BYTES
      );
      plaintext = CryptoUtils.PostQuantumAEAD.decrypt(
        requestBody.subarray(REQUEST_CIPHERTEXT_OFFSET),
        requestBody.subarray(REQUEST_NONCE_OFFSET, REQUEST_TAG_OFFSET),
        requestBody.subarray(REQUEST_TAG_OFFSET, REQUEST_CIPHERTEXT_OFFSET),
        requestKey,
        requestAad
      );
      parsedRequest = parsePaddedRequest(plaintext);
      const policy = parsedRequest ? OPERATION_POLICY[parsedRequest.operation] : null;
      if (
        !parsedRequest ||
        !policy ||
        policy.requestClass !== requestBody[9] ||
        policy.requestBytes !== requestBody.length
      ) {
        await reject(
          res,
          parsedRequest ? `operation-policy-mismatch:${parsedRequest.operation}` : 'request-undecryptable-or-malformed'
        );
        return;
      }

      let payload;
      try {
        payload = await dispatchOperation(parsedRequest.operation, parsedRequest.body);
      } catch {
        payload = { ok: false, error: ANONYMOUS_OPERATION_FAILED };
      }

      responseBody = await encodeResponse({
        policy,
        payload,
        requestId,
        fingerprintBytes,
        requestKey,
        clientKemPublicKey,
        serverHybridKeyPair
      });
      await sendBinaryResponse(res, responseBody);
    } catch (error) {
      console.warn('[PQ-ANONYMOUS-HTTP] rejected anonymous request', {
        reason: 'unhandled',
        error: error?.message || String(error),
      });
      if (!res.headersSent && !res.writableEnded) await sendOpaqueFailure(res);
    } finally {
      if (admitted) inflight = Math.max(0, inflight - 1);
      requestBody?.fill(0);
      requestKemCiphertext?.fill(0);
      requestKemSecret?.fill(0);
      clientKemPublicKey?.fill(0);
      clientX25519PublicKey?.fill(0);
      x25519Secret?.fill(0);
      combinedSecret?.fill(0);
      requestAad?.fill(0);
      requestSalt?.fill(0);
      requestKey?.fill(0);
      powSeed?.fill(0);
      plaintext?.fill(0);
      scrubRequestTree(parsedRequest);
      responseBody?.fill(0);
    }
  };
}
