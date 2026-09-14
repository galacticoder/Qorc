import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumKEM } from '../cryptography/kem';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumSignature } from '../cryptography/signature';
import { solvePowChallenge } from '../cryptography/proof-of-work';
import { anonymousHttp } from '../tauri-bindings';
import { PostQuantumUtils } from '../utils/pq-utils';
import { computeX25519SharedSecret, generateX25519KeyPair } from '../utils/noise-utils';
import websocketClient from '../websocket/websocket';
import { hasExactKeys, isPlainRecord } from '../sanitizers';
import { AnonymousRequestLane } from './anonymous-request-lane';
import type { AnonymousServerContext } from './anonymous-server-trust';
import {
  assertCurrentServerContext,
  captureCurrentServerContext,
  type CurrentServerContext,
} from '../security/local-account-scope';
import {
  ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
  DISCOVERY_LOOKUP_TIMEOUT_MS,
  isAnonymousResponseTimestampValid,
} from '../../../shared/anonymous-transfer-policy.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import {
  AVATAR_BLOB_GET_AUDIENCE,
  AVATAR_BLOB_PUT_AUDIENCE,
  AVATAR_POOL_AUDIENCE,
  DISCOVERY_BUCKET_AUDIENCE,
  DISCOVERY_MANIFEST_AUDIENCE,
  KEY_TRANSPARENCY_APPEND_AUDIENCE,
  KEY_TRANSPARENCY_SYNC_AUDIENCE,
  OPRF_EVALUATE_AUDIENCE,
  SPOOL_PIR_AUDIENCE,
  SPOOL_TAG_INDEX_AUDIENCE,
} from '../config/audiences';
import {
  KEY_TRANSPARENCY_SYNC_RESPONSE_BYTES,
  KEY_TRANSPARENCY_SYNC_RESPONSE_CLASS,
} from '../../../shared/key-transparency-protocol.js';
import {
  ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET,
  ANONYMOUS_HTTP_REQUEST_LARGE_BYTES,
  ANONYMOUS_HTTP_REQUEST_PIR_BYTES,
  ANONYMOUS_HTTP_REQUEST_POW_NONCE_OFFSET,
  ANONYMOUS_HTTP_REQUEST_POW_SOLUTION_OFFSET,
  ANONYMOUS_HTTP_REQUEST_PREFIX_BYTES,
  ANONYMOUS_HTTP_REQUEST_SMALL_BYTES,
  ANONYMOUS_HTTP_REQUEST_TAG_OFFSET,
  ANONYMOUS_HTTP_RESPONSE_AVATAR_BYTES,
  ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET,
  ANONYMOUS_HTTP_RESPONSE_PIR_BYTES,
  ANONYMOUS_HTTP_RESPONSE_PREFIX_BYTES,
  ANONYMOUS_HTTP_RESPONSE_SIGNATURE_OFFSET,
  ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES,
  ANONYMOUS_HTTP_RESPONSE_TAG_INDEX_BYTES,
  ANONYMOUS_HTTP_RESPONSE_TAG_OFFSET,
  ANONYMOUS_HTTP_WIRE_VERSION,
} from '../../../shared/anonymous-http-layout.js';
import { ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES, POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES } from '../../../shared/crypto-sizes.js';
import { SecureMemory } from '../cryptography/secure-memory';
import { Base64 } from '../cryptography/base64';
import { concatUint8Arrays } from '../../../shared/bytes.js';
import { PostQuantumHash } from '../../../shared/post-quantum-hash.js';

export type AnonymousHttpOperation =
  | typeof AVATAR_BLOB_GET_AUDIENCE
  | typeof AVATAR_BLOB_PUT_AUDIENCE
  | typeof AVATAR_POOL_AUDIENCE
  | typeof DISCOVERY_BUCKET_AUDIENCE
  | typeof DISCOVERY_MANIFEST_AUDIENCE
  | typeof KEY_TRANSPARENCY_SYNC_AUDIENCE
  | typeof KEY_TRANSPARENCY_APPEND_AUDIENCE
  | typeof OPRF_EVALUATE_AUDIENCE
  | typeof SPOOL_TAG_INDEX_AUDIENCE
  | typeof SPOOL_PIR_AUDIENCE;

const REQUEST_MAGIC = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_MAGIC);
const RESPONSE_MAGIC = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_MAGIC);
const REQUEST_AAD_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_AAD);
const RESPONSE_AAD_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_AAD);
const RESPONSE_SIGNATURE_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_SIGNATURE);
const REQUEST_POW_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_ADMISSION_POW);




const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const REQUEST_POW_DIFFICULTY = 12;
const MAX_CONCURRENT_REQUESTS = 4;
const MAX_QUEUED_REQUESTS = 64;
const QUEUE_TIMEOUT_MS = 3 * 60 * 1000;
const RESERVED_JSON_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

const OPERATION_POLICY: Readonly<Record<AnonymousHttpOperation, {
  requestClass: number;
  requestBytes: number;
  responseClass: number;
  responseBytes: number;
}>> = Object.freeze({
  [AVATAR_BLOB_GET_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 2, responseBytes: ANONYMOUS_HTTP_RESPONSE_AVATAR_BYTES },
  [AVATAR_BLOB_PUT_AUDIENCE]: { requestClass: 2, requestBytes: ANONYMOUS_HTTP_REQUEST_LARGE_BYTES, responseClass: 1, responseBytes: ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES },
  [AVATAR_POOL_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES },
  [DISCOVERY_BUCKET_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 4, responseBytes: ANONYMOUS_DISCOVERY_RESPONSE_BYTES },
  [DISCOVERY_MANIFEST_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES },
  [KEY_TRANSPARENCY_SYNC_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: KEY_TRANSPARENCY_SYNC_RESPONSE_CLASS, responseBytes: KEY_TRANSPARENCY_SYNC_RESPONSE_BYTES },
  [KEY_TRANSPARENCY_APPEND_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES },
  [OPRF_EVALUATE_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES },
  [SPOOL_TAG_INDEX_AUDIENCE]: { requestClass: 1, requestBytes: ANONYMOUS_HTTP_REQUEST_SMALL_BYTES, responseClass: 3, responseBytes: ANONYMOUS_HTTP_RESPONSE_TAG_INDEX_BYTES },
  [SPOOL_PIR_AUDIENCE]: { requestClass: 3, requestBytes: ANONYMOUS_HTTP_REQUEST_PIR_BYTES, responseClass: 5, responseBytes: ANONYMOUS_HTTP_RESPONSE_PIR_BYTES },
});

const primaryRequestLane = new AnonymousRequestLane(MAX_CONCURRENT_REQUESTS, MAX_QUEUED_REQUESTS, QUEUE_TIMEOUT_MS);
const discoveryRequestLane = new AnonymousRequestLane(2, 16, DISCOVERY_LOOKUP_TIMEOUT_MS);
const bulkRequestLane = new AnonymousRequestLane(3, MAX_QUEUED_REQUESTS, DISCOVERY_LOOKUP_TIMEOUT_MS);

function isBulkTransportOperation(operation: AnonymousHttpOperation): boolean {
  const policy = OPERATION_POLICY[operation];
  return policy.requestBytes > ANONYMOUS_HTTP_REQUEST_SMALL_BYTES || policy.responseBytes > ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES;
}


function isSafeResponseTree(root: unknown): boolean {
  const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const { value, depth } = stack.pop()!;
    nodes += 1;
    if (nodes > 500_000 || depth > 32) return false;
    if (!value || typeof value !== 'object') continue;
    if (!Array.isArray(value) && !isPlainRecord(value)) return false;
    for (const [key, child] of Object.entries(value)) {
      if (key.length > 256 || RESERVED_JSON_KEYS.has(key)) return false;
      stack.push({ value: child, depth: depth + 1 });
    }
  }
  return true;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && SecureMemory.constantTimeCompare(left, right);
}

function assertMagic(body: Uint8Array, expected: Uint8Array): void {
  if (!bytesEqual(body.subarray(0, expected.length), expected)) {
    throw new Error('Invalid anonymous transport response');
  }
}

function writeTimestamp(view: DataView, offset: number, timestamp: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new Error('Invalid anonymous transport timestamp');
  }
  view.setBigUint64(offset, BigInt(timestamp), false);
}

function readTimestamp(view: DataView, offset: number): number {
  const value = view.getBigUint64(offset, false);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('Invalid anonymous transport timestamp');
  }
  return Number(value);
}

function responseSignatureDigest(body: Uint8Array): Uint8Array {
  return PostQuantumHash.digestParts([
    RESPONSE_SIGNATURE_DOMAIN,
    body.subarray(0, ANONYMOUS_HTTP_RESPONSE_SIGNATURE_OFFSET),
    body.subarray(ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET),
  ]);
}

function requestPowSeed(body: Uint8Array): Uint8Array {
  return PostQuantumHash.digestParts([
    REQUEST_POW_DOMAIN,
    body.subarray(0, ANONYMOUS_HTTP_REQUEST_POW_SOLUTION_OFFSET),
  ], 16);
}

function decodeRawResponse(value: ArrayBuffer | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error('Invalid native anonymous transport response');
}

function decodePaddedResponse(plaintext: Uint8Array): unknown {
  if (plaintext.length < 5) throw new Error('Invalid anonymous transport response');
  const jsonLength = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength
  ).getUint32(0, false);
  if (jsonLength < 2 || jsonLength > plaintext.length - 4) {
    throw new Error('Invalid anonymous transport response');
  }
  const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
    plaintext.subarray(4, 4 + jsonLength)
  );
  const wrapper = JSON.parse(decoded) as unknown;
  if (
    !isPlainRecord(wrapper) ||
    !hasExactKeys(wrapper, ['payload', 'version']) ||
    wrapper.version !== PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_PROTOCOL ||
    !isPlainRecord(wrapper.payload) ||
    !isSafeResponseTree(wrapper.payload)
  ) {
    throw new Error('Invalid anonymous transport response');
  }
  return wrapper.payload;
}

async function executeAnonymousHttpRequest(
  operation: AnonymousHttpOperation,
  body: Record<string, unknown>,
  serverContext: CurrentServerContext,
  authentication: AnonymousServerContext,
  signal: AbortSignal,
  onProgress?: (receivedBytes: number) => void,
): Promise<unknown> {
  signal?.throwIfAborted();
  const policy = OPERATION_POLICY[operation];
  if (!policy || !isPlainRecord(body)) throw new Error('Invalid anonymous transport request');
  const serverMaterial = authentication.material;
  const trustedNow = authentication.now();
  if (!/^[a-f0-9]{64}$/.test(serverMaterial.fingerprint)) {
    throw new Error('Invalid authenticated server fingerprint');
  }

  const requestId = PostQuantumRandom.randomBytes(32);
  const fingerprint = PostQuantumUtils.hexToBytes(serverMaterial.fingerprint);
  const request = new Uint8Array(policy.requestBytes);
  const requestView = new DataView(request.buffer);
  const requestPlaintextBytes = policy.requestBytes - ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET - POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES;
  let staticKemCiphertext: Uint8Array | null = null;
  let staticKemSecret: Uint8Array | null = null;
  let clientKemKeyPair: Awaited<ReturnType<typeof PostQuantumKEM.generateKeyPair>> | null = null;
  let x25519KeyPair: ReturnType<typeof generateX25519KeyPair> | null = null;
  let x25519Secret: Uint8Array | null = null;
  let combinedSecret: Uint8Array | null = null;
  let requestSalt: Uint8Array | null = null;
  let requestKey: Uint8Array | null = null;
  let requestAad: Uint8Array | null = null;
  let requestPlaintext: Uint8Array | null = null;
  let requestPowNonce: Uint8Array | null = null;
  let requestPowSeedBytes: Uint8Array | null = null;
  let requestPowSolution: Uint8Array | null = null;
  let encryptedRequest: Awaited<ReturnType<typeof PostQuantumAEAD.encryptAsync>> | null = null;
  let response: Uint8Array | null = null;
  let responseKemCiphertext: Uint8Array | null = null;
  let responseSharedSecret: Uint8Array | null = null;
  let responseCombinedSecret: Uint8Array | null = null;
  let responseAad: Uint8Array | null = null;
  let responseSalt: Uint8Array | null = null;
  let responseKey: Uint8Array | null = null;
  let signatureDigest: Uint8Array | null = null;
  let plaintextResponse: Uint8Array | null = null;
  try {
    const staticEncapsulation = await PostQuantumKEM.encapsulate(serverMaterial.kyberPublicKey);
    staticKemCiphertext = staticEncapsulation.ciphertext;
    staticKemSecret = staticEncapsulation.sharedSecret;
    clientKemKeyPair = await PostQuantumKEM.generateKeyPair();
    x25519KeyPair = generateX25519KeyPair();
    x25519Secret = computeX25519SharedSecret(
      x25519KeyPair.secretKey,
      serverMaterial.x25519PublicKey!
    );

    request.set(REQUEST_MAGIC, 0);
    request[8] = ANONYMOUS_HTTP_WIRE_VERSION;
    request[9] = policy.requestClass;
    request[10] = 0;
    request[11] = 0;
    writeTimestamp(requestView, 12, trustedNow);
    request.set(requestId, 20);
    request.set(fingerprint, 52);
    request.set(staticKemCiphertext, 84);
    request.set(clientKemKeyPair.publicKey, 84 + ML_KEM_1024_CIPHERTEXT_BYTES);
    request.set(x25519KeyPair.publicKey, 84 + ML_KEM_1024_CIPHERTEXT_BYTES + ML_KEM_1024_PUBLIC_KEY_BYTES);
    requestPowNonce = PostQuantumRandom.randomBytes(16);
    request.set(requestPowNonce, ANONYMOUS_HTTP_REQUEST_POW_NONCE_OFFSET);
    requestPowSeedBytes = requestPowSeed(request);
    const requestPowSolutionBase64 = await solvePowChallenge({
      seed: Base64.arrayBufferToBase64(requestPowSeedBytes),
      difficulty: REQUEST_POW_DIFFICULTY,
    }, signal);
    requestPowSolution = PostQuantumUtils.base64ToUint8Array(requestPowSolutionBase64);
    if (
      requestPowSolution.length !== 8 ||
      Base64.arrayBufferToBase64(requestPowSolution) !== requestPowSolutionBase64
    ) {
      throw new Error('Invalid anonymous transport admission work');
    }
    request.set(requestPowSolution, ANONYMOUS_HTTP_REQUEST_POW_SOLUTION_OFFSET);

    requestAad = concatUint8Arrays(REQUEST_AAD_DOMAIN, request.subarray(0, ANONYMOUS_HTTP_REQUEST_PREFIX_BYTES));
    requestSalt = PostQuantumHash.blake3(requestAad);
    combinedSecret = concatUint8Arrays(staticKemSecret, x25519Secret);
    requestKey = PostQuantumHash.deriveKey(
      combinedSecret,
      requestSalt,
      PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_KDF,
      32
    );

    const encodedRequest = new TextEncoder().encode(JSON.stringify({
      version: PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_PROTOCOL,
      operation,
      body,
    }));
    try {
      if (encodedRequest.length > requestPlaintextBytes - 4) {
        throw new Error('Anonymous transport request exceeds its fixed size class');
      }
      
      requestPlaintext = new Uint8Array(requestPlaintextBytes);
      PostQuantumRandom.fillRandomBytes(requestPlaintext);
      new DataView(requestPlaintext.buffer).setUint32(0, encodedRequest.length, false);
      requestPlaintext.set(encodedRequest, 4);
    } finally {
      encodedRequest.fill(0);
    }

    encryptedRequest = await PostQuantumAEAD.encryptAsync(requestPlaintext, requestKey, requestAad);
    if (encryptedRequest.ciphertext.length !== policy.requestBytes - ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET) {
      throw new Error('Invalid anonymous transport request encryption');
    }
    request.set(encryptedRequest.nonce, ANONYMOUS_HTTP_REQUEST_PREFIX_BYTES);
    request.set(encryptedRequest.tag, ANONYMOUS_HTTP_REQUEST_TAG_OFFSET);
    request.set(encryptedRequest.ciphertext, ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET);

    await assertCurrentServerContext(serverContext);
    signal.throwIfAborted();
    const nativeResponse = await anonymousHttp.fetch(
      request,
      serverContext.serverUrl,
      { responseBytes: policy.responseBytes, signal, onProgress },
    );
    signal?.throwIfAborted();
    response = decodeRawResponse(nativeResponse);
    await assertCurrentServerContext(serverContext);
    signal.throwIfAborted();
    if (
      response.length !== policy.responseBytes ||
      response[8] !== ANONYMOUS_HTTP_WIRE_VERSION ||
      response[9] !== policy.responseClass ||
      response[10] !== 0 ||
      response[11] !== 0
    ) {
      const lengthOk = response.length === policy.responseBytes;
      const magicOk = bytesEqual(response.subarray(0, 8), RESPONSE_MAGIC);
      if (!magicOk && (lengthOk || response.length === ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES)) {
        throw new Error(
          `Anonymous transport request was rejected by the server (${operation}); ` +
          `the response is an opaque failure, so the reason is only in the server log`
        );
      }
      throw new Error(
        `Invalid anonymous transport response class for ${operation}: ` +
        `bytes ${response.length}/${policy.responseBytes}, ` +
        `wire ${response[8]}/${ANONYMOUS_HTTP_WIRE_VERSION}, ` +
        `class ${response[9]}/${policy.responseClass}, ` +
        `reserved ${response[10]},${response[11]}`
      );
    }
    assertMagic(response, RESPONSE_MAGIC);
    if (!bytesEqual(response.subarray(12, 44), requestId)) {
      throw new Error('Anonymous transport response request binding failed');
    }
    const responseView = new DataView(response.buffer, response.byteOffset, response.byteLength);
    const responseTimestamp = readTimestamp(responseView, 44);
    const currentTrustedNow = authentication.now();
    if (!isAnonymousResponseTimestampValid(responseTimestamp, trustedNow, currentTrustedNow, MAX_CLOCK_SKEW_MS)) {
      throw new Error('Anonymous transport response timestamp is invalid');
    }
    if (!bytesEqual(response.subarray(52, 84), fingerprint)) {
      throw new Error('Anonymous transport response fingerprint mismatch');
    }

    signatureDigest = responseSignatureDigest(response);
    const responseSignature = response.subarray(
      ANONYMOUS_HTTP_RESPONSE_SIGNATURE_OFFSET,
      ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET
    );
    if (!await PostQuantumSignature.verify(
      responseSignature,
      signatureDigest,
      serverMaterial.dilithiumPublicKey!
    )) {
      throw new Error('Anonymous transport response authentication failed');
    }

    responseKemCiphertext = new Uint8Array(response.subarray(84, ANONYMOUS_HTTP_RESPONSE_PREFIX_BYTES));
    responseSharedSecret = await PostQuantumKEM.decapsulate(
      responseKemCiphertext,
      clientKemKeyPair.secretKey
    );
    responseAad = concatUint8Arrays(RESPONSE_AAD_DOMAIN, response.subarray(0, ANONYMOUS_HTTP_RESPONSE_PREFIX_BYTES));
    responseSalt = PostQuantumHash.blake3(responseAad);
    responseCombinedSecret = concatUint8Arrays(requestKey, responseSharedSecret);
    responseKey = PostQuantumHash.deriveKey(
      responseCombinedSecret,
      responseSalt,
      PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_KDF,
      32
    );
    plaintextResponse = await PostQuantumAEAD.decryptAsync(
      response.subarray(ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET),
      response.subarray(ANONYMOUS_HTTP_RESPONSE_PREFIX_BYTES, ANONYMOUS_HTTP_RESPONSE_TAG_OFFSET),
      response.subarray(ANONYMOUS_HTTP_RESPONSE_TAG_OFFSET, ANONYMOUS_HTTP_RESPONSE_SIGNATURE_OFFSET),
      responseKey,
      responseAad
    );
    await assertCurrentServerContext(serverContext);
    signal.throwIfAborted();
    return decodePaddedResponse(plaintextResponse);
  } finally {
    requestId.fill(0);
    fingerprint.fill(0);
    request.fill(0);
    staticKemCiphertext?.fill(0);
    staticKemSecret?.fill(0);
    clientKemKeyPair?.publicKey.fill(0);
    clientKemKeyPair?.secretKey.fill(0);
    x25519KeyPair?.publicKey.fill(0);
    x25519KeyPair?.secretKey.fill(0);
    x25519Secret?.fill(0);
    combinedSecret?.fill(0);
    requestSalt?.fill(0);
    requestKey?.fill(0);
    requestAad?.fill(0);
    requestPlaintext?.fill(0);
    requestPowNonce?.fill(0);
    requestPowSeedBytes?.fill(0);
    requestPowSolution?.fill(0);
    encryptedRequest?.ciphertext.fill(0);
    encryptedRequest?.nonce.fill(0);
    encryptedRequest?.tag.fill(0);
    response?.fill(0);
    responseKemCiphertext?.fill(0);
    responseSharedSecret?.fill(0);
    responseCombinedSecret?.fill(0);
    responseAad?.fill(0);
    responseSalt?.fill(0);
    responseKey?.fill(0);
    signatureDigest?.fill(0);
    plaintextResponse?.fill(0);
  }
}

export async function anonymousHttpFetch(
  operation: AnonymousHttpOperation,
  body: Record<string, unknown>,
  expectedServerUrl: string,
  options: { signal?: AbortSignal; onProgress?: (receivedBytes: number) => void } = {},
): Promise<unknown> {
  options.signal?.throwIfAborted();
  const authentication = websocketClient.captureAnonymousHttpContext();
  if (!authentication) {
    throw new Error('Authenticated PQ server transport is unavailable');
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  authentication.signal.addEventListener('abort', abort, { once: true });
  options.signal?.addEventListener('abort', abort, { once: true });
  if (authentication.signal.aborted || options.signal?.aborted) abort();
  const timer = setTimeout(abort, DISCOVERY_LOOKUP_TIMEOUT_MS);
  let releaseDiscovery: (() => void) | undefined;
  let release: (() => void) | undefined;
  try {
    controller.signal.throwIfAborted();
    const serverContext = await captureCurrentServerContext(authentication.material);
    if (serverContext.serverUrl !== expectedServerUrl) {
      throw new Error('Authenticated server changed before anonymous request');
    }
    if (operation === DISCOVERY_BUCKET_AUDIENCE) {
      releaseDiscovery = await discoveryRequestLane.acquire(controller.signal);
    }
    release = await (isBulkTransportOperation(operation) ? bulkRequestLane : primaryRequestLane).acquire(controller.signal);
    await assertCurrentServerContext(serverContext);
    controller.signal.throwIfAborted();
    return await executeAnonymousHttpRequest(
      operation,
      body,
      serverContext,
      authentication,
      controller.signal,
      options.onProgress,
    );
  } finally {
    release?.();
    releaseDiscovery?.();
    clearTimeout(timer);
    authentication.signal.removeEventListener('abort', abort);
    options.signal?.removeEventListener('abort', abort);
    authentication.material.kyberPublicKey.fill(0);
    authentication.material.dilithiumPublicKey?.fill(0);
    authentication.material.x25519PublicKey?.fill(0);
  }
}
