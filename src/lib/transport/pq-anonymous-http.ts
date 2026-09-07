import {
  PQ_AEAD_CIPHERTEXT_OVERHEAD,
  PQ_AEAD_MAC_SIZE,
  PQ_AEAD_NONCE_SIZE,
  PQ_KEM_CIPHERTEXT_SIZE,
  PQ_KEM_PUBLIC_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE,
} from '../constants';
import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumHash } from '../cryptography/hash';
import { PostQuantumKEM } from '../cryptography/kem';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumSignature } from '../cryptography/signature';
import { solvePowChallenge } from '../cryptography/proof-of-work';
import { anonymousHttp } from '../tauri-bindings';
import { PostQuantumUtils } from '../utils/pq-utils';
import { computeX25519SharedSecret, generateX25519KeyPair } from '../utils/noise-utils';
import websocketClient from '../websocket/websocket';
import { hasExactKeys, isPlainRecord } from '../sanitizers';
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

const WIRE_VERSION = 1;
const REQUEST_MAGIC = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_MAGIC);
const RESPONSE_MAGIC = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_MAGIC);
const REQUEST_AAD_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_REQUEST_AAD);
const RESPONSE_AAD_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_AAD);
const RESPONSE_SIGNATURE_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_SIGNATURE);
const REQUEST_POW_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_ADMISSION_POW);

const REQUEST_SMALL_BYTES = 64 * 1024;
const REQUEST_PIR_BYTES = 2 * 1024 * 1024;
const REQUEST_LARGE_BYTES = 512 * 1024;
const RESPONSE_SMALL_BYTES = 64 * 1024;
const RESPONSE_TAG_INDEX_BYTES = 512 * 1024;
const RESPONSE_PIR_BYTES = 1024 * 1024;
const RESPONSE_AVATAR_BYTES = 4 * 1024 * 1024;
const RESPONSE_DISCOVERY_BYTES = 8912896;

const REQUEST_POW_NONCE_OFFSET = 3252;
const REQUEST_POW_SOLUTION_OFFSET = REQUEST_POW_NONCE_OFFSET + 16;
const REQUEST_PREFIX_BYTES = REQUEST_POW_SOLUTION_OFFSET + 8;
const REQUEST_NONCE_OFFSET = REQUEST_PREFIX_BYTES;
const REQUEST_TAG_OFFSET = REQUEST_NONCE_OFFSET + PQ_AEAD_NONCE_SIZE;
const REQUEST_CIPHERTEXT_OFFSET = REQUEST_TAG_OFFSET + PQ_AEAD_MAC_SIZE;

const RESPONSE_PREFIX_BYTES = 1652;
const RESPONSE_NONCE_OFFSET = RESPONSE_PREFIX_BYTES;
const RESPONSE_TAG_OFFSET = RESPONSE_NONCE_OFFSET + PQ_AEAD_NONCE_SIZE;
const RESPONSE_SIGNATURE_OFFSET = RESPONSE_TAG_OFFSET + PQ_AEAD_MAC_SIZE;
const RESPONSE_CIPHERTEXT_OFFSET = RESPONSE_SIGNATURE_OFFSET + PQ_SIG_SIGNATURE_SIZE;

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
  [AVATAR_BLOB_GET_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 2, responseBytes: RESPONSE_AVATAR_BYTES },
  [AVATAR_BLOB_PUT_AUDIENCE]: { requestClass: 2, requestBytes: REQUEST_LARGE_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES },
  [AVATAR_POOL_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES },
  [DISCOVERY_BUCKET_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 4, responseBytes: RESPONSE_DISCOVERY_BYTES },
  [DISCOVERY_MANIFEST_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES },
  [KEY_TRANSPARENCY_SYNC_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: KEY_TRANSPARENCY_SYNC_RESPONSE_CLASS, responseBytes: KEY_TRANSPARENCY_SYNC_RESPONSE_BYTES },
  [KEY_TRANSPARENCY_APPEND_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES },
  [OPRF_EVALUATE_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 1, responseBytes: RESPONSE_SMALL_BYTES },
  [SPOOL_TAG_INDEX_AUDIENCE]: { requestClass: 1, requestBytes: REQUEST_SMALL_BYTES, responseClass: 3, responseBytes: RESPONSE_TAG_INDEX_BYTES },
  [SPOOL_PIR_AUDIENCE]: { requestClass: 3, requestBytes: REQUEST_PIR_BYTES, responseClass: 5, responseBytes: RESPONSE_PIR_BYTES },
});

interface RequestWaiter {
  resolve: () => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface RequestLaneState {
  active: number;
  readonly maxActive: number;
  readonly maxQueued: number;
  readonly waiters: RequestWaiter[];
}

const primaryRequestLane: RequestLaneState = {
  active: 0,
  maxActive: MAX_CONCURRENT_REQUESTS,
  maxQueued: MAX_QUEUED_REQUESTS,
  waiters: [],
};
const pirRequestLane: RequestLaneState = {
  active: 0,
  maxActive: 1,
  maxQueued: 16,
  waiters: [],
};

function isPirTransportOperation(operation: AnonymousHttpOperation): boolean {
  return operation === SPOOL_TAG_INDEX_AUDIENCE || operation === SPOOL_PIR_AUDIENCE;
}

async function acquireRequestSlot(lane: RequestLaneState): Promise<() => void> {
  if (lane.active < lane.maxActive) {
    lane.active += 1;
    return () => releaseRequestSlot(lane);
  }
  if (lane.waiters.length >= lane.maxQueued) {
    throw new Error('Anonymous transport queue is full');
  }

  await new Promise<void>((resolve, reject) => {
    const waiter = {
      resolve,
      reject,
      timer: setTimeout(() => {
        const index = lane.waiters.indexOf(waiter);
        if (index >= 0) lane.waiters.splice(index, 1);
        reject(new Error('Anonymous transport queue timed out'));
      }, QUEUE_TIMEOUT_MS),
    };
    lane.waiters.push(waiter);
  });
  return () => releaseRequestSlot(lane);
}

function releaseRequestSlot(lane: RequestLaneState): void {
  const waiter = lane.waiters.shift();
  if (waiter) {
    clearTimeout(waiter.timer);
    waiter.resolve();
    return;
  }
  lane.active = Math.max(0, lane.active - 1);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  return PostQuantumUtils.concatBytes(...parts);
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
  return left.length === right.length && PostQuantumUtils.timingSafeEqual(left, right);
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
    body.subarray(0, RESPONSE_SIGNATURE_OFFSET),
    body.subarray(RESPONSE_CIPHERTEXT_OFFSET),
  ]);
}

function requestPowSeed(body: Uint8Array): Uint8Array {
  return PostQuantumHash.digestParts([
    REQUEST_POW_DOMAIN,
    body.subarray(0, REQUEST_POW_SOLUTION_OFFSET),
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
  expectedServerUrl: string,
  connectionPrivacyEpoch: number,
): Promise<unknown> {
  const policy = OPERATION_POLICY[operation];
  if (!policy || !isPlainRecord(body)) throw new Error('Invalid anonymous transport request');
  if (typeof expectedServerUrl !== 'string' || expectedServerUrl.length === 0 || expectedServerUrl.length > 2048) {
    throw new Error('Invalid expected server URL');
  }

  const serverMaterial = websocketClient.getAnonymousHttpServerKeyMaterial();
  const trustedNow = websocketClient.getAuthenticatedServerNow();
  if (
    !websocketClient.isConnectionPrivacyEpochCurrent(connectionPrivacyEpoch) ||
    !serverMaterial ||
    trustedNow === null
  ) {
    throw new Error('Authenticated PQ server transport is unavailable');
  }
  if (!/^[a-f0-9]{64}$/.test(serverMaterial.fingerprint)) {
    throw new Error('Invalid authenticated server fingerprint');
  }

  const requestId = PostQuantumRandom.randomBytes(32);
  const fingerprint = PostQuantumUtils.hexToBytes(serverMaterial.fingerprint);
  const request = new Uint8Array(policy.requestBytes);
  const requestView = new DataView(request.buffer);
  const requestPlaintextBytes = policy.requestBytes - REQUEST_CIPHERTEXT_OFFSET - PQ_AEAD_CIPHERTEXT_OVERHEAD;
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
    request[8] = WIRE_VERSION;
    request[9] = policy.requestClass;
    request[10] = 0;
    request[11] = 0;
    writeTimestamp(requestView, 12, trustedNow);
    request.set(requestId, 20);
    request.set(fingerprint, 52);
    request.set(staticKemCiphertext, 84);
    request.set(clientKemKeyPair.publicKey, 84 + PQ_KEM_CIPHERTEXT_SIZE);
    request.set(x25519KeyPair.publicKey, 84 + PQ_KEM_CIPHERTEXT_SIZE + PQ_KEM_PUBLIC_KEY_SIZE);
    requestPowNonce = PostQuantumRandom.randomBytes(16);
    request.set(requestPowNonce, REQUEST_POW_NONCE_OFFSET);
    requestPowSeedBytes = requestPowSeed(request);
    const requestPowSolutionBase64 = await solvePowChallenge({
      seed: PostQuantumUtils.uint8ArrayToBase64(requestPowSeedBytes),
      difficulty: REQUEST_POW_DIFFICULTY,
    });
    requestPowSolution = PostQuantumUtils.base64ToUint8Array(requestPowSolutionBase64);
    if (
      requestPowSolution.length !== 8 ||
      PostQuantumUtils.uint8ArrayToBase64(requestPowSolution) !== requestPowSolutionBase64
    ) {
      throw new Error('Invalid anonymous transport admission work');
    }
    request.set(requestPowSolution, REQUEST_POW_SOLUTION_OFFSET);

    requestAad = concatBytes(REQUEST_AAD_DOMAIN, request.subarray(0, REQUEST_PREFIX_BYTES));
    requestSalt = PostQuantumHash.blake3(requestAad);
    combinedSecret = concatBytes(staticKemSecret, x25519Secret);
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
    if (encryptedRequest.ciphertext.length !== policy.requestBytes - REQUEST_CIPHERTEXT_OFFSET) {
      throw new Error('Invalid anonymous transport request encryption');
    }
    request.set(encryptedRequest.nonce, REQUEST_NONCE_OFFSET);
    request.set(encryptedRequest.tag, REQUEST_TAG_OFFSET);
    request.set(encryptedRequest.ciphertext, REQUEST_CIPHERTEXT_OFFSET);

    const nativeResponse = await anonymousHttp.fetch(
      request,
      expectedServerUrl,
      isPirTransportOperation(operation) ? 'pir' : 'primary'
    );
    if (!websocketClient.isConnectionPrivacyEpochCurrent(connectionPrivacyEpoch)) {
      throw new Error('Authenticated server transport changed during anonymous request');
    }
    response = decodeRawResponse(nativeResponse);
    if (
      response.length !== policy.responseBytes ||
      response[8] !== WIRE_VERSION ||
      response[9] !== policy.responseClass ||
      response[10] !== 0 ||
      response[11] !== 0
    ) {
      const lengthOk = response.length === policy.responseBytes;
      const magicOk = bytesEqual(response.subarray(0, 8), RESPONSE_MAGIC);
      if (!magicOk && (lengthOk || response.length === RESPONSE_SMALL_BYTES)) {
        throw new Error(
          `Anonymous transport request was rejected by the server (${operation}); ` +
          `the response is an opaque failure, so the reason is only in the server log`
        );
      }
      throw new Error(
        `Invalid anonymous transport response class for ${operation}: ` +
        `bytes ${response.length}/${policy.responseBytes}, ` +
        `wire ${response[8]}/${WIRE_VERSION}, ` +
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
    const currentTrustedNow = websocketClient.getAuthenticatedServerNow();
    if (currentTrustedNow === null || Math.abs(responseTimestamp - currentTrustedNow) > MAX_CLOCK_SKEW_MS) {
      throw new Error('Anonymous transport response timestamp is invalid');
    }
    if (!bytesEqual(response.subarray(52, 84), fingerprint)) {
      throw new Error('Anonymous transport response fingerprint mismatch');
    }

    const currentMaterial = websocketClient.getAnonymousHttpServerKeyMaterial();
    if (!currentMaterial || currentMaterial.fingerprint !== serverMaterial.fingerprint) {
      throw new Error('Authenticated server changed during anonymous request');
    }

    signatureDigest = responseSignatureDigest(response);
    const responseSignature = response.subarray(
      RESPONSE_SIGNATURE_OFFSET,
      RESPONSE_CIPHERTEXT_OFFSET
    );
    if (!await PostQuantumSignature.verify(
      responseSignature,
      signatureDigest,
      serverMaterial.dilithiumPublicKey!
    )) {
      throw new Error('Anonymous transport response authentication failed');
    }

    responseKemCiphertext = new Uint8Array(response.subarray(84, RESPONSE_PREFIX_BYTES));
    responseSharedSecret = await PostQuantumKEM.decapsulate(
      responseKemCiphertext,
      clientKemKeyPair.secretKey
    );
    responseAad = concatBytes(RESPONSE_AAD_DOMAIN, response.subarray(0, RESPONSE_PREFIX_BYTES));
    responseSalt = PostQuantumHash.blake3(responseAad);
    responseCombinedSecret = concatBytes(requestKey, responseSharedSecret);
    responseKey = PostQuantumHash.deriveKey(
      responseCombinedSecret,
      responseSalt,
      PROTOCOL_KEYS.PQ_ANONYMOUS_HTTP_RESPONSE_KDF,
      32
    );
    plaintextResponse = await PostQuantumAEAD.decryptAsync(
      response.subarray(RESPONSE_CIPHERTEXT_OFFSET),
      response.subarray(RESPONSE_NONCE_OFFSET, RESPONSE_TAG_OFFSET),
      response.subarray(RESPONSE_TAG_OFFSET, RESPONSE_SIGNATURE_OFFSET),
      responseKey,
      responseAad
    );
    if (!websocketClient.isConnectionPrivacyEpochCurrent(connectionPrivacyEpoch)) {
      throw new Error('Authenticated server transport changed during anonymous response');
    }
    return decodePaddedResponse(plaintextResponse);
  } finally {
    requestId.fill(0);
    fingerprint.fill(0);
    request.fill(0);
    serverMaterial.kyberPublicKey.fill(0);
    serverMaterial.dilithiumPublicKey?.fill(0);
    serverMaterial.x25519PublicKey?.fill(0);
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
): Promise<unknown> {
  const connectionPrivacyEpoch = websocketClient.captureConnectionPrivacyEpoch();
  if (!websocketClient.isConnectionPrivacyEpochCurrent(connectionPrivacyEpoch)) {
    throw new Error('Authenticated PQ server transport is unavailable');
  }
  const release = await acquireRequestSlot(
    isPirTransportOperation(operation) ? pirRequestLane : primaryRequestLane
  );
  try {
    if (!websocketClient.isConnectionPrivacyEpochCurrent(connectionPrivacyEpoch)) {
      throw new Error('Authenticated server transport changed while anonymous request was queued');
    }
    return await executeAnonymousHttpRequest(
      operation,
      body,
      expectedServerUrl,
      connectionPrivacyEpoch
    );
  } finally {
    release();
  }
}
