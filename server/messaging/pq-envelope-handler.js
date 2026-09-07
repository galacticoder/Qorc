/**
 * Post-Quantum Envelope Handler
 * 
 * Handles PQ handshake establishment and encrypted envelope processing
 */

import crypto from 'crypto';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { PostQuantumHash } from '../crypto/post-quantum-hash.js';

import { SignalType } from '../signals.js';
import { SERVER_CONSTANTS } from '../config/constants.js';
import { PQ_SESSION_REQUIRED } from '../config/error-codes.js';
import { REQUIRED_WS_PQ_HANDSHAKE, validatePqHandshakePolicy } from '../security/layer-agreement-policy.js';
import {
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES
} from '../../shared/crypto-sizes.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  createAuthChannelBinding,
} from '../../shared/auth-channel-binding.js';
import { encodeBase64AndWipeCopy, UTF8_ENCODER } from '../utils/encoding.js';
import { envInt } from '../utils/env.js';
import { HEX_32_RE, HEX_64_RE } from '../utils/patterns.js';
import { isSafeJsonTree, isSafeWireMessageType } from '../utils/validation.js';
import { computeHybridPublicKeyFingerprint } from '../crypto/hybrid-key-fingerprint.js';
import { createAbortableAdmissionGate } from '../utils/admission-gate.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import {
  AUTH_CHANNEL_BINDING_BYTES,
  HASH_OUTPUT_BYTES,
  POST_QUANTUM_AEAD_KEY_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES as WS_ENVELOPE_NONCE_BYTES,
  POST_QUANTUM_AEAD_TAG_BYTES as WS_ENVELOPE_TAG_BYTES,
  X25519_KEY_BYTES
} from '../utils/crypto-consts.js';

// Server signing key for authenticated handshake acknowledgements.
let serverDilithiumSigningKey = null;
const WS_MAX_REPLAY_WINDOW_MS = 5 * 60 * 1000;
const WS_MAX_ENCRYPTED_RESPONSE_BYTES = envInt(
  'WS_MAX_ENCRYPTED_RESPONSE_BYTES',
  12 * 1024 * 1024,
  1024 * 1024,
  64 * 1024 * 1024
);
const WS_ENVELOPE_MAX_JSON_DEPTH = 32;
const WS_ENVELOPE_MAX_JSON_NODES = 20_000;
const WS_ENCRYPTED_SEND_QUEUE_MAX_COUNT = envInt('WS_ENCRYPTED_SEND_QUEUE_MAX_COUNT', 64, 4, 1024);
const WS_ENCRYPTED_SEND_QUEUE_MAX_BYTES = envInt(
  'WS_ENCRYPTED_SEND_QUEUE_MAX_BYTES',
  24 * 1024 * 1024,
  4 * 1024 * 1024,
  256 * 1024 * 1024
);
const WS_DELIVERY_TIMEOUT_MS = envInt('WS_DELIVERY_TIMEOUT_MS', 30_000, 1_000, 120_000);
const WS_OPEN = 1;
const WS_CLOSING = 2;
const WS_CLOSED = 3;
const WS_CELL_MAGIC = Buffer.from('QORC', 'ascii');
const WS_CELL_VERSION = 1;
const WS_CELL_FLAGS = 0;
const WS_CELL_SESSION_OFFSET = 8;
const WS_CELL_FINGERPRINT_OFFSET = 24;
const WS_CELL_MESSAGE_ID_OFFSET = 56;
const WS_CELL_COUNTER_OFFSET = 72;
const WS_CELL_TIMESTAMP_OFFSET = 80;
const WS_CELL_CHUNK_INDEX_OFFSET = 88;
const WS_CELL_CHUNK_COUNT_OFFSET = 92;
const WS_CELL_TOTAL_LENGTH_OFFSET = 96;
const WS_CELL_PLAINTEXT_LENGTH_OFFSET = 100;
const WS_CELL_NONCE_OFFSET = 104;
const WS_CELL_TAG_OFFSET = WS_CELL_NONCE_OFFSET + WS_ENVELOPE_NONCE_BYTES;
const WS_CELL_CIPHERTEXT_OFFSET = WS_CELL_TAG_OFFSET + WS_ENVELOPE_TAG_BYTES;
const WS_CELL_HEADER_BYTES = WS_CELL_CIPHERTEXT_OFFSET;
const WS_CELL_CIPHERTEXT_OVERHEAD_BYTES = 32;
const WS_CELL_PLAINTEXT_BYTES = SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES
  - WS_CELL_HEADER_BYTES
  - WS_CELL_CIPHERTEXT_OVERHEAD_BYTES;
const WS_CELL_MAX_LOGICAL_BYTES = 24 * 1024 * 1024;
const WS_CELL_MAX_CHUNKS = Math.ceil(WS_CELL_MAX_LOGICAL_BYTES / WS_CELL_PLAINTEXT_BYTES);
const WS_CELL_MAX_CONCURRENT = 4;
const WS_CELL_MAX_BUFFERED_BYTES = 32 * 1024 * 1024;
const WS_CELL_REASSEMBLY_TIMEOUT_MS = 200_000;
const WS_CELL_AAD_DOMAIN = UTF8_ENCODER.encode(PROTOCOL_KEYS.WS_PQ_CELL_AAD);
const AUTH_CHANNEL_BOUND_REQUEST_FIELDS = new Map([
  [SignalType.AUTH_PIR_REQUEST, 'authRequestId'],
  [SignalType.SERVER_ENTRY_REQUEST, 'requestId'],
]);
const VERIFIED_AUTH_CHANNEL_BINDING = Symbol('qorc.verified-auth-channel-binding');

export function consumeVerifiedAuthChannelBinding(payload) {
  const binding = payload?.[VERIFIED_AUTH_CHANNEL_BINDING];
  if (!(binding instanceof Uint8Array) || binding.length !== AUTH_CHANNEL_BINDING_BYTES) {
    return null;
  }
  try {
    delete payload[VERIFIED_AUTH_CHANNEL_BINDING];
  } catch {
    binding.fill(0);
    return null;
  }
  return binding;
}

class WebSocketDeliveryClosedError extends Error {
  constructor(readyState, payloadType) {
    super(`WebSocket closed before encrypted response could be delivered: ${readyState}`);
    this.name = 'WebSocketDeliveryClosedError';
    this.code = 'WS_DELIVERY_CLOSED';
    this.readyState = readyState;
    this.payloadType = payloadType;
  }
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

function wsReadyState(ws) {
  return Number.isFinite(ws?.readyState) ? ws.readyState : -1;
}

function isWebSocketOpen(ws) {
  return wsReadyState(ws) === WS_OPEN;
}

function isClosedWebSocketState(state) {
  return state === WS_CLOSING || state === WS_CLOSED || state === -1;
}

function isWebSocketDeliveryClosedError(error) {
  return error?.code === 'WS_DELIVERY_CLOSED'
    || error?.name === 'WebSocketDeliveryClosedError'
    || /WebSocket (?:is )?(?:not open|closed|closing|CLOSED)/i.test(String(error?.message || ''));
}

function sendWebSocketFrameWithDeadline(ws, frame, timeoutMs = WS_DELIVERY_TIMEOUT_MS) {
  const boundedTimeoutMs = Number.isSafeInteger(timeoutMs)
    ? Math.min(WS_DELIVERY_TIMEOUT_MS, Math.max(1, timeoutMs))
    : WS_DELIVERY_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        if (typeof ws?.terminate === 'function') {
          ws.terminate();
        } else if (isWebSocketOpen(ws)) {
          ws.close?.(1013, 'Delivery timeout');
        }
      } catch { }
      resolve(false);
    }, boundedTimeoutMs);
    timer.unref?.();

    try {
      ws.send(frame, (error) => {
        if (!error) {
          finish(resolve, true);
          return;
        }
        if (isWebSocketDeliveryClosedError(error) || isClosedWebSocketState(wsReadyState(ws))) {
          finish(resolve, false);
          return;
        }
        finish(reject, error);
      });
    } catch (error) {
      finish(reject, error);
    }
  });
}

function wipeSession(session) {
  if (session) session.invalidated = true;
  if (session?.confirmationTimer) clearTimeout(session.confirmationTimer);
  if (session) session.confirmationTimer = null;
  try { session?.recvKey?.fill(0); } catch { }
  try { session?.sendKey?.fill(0); } catch { }
}

function writeSafeU64(buffer, offset, value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid fixed-cell integer');
  buffer.writeUInt32BE(Math.floor(value / 0x1_0000_0000), offset);
  buffer.writeUInt32BE(value >>> 0, offset + 4);
}

function readSafeU64(buffer, offset) {
  const value = buffer.readUInt32BE(offset) * 0x1_0000_0000 + buffer.readUInt32BE(offset + 4);
  return Number.isSafeInteger(value) ? value : null;
}

function discardSocketCellAssembly(ws, messageId) {
  const assemblies = ws?._pqCellAssemblies;
  const assembly = assemblies?.get(messageId);
  if (!assembly) return;
  clearTimeout(assembly.timer);
  for (const part of assembly.parts) part?.fill(0);
  assemblies.delete(messageId);
  ws._pqCellBufferedBytes = Math.max(
    0,
    Number(ws._pqCellBufferedBytes || 0) - assembly.totalLength
  );
}

function clearSocketCellAssemblies(ws) {
  const assemblies = ws?._pqCellAssemblies;
  if (assemblies instanceof Map) {
    for (const messageId of Array.from(assemblies.keys())) {
      discardSocketCellAssembly(ws, messageId);
    }
  }
  ws._pqCellAssemblies = undefined;
  ws._pqCellBufferedBytes = 0;
}

export function clearSocketPQSession(ws) {
  if (!ws) return false;
  clearSocketCellAssemblies(ws);
  const session = ws._pqSessionData;
  const pendingSession = ws._pqPendingSessionData;
  wipeSession(session);
  if (pendingSession !== session) wipeSession(pendingSession);
  ws._pqSessionData = undefined;
  ws._pqSessionId = undefined;
  ws._pqPendingSessionData = undefined;
  ws._pqPendingSessionId = undefined;
  ws._pqRekeyResolve?.();
  ws._pqRekeyResolve = undefined;
  ws._pqRekeyGate = undefined;
  return Boolean(session || pendingSession);
}

function armSocketPQConfirmationTimer(ws, session) {
  session.invalidated = false;
  session.confirmationTimer = setTimeout(() => {
    if (getSocketPQSession(ws, session.sessionId) !== session || session.confirmed === true) return;
    clearSocketPQSession(ws);
    if (isWebSocketOpen(ws)) ws.close(1008, 'PQ key confirmation required');
  }, PQ_HS_CONFIRM_TIMEOUT_MS);
  session.confirmationTimer.unref?.();
}

function createSocketPQActivationGate(ws) {
  if (ws._pqRekeyGate) throw new Error('PQ activation gate already exists');
  ws._pqRekeyGate = new Promise((resolve) => {
    ws._pqRekeyResolve = resolve;
  });
}

function resolveSocketPQActivationGate(ws) {
  ws._pqRekeyResolve?.();
  ws._pqRekeyResolve = undefined;
  ws._pqRekeyGate = undefined;
}

async function waitForSocketPQActivation(ws, payload) {
  const activationGate = ws?._pqRekeyGate;
  if (!activationGate) return true;

  let payloadBytes;
  try {
    const serialized = JSON.stringify(payload);
    if (typeof serialized !== 'string') throw new Error('invalid payload');
    payloadBytes = Buffer.byteLength(serialized, 'utf8');
  } catch {
    throw new Error('Invalid secure payload during PQ activation');
  }

  const waitingCount = Number(ws._pqActivationWaitCount || 0);
  const waitingBytes = Number(ws._pqActivationWaitBytes || 0);
  if (
    waitingCount >= WS_ENCRYPTED_SEND_QUEUE_MAX_COUNT ||
    waitingBytes + payloadBytes > WS_ENCRYPTED_SEND_QUEUE_MAX_BYTES
  ) {
    clearSocketPQSession(ws);
    if (isWebSocketOpen(ws)) ws.close(1013, 'PQ activation queue saturated');
    return false;
  }

  ws._pqActivationWaitCount = waitingCount + 1;
  ws._pqActivationWaitBytes = waitingBytes + payloadBytes;
  try {
    await activationGate;
    return isWebSocketOpen(ws);
  } finally {
    ws._pqActivationWaitCount = Math.max(0, Number(ws._pqActivationWaitCount || 0) - 1);
    ws._pqActivationWaitBytes = Math.max(
      0,
      Number(ws._pqActivationWaitBytes || 0) - payloadBytes
    );
  }
}

function installSocketPQSession(ws, session) {
  clearSocketPQSession(ws);
  armSocketPQConfirmationTimer(ws, session);
  ws._pqSessionData = session;
  ws._pqSessionId = session.sessionId;
  createSocketPQActivationGate(ws);
}

function stageSocketPQSession(ws, session) {
  const current = ws?._pqSessionData;
  if (!current || current.confirmed !== true || ws._pqPendingSessionData) {
    throw new Error('PQ rekey cannot be staged in the current socket state');
  }
  armSocketPQConfirmationTimer(ws, session);
  ws._pqPendingSessionData = session;
  ws._pqPendingSessionId = session.sessionId;
  createSocketPQActivationGate(ws);
}

function discardStagedSocketPQSession(ws, expectedSession) {
  const pending = ws?._pqPendingSessionData;
  if (!pending || (expectedSession && pending !== expectedSession)) return false;
  wipeSession(pending);
  ws._pqPendingSessionData = undefined;
  ws._pqPendingSessionId = undefined;
  resolveSocketPQActivationGate(ws);
  return true;
}

function promoteStagedSocketPQSession(ws, session) {
  if (ws?._pqPendingSessionData !== session || ws._pqPendingSessionId !== session.sessionId) {
    throw new Error('PQ rekey session is no longer staged');
  }
  const previous = ws._pqSessionData;
  ws._pqSessionData = session;
  ws._pqSessionId = session.sessionId;
  ws._pqPendingSessionData = undefined;
  ws._pqPendingSessionId = undefined;
  resolveSocketPQActivationGate(ws);
  if (previous && previous !== session) wipeSession(previous);
}

function getSocketPQSession(ws, sessionId = ws?._pqSessionId) {
  const session = ws?._pqSessionId === sessionId
    ? ws?._pqSessionData
    : ws?._pqPendingSessionId === sessionId
      ? ws?._pqPendingSessionData
      : null;
  if (
    !session ||
    typeof sessionId !== 'string' ||
    session.sessionId !== sessionId ||
    session.invalidated === true
  ) {
    return null;
  }
  return session;
}

function consumeSocketRemoteCounter(session, counter) {
  if (!Number.isSafeInteger(counter) || counter <= Number(session.remoteCounter || 0)) {
    return false;
  }
  session.remoteCounter = counter;
  return true;
}

function isSocketRemoteCounterFresh(session, counter) {
  return Number.isSafeInteger(counter) && counter > Number(session.remoteCounter || 0);
}

function incrementSocketSendCounter(session) {
  const current = Number(session.sendCounter || 0);
  if (!Number.isSafeInteger(current) || current >= Number.MAX_SAFE_INTEGER) {
    throw new Error('PQ session send counter exhausted');
  }
  session.sendCounter = current + 1;
  return session.sendCounter;
}

async function acquireSocketSendTurn(ws, session, plaintextBytes) {
  const queuedCount = Number(session.sendQueueCount || 0);
  const queuedBytes = Number(session.sendQueueBytes || 0);
  if (
    session.invalidated === true ||
    queuedCount >= WS_ENCRYPTED_SEND_QUEUE_MAX_COUNT ||
    queuedBytes + plaintextBytes > WS_ENCRYPTED_SEND_QUEUE_MAX_BYTES
  ) {
    session.invalidated = true;
    if (isWebSocketOpen(ws)) ws.close(1013, 'Encrypted send queue saturated');
    throw new Error('Encrypted send queue saturated');
  }

  let unlock;
  const gate = new Promise((resolve) => { unlock = resolve; });
  const previous = session.sendTail || Promise.resolve();
  session.sendTail = previous.catch(() => { }).then(() => gate);
  session.sendQueueCount = queuedCount + 1;
  session.sendQueueBytes = queuedBytes + plaintextBytes;

  await previous.catch(() => { });
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    session.sendQueueCount = Math.max(0, Number(session.sendQueueCount || 0) - 1);
    session.sendQueueBytes = Math.max(0, Number(session.sendQueueBytes || 0) - plaintextBytes);
    unlock();
  };

  if (session.invalidated === true || getSocketPQSession(ws, session.sessionId) !== session) {
    release();
    throw new Error('PQ session changed while response was queued');
  }
  return release;
}

function getEncryptedResponsePlaintextBudgetBytes() {
  return Math.min(WS_MAX_ENCRYPTED_RESPONSE_BYTES, WS_CELL_MAX_LOGICAL_BYTES);
}

// Application-level progress chunks, each carried by authenticated fixed cells.
const SECURE_CHUNK_BYTES = 48 * 1024;
const SECURE_CHUNK_SINGLE_MAX_BYTES = SECURE_CHUNK_BYTES;
const SECURE_CHUNK_MAX_TOTAL = 512;
const SECURE_CHUNK_MAX_TOTAL_LENGTH = 24 * 1024 * 1024;
const SECURE_CHUNK_MAX_BUFFERED_BYTES = 8 * 1024 * 1024;

async function waitForWsDrain(ws, maxBufferedBytes, timeoutMs = 30000) {
  const start = Date.now();
  while (
    isWebSocketOpen(ws) &&
    typeof ws.bufferedAmount === 'number' &&
    ws.bufferedAmount > maxBufferedBytes
  ) {
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return isWebSocketOpen(ws) && Number(ws.bufferedAmount || 0) <= maxBufferedBytes;
}

/**
 * Split a large authentication response into bounded progress chunks.
 */
export async function sendSecureAuthResponse(ws, payload) {
  if (payload?.type !== SignalType.AUTH_PIR_RESPONSE) return false;

  let json;
  try {
    json = JSON.stringify(payload);
  } catch (e) {
    console.error('[SECURE-CHUNK] Failed to serialize payload', { error: e?.message });
    return false;
  }
  if (typeof json !== 'string') return false;

  const totalBytes = Buffer.byteLength(json, 'utf8');
  if (totalBytes <= SECURE_CHUNK_SINGLE_MAX_BYTES) {
    return sendSecureMessage(ws, payload);
  }

  const payloadType = SignalType.AUTH_PIR_RESPONSE;
  
  const totalLength = json.length;
  if (totalBytes > SECURE_CHUNK_MAX_TOTAL_LENGTH || totalLength > SECURE_CHUNK_MAX_TOTAL_LENGTH) {
    console.error('[SECURE-CHUNK] Refusing oversized secure response', {
      payloadType,
      totalBytesClass: byteSizeClass(totalBytes)
    });
    return false;
  }
  const totalChunks = Math.ceil(totalLength / SECURE_CHUNK_BYTES);

  if (totalChunks < 1 || totalChunks > SECURE_CHUNK_MAX_TOTAL) {
    console.error('[SECURE-CHUNK] Refusing chunk count out of range', {
      totalChunks, max: SECURE_CHUNK_MAX_TOTAL, payloadType
    });
    return false;
  }

  const messageId = crypto.randomBytes(16).toString('base64url');
  console.log('[SECURE-CHUNK] Sending chunked secure message', {
    payloadType, totalChunks, totalBytesClass: byteSizeClass(totalBytes)
  });

  for (let i = 0; i < totalChunks; i++) {
    if (!isWebSocketOpen(ws)) {
      console.warn('[SECURE-CHUNK] Aborting socket closed mid-send', { sent: i, totalChunks, payloadType });
      return false;
    }
    if (!await waitForWsDrain(ws, SECURE_CHUNK_MAX_BUFFERED_BYTES)) {
      console.warn('[SECURE-CHUNK] Aborting socket remained backpressured', {
        sent: i,
        totalChunks,
        payloadType
      });
      if (isWebSocketOpen(ws)) ws.close(1013, 'Secure response backpressure');
      return false;
    }

    const data = json.slice(i * SECURE_CHUNK_BYTES, (i + 1) * SECURE_CHUNK_BYTES);
    const delivered = await sendSecureMessage(ws, {
      type: SignalType.SECURE_CHUNK,
      messageId,
      chunkIndex: i,
      totalChunks,
      totalLength,
      payloadType,
      data
    });
    if (delivered === false) {
      console.warn('[SECURE-CHUNK] Chunk send failed', { chunkIndex: i, totalChunks, payloadType });
      return false;
    }
  }
  return true;
}

function buildHandshakeAckSignaturePayload(ack) {
  return [
    PROTOCOL_KEYS.WS_PQ_HANDSHAKE_ACK,
    String(ack?.version || ''),
    String(ack?.sessionId || ''),
    String(ack?.fingerprint || ''),
    String(ack?.clientNonce || ''),
    String(ack?.requestTimestamp || ''),
    String(ack?.requestDigest || ''),
    String(ack?.responseKemCiphertext || ''),
    String(ack?.timestamp || '')
  ].join('|');
}

function computeHandshakeRequestDigest(payload) {
  const algorithms = payload?.algorithms || {};
  const encoded = UTF8_ENCODER.encode([
    PROTOCOL_KEYS.WS_PQ_HANDSHAKE_REQUEST,
    String(payload?.version || ''),
    String(algorithms.kem || ''),
    String(algorithms.signature || ''),
    String(algorithms.classicalKeyAgreement || ''),
    String(algorithms.kdf || ''),
    String(algorithms.aead || ''),
    String(payload?.sessionId || ''),
    String(payload?.timestamp || ''),
    String(payload?.clientNonce || ''),
    String(payload?.kemCiphertext || ''),
    String(payload?.clientKemPublicKey || ''),
    String(payload?.clientX25519PublicKey || ''),
    String(payload?.fingerprint || '')
  ].join('|'));
  const digest = PostQuantumHash.blake3(encoded);
  try {
    return Buffer.from(digest.buffer, digest.byteOffset, digest.byteLength).toString('hex');
  } finally {
    encoded.fill(0);
    digest.fill(0);
  }
}

function getEnvelopeTimestampValidation(timestamp) {
  const serverTime = Date.now();
  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
    return {
      valid: false,
      serverTime,
      skewMs: null,
      direction: 'invalid'
    };
  }
  const skewMs = serverTime - timestamp;
  return {
    valid: Math.abs(skewMs) <= WS_MAX_REPLAY_WINDOW_MS,
    serverTime,
    skewMs,
    direction: skewMs >= 0 ? 'past' : 'future'
  };
}

function skewSizeClass(skewMs) {
  if (!Number.isFinite(skewMs)) return 'invalid';
  const abs = Math.abs(skewMs);
  if (abs <= WS_MAX_REPLAY_WINDOW_MS) return 'within-window';
  if (abs <= 10 * 60 * 1000) return 'lte-10m';
  if (abs <= 30 * 60 * 1000) return 'lte-30m';
  if (abs <= 2 * 60 * 60 * 1000) return 'lte-2h';
  return 'gt-2h';
}

function timestampInvalidPayload(validation, code, message) {
  return {
    type: SignalType.ERROR,
    code,
    message,
    serverTime: validation.serverTime,
    replayWindowMs: WS_MAX_REPLAY_WINDOW_MS,
    timestampSkewMs: Number.isFinite(validation.skewMs) ? validation.skewMs : undefined,
    requiresFreshHandshake: true
  };
}

async function sendOversizedResponseError(ws, session, messageType, sizeBytes) {
  console.warn('[PQ-ENCRYPT] Refusing oversized plaintext response before encryption', {
    messageKind: messageType,
    payloadType: messageType,
    plainSizeClass: byteSizeClass(sizeBytes),
    plainLimitClass: byteSizeClass(getEncryptedResponsePlaintextBudgetBytes()),
    encryptedLimitClass: byteSizeClass(WS_MAX_ENCRYPTED_RESPONSE_BYTES)
  });

  if (messageType !== SignalType.ERROR) {
    return sendPQEncryptedResponse(ws, session, {
      type: SignalType.ERROR,
      code: 'RESPONSE_TOO_LARGE',
      message: 'Server response exceeded transport limit',
      originalType: messageType
    });
  }

  throw new Error('encrypted_response_plaintext_too_large');
}

// Initialize the envelope handler with server keys
export function initializeEnvelopeHandler(serverHybridKeyPair) {
  if (serverHybridKeyPair?.dilithium?.secretKey) {
    serverDilithiumSigningKey = serverHybridKeyPair.dilithium.secretKey;
    console.log('[PQ-ENVELOPE] Signing key initialized');
  } else {
    console.warn('[PQ-ENVELOPE] No signing key provided');
  }
}

export function destroyEnvelopeHandler() {
  serverDilithiumSigningKey = null;
}

// Handle PQ handshake initialization from client
const PQ_HS_FIELD_SIZES = {
  kemCiphertext: ML_KEM_1024_CIPHERTEXT_BYTES,
  clientKemPublicKey: ML_KEM_1024_PUBLIC_KEY_BYTES,
  clientNonce: HASH_OUTPUT_BYTES,
  clientX25519PublicKey: X25519_KEY_BYTES
};
const PQ_HS_MAX_B64_CHARS = 8192;
const PQ_HS_MAX_PER_MIN = envInt('PQ_HANDSHAKE_MAX_PER_MIN', 20, 1, 600);
const PQ_HS_MAX_CONCURRENCY = envInt('PQ_HANDSHAKE_MAX_CONCURRENCY', 2, 1, 16);
const PQ_HS_MAX_QUEUE = envInt('PQ_HANDSHAKE_MAX_QUEUE', 16, 0, 64);
const PQ_HS_QUEUE_TIMEOUT_MS = envInt('PQ_HANDSHAKE_QUEUE_TIMEOUT_MS', 15_000, 1_000, 60_000);
const PQ_HS_CONFIRM_TIMEOUT_MS = envInt('PQ_HANDSHAKE_CONFIRM_TIMEOUT_MS', 45_000, 5_000, 120_000);
function pqHandshakeAdmissionError(message, code = 'PQ_HANDSHAKE_BUSY') {
  const error = new Error(message);
  error.code = code;
  return error;
}

const pqHandshakeAdmissionGate = createAbortableAdmissionGate({
  maxConcurrent: PQ_HS_MAX_CONCURRENCY,
  maxQueued: PQ_HS_MAX_QUEUE,
  queueTimeoutMs: PQ_HS_QUEUE_TIMEOUT_MS,
  abortedError: () => pqHandshakeAdmissionError(
    'PQ handshake connection closed',
    'PQ_HANDSHAKE_ABORTED'
  ),
  fullError: () => pqHandshakeAdmissionError('PQ handshake queue is full'),
  timeoutError: () => pqHandshakeAdmissionError('PQ handshake queue timed out')
});

function pqHandshakeFieldSizesValid(payload) {
  if (
    typeof payload.sessionId !== 'string' ||
    !HEX_32_RE.test(payload.sessionId) ||
    !Number.isSafeInteger(payload.timestamp) ||
    payload.timestamp < 0
  ) {
    return { valid: false, reason: 'sessionId' };
  }
  for (const [field, expectedLen] of Object.entries(PQ_HS_FIELD_SIZES)) {
    const value = payload[field];
    const expectedChars = 4 * Math.ceil(expectedLen / 3);
    if (
      typeof value !== 'string' ||
      value.length !== expectedChars ||
      value.length > PQ_HS_MAX_B64_CHARS
    ) {
      return { valid: false, reason: field };
    }
    let decoded = null;
    let canonical = null;
    try {
      decoded = CryptoUtils.Hash.base64ToUint8Array(value);
      canonical = Buffer.from(decoded);
      if (decoded.length !== expectedLen || canonical.toString('base64') !== value) {
        return { valid: false, reason: field };
      }
    } catch {
      return { valid: false, reason: field };
    } finally {
      decoded?.fill(0);
      canonical?.fill(0);
    }
  }
  return { valid: true };
}

export async function handlePQHandshake({ ws, parsed, serverHybridKeyPair }) {
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    Object.getPrototypeOf(parsed) !== Object.prototype ||
    Object.keys(parsed).sort().join(',') !== 'payload,type' ||
    parsed.type !== SignalType.PQ_HANDSHAKE_INIT
  ) {
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Invalid handshake payload'
    });
  }
  if (
    ws?._pqPendingSessionData ||
    (ws?._pqSessionData && ws._pqSessionData.confirmed !== true) ||
    ws?._pqHandshakeInFlight === true
  ) {
    clearSocketPQSession(ws);
    if (isWebSocketOpen(ws)) ws.close(1008, 'Concurrent PQ handshake');
    return;
  }
  const payload = parsed?.payload;
  if (!payload || !payload.kemCiphertext || !payload.clientKemPublicKey || !payload.sessionId || !payload.clientNonce || !payload.clientX25519PublicKey) {
    console.warn('[PQ-HANDSHAKE] Invalid handshake payload', {
      hasPayload: !!payload,
      hasKemCiphertext: !!payload?.kemCiphertext,
      hasClientKemPublicKey: !!payload?.clientKemPublicKey,
      hasSessionId: !!payload?.sessionId,
      hasClientNonce: !!payload?.clientNonce,
      hasClientX25519: !!payload?.clientX25519PublicKey
    }); 
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Invalid handshake payload'
    });
  }

  // Per connection handshake rate limit
  {
    const now = Date.now();
    if (!ws._pqHsWindowStart || now - ws._pqHsWindowStart > 60_000) {
      ws._pqHsWindowStart = now;
      ws._pqHsCount = 0;
    }
    ws._pqHsCount = (ws._pqHsCount || 0) + 1;
    if (ws._pqHsCount > PQ_HS_MAX_PER_MIN) {
      if (isWebSocketOpen(ws)) ws.close(1008, 'Handshake rate exceeded');
      return false;
    }
  }

  // Reject malformed/oversized fields
  const sizeCheck = pqHandshakeFieldSizesValid(payload);
  if (!sizeCheck.valid) {
    console.warn('[PQ-HANDSHAKE] Rejected handshake field shape', { field: sizeCheck.reason });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid handshake payload' });
  }
  ws._pqHandshakeInFlight = true;

  let pendingSession = null;
  let kemCiphertextBytes = null;
  let pqSharedSecret = null;
  let clientKemPublic = null;
  let responseKemCiphertext = null;
  let responderPqSharedSecret = null;
  let clientX25519Public = null;
  let classicalSharedSecret = null;
  let baseSalt = null;
  let baseHandshakeSecret = null;
  let sendSalt = null;
  let recvSalt = null;
  let combinedSecret = null;
  let clientSendKey = null;
  let clientRecvKey = null;
  let stagedSession = null;
  let releaseHandshakeSlot = null;
  try {
    const policy = validatePqHandshakePolicy(payload);
    if (!policy.valid) {
      console.warn('[PQ-HANDSHAKE] Handshake policy rejected', {
        reason: policy.reason
      });
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Handshake policy invalid'
      });
    }

    const handshakeTimestamp = getEnvelopeTimestampValidation(payload.timestamp);
    if (!handshakeTimestamp.valid) {
      return await sendSecureMessage(
        ws,
        timestampInvalidPayload(handshakeTimestamp, 'HANDSHAKE_TIMESTAMP_INVALID', 'Handshake timestamp invalid')
      );
    }

    const expectedFingerprint = computeHybridPublicKeyFingerprint(serverHybridKeyPair);
    if (typeof payload.fingerprint !== 'string' || payload.fingerprint !== expectedFingerprint) {
      console.warn('[PQ-HANDSHAKE] Fingerprint mismatch', {
        hasReceivedFingerprint: typeof payload.fingerprint === 'string'
      });
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Handshake fingerprint mismatch'
      });
    }
    const requestDigest = computeHandshakeRequestDigest(payload);

    releaseHandshakeSlot = await pqHandshakeAdmissionGate.acquire(ws._connectionAbortSignal);

    kemCiphertextBytes = CryptoUtils.Hash.base64ToUint8Array(payload.kemCiphertext);
    pqSharedSecret = await CryptoUtils.Kyber.decapsulate(
      kemCiphertextBytes,
      serverHybridKeyPair.kyber.secretKey,
      serverHybridKeyPair.kyber.publicKey
    );

    clientX25519Public = CryptoUtils.Hash.base64ToUint8Array(payload.clientX25519PublicKey);
    classicalSharedSecret = CryptoUtils.Hybrid.computeClassicalSharedSecret(
      serverHybridKeyPair.x25519.secretKey,
      clientX25519Public
    );

    clientKemPublic = CryptoUtils.Hash.base64ToUint8Array(payload.clientKemPublicKey);
    const responderEncapsulation = await CryptoUtils.Kyber.encapsulate(clientKemPublic);
    responseKemCiphertext = responderEncapsulation.ciphertext;
    responderPqSharedSecret = responderEncapsulation.sharedSecret;
    const responseKemCiphertextBase64 = encodeBase64AndWipeCopy(responseKemCiphertext);

    const encoder = UTF8_ENCODER;
    const baseInfo = `${REQUIRED_WS_PQ_HANDSHAKE.version}:${expectedFingerprint}:${payload.sessionId}:${payload.clientNonce}:${payload.timestamp}:${requestDigest}`;
    baseSalt = encoder.encode(`${baseInfo}${PROTOCOL_KEYS.WS_PQ_BASE_SALT_SUFFIX}`);

    combinedSecret = new Uint8Array(pqSharedSecret.length + classicalSharedSecret.length);
    combinedSecret.set(pqSharedSecret, 0);
    combinedSecret.set(classicalSharedSecret, pqSharedSecret.length);
    baseHandshakeSecret = PostQuantumHash.deriveKey(
      combinedSecret,
      baseSalt,
      PROTOCOL_KEYS.WS_PQ_TWO_WAY_EPHEMERAL_BASE,
      POST_QUANTUM_AEAD_KEY_BYTES
    );
    combinedSecret.fill(0);
    combinedSecret = new Uint8Array(baseHandshakeSecret.length + responderPqSharedSecret.length);
    combinedSecret.set(baseHandshakeSecret, 0);
    combinedSecret.set(responderPqSharedSecret, baseHandshakeSecret.length);
    const finalContext = `${baseInfo}:${responseKemCiphertextBase64}${PROTOCOL_KEYS.WS_PQ_FINAL_SALT_SUFFIX}`;
    sendSalt = encoder.encode(`${finalContext}${PROTOCOL_KEYS.WS_PQ_CLIENT_SEND_SALT_SUFFIX}`);
    recvSalt = encoder.encode(`${finalContext}${PROTOCOL_KEYS.WS_PQ_CLIENT_RECV_SALT_SUFFIX}`);

    clientSendKey = PostQuantumHash.deriveKey(
      combinedSecret,
      sendSalt,
      PROTOCOL_KEYS.WS_PQ_CLIENT_SEND,
      POST_QUANTUM_AEAD_KEY_BYTES
    );
    clientRecvKey = PostQuantumHash.deriveKey(
      combinedSecret,
      recvSalt,
      PROTOCOL_KEYS.WS_PQ_CLIENT_RECV,
      POST_QUANTUM_AEAD_KEY_BYTES
    );

    pendingSession = {
      sessionId: payload.sessionId,
      recvKey: clientSendKey,
      sendKey: clientRecvKey,
      fingerprint: expectedFingerprint,
      establishedAt: Date.now(),
      sendCounter: 0,
      remoteCounter: 0,
      confirmed: false,
      confirmationDigest: requestDigest
    };
    clientSendKey = null;
    clientRecvKey = null;

    console.log('[PQ-HANDSHAKE] Session established');

    console.log('[PQ-HANDSHAKE] Sending authenticated acknowledgement', {
      wsReady: ws.readyState === 1,
      protectedByCurrentSession: !!ws._pqSessionId
    });

    if (!serverDilithiumSigningKey) {
      throw new Error('Server signing key unavailable for handshake acknowledgement');
    }
    const ackTimestamp = Date.now();
    const ack = {
      type: SignalType.PQ_HANDSHAKE_ACK,
      version: REQUIRED_WS_PQ_HANDSHAKE.version,
      sessionId: payload.sessionId,
      fingerprint: expectedFingerprint,
      clientNonce: payload.clientNonce,
      requestTimestamp: payload.timestamp,
      requestDigest,
      responseKemCiphertext: responseKemCiphertextBase64,
      timestamp: ackTimestamp,
      serverTime: ackTimestamp
    };
    const ackSignatureMessage = UTF8_ENCODER.encode(buildHandshakeAckSignaturePayload(ack));
    let ackSignature = null;
    try {
      ackSignature = await CryptoUtils.Dilithium.sign(
        ackSignatureMessage,
        serverDilithiumSigningKey
      );
      const encodedSignature = Buffer.from(ackSignature);
      try {
        ack.signature = encodedSignature.toString('base64');
      } finally {
        encodedSignature.fill(0);
      }
    } finally {
      ackSignatureMessage.fill(0);
      ackSignature?.fill(0);
    }

    // Admission protects expensive key agreement/signing only. Never let a slow
    // socket hold a global crypto slot while its acknowledgement drains.
    releaseHandshakeSlot?.();
    releaseHandshakeSlot = null;

    const previousSession = ws._pqSessionData;
    if (previousSession) {
      stagedSession = pendingSession;
      stageSocketPQSession(ws, stagedSession);
      pendingSession = null;
      const ackDelivered = await sendSecureMessage(ws, ack, {
        sessionOverride: previousSession
      });
      if (!ackDelivered) {
        discardStagedSocketPQSession(ws, stagedSession);
        throw new Error('PQ rekey acknowledgement was not delivered');
      }
      stagedSession = null;
    } else {
      const ackDelivered = await sendSecureMessage(ws, ack);
      if (!ackDelivered) throw new Error('PQ handshake acknowledgement was not delivered');
      installSocketPQSession(ws, pendingSession);
      pendingSession = null;
    }

  } catch (error) {
    if (stagedSession) discardStagedSocketPQSession(ws, stagedSession);
    wipeSession(pendingSession);
    console.error('[PQ-HANDSHAKE] Handshake failed', {
      error: error.message
    });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Handshake failed'
    });
  } finally {
    ws._pqHandshakeInFlight = false;
    kemCiphertextBytes?.fill(0);
    pqSharedSecret?.fill(0);
    clientKemPublic?.fill(0);
    responseKemCiphertext?.fill(0);
    responderPqSharedSecret?.fill(0);
    clientX25519Public?.fill(0);
    classicalSharedSecret?.fill(0);
    baseSalt?.fill(0);
    baseHandshakeSecret?.fill(0);
    sendSalt?.fill(0);
    recvSalt?.fill(0);
    combinedSecret?.fill(0);
    clientSendKey?.fill(0);
    clientRecvKey?.fill(0);
    releaseHandshakeSlot?.();
  }
}

async function dispatchAuthenticatedCellPayload({
  ws,
  session,
  innerPayload,
  context,
  handleInnerMessage,
}) {
  const sendForSession = (payload) => (
    ws._pqPendingSessionData === session || session.confirmed !== true
      ? sendPQEncryptedResponse(ws, session, payload)
      : sendSecureMessage(ws, payload)
  );

  if (session.confirmed !== true) {
    if (
      Object.keys(innerPayload).sort().join(',') !== 'requestDigest,sessionId,type,version' ||
      innerPayload.type !== SignalType.PQ_HANDSHAKE_CONFIRM ||
      innerPayload.version !== REQUIRED_WS_PQ_HANDSHAKE.version ||
      innerPayload.sessionId !== session.sessionId ||
      innerPayload.requestDigest !== session.confirmationDigest
    ) {
      await sendForSession({ type: SignalType.ERROR, message: 'PQ key confirmation required' });
      clearSocketPQSession(ws);
      if (isWebSocketOpen(ws)) ws.close(1008, 'PQ key confirmation required');
      return false;
    }
    if (session.confirmationInFlight === true) {
      clearSocketPQSession(ws);
      if (isWebSocketOpen(ws)) ws.close(1008, 'Concurrent PQ key confirmation');
      return false;
    }
    session.confirmationInFlight = true;
    let delivered = false;
    try {
      delivered = await sendPQEncryptedResponse(ws, session, {
        type: SignalType.PQ_HANDSHAKE_CONFIRMED,
        version: REQUIRED_WS_PQ_HANDSHAKE.version,
        sessionId: session.sessionId,
        requestDigest: innerPayload.requestDigest
      });
    } finally {
      if (getSocketPQSession(ws, session.sessionId) === session) {
        session.confirmationInFlight = false;
      }
    }
    if (!delivered) {
      clearSocketPQSession(ws);
      if (isWebSocketOpen(ws)) ws.close(1011, 'PQ key confirmation delivery failed');
      return false;
    }
    session.confirmed = true;
    session.confirmationDigest = null;
    if (session.confirmationTimer) clearTimeout(session.confirmationTimer);
    session.confirmationTimer = null;
    if (ws._pqPendingSessionData === session) promoteStagedSocketPQSession(ws, session);
    else resolveSocketPQActivationGate(ws);
    return true;
  }

  if (innerPayload.type === SignalType.PQ_HANDSHAKE_CONFIRM) {
    clearSocketPQSession(ws);
    if (isWebSocketOpen(ws)) ws.close(1008, 'Repeated PQ key confirmation');
    return false;
  }

  const authRequestField = AUTH_CHANNEL_BOUND_REQUEST_FIELDS.get(innerPayload.type);
  if (authRequestField) {
    let expectedBinding = null;
    let suppliedBinding = null;
    try {
      const requestId = innerPayload[authRequestField];
      if (!canonicalBase64Shape(innerPayload.authChannelBinding, {
        exactBytes: AUTH_CHANNEL_BINDING_BYTES
      })) throw new Error('Authentication channel binding is malformed');
      expectedBinding = createAuthChannelBinding({
        sessionId: session.sessionId,
        sessionFingerprint: session.fingerprint,
        requestId,
      });
      suppliedBinding = CryptoUtils.Hash.base64ToUint8Array(innerPayload.authChannelBinding);
      if (
        suppliedBinding.length !== AUTH_CHANNEL_BINDING_BYTES ||
        !crypto.timingSafeEqual(expectedBinding, suppliedBinding)
      ) throw new Error('Authentication channel binding does not match the PQ session');
      Object.defineProperty(innerPayload, VERIFIED_AUTH_CHANNEL_BINDING, {
        configurable: true,
        enumerable: false,
        value: expectedBinding,
        writable: false,
      });
      expectedBinding = null;
    } catch {
      await sendForSession({
        type: SignalType.AUTH_ERROR,
        code: 'AUTH_CHANNEL_BINDING_INVALID',
        message: 'Authentication channel binding invalid',
        [authRequestField]: innerPayload[authRequestField],
      });
      if (isWebSocketOpen(ws)) ws.close(1008, 'Authentication channel binding invalid');
      return false;
    } finally {
      expectedBinding?.fill(0);
      suppliedBinding?.fill(0);
    }
  }

  await handleInnerMessage({
    ws,
    parsed: innerPayload,
    context,
    isPqProtected: true
  });
  return true;
}

function ingestSocketCellPlaintext(ws, messageId, chunkIndex, chunkCount, totalLength, plaintext) {
  if (chunkCount === 1) return Buffer.from(plaintext);
  if (!(ws._pqCellAssemblies instanceof Map)) ws._pqCellAssemblies = new Map();
  let assembly = ws._pqCellAssemblies.get(messageId);
  if (!assembly) {
    while (
      ws._pqCellAssemblies.size >= WS_CELL_MAX_CONCURRENT ||
      Number(ws._pqCellBufferedBytes || 0) + totalLength > WS_CELL_MAX_BUFFERED_BYTES
    ) {
      const oldest = Array.from(ws._pqCellAssemblies.entries())
        .sort((left, right) => left[1].createdAt - right[1].createdAt)[0];
      if (!oldest) throw new Error('Fixed-cell reassembly capacity exceeded');
      discardSocketCellAssembly(ws, oldest[0]);
    }
    const timer = setTimeout(
      () => discardSocketCellAssembly(ws, messageId),
      WS_CELL_REASSEMBLY_TIMEOUT_MS
    );
    timer.unref?.();
    assembly = {
      totalLength,
      chunkCount,
      parts: new Array(chunkCount),
      received: 0,
      receivedBytes: 0,
      createdAt: Date.now(),
      timer,
    };
    ws._pqCellAssemblies.set(messageId, assembly);
    ws._pqCellBufferedBytes = Number(ws._pqCellBufferedBytes || 0) + totalLength;
  } else if (assembly.totalLength !== totalLength || assembly.chunkCount !== chunkCount) {
    discardSocketCellAssembly(ws, messageId);
    throw new Error('Inconsistent fixed-cell metadata');
  }
  if (assembly.parts[chunkIndex] !== undefined) {
    discardSocketCellAssembly(ws, messageId);
    throw new Error('Duplicate fixed-cell fragment');
  }
  assembly.parts[chunkIndex] = Buffer.from(plaintext);
  assembly.received += 1;
  assembly.receivedBytes += plaintext.length;
  if (assembly.received < assembly.chunkCount) return null;

  const complete = Buffer.allocUnsafe(totalLength);
  let offset = 0;
  for (const part of assembly.parts) {
    if (!Buffer.isBuffer(part) || offset + part.length > complete.length) {
      complete.fill(0);
      discardSocketCellAssembly(ws, messageId);
      throw new Error('Incomplete fixed-cell message');
    }
    part.copy(complete, offset);
    offset += part.length;
  }
  discardSocketCellAssembly(ws, messageId);
  if (offset !== totalLength || assembly.receivedBytes !== totalLength) {
    complete.fill(0);
    throw new Error('Fixed-cell length mismatch');
  }
  return complete;
}

export async function handlePQBinaryCell({ ws, cell, context, handleInnerMessage }) {
  let nonce = null;
  let tag = null;
  let ciphertext = null;
  let aad = null;
  let plaintext = null;
  let logicalBytes = null;
  try {
    if (!Buffer.isBuffer(cell) || cell.length !== SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES) {
      throw new Error('Invalid fixed-cell size');
    }
    if (
      !cell.subarray(0, WS_CELL_MAGIC.length).equals(WS_CELL_MAGIC) ||
      cell.readUInt8(4) !== WS_CELL_VERSION ||
      cell.readUInt8(5) !== WS_CELL_FLAGS ||
      cell.readUInt16BE(6) !== WS_CELL_HEADER_BYTES
    ) throw new Error('Invalid fixed-cell header');

    const sessionId = cell.subarray(WS_CELL_SESSION_OFFSET, WS_CELL_FINGERPRINT_OFFSET).toString('hex');
    const session = getSocketPQSession(ws, sessionId);
    if (!session) throw new Error('Fixed cell is not bound to this socket');
    if (ws._pqPendingSessionData && session === ws._pqSessionData) {
      try {
        await sendPQEncryptedResponse(ws, session, {
          type: SignalType.ERROR,
          message: 'PQ rekey confirmation required'
        });
      } finally {
        clearSocketPQSession(ws);
        if (isWebSocketOpen(ws)) ws.close(1008, 'PQ rekey confirmation required');
      }
      return false;
    }
    if (!crypto.timingSafeEqual(
      cell.subarray(WS_CELL_FINGERPRINT_OFFSET, WS_CELL_MESSAGE_ID_OFFSET),
      Buffer.from(session.fingerprint, 'hex')
    )) throw new Error('Fixed-cell session fingerprint mismatch');

    const counter = readSafeU64(cell, WS_CELL_COUNTER_OFFSET);
    const timestamp = readSafeU64(cell, WS_CELL_TIMESTAMP_OFFSET);
    const chunkIndex = cell.readUInt32BE(WS_CELL_CHUNK_INDEX_OFFSET);
    const chunkCount = cell.readUInt32BE(WS_CELL_CHUNK_COUNT_OFFSET);
    const totalLength = cell.readUInt32BE(WS_CELL_TOTAL_LENGTH_OFFSET);
    const plaintextLength = cell.readUInt32BE(WS_CELL_PLAINTEXT_LENGTH_OFFSET);
    if (
      counter === null || timestamp === null ||
      !isSocketRemoteCounterFresh(session, counter) ||
      !getEnvelopeTimestampValidation(timestamp).valid ||
      totalLength < 1 || totalLength > WS_CELL_MAX_LOGICAL_BYTES ||
      chunkCount < 1 || chunkCount > WS_CELL_MAX_CHUNKS ||
      chunkCount !== Math.ceil(totalLength / WS_CELL_PLAINTEXT_BYTES) ||
      chunkIndex >= chunkCount
    ) throw new Error('Invalid fixed-cell metadata');
    const expectedPlaintextLength = chunkIndex + 1 === chunkCount
      ? totalLength - chunkIndex * WS_CELL_PLAINTEXT_BYTES
      : WS_CELL_PLAINTEXT_BYTES;
    if (plaintextLength !== expectedPlaintextLength) throw new Error('Invalid fixed-cell fragment length');
    const ciphertextLength = plaintextLength + WS_CELL_CIPHERTEXT_OVERHEAD_BYTES;
    if (WS_CELL_CIPHERTEXT_OFFSET + ciphertextLength > cell.length) {
      throw new Error('Invalid fixed-cell ciphertext length');
    }

    nonce = Buffer.from(cell.subarray(WS_CELL_NONCE_OFFSET, WS_CELL_TAG_OFFSET));
    tag = Buffer.from(cell.subarray(WS_CELL_TAG_OFFSET, WS_CELL_CIPHERTEXT_OFFSET));
    ciphertext = Buffer.from(cell.subarray(
      WS_CELL_CIPHERTEXT_OFFSET,
      WS_CELL_CIPHERTEXT_OFFSET + ciphertextLength
    ));
    aad = Buffer.concat([
      WS_CELL_AAD_DOMAIN,
      cell.subarray(0, WS_CELL_TAG_OFFSET),
      cell.subarray(WS_CELL_CIPHERTEXT_OFFSET + ciphertextLength)
    ]);
    const pqAead = new CryptoUtils.PostQuantumAEAD(session.recvKey);
    plaintext = pqAead.decrypt(ciphertext, nonce, tag, aad);
    if (plaintext.length !== plaintextLength || !consumeSocketRemoteCounter(session, counter)) {
      throw new Error('Fixed-cell authentication state changed');
    }
    const messageId = cell.subarray(WS_CELL_MESSAGE_ID_OFFSET, WS_CELL_COUNTER_OFFSET).toString('hex');
    logicalBytes = ingestSocketCellPlaintext(
      ws,
      messageId,
      chunkIndex,
      chunkCount,
      totalLength,
      plaintext
    );
    if (!logicalBytes) return true;

    const innerPayload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(logicalBytes));
    if (
      !innerPayload || typeof innerPayload !== 'object' || Array.isArray(innerPayload) ||
      !isSafeWireMessageType(innerPayload.type) ||
      !isSafeJsonTree(innerPayload, {
        maxDepth: WS_ENVELOPE_MAX_JSON_DEPTH,
        maxNodes: WS_ENVELOPE_MAX_JSON_NODES,
        maxKeyLength: 256
      })
    ) throw new Error('Invalid fixed-cell payload schema');
    return await dispatchAuthenticatedCellPayload({
      ws,
      session,
      innerPayload,
      context,
      handleInnerMessage,
    });
  } catch (error) {
    console.warn('[PQ-CELL] Rejected encrypted WebSocket cell', { error: error.message });
    clearSocketCellAssemblies(ws);
    if (isWebSocketOpen(ws)) ws.close(1008, 'Invalid encrypted cell');
    return false;
  } finally {
    nonce?.fill(0);
    tag?.fill(0);
    ciphertext?.fill(0);
    aad?.fill(0);
    plaintext?.fill(0);
    logicalBytes?.fill(0);
  }
}


// Send a logical message as one or more authenticated fixed-size binary cells.
export async function sendPQEncryptedResponse(ws, pqSessionIdOrData, payload, options = {}) {
  const payloadType = payload?.type || 'unknown';
  if (!isWebSocketOpen(ws)) return false;

  const requestedSessionId = typeof pqSessionIdOrData === 'string'
    ? pqSessionIdOrData
    : pqSessionIdOrData?.sessionId;
  const session = getSocketPQSession(ws, requestedSessionId);
  if (!session) throw new Error('PQ session is not bound to this socket');

  let plaintext = null;
  let sessionId = null;
  let fingerprint = null;
  let messageId = null;
  let releaseSendTurn = null;
  try {
    const innerJson = JSON.stringify(payload);
    if (typeof innerJson !== 'string') throw new Error('Invalid encrypted response payload');
    plaintext = Buffer.from(innerJson, 'utf8');
    if (plaintext.length < 1 || plaintext.length > getEncryptedResponsePlaintextBudgetBytes()) {
      return await sendOversizedResponseError(ws, session, payloadType, plaintext.length);
    }

    releaseSendTurn = await acquireSocketSendTurn(ws, session, plaintext.length);
    sessionId = Buffer.from(session.sessionId, 'hex');
    fingerprint = Buffer.from(session.fingerprint, 'hex');
    messageId = crypto.randomBytes(16);
    if (sessionId.length !== 16 || fingerprint.length !== 32) {
      throw new Error('Invalid PQ session identity');
    }
    const chunkCount = Math.ceil(plaintext.length / WS_CELL_PLAINTEXT_BYTES);
    const timestamp = Date.now();
    const pqAead = new CryptoUtils.PostQuantumAEAD(session.sendKey);

    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
      if (getSocketPQSession(ws, session.sessionId) !== session || !isWebSocketOpen(ws)) {
        return false;
      }
      const start = chunkIndex * WS_CELL_PLAINTEXT_BYTES;
      const end = Math.min(plaintext.length, start + WS_CELL_PLAINTEXT_BYTES);
      const chunk = plaintext.subarray(start, end);
      const counter = incrementSocketSendCounter(session);
      const nonce = crypto.randomBytes(WS_ENVELOPE_NONCE_BYTES);
      const cell = crypto.randomBytes(SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES);
      let aad = null;
      let ciphertext = null;
      let tag = null;
      try {
        WS_CELL_MAGIC.copy(cell, 0);
        cell.writeUInt8(WS_CELL_VERSION, 4);
        cell.writeUInt8(WS_CELL_FLAGS, 5);
        cell.writeUInt16BE(WS_CELL_HEADER_BYTES, 6);
        sessionId.copy(cell, WS_CELL_SESSION_OFFSET);
        fingerprint.copy(cell, WS_CELL_FINGERPRINT_OFFSET);
        messageId.copy(cell, WS_CELL_MESSAGE_ID_OFFSET);
        writeSafeU64(cell, WS_CELL_COUNTER_OFFSET, counter);
        writeSafeU64(cell, WS_CELL_TIMESTAMP_OFFSET, timestamp);
        cell.writeUInt32BE(chunkIndex, WS_CELL_CHUNK_INDEX_OFFSET);
        cell.writeUInt32BE(chunkCount, WS_CELL_CHUNK_COUNT_OFFSET);
        cell.writeUInt32BE(plaintext.length, WS_CELL_TOTAL_LENGTH_OFFSET);
        cell.writeUInt32BE(chunk.length, WS_CELL_PLAINTEXT_LENGTH_OFFSET);
        nonce.copy(cell, WS_CELL_NONCE_OFFSET);
        const ciphertextEnd = WS_CELL_CIPHERTEXT_OFFSET
          + chunk.length
          + WS_CELL_CIPHERTEXT_OVERHEAD_BYTES;
        aad = Buffer.concat([
          WS_CELL_AAD_DOMAIN,
          cell.subarray(0, WS_CELL_TAG_OFFSET),
          cell.subarray(ciphertextEnd)
        ]);
        const encrypted = pqAead.encrypt(chunk, nonce, aad);
        ciphertext = encrypted.ciphertext;
        tag = encrypted.tag;
        if (
          ciphertext.length !== chunk.length + WS_CELL_CIPHERTEXT_OVERHEAD_BYTES ||
          tag.length !== WS_ENVELOPE_TAG_BYTES ||
          WS_CELL_CIPHERTEXT_OFFSET + ciphertext.length > cell.length
        ) throw new Error('Fixed-cell encryption length mismatch');
        tag.copy(cell, WS_CELL_TAG_OFFSET);
        ciphertext.copy(cell, WS_CELL_CIPHERTEXT_OFFSET);
        const delivered = await sendWebSocketFrameWithDeadline(
          ws,
          cell,
          options.deliveryTimeoutMs
        );
        if (!delivered) return false;
      } finally {
        nonce.fill(0);
        cell.fill(0);
        aad?.fill(0);
        ciphertext?.fill(0);
        tag?.fill(0);
      }
    }
    return true;
  } catch (error) {
    if (isWebSocketDeliveryClosedError(error) || isClosedWebSocketState(wsReadyState(ws))) {
      return false;
    }
    console.error('[PQ-CELL] Failed to send encrypted response', {
      payloadType,
      error: error.message
    });
    throw error;
  } finally {
    plaintext?.fill(0);
    sessionId?.fill(0);
    fingerprint?.fill(0);
    messageId?.fill(0);
    releaseSendTurn?.();
  }
}


export async function sendSecureMessage(ws, payload, options = {}) {
  if (!options.sessionOverride && !await waitForSocketPQActivation(ws, payload)) {
    return false;
  }
  const pqSessionId = options.sessionOverride?.sessionId || ws._pqSessionId;

  // Whitelist: Only these message types are allowed without PQ encryption
  const allowedPlaintextTypes = [
    SignalType.PQ_HANDSHAKE_ACK,
    SignalType.ERROR,
    SignalType.SERVER_PUBLIC_KEY
  ];

  if (pqSessionId) {
    try {
      const session = getSocketPQSession(ws, pqSessionId);
      if (!session) {
        console.error('[SECURE-MSG] FATAL: PQ session ID exists but session not found', {
          payloadType: payload?.type
        });
        ws.close(1008, 'PQ session lost');
        throw new Error('PQ session not bound to socket');
      }

      const delivered = await sendPQEncryptedResponse(ws, session, payload);
      return delivered;
    } catch (error) {
      if (isWebSocketDeliveryClosedError(error)) {
        console.log('[SECURE-MSG] Secure response not delivered because socket closed', {
          payloadType: payload?.type,
          readyState: wsReadyState(ws)
        });
        return false;
      }

      console.error('[SECURE-MSG] FATAL: PQ encryption failed', {
        error: error.message,
        payloadType: payload?.type,
        stack: error.stack
      });
      if (isWebSocketOpen(ws)) {
        ws.close(1011, 'Encryption failure - security violation');
      }
      throw new Error(`PQ encryption failed: ${error.message}`);
    }
  }

  const isAllowedPlaintext = payload?.type && allowedPlaintextTypes.includes(payload.type);

  if (!isAllowedPlaintext) {
    console.warn('[SECURE-MSG] Blocked payload without PQ session', {
      payloadType: payload?.type
    });

    if (isWebSocketOpen(ws)) {
      try {
        ws.send(JSON.stringify({
          type: SignalType.ERROR,
          code: PQ_SESSION_REQUIRED,
          message: 'PQ handshake required before sending secure messages',
          requiresHandshake: true
        }));
      } catch (error) {
        console.warn('[SECURE-MSG] Failed to send PQ-required error', {
          error: error?.message
        });
      }
    }
    return;
  }

  const payloadString = JSON.stringify(payload);
  console.log('[SECURE-MSG] Sending whitelisted plaintext message', {
    payloadType: payload?.type,
    wsReady: isWebSocketOpen(ws),
    readyState: ws.readyState,
    bufferedAmount: ws.bufferedAmount,
    payloadSize: payloadString.length
  });

  if (!isWebSocketOpen(ws)) {
    console.log('[SECURE-MSG] Skipping plaintext message for closed socket', {
      payloadType: payload?.type,
      readyState: wsReadyState(ws)
    });
    return false;
  }

  try {
    const delivered = await sendWebSocketFrameWithDeadline(ws, payloadString);

    if (!delivered) {
      console.log('[SECURE-MSG] Plaintext message dropped because socket closed', {
        payloadType: payload?.type,
        readyState: wsReadyState(ws)
      });
      return false;
    }

    console.log('[SECURE-MSG] Plaintext message sent successfully', {
      payloadType: payload?.type,
      readyState: ws.readyState
    });
    return true;
  } catch (sendError) {
    if (isWebSocketDeliveryClosedError(sendError) || isClosedWebSocketState(wsReadyState(ws))) {
      console.log('[SECURE-MSG] Plaintext message skipped after socket closed', {
        payloadType: payload?.type,
        readyState: wsReadyState(ws)
      });
      return false;
    }
    console.error('[SECURE-MSG] Exception while sending plaintext message', {
      payloadType: payload?.type,
      error: sendError.message,
      stack: sendError.stack
    });
    throw sendError;
  }
}
