/**
 * Post-Quantum Envelope Handler
 * 
 * Handles PQ handshake establishment and encrypted envelope processing
 */

import crypto from 'crypto';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { PostQuantumHash } from '../crypto/post-quantum-hash.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { SignalType } from '../signals.js';
import { storePQSession, getPQSession, incrementPQSessionCounter, deleteCachedPQSession } from '../session/pq-session-storage.js';
import { SERVER_CONSTANTS } from '../config/constants.js';
import { validatePqHandshakePolicy } from '../security/layer-agreement-policy.js';
import { recordWsEgress, recordWsInnerMessage } from '../diagnostics/runtime-monitor.js';

// Server signing key for envelope authentication
let serverDilithiumSigningKey = null;
const WS_MAX_REPLAY_WINDOW_MS = 5 * 60 * 1000;
const WS_MAX_ENCRYPTED_RESPONSE_BYTES = envInt(
  'WS_MAX_ENCRYPTED_RESPONSE_BYTES',
  12 * 1024 * 1024,
  1024 * 1024,
  64 * 1024 * 1024
);
const WS_OPEN = 1;
const WS_CLOSING = 2;
const WS_CLOSED = 3;

class WebSocketDeliveryClosedError extends Error {
  constructor(readyState, payloadType) {
    super(`WebSocket closed before encrypted response could be delivered: ${readyState}`);
    this.name = 'WebSocketDeliveryClosedError';
    this.code = 'WS_DELIVERY_CLOSED';
    this.readyState = readyState;
    this.payloadType = payloadType;
  }
}

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

export function encryptedResponseSizeClass(bytes) {
  return byteSizeClass(bytes);
}

export function getMaxEncryptedResponseBytes() {
  return WS_MAX_ENCRYPTED_RESPONSE_BYTES;
}

export function getEncryptedResponsePlaintextBudgetBytes() {
  const signatureAndEnvelopeSlackBytes = 16 * 1024;
  return Math.max(
    1024,
    Math.floor((WS_MAX_ENCRYPTED_RESPONSE_BYTES - signatureAndEnvelopeSlackBytes) * 0.7)
  );
}

// Chunked secure transport for messages too large for a single PQ envelope
const SECURE_CHUNK_BYTES = envInt('SECURE_CHUNK_BYTES', 1024 * 1024, 256 * 1024, 6 * 1024 * 1024);
const SECURE_CHUNK_SINGLE_MAX_BYTES = envInt('SECURE_CHUNK_SINGLE_MAX_BYTES', 4 * 1024 * 1024, 64 * 1024, 8 * 1024 * 1024);
const SECURE_CHUNK_MAX_TOTAL = envInt('SECURE_CHUNK_MAX_TOTAL', 64, 1, 1024);
const SECURE_CHUNK_MAX_BUFFERED_BYTES = 8 * 1024 * 1024;

async function waitForWsDrain(ws, maxBufferedBytes, timeoutMs = 30000) {
  const start = Date.now();
  while (
    isWebSocketOpen(ws) &&
    typeof ws.bufferedAmount === 'number' &&
    ws.bufferedAmount > maxBufferedBytes
  ) {
    if (Date.now() - start > timeoutMs) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/**
 * Send a secure message splitting it into reassemblable chunks if it is too large for a single PQ envelope
 */
export async function sendSecureMessageChunked(ws, payload) {
  let json;
  try {
    json = JSON.stringify(payload);
  } catch (e) {
    cryptoLogger.error('[SECURE-CHUNK] Failed to serialize payload', { error: e?.message });
    return false;
  }
  if (typeof json !== 'string') return false;

  const totalBytes = Buffer.byteLength(json, 'utf8');
  if (totalBytes <= SECURE_CHUNK_SINGLE_MAX_BYTES) {
    return sendSecureMessage(ws, payload);
  }

  const payloadType = typeof payload?.type === 'string' ? payload.type : 'unknown';
  
  const totalLength = json.length;
  const totalChunks = Math.ceil(totalLength / SECURE_CHUNK_BYTES);

  if (totalChunks < 1 || totalChunks > SECURE_CHUNK_MAX_TOTAL) {
    cryptoLogger.error('[SECURE-CHUNK] Refusing - chunk count out of range', {
      totalChunks, max: SECURE_CHUNK_MAX_TOTAL, payloadType
    });
    return false;
  }

  const messageId = crypto.randomBytes(16).toString('base64url');
  cryptoLogger.info('[SECURE-CHUNK] Sending chunked secure message', {
    payloadType, totalChunks, totalBytesClass: byteSizeClass(totalBytes)
  });

  for (let i = 0; i < totalChunks; i++) {
    if (!isWebSocketOpen(ws)) {
      cryptoLogger.warn('[SECURE-CHUNK] Aborting - socket closed mid-send', { sent: i, totalChunks, payloadType });
      return false;
    }
    await waitForWsDrain(ws, SECURE_CHUNK_MAX_BUFFERED_BYTES);

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
      cryptoLogger.warn('[SECURE-CHUNK] Chunk send failed; aborting', { chunkIndex: i, totalChunks, payloadType });
      return false;
    }
  }
  return true;
}

function buildEnvelopeSignaturePayload(envelope) {
  return [
    String(envelope?.version || ''),
    String(envelope?.sessionId || ''),
    String(envelope?.sessionFingerprint || ''),
    String(envelope?.messageId || ''),
    String(envelope?.timestamp || ''),
    String(envelope?.counter || ''),
    String(envelope?.aad || '')
  ].join('|');
}

function computeServerFingerprint(serverHybridKeyPair) {
  const kyber = CryptoUtils.Hybrid.exportKyberPublicBase64(serverHybridKeyPair.kyber.publicKey);
  const dilithium = CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey);
  const x25519 = CryptoUtils.Hybrid.exportX25519PublicBase64(serverHybridKeyPair.x25519.publicKey);
  const encoded = JSON.stringify({
    kyberPublicBase64: kyber,
    dilithiumPublicBase64: dilithium,
    x25519PublicBase64: x25519
  });
  return Buffer.from(PostQuantumHash.blake3(new TextEncoder().encode(encoded))).toString('hex');
}

function validateEnvelopeTimestamp(timestamp) {
  return getEnvelopeTimestampValidation(timestamp).valid;
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

async function verifyClientEnvelopeSignature(session, envelope) {
  if (!envelope?.signature || typeof envelope.signature !== 'string') {
    return false;
  }
  const publicKey = session?.clientSigningPublicKey;
  if (!publicKey || !publicKey.length) {
    return false;
  }

  try {
    const signaturePayload = buildEnvelopeSignaturePayload(envelope);
    const signatureMessage = new TextEncoder().encode(signaturePayload);
    const signatureBytes = CryptoUtils.Hash.base64ToUint8Array(envelope.signature);
    return await CryptoUtils.Dilithium.verify(signatureBytes, signatureMessage, publicKey);
  } catch {
    return false;
  }
}

function consumeRemoteCounter(ws, envelope) {
  if (typeof envelope?.counter !== 'number' || !Number.isFinite(envelope.counter)) {
    return false;
  }
  const lastRemoteCounter = Number.isFinite(ws?._pqLastRemoteCounter)
    ? ws._pqLastRemoteCounter
    : 0;
  if (envelope.counter <= lastRemoteCounter) {
    return false;
  }
  ws._pqLastRemoteCounter = envelope.counter;
  return true;
}

function padEnvelopeToFixedSize(envelope) {
  const targetBytes = SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES;
  if (!targetBytes || targetBytes <= 0) {
    return JSON.stringify(envelope);
  }

  const base = { ...envelope, _pad: '' };
  const baseJson = JSON.stringify(base);
  const baseSize = Buffer.byteLength(baseJson);
  if (baseSize > targetBytes) {
    cryptoLogger.info('[PQ-ENCRYPT] Fixed-size response exceeded target. sending unpadded', {
      baseSize,
      targetBytes
    });
    return JSON.stringify(envelope);
  }

  const padNeeded = targetBytes - baseSize;
  if (padNeeded === 0) {
    return baseJson;
  }

  base._pad = crypto.randomBytes(Math.ceil(padNeeded * 0.75)).toString('base64url').slice(0, padNeeded);
  const finalJson = JSON.stringify(base);
  const finalSize = Buffer.byteLength(finalJson);
  if (finalSize !== targetBytes) {
    cryptoLogger.warn('[PQ-ENCRYPT] Fixed-size response padding mismatch', {
      finalSize,
      targetBytes
    });
    return JSON.stringify(envelope);
  }
  return finalJson;
}

function shouldPadEnvelopePayload(payload) {
  const type = payload?.type || 'unknown';
  const unpaddedControlTypes = new Set([
    SignalType.PQ_HEARTBEAT_PING,
    SignalType.PQ_HEARTBEAT_PONG,
    SignalType.SERVER_ENTRY_REQUEST,
    SignalType.SERVER_ENTRY_CHALLENGE,
    SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
    SignalType.PRIVACY_PASS_REDEMPTION,
    SignalType.PRIVACY_PASS_ISSUANCE,
    SignalType.TOKEN_VALIDATION,
    SignalType.TOKEN_VALIDATION_RESPONSE,
    SignalType.AUTH_OT_REGISTER_REQUEST,
    SignalType.AUTH_OT_REGISTER_RESPONSE,
    SignalType.AUTH_OT_REGISTER_FINALIZE,
    SignalType.AUTH_OT_REQUEST,
    SignalType.AUTH_OT_RESPONSE,
    SignalType.AUTH_OT_FINALIZE,
    SignalType.SECURE_CHUNK,
    SignalType.AUTH_FULL_SUCCESS,
    SignalType.BLIND_SIGNATURE_REQUEST,
    SignalType.BLIND_SIGNATURE_RESPONSE,
    SignalType.ZK_REFRESH_CHALLENGE,
    SignalType.ZK_REFRESH_RESPONSE,
    SignalType.ZK_DEVICE_REGISTER,
    SignalType.ZK_DEVICE_REGISTER_RESPONSE,
    SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
    SignalType.OPRF_BLIND_EVALUATE,
    SignalType.OPRF_BLIND_EVALUATE_RESPONSE,
    SignalType.PUBLISH_DISCOVERY,
    SignalType.DISCOVERY_SNAPSHOT_REQUEST,
    SignalType.DISCOVERY_SNAPSHOT,
    SignalType.PIR_MANIFEST_REQUEST,
    SignalType.PIR_MANIFEST,
    SignalType.PIR_QUERY,
    SignalType.PIR_RESPONSE,
    SignalType.AUTH_ERROR,
    SignalType.ERROR,
    SignalType.OK,
    SignalType.CLAIM_INBOX,
    SignalType.CLAIM_INBOX_RESPONSE,
    SignalType.ROTATE_INBOX,
    SignalType.ROTATE_INBOX_RESPONSE
  ]);

  return !unpaddedControlTypes.has(type);
}

function shouldTraceEnvelopePayload(payload) {
  const type = payload?.type || 'unknown';
  return new Set([
    SignalType.SERVER_ENTRY_REQUEST,
    SignalType.SERVER_ENTRY_CHALLENGE,
    SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
    SignalType.PRIVACY_PASS_REDEMPTION,
    SignalType.PRIVACY_PASS_ISSUANCE,
    SignalType.AUTH_OT_REGISTER_REQUEST,
    SignalType.AUTH_OT_REGISTER_RESPONSE,
    SignalType.AUTH_OT_REGISTER_FINALIZE,
    SignalType.AUTH_OT_REQUEST,
    SignalType.AUTH_OT_RESPONSE,
    SignalType.AUTH_OT_FINALIZE,
    SignalType.AUTH_FULL_SUCCESS,
    SignalType.PIR_MANIFEST,
    SignalType.PIR_RESPONSE,
    SignalType.AUTH_ERROR,
    SignalType.ERROR,
    SignalType.OK
  ]).has(type);
}

function oversizedResponseErrorPayload(payload, messageType) {
  if (messageType === SignalType.PIR_RESPONSE) {
    return {
      type: SignalType.PIR_RESPONSE,
      requestId: payload?.requestId,
      success: false,
      kind: payload?.kind,
      epochId: payload?.epochId,
      manifestDigest: payload?.manifestDigest,
      error: 'pir_response_too_large'
    };
  }

  if (messageType === SignalType.DISCOVERY_SNAPSHOT) {
    return {
      type: SignalType.DISCOVERY_SNAPSHOT,
      requestId: payload?.requestId,
      success: false,
      error: 'discovery_snapshot_too_large'
    };
  }

  return null;
}

function dominantResponseStringBytes(payload, messageType) {
  if (messageType === SignalType.PIR_RESPONSE && typeof payload?.response === 'string') {
    return Buffer.byteLength(payload.response, 'utf8');
  }

  if (messageType === SignalType.DISCOVERY_SNAPSHOT && typeof payload?.snapshot?.compressed === 'string') {
    return Buffer.byteLength(payload.snapshot.compressed, 'utf8');
  }

  if (messageType === SignalType.ENCRYPTED_MESSAGE && typeof payload?.encryptedPayload === 'string') {
    return Buffer.byteLength(payload.encryptedPayload, 'utf8');
  }

  return 0;
}

async function sendOversizedResponseError(ws, session, innerMessage, messageType, sizeBytes, stage) {
  cryptoLogger.warn('[PQ-ENCRYPT] Refusing oversized plaintext response before encryption', {
    messageKind: messageType,
    payloadType: messageType,
    stage,
    plainSizeClass: byteSizeClass(sizeBytes),
    plainLimitClass: byteSizeClass(getEncryptedResponsePlaintextBudgetBytes()),
    encryptedLimitClass: byteSizeClass(WS_MAX_ENCRYPTED_RESPONSE_BYTES)
  });

  const errorPayload = oversizedResponseErrorPayload(innerMessage, messageType);
  if (errorPayload) {
    return sendPQEncryptedResponse(ws, session, errorPayload);
  }

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
    cryptoLogger.info('[PQ-ENVELOPE] Signing key initialized');
  } else {
    cryptoLogger.warn('[PQ-ENVELOPE] No signing key provided');
  }
}

// Handle PQ handshake initialization from client
export async function handlePQHandshake({ ws, sessionId, parsed, serverHybridKeyPair }) {
  const payload = parsed?.payload;
  if (!payload || !payload.kemCiphertext || !payload.sessionId || !payload.clientNonce || !payload.clientX25519PublicKey || !payload.clientSigningPublicKey) {
    cryptoLogger.warn('[PQ-HANDSHAKE] Invalid handshake payload', {
      hasPayload: !!payload,
      hasKemCiphertext: !!payload?.kemCiphertext,
      hasSessionId: !!payload?.sessionId,
      hasClientNonce: !!payload?.clientNonce,
      hasClientX25519: !!payload?.clientX25519PublicKey,
      hasClientSigningPublicKey: !!payload?.clientSigningPublicKey
    }); 
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Invalid handshake payload'
    });
  }

  try {
    const policy = validatePqHandshakePolicy(payload);
    if (!policy.valid) {
      cryptoLogger.warn('[PQ-HANDSHAKE] Handshake policy rejected', {
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

    const expectedFingerprint = computeServerFingerprint(serverHybridKeyPair);
    if (typeof payload.fingerprint !== 'string' || payload.fingerprint !== expectedFingerprint) {
      cryptoLogger.warn('[PQ-HANDSHAKE] Fingerprint mismatch', {
        hasReceivedFingerprint: typeof payload.fingerprint === 'string'
      });
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Handshake fingerprint mismatch'
      });
    }

    const oldSessionId = ws._pqSessionId;
    ws._pqSessionId = undefined;

    if (oldSessionId) {
      deleteCachedPQSession(oldSessionId);
      cryptoLogger.info('[PQ-HANDSHAKE] Clearing old session for rehandshake');
    }

    const kemCiphertextBytes = CryptoUtils.Hash.base64ToUint8Array(payload.kemCiphertext);
    const pqSharedSecret = await CryptoUtils.Kyber.decapsulate(
      kemCiphertextBytes,
      serverHybridKeyPair.kyber.secretKey,
      serverHybridKeyPair.kyber.publicKey
    );

    const clientX25519Public = CryptoUtils.Hash.base64ToUint8Array(payload.clientX25519PublicKey);
    const clientSigningPublicKey = CryptoUtils.Hash.base64ToUint8Array(payload.clientSigningPublicKey);
    const classicalSharedSecret = CryptoUtils.Hybrid.computeClassicalSharedSecret(
      serverHybridKeyPair.x25519.secretKey,
      clientX25519Public
    );

    const encoder = new TextEncoder();
    const baseInfo = `${expectedFingerprint}:${payload.sessionId}`;
    const sendSalt = encoder.encode(`${baseInfo}:send-${payload.timestamp}`);
    const recvSalt = encoder.encode(`${baseInfo}:recv-${payload.timestamp}`);

    const combinedSecret = new Uint8Array(pqSharedSecret.length + classicalSharedSecret.length);
    combinedSecret.set(pqSharedSecret, 0);
    combinedSecret.set(classicalSharedSecret, pqSharedSecret.length);

    const clientSendKey = PostQuantumHash.deriveKey(combinedSecret, sendSalt, 'ws-pq-hybrid-send', 32);
    const clientRecvKey = PostQuantumHash.deriveKey(combinedSecret, recvSalt, 'ws-pq-hybrid-recv', 32);

    try {
      pqSharedSecret.fill(0);
      classicalSharedSecret.fill(0);
      combinedSecret.fill(0);
    } catch { }

    const sessionData = {
      sessionId: payload.sessionId,
      recvKey: clientSendKey,
      sendKey: clientRecvKey,
      fingerprint: expectedFingerprint,
      establishedAt: Date.now(),
      counter: 0,
      clientSigningPublicKey
    };

    await storePQSession(payload.sessionId, sessionData);

    cryptoLogger.info('[PQ-HANDSHAKE] Session established');

    cryptoLogger.info('[PQ-HANDSHAKE] Sending ack in plaintext', {
      wsReady: ws.readyState === 1,
      hasPqSessionId: !!ws._pqSessionId
    });

    await sendSecureMessage(ws, {
      type: SignalType.PQ_HANDSHAKE_ACK,
      sessionId: payload.sessionId,
      timestamp: Date.now(),
      serverTime: Date.now()
    });
    
    ws._pqSessionId = payload.sessionId;
    ws._pqLastRemoteCounter = 0;

    // Update ConnectionStateManager with pqSessionId
    if (ws._sessionId) {
      const { ConnectionStateManager } = await import('../session/connection-state.js');
      try {
        await ConnectionStateManager.updateState(ws._sessionId, {
          pqSessionId: payload.sessionId
        });
      } catch (stateError) {
        cryptoLogger.warn('[PQ-HANDSHAKE] Failed to update connection state', {
          error: stateError?.message
        });
      }
    }

  } catch (error) {
    cryptoLogger.error('[PQ-HANDSHAKE] Handshake failed', {
      error: error.message
    });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Handshake failed'
    });
  }
}

// Handle incoming PQ-encrypted envelope
export async function handlePQEnvelope({ ws, sessionId, envelope, context, handleInnerMessage }) {
  const pqSessionId = envelope.sessionId;
  if (!pqSessionId) {
    cryptoLogger.warn('[PQ-ENVELOPE] No session ID provided');
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'No PQ session ID provided'
    });
  }

  const session = await getPQSession(pqSessionId);
  if (!session) {
    cryptoLogger.warn('[PQ-ENVELOPE] Unknown PQ session');
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Unknown PQ session'
    });
  }

  if (!ws._pqSessionId) {
    ws._pqSessionId = pqSessionId;
    if (!Number.isFinite(ws._pqLastRemoteCounter)) {
      ws._pqLastRemoteCounter = 0;
    }
  }

  if (envelope.sessionFingerprint !== session.fingerprint) {
    cryptoLogger.error('[PQ-ENVELOPE] Session fingerprint mismatch');
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Session fingerprint mismatch'
    });
  }

  const envelopeTimestamp = getEnvelopeTimestampValidation(envelope.timestamp);
  if (!envelopeTimestamp.valid) {
    cryptoLogger.warn('[PQ-ENVELOPE] Timestamp outside replay window', {
      skewClass: skewSizeClass(envelopeTimestamp.skewMs),
      direction: envelopeTimestamp.direction
    });
    return await sendSecureMessage(
      ws,
      timestampInvalidPayload(envelopeTimestamp, 'ENVELOPE_TIMESTAMP_INVALID', 'Envelope timestamp invalid')
    );
  }

  const signatureValid = await verifyClientEnvelopeSignature(session, envelope);
  if (!signatureValid) {
    cryptoLogger.warn('[PQ-ENVELOPE] Client signature verification failed');
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Envelope signature invalid'
    });
  }

  if (!consumeRemoteCounter(ws, envelope)) {
    cryptoLogger.warn('[PQ-ENVELOPE] Remote counter rejected', {
      receivedCounter: envelope?.counter,
      lastCounter: ws?._pqLastRemoteCounter
    });
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Envelope counter invalid'
    });
  }

  try {
    // Decode envelope components
    const ciphertext = CryptoUtils.Hash.base64ToUint8Array(envelope.ciphertext);
    const nonce = CryptoUtils.Hash.base64ToUint8Array(envelope.nonce);
    const tag = CryptoUtils.Hash.base64ToUint8Array(envelope.tag);
    const aad = CryptoUtils.Hash.base64ToUint8Array(envelope.aad);

    // Decrypt
    const pqAead = new CryptoUtils.PostQuantumAEAD(session.recvKey);
    const plaintext = pqAead.decrypt(ciphertext, nonce, tag, aad);
    const decrypted = JSON.parse(new TextDecoder().decode(plaintext));

    const innerPayload = decrypted;

    const innerType = innerPayload?.type || decrypted?.type || 'unknown';
    recordWsInnerMessage(innerType, plaintext.length);
    if (shouldTraceEnvelopePayload(innerPayload)) {
      cryptoLogger.info('[PQ-ENVELOPE] Decrypted client payload', {
        innerType,
        sessionMatchesSocket: pqSessionId === ws._pqSessionId,
        counter: envelope.counter
      });
    }
    const expectedAad = `${innerType}|${envelope.messageId}|${envelope.timestamp}|${envelope.counter}`;
    const aadString = new TextDecoder().decode(aad);
    if (aadString !== expectedAad) {
      cryptoLogger.warn('[PQ-ENVELOPE] AAD mismatch after decrypt', {
        expectedType: innerType,
        messageId: envelope.messageId
      });
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Envelope AAD invalid'
      });
    }

    await handleInnerMessage({
      ws,
      sessionId,
      message: null,
      parsed: innerPayload,
      context
    });
  } catch (error) {
    if (Number.isFinite(envelope?.counter) && ws?._pqLastRemoteCounter === envelope.counter) {
      ws._pqLastRemoteCounter = Math.max(0, envelope.counter - 1);
    }
    cryptoLogger.error('[PQ-ENVELOPE] Decryption failed', {
      error: error.message
    });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Failed to decrypt envelope'
    });
  }
}

// Send PQ-encrypted response to client
export async function sendPQEncryptedResponse(ws, pqSessionIdOrData, payload) {
  const payloadTypeForClosedSocket = payload?.type || 'unknown';
  if (!isWebSocketOpen(ws)) {
    const readyState = wsReadyState(ws);
    if (isClosedWebSocketState(readyState)) {
      cryptoLogger.info('[PQ-ENCRYPT] Skipping encrypted response for closed socket', {
        payloadType: payloadTypeForClosedSocket,
        readyState
      });
      return false;
    }
  }

  try {
    let session;
    if (typeof pqSessionIdOrData === 'string') {
      session = await getPQSession(pqSessionIdOrData);
      if (!session) {
        throw new Error('PQ session not found');
      }
    } else {
      session = pqSessionIdOrData;
    }

    const innerMessage = payload?.type === SignalType.ENCRYPTED_MESSAGE
      ? {
        type: SignalType.ENCRYPTED_MESSAGE,
        encryptedPayload: payload.encryptedPayload
      }
      : payload;

    const messageType = innerMessage?.type || payload?.type || 'unknown';
    const plaintextBudgetBytes = getEncryptedResponsePlaintextBudgetBytes();
    const dominantBytes = dominantResponseStringBytes(innerMessage, messageType);
    if (dominantBytes > plaintextBudgetBytes) {
      return sendOversizedResponseError(
        ws,
        session,
        innerMessage,
        messageType,
        dominantBytes,
        'dominant-string-field'
      );
    }

    const innerJson = JSON.stringify(innerMessage);
    if (typeof innerJson !== 'string') {
      throw new Error('Invalid encrypted response payload');
    }

    const plaintextBytes = Buffer.byteLength(innerJson, 'utf8');
    if (plaintextBytes > plaintextBudgetBytes) {
      return sendOversizedResponseError(
        ws,
        session,
        innerMessage,
        messageType,
        plaintextBytes,
        'json-plaintext'
      );
    }

    const messageId = `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
    const counter = await incrementPQSessionCounter(session.sessionId);
    if (!counter) {
      throw new Error('Failed to update PQ session counter');
    }

    const timestamp = Date.now();
    const aadString = `${messageType}|${messageId}|${timestamp}|${counter}`;
    const aad = new TextEncoder().encode(aadString);

    const plaintext = new TextEncoder().encode(innerJson);

    const pqAead = new CryptoUtils.PostQuantumAEAD(session.sendKey);
    const nonce = crypto.randomBytes(36);
    const { ciphertext, tag } = pqAead.encrypt(plaintext, nonce, aad);

    const envelope = {
      type: SignalType.PQ_ENVELOPE,
      version: 'pq-ws-1',
      sessionId: session.sessionId,
      sessionFingerprint: session.fingerprint,
      messageId,
      counter,
      timestamp,
      ciphertext: Buffer.from(ciphertext).toString('base64'),
      nonce: Buffer.from(nonce).toString('base64'),
      tag: Buffer.from(tag).toString('base64'),
      aad: Buffer.from(aad).toString('base64')
    };

    if (serverDilithiumSigningKey) {
      try {
        const signaturePayload = buildEnvelopeSignaturePayload(envelope);
        cryptoLogger.info('[PQ-SIGN] Signing envelope', {
          hasMessageId: !!envelope.messageId,
          hasSigningKey: !!serverDilithiumSigningKey
        });
        const signatureMessage = new TextEncoder().encode(signaturePayload);
        const signatureBytes = await CryptoUtils.Dilithium.sign(signatureMessage, serverDilithiumSigningKey);
        envelope.signature = Buffer.from(signatureBytes).toString('base64');
      } catch (signError) {
        cryptoLogger.error('[PQ-ENCRYPT] FATAL: Failed to sign envelope', {
          error: signError.message
        });
        throw new Error(`Envelope signing failed: ${signError.message}`);
      }
    } else {
      cryptoLogger.error('[PQ-ENCRYPT] FATAL: No signing key available');
      throw new Error('Server signing key not initialized - cannot send secure messages');
    }

    const padded = shouldPadEnvelopePayload(innerMessage);
    const serialized = padded
      ? padEnvelopeToFixedSize(envelope)
      : JSON.stringify(envelope);
    const serializedBytes = Buffer.byteLength(serialized);

    if (serializedBytes > WS_MAX_ENCRYPTED_RESPONSE_BYTES) {
      cryptoLogger.warn('[PQ-ENCRYPT] Refusing oversized encrypted response', {
        payloadType: messageType,
        responseSizeClass: byteSizeClass(serializedBytes),
        limitClass: byteSizeClass(WS_MAX_ENCRYPTED_RESPONSE_BYTES)
      });

      const errorPayload = oversizedResponseErrorPayload(innerMessage, messageType);
      if (errorPayload) {
        return sendPQEncryptedResponse(ws, session, errorPayload);
      }

      if (messageType !== SignalType.ERROR) {
        return sendPQEncryptedResponse(ws, session, {
          type: SignalType.ERROR,
          code: 'RESPONSE_TOO_LARGE',
          message: 'Server response exceeded transport limit',
          originalType: messageType
        });
      }

      throw new Error('encrypted_response_too_large');
    }

    if (shouldTraceEnvelopePayload(innerMessage)) {
      cryptoLogger.info('[PQ-ENCRYPT] Sending encrypted response', {
        payloadType: messageType,
        serializedBytes,
        padded,
        wsReady: isWebSocketOpen(ws),
        bufferedAmount: ws.bufferedAmount
      });
    }
    recordWsEgress(serializedBytes, messageType);

    if (!isWebSocketOpen(ws)) {
      const readyState = wsReadyState(ws);
      if (isClosedWebSocketState(readyState)) {
        cryptoLogger.info('[PQ-ENCRYPT] Skipping encrypted response for closed socket', {
          payloadType: messageType,
          readyState
        });
        return false;
      }
      throw new WebSocketDeliveryClosedError(readyState, messageType);
    }

    const delivered = await new Promise((resolve, reject) => {
      ws.send(serialized, (error) => {
        if (error) {
          if (isWebSocketDeliveryClosedError(error) || isClosedWebSocketState(wsReadyState(ws))) {
            resolve(false);
            return;
          }
          reject(error);
          return;
        }
        resolve(true);
      });
    });

    if (!delivered) {
      cryptoLogger.info('[PQ-ENCRYPT] Encrypted response dropped because socket closed during send', {
        payloadType: messageType,
        readyState: wsReadyState(ws)
      });
    }

    return delivered;
  } catch (error) {
    if (isWebSocketDeliveryClosedError(error)) {
      cryptoLogger.info('[PQ-ENCRYPT] Encrypted response skipped after socket closed', {
        payloadType: payloadTypeForClosedSocket,
        readyState: wsReadyState(ws)
      });
      return false;
    }

    cryptoLogger.error('[PQ-ENCRYPT] Failed to send encrypted response', {
      error: error.message
    });
    throw error;
  }
}

// Send secure message with automatic PQ encryption when session is available
export async function sendSecureMessage(ws, payload) {
  const pqSessionId = ws._pqSessionId;

  // Whitelist: Only these message types are allowed without PQ encryption
  const allowedPlaintextTypes = [
    SignalType.PQ_HANDSHAKE_ACK,
    SignalType.PQ_HANDSHAKE_INIT,
    SignalType.ERROR,
    SignalType.AUTH_ERROR,
    SignalType.SERVER_PUBLIC_KEY
  ];

  if (pqSessionId) {
    try {
      const session = await getPQSession(pqSessionId);
      if (!session) {
        cryptoLogger.error('[SECURE-MSG] FATAL: PQ session ID exists but session not found', {
          payloadType: payload?.type
        });
        ws.close(1008, 'PQ session lost - security violation');
        throw new Error('PQ session not found in storage');
      }

      const delivered = await sendPQEncryptedResponse(ws, session, payload);
      return delivered;
    } catch (error) {
      if (isWebSocketDeliveryClosedError(error)) {
        cryptoLogger.info('[SECURE-MSG] Secure response not delivered because socket closed', {
          payloadType: payload?.type,
          readyState: wsReadyState(ws)
        });
        return false;
      }

      cryptoLogger.error('[SECURE-MSG] FATAL: PQ encryption failed', {
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
    cryptoLogger.warn('[SECURE-MSG] Blocked secure payload without PQ session', {
      payloadType: payload?.type
    });

    if (isWebSocketOpen(ws)) {
      try {
        ws.send(JSON.stringify({
          type: SignalType.ERROR,
          code: 'PQ_SESSION_REQUIRED',
          message: 'PQ handshake required before sending secure messages',
          requiresHandshake: true
        }));
      } catch (error) {
        cryptoLogger.warn('[SECURE-MSG] Failed to send PQ-required error', {
          error: error?.message
        });
      }
    }
    return;
  }

  const payloadString = JSON.stringify(payload);
  recordWsEgress(Buffer.byteLength(payloadString, 'utf8'), payload?.type || 'plaintext');
  cryptoLogger.info('[SECURE-MSG] Sending whitelisted plaintext message', {
    payloadType: payload?.type,
    wsReady: isWebSocketOpen(ws),
    readyState: ws.readyState,
    bufferedAmount: ws.bufferedAmount,
    payloadSize: payloadString.length
  });

  if (!isWebSocketOpen(ws)) {
    cryptoLogger.info('[SECURE-MSG] Skipping plaintext message for closed socket', {
      payloadType: payload?.type,
      readyState: wsReadyState(ws)
    });
    return false;
  }

  try {
    ws.send(payloadString, (error) => {
      if (error) {
        if (isWebSocketDeliveryClosedError(error) || isClosedWebSocketState(wsReadyState(ws))) {
          cryptoLogger.info('[SECURE-MSG] Plaintext message dropped because socket closed', {
            payloadType: payload?.type,
            readyState: wsReadyState(ws)
          });
          return;
        }
        cryptoLogger.error('[SECURE-MSG] Failed to send plaintext message', {
          payloadType: payload?.type,
          error: error.message,
          readyState: ws.readyState
        });
      } else {
        cryptoLogger.info('[SECURE-MSG] Plaintext message sent successfully', {
          payloadType: payload?.type,
          readyState: ws.readyState
        });
      }
    });
    return true;
  } catch (sendError) {
    if (isWebSocketDeliveryClosedError(sendError) || isClosedWebSocketState(wsReadyState(ws))) {
      cryptoLogger.info('[SECURE-MSG] Plaintext message skipped after socket closed', {
        payloadType: payload?.type,
        readyState: wsReadyState(ws)
      });
      return false;
    }
    cryptoLogger.error('[SECURE-MSG] Exception while sending plaintext message', {
      payloadType: payload?.type,
      error: sendError.message,
      stack: sendError.stack
    });
    throw sendError;
  }
}

// Get or create PQ response sender for a connection
export async function createPQResponseSender(ws, context) {
  return async (wsTarget, payload) => {
    const pqSessionId = wsTarget._pqSessionId || context?.pqSessionId;
    if (!pqSessionId) {
      cryptoLogger.error('[PQ-RESPONSE] No PQ session - SECURITY REQUIREMENT VIOLATION', {
        payloadType: payload?.type
      });
      throw new Error('PQ session required for secure communication');
    }

    const session = await getPQSession(pqSessionId);
    if (!session) {
      cryptoLogger.error('[PQ-RESPONSE] PQ session not found');
      throw new Error('PQ session not found');
    }

    return await sendPQEncryptedResponse(wsTarget, session, payload);
  };
}
