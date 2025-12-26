/**
 * Post-Quantum Envelope Handler
 * Handles PQ handshake establishment and encrypted envelope processing
 * for quantum-secure WebSocket communication
 */

import crypto from 'crypto';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { PostQuantumHash } from '../crypto/post-quantum-hash.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { SignalType } from '../signals.js';
import { storePQSession, getPQSession, incrementPQSessionCounter } from '../session/pq-session-storage.js';

// Server signing key for envelope authentication
let serverDilithiumSigningKey = null;

/**
 * Initialize the envelope handler with server keys
 */
export function initializeEnvelopeHandler(serverHybridKeyPair) {
  if (serverHybridKeyPair?.dilithium?.secretKey) {
    serverDilithiumSigningKey = serverHybridKeyPair.dilithium.secretKey;
    cryptoLogger.info('[PQ-ENVELOPE] Signing key initialized');
  } else {
    cryptoLogger.warn('[PQ-ENVELOPE] No signing key provided');
  }
}

/**
 * Handle PQ handshake initialization from client
 * Establishes quantum-secure session keys for WebSocket communication
 */
export async function handlePQHandshake({ ws, sessionId, parsed, serverHybridKeyPair }) {
  cryptoLogger.info('[PQ-HANDSHAKE] Received handshake request', {
    sessionId,
    hasPayload: !!parsed?.payload,
    serverId: process.env.SERVER_ID,
    isRehandshake: !!ws._pqSessionId,
    wasAuthenticated: !!ws._authenticated
  });

  const payload = parsed?.payload;
  if (!payload || !payload.kemCiphertext || !payload.sessionId || !payload.clientNonce || !payload.clientX25519PublicKey) {
    cryptoLogger.warn('[PQ-HANDSHAKE] Invalid handshake payload', {
      sessionId,
      hasPayload: !!payload,
      hasKemCiphertext: !!payload?.kemCiphertext,
      hasSessionId: !!payload?.sessionId,
      hasClientNonce: !!payload?.clientNonce,
      hasClientX25519: !!payload?.clientX25519PublicKey
    });
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Invalid handshake payload'
    });
  }

  try {
    cryptoLogger.info('[PQ-HANDSHAKE] CLIENT SENT SESSION ID:', {
      clientSessionId: payload.sessionId,
      clientFingerprint: payload.fingerprint?.slice(0, 16) || 'none',
      timestamp: payload.timestamp
    });

    // Clear old session ID to ensure ack is sent in plaintext
    const oldSessionId = ws._pqSessionId;
    ws._pqSessionId = undefined;

    if (oldSessionId) {
      cryptoLogger.info('[PQ-HANDSHAKE] Clearing old session for rehandshake', {
        oldSessionId: oldSessionId.slice(0, 16) + '...',
        newSessionId: payload.sessionId.slice(0, 16) + '...'
      });
    }

    // Decapsulate Kyber KEM ciphertext to get PQ shared secret
    const kemCiphertextBytes = CryptoUtils.Hash.base64ToUint8Array(payload.kemCiphertext);
    const pqSharedSecret = await CryptoUtils.Kyber.decapsulate(
      kemCiphertextBytes,
      serverHybridKeyPair.kyber.secretKey,
      serverHybridKeyPair.kyber.publicKey
    );

    // Compute classical X25519 shared secret using client's ephemeral key
    const clientX25519Public = CryptoUtils.Hash.base64ToUint8Array(payload.clientX25519PublicKey);
    const classicalSharedSecret = CryptoUtils.Hybrid.computeClassicalSharedSecret(
      serverHybridKeyPair.x25519.secretKey,
      clientX25519Public
    );

    // Combine PQ and classical secrets via XOR, then derive session keys using PQ KDF
    const encoder = new TextEncoder();
    const baseInfo = `${payload.fingerprint}:${payload.sessionId}`;
    const sendSalt = encoder.encode(`${baseInfo}:send-${payload.timestamp}`);
    const recvSalt = encoder.encode(`${baseInfo}:recv-${payload.timestamp}`);

    cryptoLogger.debug('[PQ-HANDSHAKE] Deriving hybrid session keys', {
      sessionId: payload.sessionId.slice(0, 16) + '...',
      timestamp: payload.timestamp,
      fingerprint: payload.fingerprint.slice(0, 16) + '...'
    });

    // XOR pqSharedSecret with classicalSharedSecret
    const combinedSecret = new Uint8Array(pqSharedSecret.length);
    for (let i = 0; i < pqSharedSecret.length; i++) {
      combinedSecret[i] = pqSharedSecret[i] ^ classicalSharedSecret[i % classicalSharedSecret.length];
    }

    const clientSendKey = PostQuantumHash.deriveKey(combinedSecret, sendSalt, 'ws-pq-hybrid-send', 32);
    const clientRecvKey = PostQuantumHash.deriveKey(combinedSecret, recvSalt, 'ws-pq-hybrid-recv', 32);

    // Best-effort wipe of intermediate secrets
    try {
      pqSharedSecret.fill(0);
      classicalSharedSecret.fill(0);
      combinedSecret.fill(0);
    } catch { }

    // Store session in Redis
    const sessionData = {
      sessionId: payload.sessionId,
      recvKey: clientSendKey,
      sendKey: clientRecvKey,
      fingerprint: payload.fingerprint,
      establishedAt: Date.now(),
      counter: 0
    };

    await storePQSession(payload.sessionId, sessionData);

    cryptoLogger.info('[PQ-HANDSHAKE] Session established', {
      sessionId: payload.sessionId.slice(0, 16) + '...'
    });

    cryptoLogger.info('[PQ-HANDSHAKE] Sending ack in plaintext', {
      sessionId: payload.sessionId.slice(0, 16) + '...',
      wsReady: ws.readyState === 1,
      hasPqSessionId: !!ws._pqSessionId
    });

    await sendSecureMessage(ws, {
      type: SignalType.PQ_HANDSHAKE_ACK,
      sessionId: payload.sessionId,
      timestamp: Date.now()
    });

    cryptoLogger.info('[PQ-HANDSHAKE] Ack sent successfully', {
      sessionId: payload.sessionId.slice(0, 16) + '...'
    });

    ws._pqSessionId = payload.sessionId;

    // Update ConnectionStateManager with pqSessionId
    if (ws._sessionId) {
      const { ConnectionStateManager } = await import('../presence/connection-state.js');
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

    setTimeout(async () => {
      try {
        await sendSecureMessage(ws, {
          type: SignalType.PQ_HANDSHAKE_ACK,
          sessionId: payload.sessionId,
          timestamp: Date.now(),
          redundant: true
        });
        cryptoLogger.info('[PQ-HANDSHAKE] Redundant secure ack sent');
      } catch (e) {
        cryptoLogger.warn('[PQ-HANDSHAKE] Redundant secure ack failed', { error: e?.message });
      }
    }, 50);
  } catch (error) {
    cryptoLogger.error('[PQ-HANDSHAKE] Handshake failed', {
      sessionId,
      error: error.message
    });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Handshake failed'
    });
  }
}

/**
 * Handle incoming PQ-encrypted envelope
 * Decrypts and processes the inner message
 */
export async function handlePQEnvelope({ ws, sessionId, envelope, context, handleInnerMessage }) {
  const pqSessionId = envelope.sessionId;
  if (!pqSessionId) {
    cryptoLogger.warn('[PQ-ENVELOPE] No session ID provided', { sessionId });
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'No PQ session ID provided'
    });
  }

  // Retrieve session from Redis
  const session = await getPQSession(pqSessionId);
  if (!session) {
    cryptoLogger.warn('[PQ-ENVELOPE] Unknown PQ session', {
      sessionId,
      pqSessionId: pqSessionId.slice(0, 16) + '...'
    });
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Unknown PQ session'
    });
  }

  if (envelope.sessionFingerprint !== session.fingerprint) {
    cryptoLogger.error('[PQ-ENVELOPE] Session fingerprint mismatch', { sessionId });
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Session fingerprint mismatch'
    });
  }

  try {
    // Decode envelope components
    const ciphertext = CryptoUtils.Hash.base64ToUint8Array(envelope.ciphertext);
    const nonce = CryptoUtils.Hash.base64ToUint8Array(envelope.nonce);
    const tag = CryptoUtils.Hash.base64ToUint8Array(envelope.tag);
    const aad = CryptoUtils.Hash.base64ToUint8Array(envelope.aad);

    cryptoLogger.debug('[PQ-ENVELOPE] Decrypting envelope', {
      pqSessionId: envelope.sessionId.slice(0, 16) + '...',
      messageId: envelope.messageId,
      counter: envelope.counter
    });

    // Decrypt using post-quantum AEAD
    const pqAead = new CryptoUtils.PostQuantumAEAD(session.recvKey);
    const plaintext = pqAead.decrypt(ciphertext, nonce, tag, aad);

    const decrypted = JSON.parse(new TextDecoder().decode(plaintext));

    // Extract inner payload based on message structure
    let innerPayload;
    if (decrypted.to && decrypted.encryptedPayload) {
      // Stripped-down encrypted message for routing
      innerPayload = {
        type: SignalType.ENCRYPTED_MESSAGE,
        to: decrypted.to,
        encryptedPayload: decrypted.encryptedPayload,
        messageId: decrypted.messageId || envelope.messageId
      };
    } else {
      innerPayload = decrypted;
    }

    cryptoLogger.debug('[PQ-ENVELOPE] Envelope decrypted successfully', {
      type: innerPayload?.type
    });

    // Process the inner message
    await handleInnerMessage({
      ws,
      sessionId,
      message: Buffer.from(JSON.stringify(innerPayload)),
      parsed: innerPayload,
      context
    });
  } catch (error) {
    cryptoLogger.error('[PQ-ENVELOPE] Decryption failed', {
      sessionId,
      error: error.message
    });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Failed to decrypt envelope'
    });
  }
}

/**
 * Send PQ-encrypted response to client
 * REQUIRED for all sensitive data transmission
 */
export async function sendPQEncryptedResponse(ws, pqSessionIdOrData, payload) {
  try {
    // Support both session object and session ID
    let session;
    if (typeof pqSessionIdOrData === 'string') {
      session = await getPQSession(pqSessionIdOrData);
      if (!session) {
        throw new Error('PQ session not found');
      }
    } else {
      session = pqSessionIdOrData;
    }

    const messageId = `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
    const counter = await incrementPQSessionCounter(session.sessionId);
    if (!counter) {
      throw new Error('Failed to update PQ session counter');
    }

    const timestamp = Date.now();

    const innerMessage = payload?.type === 'encrypted-message'
      ? {
        type: SignalType.ENCRYPTED_MESSAGE,
        from: payload.from,
        to: payload.to,
        encryptedPayload: payload.encryptedPayload
      }
      : payload;

    const messageType = innerMessage.type || payload.type || 'unknown';
    const aadString = `${messageType}|${messageId}|${timestamp}|${counter}`;
    const aad = new TextEncoder().encode(aadString);

    const plaintext = new TextEncoder().encode(JSON.stringify(innerMessage));

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
        const signaturePayload = `${envelope.messageId}:${envelope.timestamp}:${envelope.counter}:${envelope.sessionId}`;
        cryptoLogger.info('[PQ-SIGN] Signing envelope', {
          payload: signaturePayload,
          messageId: envelope.messageId,
          timestamp: envelope.timestamp,
          counter: envelope.counter,
          sessionId: envelope.sessionId.slice(0, 32),
          signingKeyLength: serverDilithiumSigningKey.length,
          signingKeyType: serverDilithiumSigningKey.constructor.name
        });
        const signatureMessage = new TextEncoder().encode(signaturePayload);
        const signatureBytes = await CryptoUtils.Dilithium.sign(signatureMessage, serverDilithiumSigningKey);
        envelope.signature = Buffer.from(signatureBytes).toString('base64');
      } catch (signError) {
        cryptoLogger.error('[PQ-ENCRYPT] FATAL: Failed to sign envelope', {
          error: signError.message,
          stack: signError.stack
        });
        throw new Error(`Envelope signing failed: ${signError.message}`);
      }
    } else {
      cryptoLogger.error('[PQ-ENCRYPT] FATAL: No signing key available');
      throw new Error('Server signing key not initialized - cannot send secure messages');
    }

    ws.send(JSON.stringify(envelope));
  } catch (error) {
    cryptoLogger.error('[PQ-ENCRYPT] Failed to send encrypted response', {
      error: error.message
    });
    throw error;
  }
}

/**
 * Send secure message with automatic PQ encryption when session is available
 * Only whitelisted message types allowed in plaintext during handshake
 */
export async function sendSecureMessage(ws, payload) {
  const pqSessionId = ws._pqSessionId;

  // Whitelist: Only these message types are allowed without PQ encryption
  // These are strictly for the initial handshake phase before PQ session exists
  const allowedPlaintextTypes = [
    'pq-handshake-ack',      // PQ handshake acknowledgment
    'error',                 // Generic errors (can happen before handshake)
    'server-public-key',     // Server keys must be deliverable pre-PQ handshake
    'ERROR',                 // System errors
    'register-ack'           // P2P registration acknowledgment
  ];

  // If PQ session exists, encryption is MANDATORY
  if (pqSessionId) {
    try {
      const session = await getPQSession(pqSessionId);
      if (!session) {
        cryptoLogger.error('[SECURE-MSG] FATAL: PQ session ID exists but session not found', {
          pqSessionId: pqSessionId.slice(0, 16) + '...',
          payloadType: payload?.type
        });
        ws.close(1008, 'PQ session lost - security violation');
        throw new Error('PQ session not found in storage');
      }

      await sendPQEncryptedResponse(ws, session, payload);
      return;
    } catch (error) {
      cryptoLogger.error('[SECURE-MSG] FATAL: PQ encryption failed', {
        error: error.message,
        payloadType: payload?.type,
        stack: error.stack
      });
      ws.close(1011, 'Encryption failure - security violation');
      throw new Error(`PQ encryption failed: ${error.message}`);
    }
  }

  const isAllowedPlaintext = payload?.type && allowedPlaintextTypes.includes(payload.type);

  if (!isAllowedPlaintext) {
    cryptoLogger.error('[SECURE-MSG] SECURITY VIOLATION: Message requires PQ encryption', {
      payloadType: payload?.type,
      sessionId: ws._sessionId?.slice(0, 16) || 'unknown'
    });

    ws.send(JSON.stringify({
      type: SignalType.ERROR,
      code: 'PQ_SESSION_REQUIRED',
      message: 'PQ handshake required before sending secure messages',
      requiresHandshake: true
    }));

    ws.close(1008, 'PQ session required');
    throw new Error(`Message type '${payload?.type}' requires PQ encryption`);
  }

  const payloadString = JSON.stringify(payload);
  cryptoLogger.info('[SECURE-MSG] Sending whitelisted plaintext message', {
    payloadType: payload?.type,
    wsReady: ws.readyState === 1,
    readyState: ws.readyState,
    bufferedAmount: ws.bufferedAmount,
    payloadSize: payloadString.length
  });

  try {
    ws.send(payloadString, (error) => {
      if (error) {
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
  } catch (sendError) {
    cryptoLogger.error('[SECURE-MSG] Exception while sending plaintext message', {
      payloadType: payload?.type,
      error: sendError.message,
      stack: sendError.stack
    });
    throw sendError;
  }
}

/**
 * Get or create PQ response sender for a connection
 * Ensures PQ envelope is used when available
 */
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
      cryptoLogger.error('[PQ-RESPONSE] PQ session not found', {
        pqSessionId: pqSessionId.slice(0, 16) + '...'
      });
      throw new Error('PQ session not found');
    }

    await sendPQEncryptedResponse(wsTarget, session, payload);
  };
}
