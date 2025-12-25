/**
 * Post-Quantum Crypto Handler for Electron Main Process
 */

const crypto = require('crypto');

let cryptoModules = null;

async function loadCryptoModules() {
  if (cryptoModules) return cryptoModules;
  try {
    const [blake3Module, sha3Module, gcmModule, chachaModule] = await Promise.all([
      import('@noble/hashes/blake3.js'),
      import('@noble/hashes/sha3.js'),
      import('@noble/ciphers/aes.js'),
      import('@noble/ciphers/chacha.js')
    ]);
    cryptoModules = {
      blake3: blake3Module.blake3,
      sha3_512: sha3Module.sha3_512,
      gcm: gcmModule.gcm,
      xchacha20poly1305: chachaModule.xchacha20poly1305
    };
    return cryptoModules;
  } catch (e) {
    return null;
  }
}

const NONCE_SIZE = 36;
const GCM_IV_SIZE = 12;
const MAC_SIZE = 32;

/**
 * Decrypt a pq-envelope
 */
async function decryptEnvelope(envelope, recvKeyBase64) {
  const modules = await loadCryptoModules();
  if (!modules) return null;

  try {
    const { blake3, sha3_512, gcm, xchacha20poly1305 } = modules;

    const recvKey = Buffer.from(recvKeyBase64, 'base64');
    if (recvKey.length !== 32) {
      return null;
    }

    const nonce = Buffer.from(envelope.nonce, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const aadBytes = envelope.aad ? Buffer.from(envelope.aad, 'base64') : Buffer.alloc(0);

    if (nonce.length !== NONCE_SIZE) {
      return null;
    }
    if (tag.length !== MAC_SIZE) {
      return null;
    }

    const expanded = sha3_512(recvKey);
    const k1 = expanded.slice(0, 32);
    const k2 = expanded.slice(32, 64);
    const macKeyInput = Buffer.concat([
      Buffer.from('quantum-secure-mac-v1', 'utf8'),
      recvKey
    ]);
    const macKey = blake3(macKeyInput, { dkLen: 32 });

    const macInput = Buffer.concat([ciphertext, aadBytes, nonce]);
    const expectedMac = blake3(macInput, { key: macKey });

    if (!crypto.timingSafeEqual(Buffer.from(tag), Buffer.from(expectedMac))) {
      return null;
    }

    const xnonce = nonce.slice(GCM_IV_SIZE, NONCE_SIZE);
    const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
    const layer1 = xchacha.decrypt(ciphertext);

    const iv = nonce.slice(0, GCM_IV_SIZE);
    const decipher = gcm(k1, iv, aadBytes);
    const plaintext = decipher.decrypt(layer1);

    const decoded = new TextDecoder().decode(plaintext);
    const parsed = JSON.parse(decoded);
    
    return parsed;
  } catch (e) {
    return null;
  }
}

/**
 * Encrypt a payload into a pq-envelope
 */
async function encryptEnvelope(payload, sendKeyBase64, sessionId, counter = 0, sessionFingerprint = null) {
  const modules = await loadCryptoModules();
  if (!modules) return null;

  try {
    const { blake3, sha3_512, gcm, xchacha20poly1305 } = modules;

    const sendKey = Buffer.from(sendKeyBase64, 'base64');
    if (sendKey.length !== 32) {
      return null;
    }

    const expanded = sha3_512(sendKey);
    const k1 = expanded.slice(0, 32);
    const k2 = expanded.slice(32, 64);
    const macKeyInput = Buffer.concat([
      Buffer.from('quantum-secure-mac-v1', 'utf8'),
      sendKey
    ]);
    const macKey = blake3(macKeyInput, { dkLen: 32 });

    const iv = crypto.randomBytes(GCM_IV_SIZE);
    const xnonce = crypto.randomBytes(24);
    const nonce = Buffer.concat([iv, xnonce]);

    const aadStr = `pq-session:${sessionId}:${counter}`;
    const aadBytes = Buffer.from(aadStr, 'utf8');
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const cipher = gcm(k1, iv, aadBytes);
    const layer1 = cipher.encrypt(plaintext);

    const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
    const ciphertext = xchacha.encrypt(layer1);

    const macInput = Buffer.concat([Buffer.from(ciphertext), aadBytes, nonce]);
    const tag = blake3(macInput, { key: macKey });

    let fingerprint;
    if (sessionFingerprint) {
      fingerprint = sessionFingerprint;
    } else {
      const fingerprintInput = Buffer.concat([
        Buffer.from(sessionId, 'hex'),
        sendKey
      ]);
      fingerprint = Buffer.from(blake3(fingerprintInput, { dkLen: 16 })).toString('hex');
    }

    return {
      type: 'pq-envelope',
      version: 'pq-ws-1',
      sessionId: sessionId,
      sessionFingerprint: fingerprint,
      messageId: crypto.randomUUID(),
      counter: counter,
      timestamp: Date.now(),
      nonce: nonce.toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
      tag: Buffer.from(tag).toString('base64'),
      aad: aadBytes.toString('base64')
    };
  } catch (e) {
    console.log('[PQCrypto] Encryption failed:', e?.message || e);
    return null;
  }
}

/**
 * Get the inner message type from a payload
 */
function getMessageType(decrypted) {
  if (!decrypted) return '';
  
  const outerType = decrypted?.type || '';
  const innerData = decrypted?.data || decrypted;
  
  if (outerType === 'encrypted-message' || outerType === 'ENCRYPTED_MESSAGE') {
    const encPayload = decrypted?.encryptedPayload || innerData?.encryptedPayload;
    if (encPayload) {
      const payloadType = encPayload?.type || encPayload?.signalType || encPayload?.messageSignalType;
      if (payloadType) return payloadType;
    }
    
    const nestedType = innerData?.type || innerData?.signalType || innerData?.messageSignalType;
    if (nestedType && nestedType !== 'encrypted-message' && nestedType !== 'ENCRYPTED_MESSAGE') {
      return nestedType;
    }
    
    const content = decrypted?.content || innerData?.content;
    if (content && typeof content === 'string') {
      try {
        const parsed = JSON.parse(content);
        if (parsed?.type) return parsed.type;
      } catch (_) {}
    }
  }
  
  return innerData?.type || innerData?.signalType || outerType;
}

/**
 * Check if a message type should show a notification
 */
function shouldNotify(messageType, decrypted) {
  const skipTypes = [
    'typing-start', 'typing-stop', 'typing-indicator',
    'delivery-receipt', 'read-receipt',
    'message-read', 'message-delivered',
    'presence', 'status-update',
    'pq-heartbeat-ping', 'pq-heartbeat-pong',
    'session-reset-request', 'session-reset-ack',
    'libsignal-request-bundle', 'libsignal-bundle-response'
  ];

  if (skipTypes.some(t => messageType === t || messageType.includes(t))) {
    return false;
  }

  const innerData = decrypted?.data || decrypted;
  const isActualMessage = messageType === 'encrypted-message' ||
    messageType === 'message' ||
    messageType === 'text' ||
    messageType === 'file-message' ||
    (innerData?.content && typeof innerData.content === 'string' && innerData.content.length > 0);
  const isCallSignal = messageType.startsWith('call-') ||
    ['call-offer', 'call-answer', 'call-ice', 'call-signal', 'call-end'].includes(messageType);

  return isActualMessage || isCallSignal;
}

module.exports = {
  loadCryptoModules,
  decryptEnvelope,
  encryptEnvelope,
  getMessageType,
  shouldNotify
};
