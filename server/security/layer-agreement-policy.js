import { ML_KEM_1024_ALGORITHM } from '../utils/crypto-consts.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

export const REQUIRED_WS_PQ_HANDSHAKE = Object.freeze({
  version: PROTOCOL_KEYS.WS_PQ_PROTOCOL_VERSION,
  kem: ML_KEM_1024_ALGORITHM,
  signature: 'ML-DSA-87',
  classicalKeyAgreement: 'X25519',
  kdf: 'BLAKE3-HKDF-SHA256-DOMAIN-SEPARATED',
  aead: 'QORC-PQ-AEAD',
});

export function validateWsWireProtection({ hasPqSession, isPqProtected, messageType } = {}) {
  if (hasPqSession && !isPqProtected) {
    return { valid: false, reason: 'plaintext_after_pq_session' };
  }
  if (!hasPqSession && isPqProtected) {
    return { valid: false, reason: 'protected_message_without_session' };
  }
  return { valid: true };
}

export function validatePqHandshakePolicy(payload) {
  if (
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload) ||
    Object.getPrototypeOf(payload) !== Object.prototype
  ) {
    return { valid: false, reason: 'missing_payload' };
  }

  const expectedPayloadKeys = [
    'algorithms',
    'clientKemPublicKey',
    'clientNonce',
    'clientX25519PublicKey',
    'fingerprint',
    'kemCiphertext',
    'sessionId',
    'timestamp',
    'version',
  ];
  if (Object.keys(payload).sort().join(',') !== expectedPayloadKeys.sort().join(',')) {
    return { valid: false, reason: 'invalid_payload_shape' };
  }

  const algorithms = payload.algorithms || {};
  if (
    typeof algorithms !== 'object' ||
    Array.isArray(algorithms) ||
    Object.getPrototypeOf(algorithms) !== Object.prototype ||
    Object.keys(algorithms).sort().join(',') !== 'aead,classicalKeyAgreement,kdf,kem,signature'
  ) {
    return { valid: false, reason: 'invalid_algorithms_shape' };
  }
  const requiredFields = [
    ['version', payload.version, REQUIRED_WS_PQ_HANDSHAKE.version],
    ['kem', algorithms.kem, REQUIRED_WS_PQ_HANDSHAKE.kem],
    ['signature', algorithms.signature, REQUIRED_WS_PQ_HANDSHAKE.signature],
    ['classicalKeyAgreement', algorithms.classicalKeyAgreement, REQUIRED_WS_PQ_HANDSHAKE.classicalKeyAgreement],
    ['kdf', algorithms.kdf, REQUIRED_WS_PQ_HANDSHAKE.kdf],
    ['aead', algorithms.aead, REQUIRED_WS_PQ_HANDSHAKE.aead],
  ];

  for (const [name, actual, expected] of requiredFields) {
    if (actual !== expected) {
      return { valid: false, reason: `invalid_${name}` };
    }
  }

  const requiredPayloadFields = [
    'sessionId',
    'timestamp',
    'clientNonce',
    'clientKemPublicKey',
    'kemCiphertext',
    'clientX25519PublicKey',
    'fingerprint',
  ];
  for (const field of requiredPayloadFields) {
    if (payload[field] === undefined || payload[field] === null || payload[field] === '') {
      return { valid: false, reason: `missing_${field}` };
    }
  }

  return { valid: true, algorithms: REQUIRED_WS_PQ_HANDSHAKE };
}
