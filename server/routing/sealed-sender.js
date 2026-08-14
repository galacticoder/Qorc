/**
 * Sealed Sender Encryption
 */

import { SPOOL_DETECTION_PROBE_BYTES, SPOOL_TAG_BYTES, isSpoolProbeHex, isSpoolTag } from '../../shared/spool-tag-protocol.js';
import { ML_KEM_1024_CIPHERTEXT_BYTES } from '../../shared/crypto-sizes.js';
import { BASE64_ALPHABET, SEALED_NONCE_BYTES } from '../utils/crypto-consts.js';
import { CANONICAL_BASE64_RE } from '../utils/patterns.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

export const SEALED_ENVELOPE_VERSION = PROTOCOL_KEYS.SEALED_ENVELOPE_VERSION;
export const SEALED_STANDARD_CIPHERTEXT_BYTES = 131072 + 16;
export const SEALED_LARGE_CIPHERTEXT_BYTES = 262144 + 16;
export const SEALED_KEM_CIPHERTEXT_BYTES = ML_KEM_1024_CIPHERTEXT_BYTES;
export { SEALED_NONCE_BYTES };
const ALLOWED_CIPHERTEXT_SIZES = new Set([
  SEALED_STANDARD_CIPHERTEXT_BYTES,
  SEALED_LARGE_CIPHERTEXT_BYTES
]);

// Validate a sealed envelope structure
const ALLOWED_ENVELOPE_FIELDS = new Set(['version', 'ciphertext', 'ephemeralKey', 'nonce', 'tag', 'probe']);

function canonicalBase64DecodedLength(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !CANONICAL_BASE64_RE.test(value)
  ) {
    return null;
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  if (padding === 2) {
    const sextet = BASE64_ALPHABET.indexOf(value[value.length - 3]);
    if (sextet < 0 || (sextet & 0x0f) !== 0) return null;
  } else if (padding === 1) {
    const sextet = BASE64_ALPHABET.indexOf(value[value.length - 2]);
    if (sextet < 0 || (sextet & 0x03) !== 0) return null;
  }
  return (value.length / 4) * 3 - padding;
}

export function validateSealedEnvelope(envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    Array.isArray(envelope) ||
    (Object.getPrototypeOf(envelope) !== Object.prototype && Object.getPrototypeOf(envelope) !== null)
  ) {
    return { valid: false, error: 'invalid_format' };
  }

  const keys = Object.keys(envelope);
  if (keys.length !== ALLOWED_ENVELOPE_FIELDS.size) {
    return { valid: false, error: 'invalid_field_count' };
  }

  // Check version
  if (envelope.version !== SEALED_ENVELOPE_VERSION) {
    return { valid: false, error: 'unsupported_version' };
  }

  for (const key of Object.keys(envelope)) {
    if (!ALLOWED_ENVELOPE_FIELDS.has(key)) {
      return { valid: false, error: 'unexpected_field' };
    }
  }

  // Check required fields exist
  const requiredFields = ['ciphertext', 'ephemeralKey', 'nonce'];
  for (const field of requiredFields) {
    if (!envelope[field] || typeof envelope[field] !== 'string') {
      return { valid: false, error: `missing_${field}` };
    }
  }
  
  const ciphertextBytes = canonicalBase64DecodedLength(envelope.ciphertext);
  if (ciphertextBytes === null) {
    return { valid: false, error: 'invalid_ciphertext_encoding' };
  }
  if (!ALLOWED_CIPHERTEXT_SIZES.has(ciphertextBytes)) {
    return { valid: false, error: 'invalid_ciphertext_size' };
  }

  const ephemeralKeyBytes = canonicalBase64DecodedLength(envelope.ephemeralKey);
  if (ephemeralKeyBytes !== SEALED_KEM_CIPHERTEXT_BYTES) {
    return { valid: false, error: 'invalid_ephemeral_key' };
  }

  const nonceBytes = canonicalBase64DecodedLength(envelope.nonce);
  if (nonceBytes !== SEALED_NONCE_BYTES) {
    return { valid: false, error: 'invalid_nonce' };
  }

  // every envelope carries a tag including cover traffic
  if (!isSpoolTag(envelope.tag)) {
    return { valid: false, error: 'invalid_tag' };
  }

  if (!isSpoolProbeHex(envelope.probe)) {
    return { valid: false, error: 'invalid_probe' };
  }

  return {
    valid: true,
    decodedBytes:
      ciphertextBytes + ephemeralKeyBytes + nonceBytes + SPOOL_TAG_BYTES + SPOOL_DETECTION_PROBE_BYTES
  };
}
