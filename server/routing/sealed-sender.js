/**
 * Sealed Sender Encryption
 */

// Sealed envelope version
const SEALED_ENVELOPE_VERSION = 'ss-v1';
const MIN_ENVELOPE_SIZE = 2048;
const MAX_ENVELOPE_SIZE = 1024 * 1024;

/**
 * Validate a sealed envelope structure
 */
export function validateSealedEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, error: 'invalid_format' };
  }
  
  // Check version
  if (envelope.version !== SEALED_ENVELOPE_VERSION) {
    return { valid: false, error: 'unsupported_version' };
  }
  
  // Check required fields exist
  const requiredFields = ['ciphertext', 'ephemeralKey', 'nonce'];
  for (const field of requiredFields) {
    if (!envelope[field] || typeof envelope[field] !== 'string') {
      return { valid: false, error: `missing_${field}` };
    }
  }
  
  // Validate ciphertext is base64 and within size limits
  try {
    const ciphertextBytes = Buffer.from(envelope.ciphertext, 'base64');
    if (ciphertextBytes.length < MIN_ENVELOPE_SIZE) {
      return { valid: false, error: 'envelope_too_small' };
    }
    if (ciphertextBytes.length > MAX_ENVELOPE_SIZE) {
      return { valid: false, error: 'envelope_too_large' };
    }
  } catch {
    return { valid: false, error: 'invalid_ciphertext_encoding' };
  }
  
  return { valid: true };
}

/**
 * Anti patterns to check for in envelopes
 */
export function checkForAntiPatterns(envelope) {
  const issues = [];
  
  // Check for common identity leaks
  if (envelope.from || envelope.sender || envelope.senderUsername) {
    issues.push('sender_identity_in_envelope');
  }
  
  if (envelope.senderInbox) {
    issues.push('sender_inbox_exposed');
  }
  
  // Check for hashed usernames
  if (envelope.fromHash || envelope.senderHash) {
    issues.push('hashed_identity_in_envelope');
  }
  
  // Check for public key in outer envelope
  if (envelope.senderPublicKey || envelope.fromPublicKey) {
    issues.push('public_key_in_outer_envelope');
  }
  
  return issues;
}

export const SealedSender = {
  SEALED_ENVELOPE_VERSION,
  MIN_ENVELOPE_SIZE,
  MAX_ENVELOPE_SIZE,
  validateSealedEnvelope,
  checkForAntiPatterns,
};
