import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, isHex } from './bytes.js';
import { PostQuantumHash } from './post-quantum-hash.js';
import { SPOOL_TAG_PROTOCOL } from './protocol-keys.js';

export { SPOOL_TAG_PROTOCOL } from './protocol-keys.js';

/**
 * Spool tag protocol
 *
 * A one time detection label attached to every spooled message, so a recipient
 * can find its own entries by scanning a compact index instead of trial
 * decapsulating the whole spool. A tag is 8 bytes against a 132,668-byte PIR
 * envelope.
 *
 * Tags cannot come from the message ratchet: its DH step re-keys the receiving
 * chain from the sender's next ephemeral public key, and that key sits inside
 * the entry being searched for, so detection would depend on having already
 * found the thing.
 *
 * Tags must never repeat and must never be derivable from recipients
 * long lived material. A stable per recipient tag would be a permanent
 * pseudonym, which at least yields 1-of-N/B.
 */

export const SPOOL_TAG_BYTES = 8;
export const SPOOL_TAG_HEX_CHARS = SPOOL_TAG_BYTES * 2;
export const SPOOL_DETECTION_KEY_BYTES = 32;
export const SPOOL_DETECTION_PROBE_BYTES = 32;
export const SPOOL_DETECTION_PROBE_HEX_CHARS = SPOOL_DETECTION_PROBE_BYTES * 2;
export const SPOOL_TAG_INDEX_POLL_INTERVAL_MS = 180 * 1000;

const DETECTION_DOMAIN = new TextEncoder().encode(`${SPOOL_TAG_PROTOCOL}:detection`);

export function spoolDetectionTag(sharedSecret) {
  if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== SPOOL_DETECTION_KEY_BYTES) {
    throw new Error('Invalid detection shared secret');
  }
  const tag = PostQuantumHash.domainKdf(
    DETECTION_DOMAIN,
    sharedSecret,
    SPOOL_TAG_BYTES
  );
  try {
    return encodeSpoolTag(tag);
  } finally {
    tag.fill(0);
  }
}

export function isSpoolProbeHex(value) {
  return isHex(value, { exactBytes: SPOOL_DETECTION_PROBE_BYTES });
}

export function encodeSpoolTag(tag) {
  if (!(tag instanceof Uint8Array) || tag.length !== SPOOL_TAG_BYTES) {
    throw new Error('Invalid spool tag');
  }
  return bytesToHex(tag);
}

export function isSpoolTag(value) {
  return isHex(value, { exactBytes: SPOOL_TAG_BYTES });
}

export function untargetedProbeHex() {
  const ephemeral = new Uint8Array(SPOOL_DETECTION_PROBE_BYTES);
  globalThis.crypto.getRandomValues(ephemeral);
  try {
    const pub = x25519.getPublicKey(ephemeral);
    try {
      return bytesToHex(pub);
    } finally {
      pub.fill(0);
    }
  } finally {
    ephemeral.fill(0);
  }
}
