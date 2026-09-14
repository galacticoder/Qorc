import { wipeByteArrays } from './wipe.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import { CANONICAL_BASE64_RE } from '../../shared/patterns.js';

export const UTF8_ENCODER = new TextEncoder();

export function encodeBase64AndWipeCopy(value) {
  const copy = Buffer.from(value);
  try {
    return copy.toString('base64');
  } finally {
    copy.fill(0);
  }
}

export function decodeCanonicalBase64(value, expectedLength, maxChars = 4096) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxChars ||
    value.length % 4 !== 0 ||
    !CANONICAL_BASE64_RE.test(value)
  ) {
    throw new Error('Invalid base64 value');
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== expectedLength || decoded.toString('base64') !== value) {
    decoded.fill(0);
    throw new Error('Invalid base64 value');
  }
  return decoded;
}

export function isCanonicalBase64Bytes(value, expectedLength) {
  if (!Number.isSafeInteger(expectedLength) || expectedLength < 1) return false;
  return canonicalBase64Shape(value, { exactBytes: expectedLength });
}

export function decodeCanonicalBase64List(values, expectedLength, maxChars = 4096) {
  const decoded = [];
  try {
    for (const value of values) {
      decoded.push(decodeCanonicalBase64(value, expectedLength, maxChars));
    }
    return decoded;
  } catch (error) {
    wipeByteArrays(decoded);
    throw error;
  }
}
