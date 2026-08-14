import { sha3_512 } from '@noble/hashes/sha3.js';
import {
  REQUEST_ID_RE,
  SESSION_FINGERPRINT_RE,
  SESSION_ID_RE
} from './patterns.js';

export {
  REQUEST_ID_RE,
  SESSION_FINGERPRINT_RE,
  SESSION_ID_RE
} from './patterns.js';

export const AUTH_CHANNEL_BINDING_BYTES = 64;
const AUTH_CHANNEL_BINDING_CONTEXT = 'Qor-Authentication-Channel-Binding-v1';

const encoder = new TextEncoder();

export function createAuthChannelBinding({ sessionId, sessionFingerprint, requestId }) {
  if (!SESSION_ID_RE.test(sessionId || '')) {
    throw new Error('Invalid authentication channel session identifier');
  }
  if (!SESSION_FINGERPRINT_RE.test(sessionFingerprint || '')) {
    throw new Error('Invalid authentication channel server fingerprint');
  }
  if (!REQUEST_ID_RE.test(requestId || '')) {
    throw new Error('Invalid authentication channel request identifier');
  }

  const preimage = encoder.encode(
    `${AUTH_CHANNEL_BINDING_CONTEXT}\0${sessionFingerprint}\0${sessionId}\0${requestId}`
  );
  try {
    return sha3_512(preimage);
  } finally {
    preimage.fill(0);
  }
}
