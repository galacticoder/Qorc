/**
 * Handler Core
 */

import { SignalType } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { MessageDatabase, UserDatabase, BlockingDatabase } from '../database/database.js';
import { logEvent, logError, logDeliveryEvent } from '../security/logging.js';
import { getPQSession } from '../session/pq-session-storage.js';
import { sendPQEncryptedResponse, sendSecureMessage, createPQResponseSender } from '../messaging/pq-envelope-handler.js';
import { handleBundlePublish, handleBundleFailure } from '../messaging/libsignal-handler.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import crypto from 'crypto';
import { routeToInbox } from '../routing/blind-router.js';
import { SealedSender } from '../routing/sealed-sender.js';
import { TimingProtection } from '../routing/timing-protection.js';

// Anonymize identifiers in logs
const logSalt = crypto.randomBytes(16).toString('hex');
export function anonId(id) {
  if (!id) return '[none]';
  return crypto.createHash('blake2b512').update(`${logSalt}:${id}`).digest('hex').slice(0, 8);
}

// Key length constants
export const KYBER_PUBLIC_KEY_LENGTH = 1568;
export const DILITHIUM_PUBLIC_KEY_LENGTH = 2592;
export const X25519_PUBLIC_KEY_LENGTH = 32;

export function isValidBase64Key(b64, expectedLen) {
  if (!b64 || typeof b64 !== 'string') return false;
  try {
    const bytes = Buffer.from(b64, 'base64');
    return bytes.length === expectedLen;
  } catch (_e) {
    return false;
  }
}

export function sanitizeHybridKeysServer(keys) {
  const out = {};
  if (keys && typeof keys === 'object') {
    if (isValidBase64Key(keys.kyberPublicBase64, KYBER_PUBLIC_KEY_LENGTH)) out.kyberPublicBase64 = keys.kyberPublicBase64;
    if (isValidBase64Key(keys.dilithiumPublicBase64, DILITHIUM_PUBLIC_KEY_LENGTH)) out.dilithiumPublicBase64 = keys.dilithiumPublicBase64;
    if (isValidBase64Key(keys.x25519PublicBase64, X25519_PUBLIC_KEY_LENGTH)) out.x25519PublicBase64 = keys.x25519PublicBase64;
  }
  return out;
}

// Re-export commonly used modules
export {
  SignalType,
  CryptoUtils,
  MessageDatabase,
  UserDatabase,
  BlockingDatabase,
  logEvent,
  logError,
  logDeliveryEvent,
  getPQSession,
  sendPQEncryptedResponse,
  sendSecureMessage,
  createPQResponseSender,
  handleBundlePublish,
  handleBundleFailure,
  rateLimitMiddleware,
  cryptoLogger,
  crypto,
  routeToInbox,
  SealedSender,
  TimingProtection
};
