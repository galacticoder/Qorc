/**
 * Handler Core
 */

import crypto from 'crypto';
import { SignalType } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { UserDatabase, BlockingDatabase } from '../database/database.js';
import { logEvent, logError, logDeliveryEvent } from '../security/logging.js';
import { getPQSession } from '../session/pq-session-storage.js';
import { sendPQEncryptedResponse, sendSecureMessage, createPQResponseSender } from '../messaging/pq-envelope-handler.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { SealedSender } from '../routing/sealed-sender.js';
import { TimingProtection } from '../routing/timing-protection.js';

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

export function hasAccountAuthentication(ws, state = {}) {
  return !!state?.hasAuthenticated || !!ws?._authenticated || !!ws?._hasAuthenticated;
}

export function hasServerOrAccountAuthentication(ws, state = {}) {
  return hasAccountAuthentication(ws, state) || !!state?.hasServerAuth || !!ws?._hasServerAuth;
}

export {
  SignalType,
  CryptoUtils,
  UserDatabase,
  BlockingDatabase,
  logEvent,
  logError,
  logDeliveryEvent,
  getPQSession,
  sendPQEncryptedResponse,
  sendSecureMessage,
  createPQResponseSender,
  rateLimitMiddleware,
  cryptoLogger,
  crypto,
  SealedSender,
  TimingProtection
};
