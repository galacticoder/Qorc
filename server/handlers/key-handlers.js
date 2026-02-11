/**
 * Key Handlers
 * 
 * Handles hybrid public key updates and storage.
 */

import {
  SignalType,
  CryptoUtils,
  UserDatabase,
  logEvent,
  logError,
  sendSecureMessage,
  cryptoLogger
} from './core.js';
import { sanitizeHybridKeysServer } from './core.js';

export async function handleHybridKeysUpdate({ ws, parsed, state, serverHybridKeyPair }) {
  if (!state?.hasAuthenticated || !state?.credentialId) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  cryptoLogger.info('[HYBRID-KEYS] Received key update request', {
    credentialId: state.credentialId?.slice(0, 8) + '...',
    hasUserData: !!parsed.userData
  });

  try {
    let senderDilithiumPublicKey = parsed.userData?.metadata?.sender?.dilithiumPublicKey;

    if (!senderDilithiumPublicKey) {
      const existingKeys = await UserDatabase.getHybridPublicKeys(state.credentialId);
      if (existingKeys?.dilithiumPublicBase64) {
        senderDilithiumPublicKey = existingKeys.dilithiumPublicBase64;
      }
    }

    if (!senderDilithiumPublicKey) {
      throw new Error('Sender Dilithium public key required for verification');
    }

    const decryptResult = await CryptoUtils.Hybrid.decryptIncoming(
      parsed.userData,
      {
        kyberPublicKey: serverHybridKeyPair.kyber.publicKey,
        kyberSecretKey: serverHybridKeyPair.kyber.secretKey,
        x25519SecretKey: serverHybridKeyPair.x25519.secretKey
      },
      { senderDilithiumPublicKey }
    );

    let parsedKeys;
    if (decryptResult.payloadJson && typeof decryptResult.payloadJson === 'object') {
      parsedKeys = decryptResult.payloadJson;
    } else if (decryptResult.payload) {
      if (typeof decryptResult.payload === 'string') {
        parsedKeys = JSON.parse(decryptResult.payload);
      } else if (decryptResult.payload instanceof Uint8Array || Buffer.isBuffer(decryptResult.payload)) {
        parsedKeys = JSON.parse(Buffer.from(decryptResult.payload).toString('utf8'));
      } else {
        parsedKeys = decryptResult.payload;
      }
    } else {
      parsedKeys = decryptResult;
    }

    const sanitizedKeys = sanitizeHybridKeysServer(parsedKeys);

    if (Object.keys(sanitizedKeys).length === 0 || !sanitizedKeys.kyberPublicBase64 || !sanitizedKeys.dilithiumPublicBase64) {
      await sendSecureMessage(ws, {
        type: SignalType.KEYS_STORED,
        success: false,
        error: 'Invalid or missing hybrid keys'
      });
      cryptoLogger.error('[HYBRID-KEYS] Invalid hybrid keys after sanitization', sanitizedKeys);
      return;
    }

    await UserDatabase.updateHybridPublicKeys(state.credentialId, sanitizedKeys);

    await sendSecureMessage(ws, {
      type: SignalType.KEYS_STORED,
      success: true,
      message: 'Hybrid keys updated'
    });

    logEvent('hybrid-keys-updated', { 
      credentialId: state.credentialId?.slice(0, 8),
      keyCount: Object.keys(sanitizedKeys).length
    });
  } catch (error) {
    cryptoLogger.error('[HYBRID-KEYS] Update failed', {
      error: error.message
    });
    logError(error, { operation: 'hybrid-keys-update' });
    await sendSecureMessage(ws, {
      type: SignalType.KEYS_STORED,
      success: false,
      error: 'Failed to process keys'
    });
  }
}

export async function handleRateLimitStatus({ ws, state }) {
  try {
    const { rateLimitMiddleware } = await import('../rate-limiting/rate-limit-middleware.js');
    const stats = rateLimitMiddleware.getStats();
    const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();
    const userStatus = state?.credentialId ? await rateLimitMiddleware.getUserStatus(state.credentialId) : null;

    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      stats,
      globalConnectionStatus: globalStatus,
      userStatus,
    });
  } catch (error) {
    logError(error, { operation: 'rate-limit-status' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error getting rate limit status' });
  }
}
