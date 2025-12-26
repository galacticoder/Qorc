/**
 * LibSignal Protocol Bundle Handler
 * Handles Signal Protocol bundle storage, retrieval, and validation
 * for quantum-secure end-to-end encrypted messaging
 */

import { LibsignalBundleDB } from '../database/database.js';
import { SecureStateManager } from '../authentication/authentication.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { SignalType } from '../signals.js';

/**
 * Handle Signal Protocol bundle publication from client
 */
export async function handleBundlePublish({ ws, parsed, state, context, sendPQResponse }) {
  cryptoLogger.info('[LIBSIGNAL] Bundle publish request', {
    username: (state.username || 'unknown').slice(0, 8) + '...'
  });

  try {
    const username = state.username;
    if (!username) {
      cryptoLogger.error('[LIBSIGNAL] Bundle publish rejected - not authenticated');
      await sendPQResponse(ws, {
        type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
        success: false,
        error: 'User not authenticated'
      });
      ws.close(1008, 'User not authenticated for bundle publish');
      return;
    }

    const bundle = parsed.bundle;
    if (!bundle) {
      cryptoLogger.error('[LIBSIGNAL] No bundle provided', { username });
      await sendPQResponse(ws, {
        type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
        success: false,
        error: 'No bundle provided'
      });
      ws.close(1008, 'Missing Signal bundle');
      return;
    }

    // Validate bundle structure
    const validationErrors = validateBundleStructure(bundle);
    if (validationErrors.length > 0) {
      const errorMsg = `Invalid bundle structure: ${validationErrors.join(', ')}`;
      cryptoLogger.error('[LIBSIGNAL] Bundle validation failed', {
        username,
        errors: validationErrors
      });
      await sendPQResponse(ws, {
        type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
        success: false,
        error: errorMsg
      });
      setTimeout(() => {
        try {
          ws.close(1008, 'Invalid Signal bundle structure');
        } catch {}
      }, 100);
      return;
    }

    // Transform nested bundle to flat structure for database
    const flatBundle = transformBundleForStorage(bundle);

    // Store bundle in database
    await LibsignalBundleDB.publish(username, flatBundle);
    cryptoLogger.info('[LIBSIGNAL] Bundle stored successfully', {
      username: username.slice(0, 8) + '...'
    });

    // Complete authentication if this was the final step
    if (ws.clientState?.pendingSignalBundle && context?.authHandler) {
      cryptoLogger.info('[LIBSIGNAL] Completing authentication after bundle', {
        username: username.slice(0, 8) + '...'
      });

      ws.clientState = SecureStateManager.setState(ws, {
        pendingSignalBundle: false
      });

      const isNewUser = ws.clientState?.isNewUser || false;
      await context.authHandler.finalizeAuth(
        ws,
        username,
        isNewUser ? 'User registered with Signal bundle' : 'User logged in with Signal bundle'
      );
    }

    // Send success acknowledgment
    await sendPQResponse(ws, {
      type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
      success: true
    });
  } catch (error) {
    const username = state.username || 'unknown';
    cryptoLogger.error('[LIBSIGNAL] Bundle storage failed', {
      username,
      error: error.message
    });
    await sendPQResponse(ws, {
      type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
      success: false,
      error: error.message
    });
    ws.close(1011, 'Bundle storage failed');
  }
}

/**
 * Handle Signal Protocol bundle failure from client
 */
export async function handleBundleFailure({ ws, parsed, state, sendPQResponse }) {
  const failureUsername = state.username || parsed.username || 'unknown';
  cryptoLogger.error('[LIBSIGNAL] Client bundle generation failed', {
    username: failureUsername.slice(0, 8) + '...',
    stage: parsed.stage,
    error: parsed.error
  });

  await sendPQResponse(ws, {
    type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
    success: false,
    error: `Client bundle generation failed at ${parsed.stage}: ${parsed.error}`
  });

  setTimeout(() => {
    try {
      ws.close(1008, `Signal bundle failure: ${parsed.stage}`);
    } catch {}
  }, 100);
}

/**
 * Handle Signal Protocol bundle request from client
 */
export async function handleBundleRequest({ ws, parsed, state, sendPQResponse }) {
  cryptoLogger.info('[LIBSIGNAL] Bundle request', {
    requester: (state.username || 'unknown').slice(0, 8) + '...',
    target: (parsed.username || 'unknown').slice(0, 8) + '...'
  });

  try {
    const requestedUsername = parsed.username;
    if (!requestedUsername) {
      throw new Error('No username provided');
    }

    const throttleKey = `bundle:throttle:${state.username}:${requestedUsername}`;
    const now = Date.now();
    
    try {
      const { withRedisClient } = await import('../presence/presence.js');
      const shouldThrottle = await withRedisClient(async (client) => {
        const lastRequest = await client.get(throttleKey);
        if (lastRequest && (now - parseInt(lastRequest, 10)) < 1000) {
          return true;
        }
        await client.set(throttleKey, now.toString(), 'EX', 2);
        return false;
      });
      
      if (shouldThrottle) {
        cryptoLogger.warn('[LIBSIGNAL] Throttling bundle request', {
          requester: state.username,
          target: requestedUsername
        });
        await sendPQResponse(ws, { type: SignalType.OK });
        return;
      }
    } catch (error) {
      cryptoLogger.warn('[LIBSIGNAL] Redis throttle check failed, allowing request', { error: error.message });
    }

    // Retrieve bundle from database
    const flatBundle = await LibsignalBundleDB.take(requestedUsername);

    // Transform flat bundle to nested structure for client
    const bundle = flatBundle ? transformBundleForClient(flatBundle) : null;

    const responsePayload = {
      type: SignalType.LIBSIGNAL_DELIVER_BUNDLE,
      username: requestedUsername,
      bundle,
      success: !!bundle,
      error: bundle ? undefined : 'Bundle not found'
    };

    if (bundle) {
      cryptoLogger.info('[LIBSIGNAL] Bundle found and sending', {
        target: requestedUsername.slice(0, 8) + '...'
      });
    } else {
      cryptoLogger.warn('[LIBSIGNAL] Bundle not found', {
        target: requestedUsername.slice(0, 8) + '...'
      });
    }

    // Check WebSocket state
    if (ws.readyState !== 1) {
      cryptoLogger.error('[LIBSIGNAL] Cannot send bundle - WebSocket not open', {
        state: ws.readyState
      });
      return;
    }

    // Send bundle response
    await sendPQResponse(ws, responsePayload);
    cryptoLogger.debug('[LIBSIGNAL] Bundle response sent via PQ envelope');
  } catch (error) {
    cryptoLogger.error('[LIBSIGNAL] Bundle retrieval failed', {
      error: error.message
    });
    if (ws.readyState === 1) {
      await sendPQResponse(ws, {
        type: SignalType.LIBSIGNAL_DELIVER_BUNDLE,
        username: parsed.username,
        bundle: null,
        success: false,
        error: error.message
      });
    }
  }
}

/**
 * Validate bundle structure comprehensively
 */
function validateBundleStructure(bundle) {
  const errors = [];

  if (!bundle.registrationId || typeof bundle.registrationId !== 'number') {
    errors.push('Missing or invalid registrationId');
  }

  if (!bundle.identityKeyBase64 || typeof bundle.identityKeyBase64 !== 'string') {
    errors.push('Missing or invalid identityKeyBase64');
  }

  if (!bundle.signedPreKey || typeof bundle.signedPreKey !== 'object') {
    errors.push('Missing or invalid signedPreKey');
  } else {
    if (bundle.signedPreKey.keyId === undefined || bundle.signedPreKey.keyId === null) {
      errors.push('signedPreKey missing keyId');
    }
    if (!bundle.signedPreKey.publicKeyBase64 || typeof bundle.signedPreKey.publicKeyBase64 !== 'string') {
      errors.push('signedPreKey missing or invalid publicKeyBase64');
    }
    const spkSig = bundle.signedPreKey.signatureBase64 || bundle.signedPreKey.signature;
    if (!spkSig || typeof spkSig !== 'string') {
      errors.push('signedPreKey missing or invalid signature');
    }
  }

  if (bundle.deviceId !== undefined && typeof bundle.deviceId !== 'number') {
    errors.push('Invalid deviceId type');
  }

  if (bundle.kyberPreKey) {
    if (typeof bundle.kyberPreKey !== 'object') {
      errors.push('Invalid kyberPreKey structure');
    } else {
      if (!bundle.kyberPreKey.publicKeyBase64 || typeof bundle.kyberPreKey.publicKeyBase64 !== 'string') {
        errors.push('kyberPreKey missing or invalid publicKeyBase64');
      }
      const kySig = bundle.kyberPreKey.signatureBase64 || bundle.kyberPreKey.signature;
      if (!kySig || typeof kySig !== 'string') {
        errors.push('kyberPreKey missing or invalid signature');
      }
    }
  }

  return errors;
}

/**
 * Transform nested bundle structure to flat structure for database
 */
function transformBundleForStorage(bundle) {
  return {
    registrationId: bundle.registrationId,
    deviceId: bundle.deviceId,
    identityKeyBase64: bundle.identityKeyBase64,
    preKeyId: bundle.preKey?.keyId ?? null,
    preKeyPublicBase64: bundle.preKey?.publicKeyBase64 ?? null,
    signedPreKeyId: bundle.signedPreKey?.keyId,
    signedPreKeyPublicBase64: bundle.signedPreKey?.publicKeyBase64,
    signedPreKeySignatureBase64: bundle.signedPreKey?.signatureBase64 || bundle.signedPreKey?.signature,
    kyberPreKeyId: bundle.kyberPreKey?.keyId,
    kyberPreKeyPublicBase64: bundle.kyberPreKey?.publicKeyBase64,
    kyberPreKeySignatureBase64: bundle.kyberPreKey?.signatureBase64 || bundle.kyberPreKey?.signature
  };
}

/**
 * Transform flat bundle from database to nested structure for client
 */
function transformBundleForClient(flatBundle) {
  return {
    registrationId: flatBundle.registrationId,
    deviceId: flatBundle.deviceId,
    identityKeyBase64: flatBundle.identityKeyBase64,
    preKey: flatBundle.preKeyId ? {
      keyId: flatBundle.preKeyId,
      publicKeyBase64: flatBundle.preKeyPublicBase64
    } : undefined,
    signedPreKey: {
      keyId: flatBundle.signedPreKeyId,
      publicKeyBase64: flatBundle.signedPreKeyPublicBase64,
      signatureBase64: flatBundle.signedPreKeySignatureBase64
    },
    kyberPreKey: {
      keyId: flatBundle.kyberPreKeyId,
      publicKeyBase64: flatBundle.kyberPreKeyPublicBase64,
      signatureBase64: flatBundle.kyberPreKeySignatureBase64
    }
  };
}
