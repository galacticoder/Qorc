/**
 * LibSignal Protocol Bundle Handler
 * 
 * Handles Signal Protocol bundle storage, retrieval, and validation
 */

import { LibsignalBundleDB } from '../database/database.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { SignalType } from '../signals.js';

// Handle Signal Protocol bundle publication from client
export async function handleBundlePublish({ ws, parsed, sendPQResponse }) {
  const inboxId = ws._primaryInboxId;

  cryptoLogger.info('[LIBSIGNAL] Bundle publish request', {
    inboxId: inboxId?.slice(0, 8) || 'unknown'
  });

  try {
    if (!inboxId) {
      cryptoLogger.error('[LIBSIGNAL] Bundle publish rejected - no inboxId', {
        hasInboxId: false
      });
      await sendPQResponse(ws, {
        type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
        success: false,
        error: 'Not authenticated for blind routing'
      });
      ws.close(1008, 'Inbox ID required for bundle publish');
      return;
    }

    const bundle = parsed.bundle;
    if (!bundle) {
      cryptoLogger.error('[LIBSIGNAL] No bundle provided');
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
        } catch { }
      }, 100);
      return;
    }

    const flatBundle = transformBundleForStorage(bundle);
    await LibsignalBundleDB.publish(inboxId, flatBundle);
    cryptoLogger.info('[LIBSIGNAL] Bundle stored successfully', {
      inboxId: inboxId.slice(0, 8)
    });

    await sendPQResponse(ws, {
      type: SignalType.LIBSIGNAL_PUBLISH_STATUS,
      success: true
    });
  } catch (error) {
    cryptoLogger.error('[LIBSIGNAL] Bundle storage failed', {
      inboxId: inboxId?.slice(0, 8) || 'unknown',
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

// Handle Signal Protocol bundle failure from client
export async function handleBundleFailure({ ws, parsed, sendPQResponse }) {
  const inboxId = ws._primaryInboxId;
  cryptoLogger.error('[LIBSIGNAL] Client bundle generation failed', {
    inboxId: inboxId?.slice(0, 8) || 'unknown',
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
    } catch { }
  }, 100);
}


// Validate bundle structure
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

  // TODO: fix this the bundle doesnt have the deviceID.
  // deviceId isnt the users its from the signal protocol and stays anon.
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

// Transform nested bundle structure to flat structure for database
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