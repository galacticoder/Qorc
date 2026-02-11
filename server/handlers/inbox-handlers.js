/**
 * Inbox Handlers
 * 
 * Handles inbox claiming, rotation, and blind routing.
 */

import { routeToDestinationInbox } from './message-handlers.js';
import {
  SignalType,
  MessageDatabase,
  sendSecureMessage,
  cryptoLogger,
  TimingProtection
} from './core.js';

/**
 * Handle blind route message
 */
export async function handleBlindRoute({ ws, parsed, state }) {
  if (!state?.hasAuthenticated && !ws._unlinkedSession) {
    cryptoLogger.warn('[BLIND-ROUTE] Rejected - not authenticated');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { destinationInbox, sealedEnvelope } = parsed;

  if (!destinationInbox || typeof destinationInbox !== 'string') {
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: 'invalid_destination'
    });
  }

  if (!sealedEnvelope) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLIND_ROUTE_ACK,
      success: false,
      error: 'missing_envelope'
    });
  }

  // Route using blind router
  const result = await routeToDestinationInbox(destinationInbox, sealedEnvelope);

  await sendSecureMessage(ws, {
    type: SignalType.BLIND_ROUTE_ACK,
    success: result.delivered || result.queued,
    queued: result.queued,
    error: result.error
  });
}

/**
 * Handle inbox claim request
 */
export async function handleClaimInbox({ ws, parsed, state }) {
  const { capabilityToken, inboxId, blindSignature, blindSignatureKid } = parsed;

  if (!capabilityToken || !inboxId) {
    return await sendSecureMessage(ws, {
      type: SignalType.CLAIM_INBOX_RESPONSE,
      success: false,
      error: 'missing_params'
    });
  }

  // UNLINKED AUTHENTICATION: Check blind signature if provided
  let isAuthorized = !!state?.hasAuthenticated;
  if (!isAuthorized && blindSignature) {
    try {
      if (!blindSignatureKid || typeof blindSignatureKid !== 'string') {
        throw new Error('Missing blind signature key id');
      }
      const { BlindSignatureIssuer } = await import('../security/blind-signatures.js');
      const isValid = await BlindSignatureIssuer.verifySignature(inboxId, blindSignature, blindSignatureKid);
      if (isValid) {
        isAuthorized = true;
        ws._unlinkedSession = true;
        console.log(`[ROUTING] Authorized unlinked inbox claim via blind signature for ${inboxId.slice(0, 8)}...`);
      }
    } catch (e) {
      console.error('[ROUTING] Blind signature verification failed:', e.message);
    }
  }

  if (!isAuthorized) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { claimInbox, registerLocalSocket } = await import('../routing/blind-router.js');
  if (!ws._blindSocketId) {
    try { registerLocalSocket(ws); } catch { }
  }
  const result = await claimInbox(ws, capabilityToken, inboxId, isAuthorized);

  if (result.success) {
    if (!ws._primaryInboxId) {
      ws._primaryInboxId = inboxId;
    }

    if (!ws._claimedInboxes) ws._claimedInboxes = new Set();
    ws._claimedInboxes.add(inboxId);

    TimingProtection.registerForCoverTraffic(inboxId);

    // Deliver any queued offline messages
    try {
      const queued = await MessageDatabase.takeOfflineMessages(inboxId, 200);
      if (queued.length > 0) {
        cryptoLogger.info(`[ROUTING] Delivering ${queued.length} offline messages to newly claimed inbox: ${inboxId.slice(0, 8)}`);
        for (const msg of queued) {
          try {
            await sendSecureMessage(ws, msg);
          } catch (e) {
            await MessageDatabase.queueOfflineMessage(inboxId, msg);
          }
        }
      }
    } catch (e) {
      cryptoLogger.error('[ROUTING] Offline message delivery failed:', e.message);
    }
  }

  await sendSecureMessage(ws, {
    type: SignalType.CLAIM_INBOX_RESPONSE,
    success: result.success,
    inboxId: result.success ? inboxId : undefined,
    error: result.error
  });
}

/**
 * Handle inbox rotation
 */
export async function handleRotateInbox({ ws, parsed, state }) {
  if (!state?.hasAuthenticated) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { capabilityToken, oldInboxIds, newInboxIds } = parsed;

  if (!capabilityToken || !oldInboxIds || !newInboxIds) {
    return await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: false,
      error: 'missing_params'
    });
  }

  try {
    const { rotateInboxes } = await import('../routing/blind-router.js');
    const result = await rotateInboxes(ws, capabilityToken, oldInboxIds, newInboxIds);

    if (result.success) {
      // Update claimed inboxes
      if (ws._claimedInboxes) {
        for (const oldId of oldInboxIds) {
          ws._claimedInboxes.delete(oldId);
        }
      }
      if (!ws._claimedInboxes) ws._claimedInboxes = new Set();
      for (const newId of newInboxIds) {
        ws._claimedInboxes.add(newId);
      }

      cryptoLogger.info('[ROUTING] Inbox rotation completed', {
        oldCount: oldInboxIds.length,
        newCount: newInboxIds.length
      });
    }

    await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: result.success,
      newInboxIds: result.success ? newInboxIds : undefined,
      error: result.error
    });
  } catch (error) {
    cryptoLogger.error('[ROUTING] Inbox rotation failed', { error: error.message });
    await sendSecureMessage(ws, {
      type: SignalType.ROTATE_INBOX_RESPONSE,
      success: false,
      error: 'rotation_failed'
    });
  }
}

/**
 * Handle ownership proof for inbox verification
 */
export async function handleOwnershipProof({ ws, parsed, state }) {
  if (!state?.hasAuthenticated) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { inboxId, proof, signature } = parsed;
  if (!inboxId || !proof) {
    return await sendSecureMessage(ws, {
      type: SignalType.OWNERSHIP_PROOF_RESPONSE,
      success: false,
      error: 'missing_params'
    });
  }

  try {
    const { verifyOwnershipProof } = await import('../routing/blind-router.js');
    const result = await verifyOwnershipProof(inboxId, proof, signature);

    await sendSecureMessage(ws, {
      type: SignalType.OWNERSHIP_PROOF_RESPONSE,
      success: result.valid,
      error: result.error
    });
  } catch (error) {
    cryptoLogger.error('[ROUTING] Ownership proof verification failed', { error: error.message });
    await sendSecureMessage(ws, {
      type: SignalType.OWNERSHIP_PROOF_RESPONSE,
      success: false,
      error: 'verification_failed'
    });
  }
}
