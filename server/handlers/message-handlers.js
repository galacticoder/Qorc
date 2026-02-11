/**
 * Message Handlers
 * 
 * Handles blind routing of encrypted messages.
 */

import {
  BlockingDatabase,
  logDeliveryEvent,
  cryptoLogger,
  routeToInbox,
  SealedSender
} from './core.js';

/**
 * Route message to destination inbox
 */
async function routeToDestinationInbox(destinationInboxId, sealedEnvelope, options = {}) {
  if (!destinationInboxId || typeof destinationInboxId !== 'string') {
    return { delivered: false, error: 'invalid_inbox_id' };
  }

  // Validate sealed envelope structure
  const validation = SealedSender.validateSealedEnvelope(sealedEnvelope);
  if (!validation.valid) {
    cryptoLogger.warn('[DELIVERY] Invalid sealed envelope', { error: validation.error });
    return { delivered: false, error: validation.error };
  }

  // Check for anti patterns that would leak sender identity
  const antiPatterns = SealedSender.checkForAntiPatterns(sealedEnvelope);
  if (antiPatterns.length > 0) {
    cryptoLogger.error('[DELIVERY] Sender identity leak detected', { antiPatterns });
    return { delivered: false, error: 'sender_identity_leak' };
  }

  // Route using blind router
  const result = await routeToInbox(destinationInboxId, sealedEnvelope, options);

  if (result.delivered) {
    logDeliveryEvent('blind-delivery', {
      inboxPrefix: destinationInboxId.slice(0, 8) + '...',
      local: result.local,
      remote: result.remote
    });
  }

  return result;
}

/**
 * Deliver message to inbox
 */
async function deliverToInbox(recipientInboxId, message, options = {}) {
  if (!recipientInboxId || typeof recipientInboxId !== 'string') {
    return { delivered: false, error: 'invalid_inbox_id' };
  }

  // Route using blind router
  const result = await routeToInbox(recipientInboxId, message, options);

  if (result.delivered) {
    logDeliveryEvent('inbox-delivery', {
      inboxPrefix: recipientInboxId.slice(0, 8) + '...',
      local: result.local,
      remote: result.remote
    });
  }

  return result;
}

/**
 * Check if either party has blocked the other
 */
async function checkBlockingByIdentityKeys(senderIdentityKeyHash, recipientIdentityKeyHash) {
  if (!senderIdentityKeyHash || !recipientIdentityKeyHash) {
    return false;
  }

  try {
    const senderBlocked = await BlockingDatabase.isBlocked(recipientIdentityKeyHash, senderIdentityKeyHash);
    const recipientBlocked = await BlockingDatabase.isBlocked(senderIdentityKeyHash, recipientIdentityKeyHash);
    return senderBlocked || recipientBlocked;
  } catch (error) {
    cryptoLogger.warn('[BLOCKING] Identity key blocking check failed', { error: error.message });
    return false;
  }
}

export { routeToDestinationInbox, deliverToInbox, checkBlockingByIdentityKeys };
