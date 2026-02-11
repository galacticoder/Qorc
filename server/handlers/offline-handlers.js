/**
 * Offline Handlers
 * 
 * Handles storage and retrieval of offline messages.
 */

import {
  SignalType,
  MessageDatabase,
  logError,
  logDeliveryEvent,
  sendSecureMessage,
  cryptoLogger
} from './core.js';
import { checkBlockingByIdentityKeys } from './message-handlers.js';

export async function handleStoreOfflineMessage({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated && !ws._unlinkedSession) {
    cryptoLogger.warn('[OFFLINE-STORE] Rejected from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      unlinked: !!ws._unlinkedSession
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { messageId, destinationInbox, longTermEnvelope, version, senderIdentityKeyHash, recipientIdentityKeyHash } = parsed;

  if (!messageId || !destinationInbox) {
    cryptoLogger.warn('[OFFLINE-STORE] Rejected - missing messageId or destinationInbox');
    return await sendSecureMessage(ws, {
      type: SignalType.OFFLINE_STORE_ACK,
      success: false,
      messageId,
      error: 'Invalid request - destinationInbox required'
    });
  }

  // Check if either party has blocked the other
  if (senderIdentityKeyHash && recipientIdentityKeyHash) {
    const isBlocked = await checkBlockingByIdentityKeys(senderIdentityKeyHash, recipientIdentityKeyHash);
    if (isBlocked) {
      logDeliveryEvent('offline-message-blocked', { reason: 'identity-key-block' });
      return await sendSecureMessage(ws, {
        type: SignalType.OFFLINE_STORE_ACK,
        success: true,
        messageId,
        stored: true,
        message: 'Message processed (blocked)'
      });
    }
  }

  try {
    const offlinePayload = {
      type: SignalType.OFFLINE_MESSAGE_DELIVERY,
      messageId,
      longTermEnvelope,
      version: version || 1,
      timestamp: Date.now()
    };

    const stored = await MessageDatabase.queueOfflineMessage(destinationInbox, offlinePayload);

    await sendSecureMessage(ws, {
      type: SignalType.OFFLINE_STORE_ACK,
      success: stored,
      messageId,
      stored
    });

    if (stored) {
      logDeliveryEvent('offline-stored', {
        inboxPrefix: destinationInbox.slice(0, 8) + '...'
      });
    }
  } catch (error) {
    cryptoLogger.error('[OFFLINE-STORE] Error', {
      error: error?.message
    });
    logError(error, { operation: 'store-offline-message' });
    await sendSecureMessage(ws, {
      type: SignalType.OFFLINE_STORE_ACK,
      success: false,
      messageId,
      error: 'Storage error'
    });
  }
}

export async function handleRetrieveOfflineMessages({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated && !ws._unlinkedSession) {
    cryptoLogger.warn('[OFFLINE-RETRIEVE] Rejected from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      unlinked: !!ws._unlinkedSession
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const inboxId = parsed.inboxId || ws._primaryInboxId;

  if (!inboxId) {
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'No inbox ID available'
    });
  }

  try {
    const limit = Math.min(parsed.limit || 100, 500);
    const messages = await MessageDatabase.takeOfflineMessages(inboxId, limit);

    await sendSecureMessage(ws, {
      type: SignalType.OFFLINE_MESSAGES_RESPONSE,
      messages,
      count: messages.length,
      inboxId: inboxId.slice(0, 8) + '...'
    });

    if (messages.length > 0) {
      logDeliveryEvent('offline-retrieved', {
        count: messages.length,
        inboxPrefix: inboxId.slice(0, 8) + '...'
      });
    }
  } catch (error) {
    cryptoLogger.error('[OFFLINE-RETRIEVE] Error', { error: error?.message });
    logError(error, { operation: 'retrieve-offline-messages' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error retrieving offline messages' });
  }
}
