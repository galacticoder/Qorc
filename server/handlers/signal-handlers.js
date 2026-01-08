import { SignalType } from '../signals.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { MessageDatabase, UserDatabase, BlockingDatabase, AvatarDatabase } from '../database/database.js';
import { ConnectionStateManager } from '../presence/connection-state.js';
import { checkBlocking, clearBlockingCache } from '../security/blocking.js';
import { logEvent, logError, logDeliveryEvent } from '../security/logging.js';
import { presenceService } from '../presence/presence-service.js';
import { getPQSession } from '../session/pq-session-storage.js';
import { sendPQEncryptedResponse, sendSecureMessage, createPQResponseSender } from '../messaging/pq-envelope-handler.js';
import { handleBundlePublish, handleBundleRequest, handleBundleFailure } from '../messaging/libsignal-handler.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

const KYBER_PUBLIC_KEY_LENGTH = 1568;
const DILITHIUM_PUBLIC_KEY_LENGTH = 2592;
const X25519_PUBLIC_KEY_LENGTH = 32;

function isValidBase64Key(b64, expectedLen) {
  if (!b64 || typeof b64 !== 'string') return false;
  try {
    const bytes = Buffer.from(b64, 'base64');
    return bytes.length === expectedLen;
  } catch (_e) {
    return false;
  }
}

function sanitizeHybridKeysServer(keys) {
  const out = {};
  if (keys && typeof keys === 'object') {
    if (isValidBase64Key(keys.kyberPublicBase64, KYBER_PUBLIC_KEY_LENGTH)) out.kyberPublicBase64 = keys.kyberPublicBase64;
    if (isValidBase64Key(keys.dilithiumPublicBase64, DILITHIUM_PUBLIC_KEY_LENGTH)) out.dilithiumPublicBase64 = keys.dilithiumPublicBase64;
    if (isValidBase64Key(keys.x25519PublicBase64, X25519_PUBLIC_KEY_LENGTH)) out.x25519PublicBase64 = keys.x25519PublicBase64;
  }
  return out;
}

async function deliverToLocalConnections(targetUsername, message, options = {}) {
  const { skipAuth = false } = options;
  let localSet = global.gateway?.getLocalConnections?.(targetUsername);

  if (!localSet || !localSet.size) {
    return { delivered: false, count: 0 };
  }

  let deliveredCount = 0;
  for (const client of localSet) {
    if (!client || client.readyState !== 1) continue;

    const recipientSessionId = client._sessionId;
    if (!recipientSessionId) continue;

    if (!skipAuth) {
      const isAuthed = !!(client._authenticated || client?.clientState?.hasAuthenticated);
      if (!isAuthed) continue;
    }

    let recipientPqSessionId = client._pqSessionId;
    if (!recipientPqSessionId) {
      try {
        const recipientState = await ConnectionStateManager.getState(recipientSessionId);
        if (recipientState?.pqSessionId) {
          recipientPqSessionId = recipientState.pqSessionId;
          client._pqSessionId = recipientPqSessionId;
        }
      } catch { }
    }
    if (!recipientPqSessionId) continue;

    const recipientPqSession = await getPQSession(recipientPqSessionId);
    if (!recipientPqSession) continue;

    try {
      await sendPQEncryptedResponse(client, recipientPqSession, message);
      deliveredCount++;
    } catch (err) {
      cryptoLogger.error('[DELIVERY] PQ envelope failed', {
        session: recipientSessionId.slice(0, 8) + '...',
        error: err.message
      });
    }
  }

  return { delivered: deliveredCount > 0, count: deliveredCount };
}

async function tryRemoteDelivery(targetUsername, message) {
  const localServerId = process.env.SERVER_ID || 'default';
  let remoteTargets = [];
  try {
    const distributed = await global.gateway?.getDistributedConnectionServers?.(targetUsername);
    if (Array.isArray(distributed)) {
      remoteTargets = distributed.filter((t) => t && t.serverId && t.serverId !== localServerId);
    }
  } catch { }

  if (remoteTargets.length > 0) {
    try {
      const receivers = await presenceService.publishToUser(targetUsername, JSON.stringify(message));
      return { delivered: true, receivers, remoteTargets: remoteTargets.length };
    } catch (error) {
      logError(error, { operation: 'cross-instance-delivery' });
      return { delivered: false, error: error.message };
    }
  }

  return { delivered: false, offline: true };
}

export async function handleEncryptedMessage({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[MESSAGE-FORWARD] Rejected message from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      hasState: !!state,
      hasAuth: state?.hasAuthenticated
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  if (!state.username || typeof state.username !== 'string') {
    cryptoLogger.error('[MESSAGE-FORWARD] Missing username in authenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      hasUsername: !!state.username
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid session state' });
  }

  if (ws._username && ws._username !== state.username) {
    cryptoLogger.error('[MESSAGE-FORWARD] Session username mismatch', {
      sessionId: sessionId?.slice(0, 8) + '...',
      wsUsername: ws._username?.slice(0, 4) + '...',
      stateUsername: state.username?.slice(0, 4) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Session mismatch' });
  }

  const { to: toUser, encryptedPayload, messageId } = parsed;
  if (!toUser || !encryptedPayload) {
    cryptoLogger.error('[MESSAGE-FORWARD] Invalid message format', {
      hasTo: !!toUser,
      hasPayload: !!encryptedPayload
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message format' });
  }

  const normalizedMessage = {
    type: parsed.type,
    to: toUser,
    encryptedPayload,
    from: state.username
  };

  const senderBlockedByRecipient = await checkBlocking(state.username, toUser);
  const recipientBlockedBySender = await checkBlocking(toUser, state.username);

  if (senderBlockedByRecipient || recipientBlockedBySender) {
    logDeliveryEvent('message-blocked', {
      from: state.username,
      to: toUser,
      reason: senderBlockedByRecipient ? 'sender-blocked-by-recipient' : 'recipient-blocked-by-sender'
    });
    return await sendSecureMessage(ws, { type: SignalType.OK, message: 'blocked' });
  }

  const localResult = await deliverToLocalConnections(toUser, normalizedMessage);
  if (localResult.delivered) {
    await sendSecureMessage(ws, { type: SignalType.OK, message: 'relayed' });
    logDeliveryEvent('local-delivery', { to: toUser, deliveredCount: localResult.count });
    return;
  }

  const remoteResult = await tryRemoteDelivery(toUser, normalizedMessage);
  if (remoteResult.delivered) {
    await sendSecureMessage(ws, { type: SignalType.OK, message: 'relayed' });
    logDeliveryEvent('cross-instance-published', { to: toUser, receivers: remoteResult.receivers, remoteTargets: remoteResult.remoteTargets });
    return;
  }

  try {
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Offline recipient requires long-term storage',
      code: 'OFFLINE_LONGTERM_REQUIRED',
      to: toUser,
      messageId: messageId || null
    });
    logDeliveryEvent('offline-longterm-required', { to: toUser });
  } catch (error) {
    logError(error, { operation: 'offline-longterm-required' });
  }
}

export async function handleSessionResetRequest({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[SESSION-RESET] Rejected from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  if (!state.username || typeof state.username !== 'string') {
    cryptoLogger.error('[SESSION-RESET] Missing username in authenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid session state' });
  }

  const { targetUsername } = parsed;
  if (!targetUsername || typeof targetUsername !== 'string') {
    cryptoLogger.error('[SESSION-RESET] Invalid target username', {
      from: state.username.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid target username' });
  }

  cryptoLogger.info('[SESSION-RESET] Forwarding session reset request', {
    from: state.username.slice(0, 8) + '...',
    to: targetUsername.slice(0, 8) + '...'
  });

  const resetNotification = {
    type: SignalType.SESSION_RESET_REQUEST,
    from: state.username,
    reason: 'stale-keys-detected'
  };

  const result = await deliverToLocalConnections(targetUsername, resetNotification);
  if (result.delivered) {
    cryptoLogger.info('[SESSION-RESET] Notification delivered', {
      from: state.username.slice(0, 8) + '...',
      to: targetUsername.slice(0, 8) + '...',
      count: result.count
    });
  }

  await sendSecureMessage(ws, { type: SignalType.OK, message: 'session-reset-sent' });
}

export async function handleSessionEstablished({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[SESSION-ESTABLISHED] Rejected from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  if (!state.username || typeof state.username !== 'string') {
    cryptoLogger.error('[SESSION-ESTABLISHED] Missing username in authenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid session state' });
  }

  const targetUsername = parsed.username;
  if (!targetUsername || typeof targetUsername !== 'string') {
    cryptoLogger.error('[SESSION-ESTABLISHED] Invalid target username', {
      from: state.username.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid target username' });
  }

  cryptoLogger.info('[SESSION-ESTABLISHED] Forwarding session establishment confirmation', {
    from: state.username.slice(0, 8) + '...',
    to: targetUsername.slice(0, 8) + '...'
  });

  const sessionEstablishedNotification = {
    type: SignalType.SESSION_ESTABLISHED,
    from: state.username,
    username: state.username
  };

  const result = await deliverToLocalConnections(targetUsername, sessionEstablishedNotification);
  if (result.delivered) {
    cryptoLogger.info('[SESSION-ESTABLISHED] Notification delivered', {
      from: state.username.slice(0, 8) + '...',
      to: targetUsername.slice(0, 8) + '...',
      count: result.count
    });
  }

  await sendSecureMessage(ws, { type: SignalType.OK, message: 'session-established-sent' });
}

export async function handleStoreOfflineMessage({ ws, parsed, state }) {
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[OFFLINE-STORE] Rejected - not authenticated');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { messageId, to, longTermEnvelope, version } = parsed;
  if (!messageId || !to) {
    cryptoLogger.warn('[OFFLINE-STORE] Rejected - missing messageId or to');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message data' });
  }

  if (version !== 'lt-v1' || !longTermEnvelope) {
    cryptoLogger.warn('[OFFLINE-STORE] Rejected - missing lt-v1 or envelope');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Long-term encryption required' });
  }

  const senderBlockedByRecipient = await checkBlocking(state.username, to);
  const recipientBlockedBySender = await checkBlocking(to, state.username);

  if (senderBlockedByRecipient || recipientBlockedBySender) {
    logDeliveryEvent('offline-message-blocked', {
      from: state.username,
      to,
      reason: senderBlockedByRecipient ? 'sender-blocked-by-recipient' : 'recipient-blocked-by-sender'
    });
    return await sendSecureMessage(ws, { type: SignalType.OK, message: 'blocked' });
  }

  try {
    const offlineMessage = {
      type: SignalType.ENCRYPTED_MESSAGE,
      to,
      longTermEnvelope,
      version: 'lt-v1',
      from: state.username
    };

    const success = await MessageDatabase.queueOfflineMessage(to, offlineMessage);
    if (success) {
      cryptoLogger.info('[OFFLINE-STORE] Message stored successfully', {
        from: state.username?.slice(0, 8) + '...',
        to: to?.slice(0, 8) + '...',
        messageId: messageId?.slice(0, 16) + '...'
      });
      await sendSecureMessage(ws, { type: SignalType.OK, message: 'Offline message stored' });
      logEvent('offline-message-stored', { username: state.username });
    } else {
      cryptoLogger.error('[OFFLINE-STORE] Database queueOfflineMessage returned false');
      await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to store offline message' });
    }
  } catch (error) {
    cryptoLogger.error('[OFFLINE-STORE] Exception', { error: error?.message });
    logError(error, { operation: 'store-offline-message' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error storing offline message' });
  }
}

export async function handleRetrieveOfflineMessages({ ws, state }) {
  cryptoLogger.info('[OFFLINE-RETRIEVE] Handler called', {
    hasState: !!state,
    hasAuthenticated: state?.hasAuthenticated,
    username: state?.username?.slice(0, 8) + '...',
    hasPqSessionId: !!ws._pqSessionId
  });

  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[OFFLINE-RETRIEVE] Rejected - not authenticated');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const offlineMessages = await MessageDatabase.takeOfflineMessages(state.username, 50);
    cryptoLogger.info('[OFFLINE-RETRIEVE] Retrieved messages from DB', {
      username: state.username?.slice(0, 8) + '...',
      count: offlineMessages?.length ?? 0
    });

    const pqSessionId = ws._pqSessionId;

    if (pqSessionId) {
      const session = await getPQSession(pqSessionId);

      if (session) {
        const responsePayload = {
          type: SignalType.OFFLINE_MESSAGES_RESPONSE,
          messages: offlineMessages,
          count: offlineMessages.length,
        };
        cryptoLogger.info('[OFFLINE-RETRIEVE] Sending response', {
          username: state.username?.slice(0, 8) + '...',
          messageCount: offlineMessages.length,
          responseType: responsePayload.type
        });
        await sendPQEncryptedResponse(ws, session, responsePayload);
        cryptoLogger.info('[OFFLINE-RETRIEVE] Response sent successfully');
        logEvent('offline-messages-retrieved', {
          username: state.username,
          count: offlineMessages.length,
          pqEncrypted: true
        });
      } else {
        cryptoLogger.error('[OFFLINE-RETRIEVE] PQ session not found in storage', {
          pqSessionId: pqSessionId?.slice(0, 16) + '...'
        });
        throw new Error('PQ session required');
      }
    } else {
      cryptoLogger.error('[OFFLINE-RETRIEVE] No PQ session ID on websocket');
      throw new Error('PQ session required');
    }
  } catch (error) {
    cryptoLogger.error('[OFFLINE-RETRIEVE] Error', { error: error?.message });
    logError(error, { operation: 'retrieve-offline-messages' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error retrieving offline messages' });
  }
}

export async function handleRateLimitStatus({ ws, state }) {
  try {
    const stats = rateLimitMiddleware.getStats();
    const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();
    const userStatus = state?.username ? await rateLimitMiddleware.getUserStatus(state.username) : null;

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

export async function handleServerLogin({ ws, parsed }) {
  if (parsed.resetType === 'global') {
    await rateLimitMiddleware.resetGlobalConnectionLimits();
    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      message: 'Global connection rate limits reset successfully',
    });
  } else if (parsed.resetType === 'user' && parsed.username) {
    await rateLimitMiddleware.resetUserLimits(parsed.username);
    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      message: `Rate limits reset for user: ${parsed.username}`,
    });
  } else {
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Invalid reset type or missing username',
    });
  }
}

export async function handleCheckUserExists({ ws, parsed, state: _state, context, serverHybridKeyPair }) {
  const { username } = parsed;

  const sendResponse = async (responseData) => {
    const pqSessionId = context?.pqSessionId || ws?._pqSessionId;
    if (pqSessionId) {
      const pqSession = await getPQSession(pqSessionId);
      if (pqSession) {
        try {
          await sendPQEncryptedResponse(ws, pqSession, responseData);
          return;
        } catch (err) {
          cryptoLogger.error('[USER-CHECK] PQ send failed', {
            error: err.message
          });
          throw err;
        }
      }
    }
    cryptoLogger.error('[USER-CHECK] No PQ session');
    throw new Error('PQ session required');
  };

  if (!username || typeof username !== 'string') {
    return await sendResponse({
      type: SignalType.USER_EXISTS_RESPONSE,
      exists: false,
      error: 'Invalid username',
    });
  }

  try {
    const user = await UserDatabase.loadUser(username);

    const response = {
      type: SignalType.USER_EXISTS_RESPONSE,
      exists: !!user,
      username: username,
    };

    let sanitizedKeys = null;
    const userHybridKeys = user?.hybridPublicKeys ?? user?.hybridpublickeys;
    if (user && userHybridKeys) {
      try {
        const parsedKeys = typeof userHybridKeys === 'string'
          ? JSON.parse(userHybridKeys)
          : userHybridKeys;
        sanitizedKeys = sanitizeHybridKeysServer(parsedKeys);
        response.hybridPublicKeys = sanitizedKeys;
      } catch (parseError) {
        cryptoLogger.error('[USER-CHECK] Failed to parse hybrid keys', {
          error: parseError.message
        });
      }
    }

    try {
      if (sanitizedKeys && sanitizedKeys.kyberPublicBase64 && sanitizedKeys.dilithiumPublicBase64) {
        const issuedAt = Date.now();
        const expiresAt = issuedAt + 5 * 60 * 1000;
        const proof = CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey);
        const canonical = JSON.stringify({
          username,
          dilithiumPublicKey: sanitizedKeys.dilithiumPublicBase64,
          kyberPublicKey: sanitizedKeys.kyberPublicBase64,
          x25519PublicKey: sanitizedKeys.x25519PublicBase64 || '',
          proof,
          issuedAt,
          expiresAt
        });
        const signatureBytes = await CryptoUtils.Dilithium.sign(new TextEncoder().encode(canonical), serverHybridKeyPair.dilithium.secretKey);
        const signature = Buffer.from(signatureBytes).toString('base64');
        response.peerCertificate = {
          username,
          dilithiumPublicKey: sanitizedKeys.dilithiumPublicBase64,
          kyberPublicKey: sanitizedKeys.kyberPublicBase64,
          x25519PublicKey: sanitizedKeys.x25519PublicBase64 || '',
          proof,
          issuedAt,
          expiresAt,
          signature
        };
      }
    } catch (certErr) {
      cryptoLogger.warn('[USER-CHECK] Failed to attach peer certificate', { error: certErr?.message || String(certErr) });
    }

    await sendResponse(response);
  } catch (error) {
    logError(error, { operation: 'check-user-exists', username });
    await sendResponse({
      type: SignalType.USER_EXISTS_RESPONSE,
      exists: false,
      error: 'Failed to check user existence',
    });
  }
}

export async function handleBlockListSync({ ws, parsed, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const { encryptedBlockList, blockListHash, salt, version, lastUpdated } = parsed;

    if (!encryptedBlockList || !blockListHash || !salt) {
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Missing encrypted block list, hash, or salt'
      });
    }

    await BlockingDatabase.storeEncryptedBlockList(
      state.username,
      encryptedBlockList,
      blockListHash,
      salt,
      version,
      lastUpdated
    );

    await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_SYNC,
      success: true,
      message: 'Block list synchronized successfully',
    });

    logEvent('block-list-synced', { username: state.username });
  } catch (error) {
    logError(error, { operation: 'block-list-sync' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error synchronizing block list'
    });
  }
}

export async function handleRetrieveBlockList({ ws, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const blockList = await BlockingDatabase.getEncryptedBlockList(state.username);

    if (blockList) {
      await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_RESPONSE,
        encryptedBlockList: blockList.encryptedBlockList,
        blockListHash: blockList.blockListHash,
        salt: blockList.salt,
        version: blockList.version,
        lastUpdated: blockList.lastUpdated,
      });
    } else {
      await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_RESPONSE,
        encryptedBlockList: null,
        message: 'No block list found',
      });
    }

    logEvent('block-list-retrieved', { username: state.username });
  } catch (error) {
    logError(error, { operation: 'retrieve-block-list' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error retrieving block list'
    });
  }
}

export async function handleBlockTokensUpdate({ ws, parsed, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }
  try {
    const tokens = Array.isArray(parsed.blockTokens) ? parsed.blockTokens : [];
    const blockerHash = typeof parsed.blockerHash === 'string' ? parsed.blockerHash : undefined;
    await BlockingDatabase.storeBlockTokens(tokens, blockerHash);

    const blockedHashes = tokens.map(t => t.blockedHash).filter(Boolean);
    await clearBlockingCache(blockerHash, blockedHashes);

    await sendSecureMessage(ws, { type: SignalType.OK, message: 'block-tokens-updated' });
  } catch (_error) {
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to update block tokens' });
  }
}

export async function handleAvatarUpload({ ws, parsed, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.AVATAR_UPLOAD_RESPONSE, success: false, error: 'Authentication required' });
  }

  try {
    const { envelope, shareWithOthers, publicData } = parsed;
    if (!envelope || typeof envelope !== 'object') {
      return await sendSecureMessage(ws, { type: SignalType.AVATAR_UPLOAD_RESPONSE, success: false, error: 'Invalid envelope' });
    }

    if (envelope.version !== 'lt-v1') {
      return await sendSecureMessage(ws, { type: SignalType.AVATAR_UPLOAD_RESPONSE, success: false, error: 'Unsupported envelope version' });
    }

    const envelopeStr = JSON.stringify(envelope);

    if (envelopeStr.length > 1024 * 1024) {
      return await sendSecureMessage(ws, { type: SignalType.AVATAR_UPLOAD_RESPONSE, success: false, error: 'Avatar too large' });
    }

    let publicDataStr = null;
    if (shareWithOthers && publicData) {
      publicDataStr = typeof publicData === 'string' ? publicData : JSON.stringify(publicData);
    }

    await AvatarDatabase.storeAvatar(state.username, envelopeStr, !!shareWithOthers, publicDataStr);

    await sendSecureMessage(ws, { type: SignalType.AVATAR_UPLOAD_RESPONSE, success: true });
  } catch (error) {
    await sendSecureMessage(ws, { type: SignalType.AVATAR_UPLOAD_RESPONSE, success: false, error: 'Upload failed' });
  }
}

export async function handleAvatarFetch({ ws, parsed, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.AVATAR_FETCH_RESPONSE, found: false, error: 'Authentication required' });
  }

  try {
    const { target } = parsed;

    if (target === 'own') {
      const result = await AvatarDatabase.getOwnAvatar(state.username);

      let envelope = null;
      if (result) {
        try {
          envelope = JSON.parse(result.encryptedEnvelope);
          if (!envelope || envelope.version !== 'lt-v1') {
            envelope = null;
          }
        } catch (e) {
          envelope = null;
        }
      }

      if (envelope) {
        await sendSecureMessage(ws, {
          type: SignalType.AVATAR_FETCH_RESPONSE,
          target: 'own',
          found: true,
          envelope: envelope,
          isDefault: false
        });
      } else {
        await sendSecureMessage(ws, {
          type: SignalType.AVATAR_FETCH_RESPONSE,
          target: 'own',
          found: false
        });
      }
    } else if (typeof target === 'string' && target.length > 0) {
      const result = await AvatarDatabase.getPeerAvatar(target);

      if (result) {
        let publicData;
        try {
          publicData = JSON.parse(result.publicData);
        } catch {
          publicData = result.publicData;
        }

        await sendSecureMessage(ws, {
          type: SignalType.AVATAR_FETCH_RESPONSE,
          target,
          found: true,
          envelope: publicData
        });
      } else {
        await sendSecureMessage(ws, {
          type: SignalType.AVATAR_FETCH_RESPONSE,
          target,
          found: false
        });
      }
    } else {
      await sendSecureMessage(ws, { type: SignalType.AVATAR_FETCH_RESPONSE, found: false, error: 'Invalid target' });
    }
  } catch {
    await sendSecureMessage(ws, { type: SignalType.AVATAR_FETCH_RESPONSE, found: false, error: 'Fetch failed' });
  }
}

export async function handleP2PFetchPeerCert({ ws, parsed, state, serverHybridKeyPair }) {
  try {
    if (!state?.hasAuthenticated || !state?.username) {
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
    }
    const target = typeof parsed?.username === 'string' ? parsed.username.trim() : '';
    if (!target || target.length > 128) {
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid username' });
    }
    const keys = await UserDatabase.getHybridPublicKeys(target);
    if (!keys) {
      return await sendSecureMessage(ws, { type: SignalType.P2P_PEER_CERT, username: target, error: 'NOT_FOUND' });
    }
    if (!keys || !keys.kyberPublicBase64 || !keys.dilithiumPublicBase64) {
      return await sendSecureMessage(ws, { type: SignalType.P2P_PEER_CERT, username: target, error: 'KEYS_MISSING' });
    }
    const issuedAt = Date.now();
    const expiresAt = issuedAt + 5 * 60 * 1000;
    const proof = CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey);
    const canonical = JSON.stringify({
      username: target,
      dilithiumPublicKey: keys.dilithiumPublicBase64,
      kyberPublicKey: keys.kyberPublicBase64,
      x25519PublicKey: keys.x25519PublicBase64 || '',
      proof,
      issuedAt,
      expiresAt
    });
    const signatureBytes = await CryptoUtils.Dilithium.sign(new TextEncoder().encode(canonical), serverHybridKeyPair.dilithium.secretKey);
    const signature = Buffer.from(signatureBytes).toString('base64');

    await sendSecureMessage(ws, {
      type: SignalType.P2P_PEER_CERT,
      username: target,
      dilithiumPublicKey: keys.dilithiumPublicBase64,
      kyberPublicKey: keys.kyberPublicBase64,
      x25519PublicKey: keys.x25519PublicBase64 || '',
      proof,
      issuedAt,
      expiresAt,
      signature
    });
  } catch (_err) {
    try { await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to build peer certificate' }); } catch { }
  }
}

export async function handleHybridKeysUpdate({ ws, parsed, state, serverHybridKeyPair }) {
  if (!state.username) {
    cryptoLogger.error('[AUTH] Hybrid keys update received but no username in state');
    return await sendSecureMessage(ws, {
      type: SignalType.KEYS_STORED,
      success: false,
      error: 'Authentication state error'
    });
  }

  cryptoLogger.info('[AUTH] Hybrid keys update received', {
    username: state.username.slice(0, 8) + '...'
  });

  try {
    let senderDilithiumPublicKey = parsed.userData?.metadata?.sender?.dilithiumPublicKey;

    if (!senderDilithiumPublicKey) {
      const existingKeys = await UserDatabase.getHybridPublicKeys(state.username);
      if (existingKeys?.dilithiumPublicBase64) {
        senderDilithiumPublicKey = existingKeys.dilithiumPublicBase64;
      }
    }

    if (!senderDilithiumPublicKey) {
      throw new Error('Sender Dilithium public key required for verification');
    }

    const userPayload = await CryptoUtils.Hybrid.decryptIncoming(
      parsed.userData,
      {
        kyberSecretKey: serverHybridKeyPair.kyber.secretKey,
        kyberPublicKey: serverHybridKeyPair.kyber.publicKey,
        x25519SecretKey: serverHybridKeyPair.x25519.secretKey
      },
      { senderDilithiumPublicKey }
    );

    let parsedKeys;
    if (userPayload.payloadJson) {
      parsedKeys = userPayload.payloadJson;
    } else {
      const decoded = new TextDecoder().decode(userPayload.payload);
      parsedKeys = JSON.parse(decoded);
    }

    const extracted = {
      kyberPublicBase64: parsedKeys.kyberPublicBase64 || '',
      dilithiumPublicBase64: parsedKeys.dilithiumPublicBase64 || '',
      x25519PublicBase64: parsedKeys.x25519PublicBase64 || ''
    };
    const hybridPublicKeys = sanitizeHybridKeysServer(extracted);

    await UserDatabase.updateHybridPublicKeys(state.username, hybridPublicKeys);

    cryptoLogger.info('[AUTH] Hybrid keys stored successfully', {
      username: state.username.slice(0, 8) + '...',
      dilithiumPrefix: hybridPublicKeys.dilithiumPublicBase64.slice(0, 6) + '...',
      dilithiumSuffix: '...' + hybridPublicKeys.dilithiumPublicBase64.slice(-6)
    });

    await sendSecureMessage(ws, {
      type: SignalType.KEYS_STORED,
      success: true
    });
  } catch (error) {
    cryptoLogger.error('[AUTH] Failed to process hybrid keys', {
      username: state.username,
      error: error.message
    });
    await sendSecureMessage(ws, {
      type: SignalType.KEYS_STORED,
      success: false,
      error: 'Failed to process keys'
    });
  }
}

export async function handleRegister({ ws, sessionId, parsed, serverHybridKeyPair }) {
  const { register, signature, publicKey } = parsed.payload || {};
  const username = parsed.from;

  if (!register || !signature || !publicKey || !username) {
    cryptoLogger.warn('[REGISTER] Missing required fields');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid registration format' });
  }

  if (register.username !== username) {
    cryptoLogger.warn('[REGISTER] Username mismatch');
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Username mismatch' });
  }

  const now = Date.now();
  if (Math.abs(now - register.timestamp) > 5 * 60 * 1000) {
    cryptoLogger.warn('[REGISTER] Stale registration', { username });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Registration expired' });
  }

  const storedKeys = await UserDatabase.getHybridPublicKeys(username);

  if (!storedKeys || !storedKeys.dilithiumPublicBase64) {
    cryptoLogger.warn('[REGISTER] User not found or no keys', { username });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'User not found' });
  }

  if (storedKeys.dilithiumPublicBase64 !== publicKey) {
    cryptoLogger.warn('[REGISTER] Public key mismatch', { username });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid public key' });
  }

  try {
    const canonical = new TextEncoder().encode(JSON.stringify(register));
    const signatureBytes = Buffer.from(signature, 'base64');
    const publicKeyBytes = Buffer.from(publicKey, 'base64');

    const isValid = await CryptoUtils.Dilithium.verify(signatureBytes, canonical, publicKeyBytes);

    if (!isValid) {
      cryptoLogger.warn('[REGISTER] Invalid signature', { username });
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid signature' });
    }
  } catch (err) {
    cryptoLogger.error('[REGISTER] Verification error', { username, error: err.message });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Verification failed' });
  }

  ws._username = username;
  ws._authenticated = true;
  ws._hasAuthenticated = true;

  await ConnectionStateManager.updateState(sessionId, {
    username: username,
    hasAuthenticated: true,
    lastActivity: Date.now()
  });

  if (global.gateway?.addLocalConnection) {
    await global.gateway.addLocalConnection(username, ws);
  }

  cryptoLogger.info('[REGISTER] P2P signaling session authenticated', { username });
  await sendSecureMessage(ws, { type: SignalType.REGISTER_ACK, success: true });
}

export async function handleUserDisconnect({ ws, sessionId, parsed, state }) {
  const payloadUsername = typeof parsed.username === 'string' ? parsed.username.trim() : null;
  const stateUsername = state?.username;

  if (!state?.hasAuthenticated || !stateUsername) {
    cryptoLogger.warn('[USER-DISCONNECT] Rejected - not authenticated', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  if (!payloadUsername || payloadUsername !== stateUsername) {
    cryptoLogger.warn('[USER-DISCONNECT] Username mismatch', {
      sessionId: sessionId?.slice(0, 8) + '...',
      stateUsername: stateUsername.slice(0, 4) + '...',
      payloadUsername: payloadUsername ? payloadUsername.slice(0, 4) + '...' : null
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid disconnect request' });
  }

  logEvent('user-disconnect', {
    username: stateUsername.slice(0, 4) + '...',
    sessionId: sessionId?.slice(0, 8) + '...',
    timestamp: parsed.timestamp || Date.now()
  });

  try {
    ws.close(1000, 'User disconnect');
  } catch (_e) { }
}

export { handleBundlePublish, handleBundleRequest, handleBundleFailure, deliverToLocalConnections, tryRemoteDelivery, sanitizeHybridKeysServer };
