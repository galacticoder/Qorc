/**
 * Blocking Handlers
 * 
 * Handles block list synchronization
 */

import {
  SignalType,
  BlockingDatabase,
  logEvent,
  logError,
  sendSecureMessage,
  hasAccountAuthentication
} from './core.js';

export async function handleBlockListSync({ ws, parsed, state }) {
  const requestId = typeof parsed?.requestId === 'string' ? parsed.requestId.slice(0, 128) : undefined;

  if (!hasAccountAuthentication(ws, state)) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_SYNC,
      requestId,
      success: false,
      error: 'authentication_required'
    });
  }

  if (!ws._primaryBlockListLookupId) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_SYNC,
      requestId,
      success: false,
      error: 'block_list_route_not_claimed'
    });
  }

  try {
    const { encryptedBlockList, blockListHash, salt, version, lastUpdated } = parsed;

    if (!encryptedBlockList || !blockListHash) {
      return await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_SYNC,
        requestId,
        success: false,
        error: 'missing_block_list_payload'
      });
    }

    await BlockingDatabase.storeEncryptedBlockListByLookupId(
      ws._primaryBlockListLookupId,
      encryptedBlockList,
      blockListHash,
      salt || '',
      version,
      lastUpdated
    );

    await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_SYNC,
      success: true,
      message: 'Block list synchronized successfully',
    });

    logEvent('block-list-synced', { hasInbox: !!ws._primaryBlockListLookupId });
  } catch (error) {
    logError(error, { operation: 'block-list-sync' });
    await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_SYNC,
      requestId,
      success: false,
      error: 'block_list_sync_failed'
    });
  }
}

export async function handleRetrieveBlockList({ ws, parsed, state }) {
  const requestId = typeof parsed?.requestId === 'string' ? parsed.requestId.slice(0, 128) : undefined;

  if (!hasAccountAuthentication(ws, state)) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_RESPONSE,
      requestId,
      encryptedBlockList: null,
      success: false,
      error: 'authentication_required'
    });
  }

  if (!ws._primaryBlockListLookupId) {
    return await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_RESPONSE,
      requestId,
      encryptedBlockList: null,
      success: false,
      error: 'block_list_route_not_claimed'
    });
  }

  try {
    const blockList = await BlockingDatabase.getEncryptedBlockListByLookupId(ws._primaryBlockListLookupId);

    if (blockList) {
      await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_RESPONSE,
        requestId,
        success: true,
        encryptedBlockList: blockList.encryptedBlockList,
        blockListHash: blockList.blockListHash,
        salt: blockList.salt,
        version: blockList.version,
        lastUpdated: blockList.lastUpdated,
      });
    } else {
      await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_RESPONSE,
        requestId,
        success: true,
        encryptedBlockList: null,
        message: 'No block list found',
      });
    }

    logEvent('block-list-retrieved', { hasInbox: !!ws._primaryBlockListLookupId });
  } catch (error) {
    logError(error, { operation: 'retrieve-block-list' });
    await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_RESPONSE,
      requestId,
      encryptedBlockList: null,
      success: false,
      error: 'block_list_retrieve_failed'
    });
  }
}
