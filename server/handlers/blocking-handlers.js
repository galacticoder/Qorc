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
  sendSecureMessage
} from './core.js';

export async function handleBlockListSync({ ws, parsed, state }) {
  if (!state?.hasAuthenticated || !ws._primaryInboxId) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const { encryptedBlockList, blockListHash, salt, version, lastUpdated } = parsed;

    if (!encryptedBlockList || !blockListHash) {
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Missing encrypted block list or hash'
      });
    }

    await BlockingDatabase.storeEncryptedBlockList(
      ws._primaryInboxId,
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

    logEvent('block-list-synced', { inboxId: ws._primaryInboxId?.slice(0, 8) });
  } catch (error) {
    logError(error, { operation: 'block-list-sync' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error synchronizing block list'
    });
  }
}

export async function handleRetrieveBlockList({ ws, state }) {
  if (!state?.hasAuthenticated || !ws._primaryInboxId) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const blockList = await BlockingDatabase.getEncryptedBlockList(ws._primaryInboxId);

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

    logEvent('block-list-retrieved', { inboxId: ws._primaryInboxId?.slice(0, 8) });
  } catch (error) {
    logError(error, { operation: 'retrieve-block-list' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error retrieving block list'
    });
  }
}

export async function handleBlockTokensUpdate({ ws, parsed, state }) {
  if (!state?.hasAuthenticated) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const { action, blockerIdentityKeyHash, blockedIdentityKeyHash } = parsed;

    if (!blockerIdentityKeyHash || !blockedIdentityKeyHash) {
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Missing identity key hashes'
      });
    }

    let success = false;
    if (action === 'block') {
      success = await BlockingDatabase.addBlock(blockerIdentityKeyHash, blockedIdentityKeyHash);
    } else if (action === 'unblock') {
      success = await BlockingDatabase.removeBlock(blockerIdentityKeyHash, blockedIdentityKeyHash);
    }

    await sendSecureMessage(ws, {
      type: SignalType.BLOCK_TOKENS_UPDATE,
      success,
      action
    });

    logEvent('block-tokens-updated', { action, success });
  } catch (error) {
    logError(error, { operation: 'block-tokens-update' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error updating block tokens'
    });
  }
}
