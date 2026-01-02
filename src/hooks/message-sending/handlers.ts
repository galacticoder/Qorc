import { EventType } from '../../lib/types/event-types';
import type { UserWithKeys, PendingRetryMessage } from '../../lib/types/message-sending-types';
import { logError } from '../../lib/utils/message-sending-utils';

// Setup session reset handler
export const createSessionResetHandler = (
  recentSessionResetsRef: React.RefObject<Map<string, number>>,
  peerCanDecryptRef: React.RefObject<Map<string, boolean>>,
  preKeyFailureCountRef: React.RefObject<Map<string, number>>
) => {
  return (event: Event) => {
    try {
      const { peerUsername } = (event as CustomEvent).detail || {};
      if (typeof peerUsername === 'string') {
        recentSessionResetsRef.current.set(peerUsername, Date.now());
        peerCanDecryptRef.current.delete(peerUsername);
        preKeyFailureCountRef.current.delete(peerUsername);
      }
    } catch { }
  };
};

// Setup session established handler
export const createSessionEstablishedHandler = (
  peerCanDecryptRef: React.RefObject<Map<string, boolean>>
) => {
  return async (event: Event) => {
    try {
      const { peer, fromPeer } = (event as CustomEvent).detail || {};
      const peerUsername = peer || fromPeer;
      if (typeof peerUsername !== 'string') return;

      peerCanDecryptRef.current.set(peerUsername, true);

      window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
        detail: { peer: peerUsername }
      }));
    } catch (_err) {
      console.error('[MessageSender] Error handling SESSION_ESTABLISHED:', _err);
    }
  };
};

// Setup session ready handler for retrying pending messages
export const createSessionReadyHandler = (
  pendingRetryMessagesRef: React.RefObject<Map<string, PendingRetryMessage>>,
  handleSendMessage: (
    user: UserWithKeys,
    content: string,
    replyTo?: string | { id: string; sender?: string; content?: string },
    fileData?: string,
    messageSignalType?: string,
    originalMessageId?: string,
    editMessageId?: string,
  ) => Promise<void>
) => {
  return (event: Event) => {
    try {
      const { peer, peerUsername, fromPeer } = (event as CustomEvent).detail || {};
      const id = (peerUsername || fromPeer || peer) as string | undefined;
      if (!id || typeof id !== 'string') return;

      const pending = pendingRetryMessagesRef.current.get(id);
      pendingRetryMessagesRef.current.delete(id);
      if (!pending) return;

      handleSendMessage(
        pending.user,
        pending.content,
        pending.replyTo,
        pending.fileData,
        pending.messageSignalType,
        pending.originalMessageId,
        pending.editMessageId,
      ).catch((error) => {
        console.error('[MessageSender] Retry after session establishment failed:', error);
      });
    } catch (_error) {
      console.error('[MessageSender] Error handling session-ready event:', _error);
    }
  };
};

// Handle session reset for unacknowledged messages
export const createSessionResetRetryHandler = (
  pendingRetryMessagesRef: React.RefObject<Map<string, PendingRetryMessage>>,
  secureDBRef?: React.RefObject<any>
) => {
  return async (event: Event) => {
    try {
      const { peerUsername } = (event as CustomEvent).detail || {};
      if (!peerUsername || !secureDBRef?.current) return;

      const db = secureDBRef.current;
      const unacknowledged: Array<{
        user: UserWithKeys;
        content: string;
        replyTo?: string | { id: string; sender?: string; content?: string };
        fileData?: string;
        messageSignalType?: string;
        originalMessageId?: string;
        editMessageId?: string;
        timestamp: number;
      }> = [];

      const messageListKey = `${peerUsername}:message-list`;
      const messageList = (await db.retrieveEphemeral('unacknowledged-messages', messageListKey) as number[] | null) || [];

      if (messageList.length === 0) return;

      for (const timestamp of messageList) {
        const messageKey = `${peerUsername}:${timestamp}`;
        const messageData = await db.retrieveEphemeral('unacknowledged-messages', messageKey);
        if (messageData) {
          unacknowledged.push(messageData as any);
        }
      }

      if (unacknowledged.length === 0) return;

      const lastMessage = unacknowledged[unacknowledged.length - 1];
      pendingRetryMessagesRef.current.set(peerUsername, {
        user: lastMessage.user,
        content: lastMessage.content,
        replyTo: lastMessage.replyTo,
        fileData: lastMessage.fileData,
        messageSignalType: lastMessage.messageSignalType,
        originalMessageId: lastMessage.originalMessageId,
        editMessageId: lastMessage.editMessageId,
        retryCount: 0,
      });

      for (const timestamp of messageList) {
        try {
          await db.delete('ephemeral:unacknowledged-messages', `${peerUsername}:${timestamp}`);
        } catch { }
      }
      try {
        await db.delete('ephemeral:unacknowledged-messages', messageListKey);
      } catch { }
    } catch (_error) {
      logError('session-reset-handler-error', _error);
    }
  };
};
