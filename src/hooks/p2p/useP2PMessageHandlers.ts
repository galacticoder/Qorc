import React, { useEffect, useRef } from 'react';
import { Message } from '../../components/chat/messaging/types';
import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import { SecurityAuditLogger } from '../../lib/cryptography/audit-logger';
import { profilePictureSystem } from '../../lib/profile-picture-system';
import type { EncryptedMessage } from './useP2PMessaging';

interface UseP2PMessageHandlersProps {
  p2pMessaging: {
    onMessage: (handler: (msg: EncryptedMessage) => Promise<void>) => () => void;
  };
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  saveMessageWithContext: (message: Message) => Promise<any> | void;
  loginUsernameRef: React.RefObject<string | null>;
}

export function useP2PMessageHandlers({
  p2pMessaging,
  setMessages,
  saveMessageWithContext,
  loginUsernameRef,
}: UseP2PMessageHandlersProps) {
  const saveMessageRef = useRef(saveMessageWithContext);
  useEffect(() => { saveMessageRef.current = saveMessageWithContext; }, [saveMessageWithContext]);

  // Register once and clean up the listener on unmount/change
  useEffect(() => {
    const cleanup = p2pMessaging.onMessage(async (encryptedMessage: EncryptedMessage) => {
      try {
        // Profile picture requests/responses
        if (encryptedMessage.messageType === SignalType.SIGNAL) {
          const payload = encryptedMessage.content as any;
          if (payload?.type === 'profile-picture-request' || payload?.type === 'profile-picture-response') {
            profilePictureSystem.handleIncomingMessage(payload, encryptedMessage.from).catch(() => { });
            return;
          }
        }

        // Typing indicators
        if (encryptedMessage.messageType === SignalType.TYPING) {
          window.dispatchEvent(new CustomEvent(EventType.TYPING_INDICATOR, {
            detail: {
              username: encryptedMessage.from,
              isTyping: encryptedMessage.content === SignalType.TYPING_START,
            }
          }));
          return;
        }

        // Reactions
        if (encryptedMessage.messageType === SignalType.REACTION) {
          const targetMessageId = encryptedMessage.metadata?.targetMessageId;
          const action = encryptedMessage.metadata?.action;
          const emoji = encryptedMessage.content;

          if (targetMessageId && emoji && (action === SignalType.REACTION_ADD || action === SignalType.REACTION_REMOVE)) {
            window.dispatchEvent(new CustomEvent(EventType.LOCAL_REACTION_UPDATE, {
              detail: {
                messageId: targetMessageId,
                emoji,
                isAdd: action === SignalType.REACTION_ADD,
                username: encryptedMessage.from
              }
            }));
          }
          return;
        }

        // [NEW] Call Signals (P2P Calling)
        if (encryptedMessage.messageType === SignalType.CALL_SIGNAL) {
          const payload = encryptedMessage.content as any;

          let signal = payload;
          if (payload?.type === EventType.CALL_SIGNAL && typeof payload.content === 'string') {
              signal = JSON.parse(payload.content);
          }

          window.dispatchEvent(new CustomEvent(EventType.CALL_SIGNAL, {
            detail: signal
          }));
          return;
        }

        // Message deletion
        if (encryptedMessage.messageType === SignalType.DELETE) {
          const targetMessageId = encryptedMessage.metadata?.targetMessageId;
          if (targetMessageId) {
            let messageToPersist: Message | null = null;
            setMessages(prev => prev.map(msg => {
              if (msg.id === targetMessageId) {
                const updated = { ...msg, isDeleted: true, content: 'This message was deleted' };
                messageToPersist = updated;
                return updated;
              }
              return msg;
            }));

            if (messageToPersist) {
              try { saveMessageRef.current(messageToPersist); } catch { }
            }

            try {
              window.dispatchEvent(new CustomEvent(EventType.REMOTE_MESSAGE_DELETE, { detail: { messageId: targetMessageId } }));
            } catch { }
          }
          return;
        }

        // Message editing
        if (encryptedMessage.messageType === SignalType.EDIT) {
          const targetMessageId = encryptedMessage.metadata?.targetMessageId;
          const newContent = encryptedMessage.metadata?.newContent || encryptedMessage.content;
          if (targetMessageId && newContent) {
            let messageToPersist: Message | null = null;
            setMessages(prev => prev.map(msg => {
              if (msg.id === targetMessageId) {
                const updated = { ...msg, content: newContent, isEdited: true };
                messageToPersist = updated;
                return updated;
              }
              return msg;
            }));

            if (messageToPersist) {
              try { saveMessageRef.current(messageToPersist); } catch { }
            }

            try {
              window.dispatchEvent(new CustomEvent(EventType.REMOTE_MESSAGE_EDIT, { detail: { messageId: targetMessageId, newContent } }));
            } catch { }
          }
          return;
        }

        // File metadata (ignored and handled separately)
        if (encryptedMessage.messageType === SignalType.FILE) {
          return;
        }

        // Regular text message
        const message: Message = {
          id: encryptedMessage.id,
          content: encryptedMessage.content,
          sender: encryptedMessage.from,
          recipient: encryptedMessage.to,
          timestamp: new Date(encryptedMessage.timestamp),
          type: SignalType.TEXT,
          isCurrentUser: false,
          p2p: true,
          transport: 'p2p',
          encrypted: encryptedMessage.encrypted,
          receipt: { delivered: true, read: false },
          ...(encryptedMessage.metadata?.replyTo && {
            replyTo: {
              id: encryptedMessage.metadata.replyTo.id,
              sender: encryptedMessage.metadata.replyTo.sender,
              content: encryptedMessage.metadata.replyTo.content
            }
          })
        } as Message;

        setMessages(prev => {
          const exists = prev.some(m => {
            if (m.id === message.id) return true;
            try {
              const sameSender = m.sender === message.sender;
              const sameRecipient = m.recipient === message.recipient;
              const sameType = m.type === message.type;
              const sameContent = m.content === message.content;
              const mt = m.timestamp instanceof Date ? m.timestamp.getTime() : (m.timestamp ? new Date(m.timestamp as any).getTime() : undefined);
              const tt = message.timestamp instanceof Date ? message.timestamp.getTime() : (message.timestamp ? new Date(message.timestamp as any).getTime() : undefined);
              const closeInTime = mt && tt ? Math.abs(mt - tt) < 2000 : false;
              return sameSender && sameRecipient && sameType && sameContent && closeInTime;
            } catch {
              return false;
            }
          });
          if (exists) return prev;
          return [...prev, message];
        });

        saveMessageRef.current(message);

      } catch (err) {
        SecurityAuditLogger.log(SignalType.ERROR, 'p2p-message-handle-failed', { error: String(err) });
      }
    });

    return () => {
      cleanup?.();
    };
  }, [p2pMessaging]);
}
