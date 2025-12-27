import { useEffect, useRef } from 'react';
import { Message } from '../components/chat/messaging/types';
import { EventType } from '../lib/event-types';
import { SignalType } from '../lib/signal-types';
import { SecurityAuditLogger } from '../lib/post-quantum-crypto';
import type { EncryptedMessage } from './useP2PMessaging';

interface UseP2PMessageHandlersProps {
  p2pMessaging: {
    onMessage: (handler: (msg: EncryptedMessage) => Promise<void>) => void;
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

  useEffect(() => {
    p2pMessaging.onMessage(async (encryptedMessage: EncryptedMessage) => {
      try {
        // Typing indicators
        if (encryptedMessage.messageType === 'typing') {
          window.dispatchEvent(new CustomEvent(EventType.TYPING_INDICATOR, {
            detail: {
              username: encryptedMessage.from,
              isTyping: encryptedMessage.content === SignalType.TYPING_START,
            }
          }));
          SecurityAuditLogger.log('info', 'p2p-typing-received', {});
          return;
        }

        // Reactions
        if (encryptedMessage.messageType === 'reaction') {
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
            SecurityAuditLogger.log('info', 'p2p-reaction-received', {});
          }
          return;
        }

        // Message deletion
        if (encryptedMessage.messageType === 'delete') {
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

            SecurityAuditLogger.log('info', 'p2p-delete-received', {});
          }
          return;
        }

        // Message editing
        if (encryptedMessage.messageType === 'edit') {
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

            SecurityAuditLogger.log('info', 'p2p-edit-received', {});
          }
          return;
        }

        // File metadata (ignored - handled separately)
        if (encryptedMessage.messageType === 'file') {
          SecurityAuditLogger.log('info', 'p2p-file-metadata-ignored', {});
          return;
        }

        // Regular text message
        const message: Message = {
          id: encryptedMessage.id,
          content: encryptedMessage.content,
          sender: encryptedMessage.from,
          recipient: encryptedMessage.to,
          timestamp: new Date(encryptedMessage.timestamp),
          type: 'text',
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
        SecurityAuditLogger.log('info', `p2p-${encryptedMessage.messageType || 'message'}-received`, {});
      } catch {
        SecurityAuditLogger.log('error', 'p2p-message-handle-failed', { error: 'unknown' });
      }
    });
  }, []);
}
