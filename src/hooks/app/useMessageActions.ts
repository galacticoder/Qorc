import { useCallback } from 'react';
import { Message, MessageReply } from '../../components/chat/messaging/types';
import { User } from '../../components/chat/messaging/UserList';
import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { SecurityAuditLogger } from '../../lib/cryptography/audit-logger';
import { formatFileSize } from '../../lib/utils/file-utils';
import { toast } from 'sonner';
import { messageVault } from '../../lib/security/message-vault';

const getReplyContent = (message: Message): string => {
  if (message.type === SignalType.FILE || message.type === SignalType.FILE_MESSAGE || message.filename) {
    const fileSize = message.fileSize ? ` (${formatFileSize(message.fileSize)})` : '';
    const filename = message.filename || 'File';

    if (message.filename && /\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff)$/i.test(message.filename)) {
      return `Image: ${message.filename}${fileSize}`;
    } else if (message.filename && /\.(mp4|webm|ogg|avi|mov|wmv|flv|mkv)$/i.test(message.filename)) {
      return `Video: ${message.filename}${fileSize}`;
    } else if (message.filename && (message.filename.toLowerCase().includes('voice-note') || /\.(mp3|wav|ogg|webm|m4a|aac|flac)$/i.test(message.filename))) {
      return `Voice message`;
    } else {
      return `File: ${filename}${fileSize}`;
    }
  }
  return message.content || '';
};

interface MessageActionsProps {
  selectedConversation: string | null;
  getOrCreateUser: (username: string) => User;
  messageSender: {
    handleSendMessage: (
      targetUser: User,
      content: string,
      replyTo?: Message,
      fileData?: any,
      messageSignalType?: string,
      messageId?: string
    ) => Promise<void>;
  };
  p2pMessaging: {
    isPeerConnected: (peer: string) => boolean;
    connectToPeer: (peer: string) => Promise<void>;
  };
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  saveMessageWithContext: (message: Message) => Promise<void>;
  loginUsernameRef: React.RefObject<string | null>;
  users: User[];
  saveMessageToLocalDB: (message: any, peer?: string) => Promise<void>;
}

export function useMessageActions({
  selectedConversation,
  getOrCreateUser,
  messageSender,
  p2pMessaging,
  setMessages,
  saveMessageWithContext,
  loginUsernameRef,
  users,
  saveMessageToLocalDB,
}: MessageActionsProps) {
  const onSendMessage = useCallback(async (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => {
    if (!selectedConversation) return;

    const targetUser = getOrCreateUser(selectedConversation);

    const replyToMessage = replyTo ? {
      id: replyTo.id,
      sender: replyTo.sender,
      content: replyTo.content,
      timestamp: new Date(),
      type: SignalType.TEXT as const,
      isCurrentUser: false,
      version: '1'
    } as Message : undefined;

    if (messageSignalType === SignalType.TYPING_START || messageSignalType === SignalType.TYPING_STOP) {
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType);
    }

    if (messageSignalType === SignalType.DELETE_MESSAGE || messageSignalType === SignalType.EDIT_MESSAGE) {
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType, messageId);
    }

    const isConnected = p2pMessaging.isPeerConnected(selectedConversation);

    if (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) {
      try {
        const payload = {
          reactTo: messageId,
          emoji: content,
          timestamp: Date.now()
        };
        const result = await unifiedSignalTransport.send(
          selectedConversation,
          payload,
          messageSignalType as SignalType,
          { destinationInbox: (targetUser as any)?.inboxId }
        );

        if (result.success) {
          window.dispatchEvent(new CustomEvent(EventType.LOCAL_REACTION_UPDATE, {
            detail: {
              messageId,
              emoji: content,
              isAdd: messageSignalType === SignalType.REACTION_ADD,
              username: loginUsernameRef.current
            }
          }));
          return;
        }
      } catch { }

      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType, messageId);
    }

    if (isConnected) {
      try {
        const mId = crypto.randomUUID();
        const payload = {
          messageId: mId,
          content,
          timestamp: Date.now(),
          replyTo: replyTo ? {
            id: replyTo.id,
            sender: replyTo.sender,
            content: replyTo.content
          } : undefined
        };
        const result = await unifiedSignalTransport.send(
          selectedConversation,
          payload,
          SignalType.TEXT,
          { destinationInbox: (targetUser as any)?.inboxId }
        );

        if (result.success) {
          await messageVault.store(mId, content);

          const newMessage: Message = {
            id: mId,
            content: '',
            secureContentId: mId,
            sender: loginUsernameRef.current || '',
            recipient: selectedConversation,
            timestamp: new Date(),
            type: SignalType.TEXT,
            isCurrentUser: true,
            p2p: result.transport === 'p2p',
            transport: result.transport,
            encrypted: true,
            receipt: { delivered: false, read: false },
          } as Message;

          if (replyTo) {
            const replyId = `reply-${replyTo.id}-${mId}`;
            const replyContent = getReplyContent(replyTo as Message);
            await messageVault.store(replyId, replyContent);
            newMessage.replyTo = {
              id: replyTo.id,
              sender: replyTo.sender,
              content: '',
              secureContentId: replyId
            };
          }

          setMessages(prev => [...prev, newMessage]);
          saveMessageWithContext({ ...newMessage, content });
          return;
        }
      } catch { }
    }

    try {
      await messageSender.handleSendMessage(
        targetUser as any,
        content,
        replyToMessage,
        undefined,
        messageSignalType,
        messageId
      );
    } catch (error) {
      console.error("Failed to send message:", error);
      toast.error(error instanceof Error ? error.message : "Failed to send message", {
        duration: 5000
      });
    }
  }, [selectedConversation, getOrCreateUser, messageSender, p2pMessaging, setMessages, saveMessageWithContext, loginUsernameRef]);

  const onSendFile = useCallback(async (fileData: any) => {
    const MAX_LOCAL_STORAGE_SIZE = 5 * 1024 * 1024;

    const dataToSave = { ...fileData };
    if (fileData.size > MAX_LOCAL_STORAGE_SIZE) {
      if (dataToSave.originalBase64Data) {
        dataToSave.originalBase64Data = null;
      }
      if (typeof dataToSave.content === 'string' && dataToSave.content.startsWith('data:')) {
        dataToSave.content = '';
      }
      dataToSave.isLocalStorageTruncated = true;
    }

    try {
      if (selectedConversation) {
        let isConnected = p2pMessaging.isPeerConnected(selectedConversation);

        if (!isConnected) {
          try {
            await p2pMessaging.connectToPeer(selectedConversation);
            isConnected = true;
          } catch { }
        }

        // Try P2P first if connected
        if (isConnected) {
          try {
            const targetUser = users.find(user => user.username === selectedConversation);
            const payload = {
              filename: fileData.filename,
              size: fileData.size,
              type: fileData.type,
              url: fileData.url,
              timestamp: Date.now()
            };
            const result = await unifiedSignalTransport.send(
              selectedConversation,
              payload,
              SignalType.FILE,
              { destinationInbox: (targetUser as any)?.inboxId }
            );

            if (result.success) {
              await saveMessageToLocalDB(dataToSave);
              return;
            }
          } catch { }
        }
      }

      await saveMessageToLocalDB(dataToSave);

    } catch (error) {
      SecurityAuditLogger.log(SignalType.ERROR, 'file-transfer-failed', { error: error instanceof Error ? error.message : 'unknown' });
      toast.error(error instanceof Error ? error.message : "Failed to send file", {
        duration: 5000
      });

      await saveMessageToLocalDB(dataToSave);
    }
  }, [selectedConversation, p2pMessaging, users, saveMessageToLocalDB]);

  return { onSendMessage, onSendFile };
}
