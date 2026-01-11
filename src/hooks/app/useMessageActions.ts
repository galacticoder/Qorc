import { useCallback } from 'react';
import { Message, MessageReply } from '../../components/chat/messaging/types';
import { User } from '../../components/chat/messaging/UserList';
import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { p2pConfig } from '../../config/p2p.config';
import { SecurityAuditLogger } from '../../lib/cryptography/audit-logger';
import { formatFileSize } from '../../lib/utils/file-utils';
import { toast } from 'sonner';

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
    sendP2PMessage: (
      peer: string,
      content: string,
      keys?: { dilithiumPublicBase64: string; kyberPublicBase64: string; x25519PublicBase64?: string },
      options?: { messageType?: string; metadata?: any }
    ) => Promise<{ status: string; messageId?: string }>;
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
      if (p2pConfig.features.textMessages && isConnected && targetUser.hybridPublicKeys) {
        try {
          const result = await p2pMessaging.sendP2PMessage(
            selectedConversation,
            content,
            {
              dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64,
              kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64,
              x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
            },
            {
              messageType: SignalType.REACTION,
              metadata: {
                targetMessageId: messageId,
                action: messageSignalType
              }
            }
          );

          if (result.status === 'sent') {
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
      }
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType, messageId);
    }

    if (p2pConfig.features.textMessages && isConnected) {
      try {
        if (targetUser.hybridPublicKeys) {
          const result = await p2pMessaging.sendP2PMessage(
            selectedConversation,
            content,
            {
              dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64,
              kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64,
              x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
            },
            {
              metadata: replyTo ? {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: replyTo.content
                }
              } : undefined
            }
          );

          if (result.status === 'sent') {
            const newMessage: Message = {
              id: result.messageId || crypto.randomUUID(),
              content: content,
              sender: loginUsernameRef.current || '',
              recipient: selectedConversation,
              timestamp: new Date(),
              type: SignalType.TEXT,
              isCurrentUser: true,
              p2p: true,
              transport: 'p2p',
              encrypted: true,
              receipt: { delivered: false, read: false },
              ...(replyTo && { replyTo: { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo as Message) } })
            } as Message;

            setMessages(prev => [...prev, newMessage]);
            saveMessageWithContext(newMessage);
            return;
          }
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
      if (p2pConfig.features.fileTransfers && selectedConversation) {
        let isConnected = p2pMessaging.isPeerConnected(selectedConversation);

        if (!isConnected) {
          try {
            await p2pMessaging.connectToPeer(selectedConversation);
            isConnected = true;
          } catch { }
        }

        if (isConnected) {
          const targetUser = users.find(user => user.username === selectedConversation);

          if (targetUser && targetUser.hybridPublicKeys) {
            try {
              const result = await p2pMessaging.sendP2PMessage(
                selectedConversation,
                JSON.stringify({
                  filename: fileData.filename,
                  size: fileData.size,
                  type: fileData.type,
                  url: fileData.url,
                }),
                {
                  dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                  kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                  x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                },
                {
                  messageType: SignalType.FILE,
                  metadata: {
                    filename: fileData.filename,
                    size: fileData.size,
                    type: fileData.type,
                    url: fileData.url,
                  }
                }
              );

              if (result.status === 'sent') {
                await saveMessageToLocalDB(dataToSave);
                return;
              }
            } catch { }
          }
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
