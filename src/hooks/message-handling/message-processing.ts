import { v4 as uuidv4 } from 'uuid';
import { SignalType } from '../../lib/types/signal-types';
import { Message } from '../../components/chat/messaging/types';
import { safeJsonParseForMessages, safeJsonParseForFileMessages, createBlobUrlFromBase64 } from '../../lib/utils/message-handler-utils';
import { messageVault } from '../../lib/security/message-vault';

// Process text message and add to state
export const processTextMessage = async (
  payload: any,
  loginUsername: string,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
): Promise<{ messageId: string; messageAdded: boolean }> => {
  const trimmedContent = (payload.content || '').trim();

  if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
    const typingCheckData = safeJsonParseForMessages(payload.content);
    if (typingCheckData && (typingCheckData.type === SignalType.TYPING_START || typingCheckData.type === SignalType.TYPING_STOP)) {
      return { messageId: '', messageAdded: false };
    }
  }

  let messageId = payload.messageId || uuidv4();
  let messageContent = payload.content;

  if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
    const contentData = safeJsonParseForMessages(payload.content);
    if (contentData && contentData.messageId) {
      messageId = contentData.messageId;
      messageContent = contentData.content || contentData.message || payload.content;
      if (contentData.replyTo) {
        payload.replyTo = contentData.replyTo;
      }
    }
  }

  let messageExists = false;
  let messageAdded = false;
  let replyToToStore: { id: string; content: string } | null = null;
  let replyToForSave: Message['replyTo'] | undefined;

  // Store in vault first
  await messageVault.store(messageId, messageContent);

  setMessages(prev => {
    messageExists = prev.some(msg => msg.id === messageId);
    if (messageExists) return prev;

    messageAdded = true;
    let replyToFilled: Message['replyTo'] | undefined;

    if (payload.replyTo && typeof payload.replyTo === 'object' && payload.replyTo.id) {
      let replyContent = payload.replyTo.content || '';
      const ref = prev.find(m => m.id === payload.replyTo.id);
      if (!replyContent) {
        if (ref?.isDeleted) {
          replyContent = 'Message deleted';
        } else if (ref?.secureContentId) {
          replyContent = "[Message]";
        } else if (ref?.content) {
          replyContent = ref.content;
        }
      }
      if (!replyContent || replyContent.trim().length === 0) {
        replyContent = "Message doesn't exist";
      }

      const replyId = `reply-${payload.replyTo.id}-${messageId}`;
      replyToToStore = { id: replyId, content: replyContent };

      replyToFilled = {
        id: payload.replyTo.id,
        sender: payload.replyTo.sender || (ref?.sender ?? payload.from),
        content: '',
        secureContentId: replyId
      };
      replyToForSave = { ...replyToFilled, content: replyContent };
    }

    const message: Message = {
      id: messageId,
      content: '',
      secureContentId: messageId,
      sender: payload.from,
      recipient: payload?.to || loginUsername,
      timestamp: new Date(payload.timestamp || Date.now()),
      type: SignalType.TEXT,
      isCurrentUser: false,
      p2p: payload.p2p || false,
      encrypted: true,
      version: payload.version || '1.0',
      fromOriginal: payload.fromOriginal,
      ...(replyToFilled && { replyTo: replyToFilled })
    };

    return [...prev, message];
  });

  // Handle reply vault storage outside of setMessages
  if (replyToToStore) {
    await messageVault.store(replyToToStore.id, replyToToStore.content);
  }

  if (!messageExists && messageAdded) {
    try {
      await saveMessageToLocalDB({
        id: messageId,
        content: messageContent,
        sender: payload.from,
        recipient: payload?.to || loginUsername,
        p2p: payload.p2p || false,
        encrypted: true,
        transport: payload.p2p ? 'p2p' : 'websocket',
        timestamp: new Date(payload.timestamp || Date.now()),
        type: SignalType.TEXT,
        isCurrentUser: false,
        version: payload.version || '1.0',
        fromOriginal: payload.fromOriginal,
        ...(replyToForSave && { replyTo: replyToForSave })
      });
    } catch (dbError) {
      console.error('[EncryptedMessageHandler] Failed to save message to database:', dbError);
    }
  }

  return { messageId, messageAdded };
};

// Process file message and add to state
export const processFileMessage = async (
  payload: any,
  loginUsername: string,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  blobCache: any,
  secureDBRef?: React.RefObject<any>
): Promise<{ messageId: string; messageAdded: boolean }> => {
  let messageId = payload.messageId || uuidv4();
  let fileName = payload.fileName;
  let fileType = payload.fileType || 'application/octet-stream';
  let fileSize = payload.fileSize || 0;
  let dataBase64: string | null = null;

  const fileContentData = safeJsonParseForFileMessages(payload.content);
  if (fileContentData) {
    messageId = fileContentData.messageId || messageId;
    fileName = fileContentData.fileName || fileContentData.fileData || payload.fileName;
    fileType = fileContentData.fileType || fileType;
    fileSize = fileContentData.fileSize || fileSize;
    dataBase64 = fileContentData.dataBase64 || null;
  }

  let contentValue: string = payload.content;
  if (dataBase64 && typeof dataBase64 === 'string') {
    const blobUrl = createBlobUrlFromBase64(dataBase64, fileType, blobCache);
    if (blobUrl) {
      contentValue = blobUrl;
    }
  }

  if (dataBase64) {
    await messageVault.store(`${messageId}-file`, dataBase64);
  }

  let messageExists = false;
  setMessages(prev => {
    messageExists = prev.some(msg => msg.id === messageId);
    if (messageExists) return prev;

    let fileContent = contentValue || fileName || 'File';
    if (dataBase64) {
      const blobUrl = createBlobUrlFromBase64(dataBase64, fileType, blobCache);
      if (blobUrl) {
        fileContent = blobUrl;
      } else {
        messageExists = true;
        return prev;
      }
    }

    const message: Message = {
      id: messageId,
      content: fileContent,
      sender: payload.from,
      recipient: payload?.to || loginUsername,
      timestamp: new Date(payload.timestamp || Date.now()),
      type: SignalType.FILE,
      isCurrentUser: false,
      filename: fileName,
      mimeType: fileType,
      fileSize: fileSize,
      originalBase64Data: '',
      secureContentId: messageId,
      version: payload.version || '1.0',
      fromOriginal: payload.fromOriginal,
      fileInfo: {
        name: fileName || 'File',
        type: fileType,
        size: fileSize,
        data: new ArrayBuffer(0)
      }
    };

    return [...prev, message];
  });

  if (!messageExists) {
    await saveMessageToLocalDB({
      id: messageId,
      content: contentValue || fileName || 'File',
      sender: payload.from,
      recipient: payload?.to || loginUsername,
      timestamp: new Date(payload.timestamp || Date.now()),
      type: SignalType.FILE,
      isCurrentUser: false,
      filename: fileName,
      mimeType: fileType,
      fileSize: fileSize,
      originalBase64Data: dataBase64,
      version: payload.version || '1.0',
      fromOriginal: payload.fromOriginal,
      fileInfo: {
        name: fileName || 'File',
        type: fileType,
        size: fileSize,
        data: new ArrayBuffer(0)
      }
    });

    if (secureDBRef?.current && dataBase64) {
      try {
        let cleanBase64 = dataBase64.trim();
        const inlinePrefixIndex = cleanBase64.indexOf(',');
        if (inlinePrefixIndex > 0 && inlinePrefixIndex < 128) {
          cleanBase64 = cleanBase64.slice(inlinePrefixIndex + 1);
        }
        const binary = Uint8Array.from(atob(cleanBase64), char => char.charCodeAt(0));
        const blob = new Blob([binary], { type: fileType || 'application/octet-stream' });
        await secureDBRef.current.saveFile(messageId, blob);
      } catch { }
    }
  }

  return { messageId, messageAdded: !messageExists };
};

// Check if message requires blocking filter
export const checkBlockingFilter = async (
  payload: any,
  loginUsername: string,
  blockingSystem: any
): Promise<boolean> => {
  if (payload.from && payload.from !== loginUsername &&
    payload.type !== SignalType.READ_RECEIPT && payload.type !== SignalType.DELIVERY_RECEIPT &&
    payload.type !== SignalType.TYPING_START && payload.type !== SignalType.TYPING_STOP &&
    payload.type !== SignalType.TYPING_INDICATOR) {
    try {
      const shouldFilter = await blockingSystem.filterIncomingMessage({
        sender: payload.from,
        content: payload.content || ''
      }, null);
      return shouldFilter;
    } catch { }
  }
  return true;
};

// Determine message type
export const getMessageType = (payload: any): { isTextMessage: boolean; isFileMessage: boolean; isCallSignal: boolean } => {
  const isTextMessage = (payload.type === SignalType.MESSAGE || payload.type === SignalType.TEXT || !payload.type) &&
    payload.content && typeof payload.content === 'string' && payload.content.trim().length > 0;
  const isFileMessage = payload.type === SignalType.FILE_MESSAGE && payload.fileName;
  const isCallSignal = payload.type?.startsWith?.('call-');

  return { isTextMessage, isFileMessage, isCallSignal };
};
