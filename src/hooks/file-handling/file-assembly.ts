import { v4 as uuidv4 } from "uuid";
import { toast } from "sonner";
import { SignalType } from "../../lib/types/signal-types";
import { Message } from '../../components/chat/messaging/types';
import { dispatchCompleteEvent, dispatchCanceledEvent, detectMimeType, releaseFileEntry } from "../../lib/utils/file-utils";
import type { ExtendedFileState } from "../../lib/types/file-types";

// Validate all chunks are present
export const validateAllChunks = (fileEntry: ExtendedFileState): boolean => {
  for (let i = 0; i < fileEntry.totalChunks; i++) {
    if (fileEntry.decryptedChunks[i] === null || fileEntry.decryptedChunks[i] === undefined) {
      console.error('[file-assembly] Missing chunk', { chunkIndex: i, filename: fileEntry.safeFilename });
      return false;
    }
  }
  return true;
};

// Assemble file blob from chunks
export const assembleFileBlob = (fileEntry: ExtendedFileState): Blob | null => {
  const detectedMime = detectMimeType(fileEntry.safeFilename);
  try {
    const parts = (fileEntry.decryptedChunks || []).filter((p) => p != null) as Blob[];
    return new Blob(parts, { type: detectedMime });
  } catch (e) {
    console.error('[file-assembly] Failed to assemble file blob:', e);
    return null;
  }
};

// Save file to SecureDB
export const saveFileToDb = async (
  secureDB: any,
  messageId: string,
  fileBlob: Blob
): Promise<void> => {
  if (!secureDB) return;

  try {
    const saveResult = await secureDB.saveFile(messageId, fileBlob);
    if (!saveResult.success && saveResult.quotaExceeded) {
      toast.warning('Storage limit reached. This file will not persist after restart.', {
        duration: 5000
      });
    }
  } catch (saveErr) {
    console.error('[file-assembly] Failed to save file to SecureDB:', saveErr);
  }
};

// Convert blob to base64
export const blobToBase64 = async (fileBlob: Blob): Promise<string | undefined> => {
  try {
    return await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const result = reader.result as string;
        const base64 = result.split(',')[1];
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(fileBlob);
    });
  } catch (e) {
    console.error('[file-assembly] Failed to convert blob to base64:', e);
    return undefined;
  }
};

// Create file message
export const createFileMessage = (
  fileEntry: ExtendedFileState,
  fileUrl: string,
  fileBlob: Blob,
  from: string,
  toUser?: string,
  originalBase64Data?: string
): Message => {
  const detectedMime = detectMimeType(fileEntry.safeFilename);
  return {
    id: fileEntry.messageId || uuidv4(),
    content: fileUrl,
    sender: from,
    recipient: toUser,
    timestamp: new Date(),
    isCurrentUser: false,
    isSystemMessage: false,
    type: SignalType.FILE_MESSAGE,
    filename: fileEntry.safeFilename,
    fileSize: fileBlob.size,
    mimeType: detectedMime,
    encrypted: true,
    transport: 'websocket',
    version: '1.0',
    receipt: { delivered: false, read: false },
    originalBase64Data,
  };
};

// Complete file transfer
export const completeFileTransfer = async (
  fileEntry: ExtendedFileState,
  fileKey: string,
  from: string,
  toUser: string | undefined,
  store: Record<string, any>,
  blobCache: { enqueue: (url: string, source: string) => void },
  secureDBRef: React.RefObject<any | null> | undefined,
  onNewMessage: (message: Message) => void
): Promise<boolean> => {
  if (!validateAllChunks(fileEntry)) {
    console.error('[file-assembly] Transfer incomplete - missing chunks', {
      from,
      filename: fileEntry.safeFilename,
      receivedCount: fileEntry.receivedCount,
      totalChunks: fileEntry.totalChunks
    });
    return false;
  }

  const fileBlob = assembleFileBlob(fileEntry);
  if (!fileBlob) {
    return false;
  }

  const fileUrl = URL.createObjectURL(fileBlob);
  blobCache.enqueue(fileUrl, fileEntry.safeFilename);

  const messageId = fileEntry.messageId || uuidv4();
  await saveFileToDb(secureDBRef?.current, messageId, fileBlob);

  const originalBase64Data = await blobToBase64(fileBlob);
  const detectedMime = detectMimeType(fileEntry.safeFilename);

  const message = createFileMessage(fileEntry, fileUrl, fileBlob, from, toUser, originalBase64Data);
  onNewMessage(message);

  dispatchCompleteEvent({
    from,
    filename: fileEntry.safeFilename,
    size: fileBlob.size,
    mimeType: detectedMime,
    messageId: fileEntry.messageId || ''
  });

  delete store[fileKey];
  releaseFileEntry(fileEntry);

  return true;
};

// Handle failed file assembly
export const handleAssemblyFailure = (
  fileEntry: ExtendedFileState,
  fileKey: string,
  store: Record<string, any>,
  blobCache: { clear: () => void },
  from: string,
  reason: string,
  setLoginError: (err: string) => void,
  errorMessage: string
): void => {
  releaseFileEntry(fileEntry);
  delete store[fileKey];
  blobCache.clear();
  setLoginError(errorMessage);
  dispatchCanceledEvent({ from, filename: fileEntry.safeFilename, reason });
};
