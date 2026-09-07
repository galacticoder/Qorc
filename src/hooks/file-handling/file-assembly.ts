import { toast } from "sonner";
import { SignalType } from "../../lib/types/signal-types";
import { Message } from '../../components/chat/messaging/types';
import { dispatchCanceledEvent, detectMimeType, releaseFileEntry } from "../../lib/utils/file-utils";
import type { ExtendedFileState } from "../../lib/types/file-types";
import { deliveryReceiptOutbox } from '../../lib/signals/delivery-receipt-outbox';
import { bytesToHex } from '../../lib/utils/byte-utils';
import { PROTOCOL_KEYS } from '../../lib/config/protocol-keys';
import type { SecureDB } from '../../lib/database/secureDB';

// Validate all chunks are present
export const validateAllChunks = (fileEntry: ExtendedFileState): boolean => {
  for (let i = 0; i < fileEntry.totalChunks; i++) {
    if (fileEntry.decryptedChunks[i] === null || fileEntry.decryptedChunks[i] === undefined) {
      return false;
    }
  }
  return true;
};

// Assemble file blob from chunks
export const assembleFileBlob = (fileEntry: ExtendedFileState): Blob | null => {
  const detectedMime = detectMimeType(fileEntry.safeFilename);
  try {
    const parts = (fileEntry.decryptedChunks || [])
      .filter((part): part is Uint8Array => part instanceof Uint8Array)
      .map((part) => part as BlobPart);
    return new Blob(parts, { type: detectedMime });
  } catch {
    return null;
  }
};

export const deriveIncomingFileMessageId = async (from: string, wireMessageId: string): Promise<string> => {
  const input = new TextEncoder().encode(`${PROTOCOL_KEYS.INCOMING_FILE_MESSAGE_ID}\0${from}\0${wireMessageId}`);
  let digest: Uint8Array | null = null;
  try {
    digest = new Uint8Array(await crypto.subtle.digest('SHA-384', input));
    return `file-${bytesToHex(digest)}`;
  } finally {
    input.fill(0);
    digest?.fill(0);
  }
};

// Create file message
export const createFileMessage = (
  fileEntry: ExtendedFileState,
  fileBlob: Blob,
  from: string,
  messageId: string,
  toUser?: string,
): Message => {
  const detectedMime = detectMimeType(fileEntry.safeFilename);
  return {
    id: messageId,
    content: '',
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
    p2p: fileEntry.transport === 'p2p',
    transport: fileEntry.transport,
    receipt: { delivered: false, read: false },
    wireMessageId: fileEntry.messageId,
  };
};


export const completeFileTransfer = async (
  fileEntry: ExtendedFileState,
  from: string,
  toUser: string | undefined,
  secureDB: SecureDB,
  onNewMessage: (message: Message) => void,
  isCurrent: () => boolean
): Promise<{ assembled: boolean; durablySaved: boolean }> => {
  if (!isCurrent()) return { assembled: false, durablySaved: false };
  if (!validateAllChunks(fileEntry)) {
    return { assembled: false, durablySaved: false };
  }

  const fileBlob = assembleFileBlob(fileEntry);
  if (!fileBlob) {
    return { assembled: false, durablySaved: false };
  }
  if (!fileEntry.fileSize || fileBlob.size !== fileEntry.fileSize) {
    return { assembled: false, durablySaved: false };
  }

  if (!fileEntry.messageId) return { assembled: false, durablySaved: false };
  const messageId = await deriveIncomingFileMessageId(from, fileEntry.messageId);
  if (!isCurrent()) return { assembled: false, durablySaved: false };
  const message = createFileMessage(fileEntry, fileBlob, from, messageId, toUser);
  let durablySaved = false;
  let duplicate = false;
  try {
    const saveResult = await secureDB.storeFileMessage(
      { ...message, timestamp: message.timestamp.getTime() },
      fileBlob
    );
    durablySaved = !!saveResult?.success;
    duplicate = !!saveResult?.duplicate;
    if (!saveResult?.success && saveResult?.quotaExceeded) {
      toast.warning('Storage limit reached. File delivery is paused until space is available.', {
        duration: 5000
      });
    }
  } catch {
  }

  if (!isCurrent()) {
    return { assembled: false, durablySaved: false };
  }

  if (!durablySaved) {
    return { assembled: true, durablySaved: false };
  }

  if (!toUser || !fileEntry.messageId) return { assembled: true, durablySaved: false };
  try {
    if (!await deliveryReceiptOutbox.queueDelivery(toUser, from, fileEntry.messageId)) {
      return { assembled: true, durablySaved: false };
    }
  } catch {
    return { assembled: true, durablySaved: false };
  }

  if (!duplicate) onNewMessage(message);

  return { assembled: true, durablySaved };
};

// Handle failed file assembly
export const handleAssemblyFailure = (
  fileEntry: ExtendedFileState,
  fileKey: string,
  store: Record<string, any>,
  from: string,
  reason: string,
  setLoginError: (err: string) => void,
  errorMessage: string
): void => {
  releaseFileEntry(fileEntry);
  delete store[fileKey];
  setLoginError(errorMessage);
  dispatchCanceledEvent({ from, filename: fileEntry.safeFilename, reason });
};
