import { sanitizeTextInput, sanitizeFilename, isPlainObject, hasPrototypePollutionKeys } from "../../lib/sanitizers";
import {
  MAX_TOTAL_CHUNKS,
  MAX_FILE_SIZE_BYTES,
  MAX_CHUNK_SIZE_BYTES,
} from "../../lib/constants";
import { enforceConcurrentLimit, dispatchCanceledEvent } from "../../lib/utils/file-utils";
import type { IncomingFileChunks } from "../../pages/types";
import type { FileChunkPayload, ExtendedFileState } from "../../lib/types/file-types";

export interface ChunkValidationResult {
  valid: boolean;
  error?: string;
  from: string;
  toUser?: string;
  safeFilename: string;
  fileKey: string;
  chunkIndex: number;
  totalChunks: number;
  chunkData: string;
  envelope?: any;
  messageId?: string;
  fileSize: number;
  chunkSize: number;
}

// Validate incoming payload structure
export const validatePayload = (payload: any): payload is FileChunkPayload => {
  if (!isPlainObject(payload) || hasPrototypePollutionKeys(payload)) {
    return false;
  }
  const { chunkIndex, totalChunks, chunkData } = payload;
  return typeof chunkIndex === 'number' && typeof totalChunks === 'number' && typeof chunkData === 'string';
};

// Extract and sanitize chunk data from payload
export const extractChunkData = (payload: any, message: any): ChunkValidationResult | null => {
  if (!validatePayload(payload)) {
    return null;
  }

  const { chunkIndex, totalChunks, chunkData, envelope, filename, messageId } = payload as FileChunkPayload;
  const from = sanitizeTextInput(String(message?.from ?? ''), { maxLength: 96, allowNewlines: false }) || 'unknown';
  const toUser = sanitizeTextInput(String((message as any)?.to ?? (payload as any)?.to ?? ''), { maxLength: 96, allowNewlines: false }) || undefined;
  const safeFilename = sanitizeFilename(filename);
  const fileKey = `${from}-${safeFilename}`;

  return {
    valid: true,
    from,
    toUser,
    safeFilename,
    fileKey,
    chunkIndex,
    totalChunks,
    chunkData,
    envelope,
    messageId: typeof messageId === 'string' ? sanitizeTextInput(messageId, { maxLength: 256, allowNewlines: false }) : undefined,
    fileSize: Number(payload.fileSize || 0),
    chunkSize: Number(payload.chunkSize || 0),
  };
};

// Validate new transfer metadata
export const validateNewTransfer = (
  data: ChunkValidationResult,
  store: IncomingFileChunks,
  setLoginError: (err: string) => void
): boolean => {
  if (!enforceConcurrentLimit(store)) {
    setLoginError('Too many simultaneous file transfers');
    dispatchCanceledEvent({ from: data.from, filename: data.safeFilename, reason: 'concurrency-limit' });
    return false;
  }

  if (data.totalChunks <= 0 || data.totalChunks > MAX_TOTAL_CHUNKS) {
    console.error('[chunk-validation] totalChunks out of bounds:', { totalChunks: data.totalChunks, filename: data.safeFilename });
    setLoginError('File transfer rejected (invalid metadata)');
    return false;
  }

  if (!Number.isFinite(data.fileSize) || data.fileSize < 0 || data.fileSize > MAX_FILE_SIZE_BYTES) {
    console.error('[chunk-validation] fileSize invalid:', { fileSize: data.fileSize, filename: data.safeFilename });
    setLoginError('File too large or invalid');
    return false;
  }

  if (!Number.isFinite(data.chunkSize) || data.chunkSize <= 0 || data.chunkSize > MAX_CHUNK_SIZE_BYTES) {
    console.error('[chunk-validation] chunkSize invalid:', { chunkSize: data.chunkSize, filename: data.safeFilename });
    setLoginError('Invalid file transfer metadata');
    return false;
  }

  const expectedMaxBytes = data.chunkSize * data.totalChunks;
  if (expectedMaxBytes > MAX_FILE_SIZE_BYTES * 4) {
    console.error('[chunk-validation] Transfer exceeds safety cap:', { expectedMaxBytes, filename: data.safeFilename });
    setLoginError('File transfer rejected (unsafe size)');
    return false;
  }

  return true;
};

// Create new file entry
export const createFileEntry = (data: ChunkValidationResult): ExtendedFileState => {
  return {
    decryptedChunks: Array(data.totalChunks).fill(null),
    totalChunks: data.totalChunks,
    encryptedAESKey: '',
    filename: data.safeFilename,
    receivedCount: 0,
    fileSize: data.fileSize,
    chunkSize: data.chunkSize,
    startedAt: Date.now(),
    lastUpdated: Date.now(),
    paused: false,
    bytesReceivedApprox: 0,
    receivedSet: new Set<number>(),
    rateBucket: { windowStart: Date.now(), count: 0 },
    safeFilename: data.safeFilename,
    originalFilename: data.safeFilename || 'file.bin',
    messageId: data.messageId,
  };
};

// Validate chunk index bounds
export const isValidChunkIndex = (chunkIndex: number, totalChunks: number): boolean => {
  return chunkIndex >= 0 && chunkIndex < totalChunks;
};
