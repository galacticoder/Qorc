import {
  sanitizeFilename,
  isPlainObject,
  hasPrototypePollutionKeys,
  hasExactKeys,
  isCanonicalAuthUsername,
  sanitizeMessageId,
} from "../../lib/sanitizers";
import {
  MAX_TOTAL_CHUNKS,
  MAX_FILE_SIZE_BYTES,
  MAX_CHUNK_SIZE_BYTES,
} from "../../lib/constants";
import { enforceConcurrentLimit, dispatchCanceledEvent } from "../../lib/utils/file-utils";
import type { FileChunkPayload, ExtendedFileState } from "../../lib/types/file-types";

export interface ChunkValidationResult {
  from: string;
  toUser?: string;
  safeFilename: string;
  fileKey: string;
  chunkIndex: number;
  totalChunks: number;
  chunkData: string;
  envelope?: any;
  messageId?: string;
  transportMessageId?: string;
  fileSize: number;
  chunkSize: number;
  chunkMac: string;
  recoveryProbe: boolean;
  transport: NonNullable<ExtendedFileState['transport']>;
}

export type NewTransferValidation = 'valid' | 'busy' | 'invalid';

const FILE_CHUNK_KEYS = [
  'chunkData',
  'chunkIndex',
  'chunkMac',
  'chunkSize',
  'envelope',
  'fileId',
  'fileSize',
  'fileTransferId',
  'filename',
  'from',
  'isLastChunk',
  'messageId',
  'recoveryProbe',
  'timestamp',
  'to',
  'totalChunks',
  'type',
] as const;

// Validate incoming payload structure
export const validatePayload = (payload: any): payload is FileChunkPayload => {
  if (!isPlainObject(payload) || hasPrototypePollutionKeys(payload)) {
    return false;
  }
  if (!hasExactKeys(payload, FILE_CHUNK_KEYS)) return false;
  const { chunkIndex, totalChunks, chunkData } = payload;
  return typeof chunkIndex === 'number' && Number.isSafeInteger(chunkIndex) &&
    typeof totalChunks === 'number' && Number.isSafeInteger(totalChunks) &&
    typeof chunkData === 'string' &&
    chunkData.length > 0 &&
    typeof payload.messageId === 'string' &&
    typeof payload.fileId === 'string' &&
    payload.fileTransferId === payload.fileId &&
    typeof payload.filename === 'string' &&
    payload.filename.length > 0 &&
    payload.filename.length <= 128 &&
    sanitizeFilename(payload.filename, 128) === payload.filename &&
    typeof payload.fileSize === 'number' &&
    typeof payload.chunkSize === 'number' &&
    typeof payload.chunkMac === 'string' &&
    payload.chunkMac.length === 44 &&
    /^[A-Za-z0-9+/]{43}=$/.test(payload.chunkMac) &&
    typeof payload.isLastChunk === 'boolean' &&
    payload.isLastChunk === (chunkIndex === totalChunks - 1) &&
    typeof payload.recoveryProbe === 'boolean' &&
    (!payload.recoveryProbe || chunkIndex === 0) &&
    payload.type === 'file-message-chunk' &&
    isCanonicalAuthUsername(payload.from) &&
    isCanonicalAuthUsername(payload.to) &&
    typeof payload.timestamp === 'number' && Number.isSafeInteger(payload.timestamp) &&
    payload.timestamp > 0 &&
    isPlainObject(payload.envelope) &&
    !hasPrototypePollutionKeys(payload.envelope);
};

// Extract and sanitize chunk data from payload
export const extractChunkData = (payload: any, message: any): ChunkValidationResult | null => {
  if (!validatePayload(payload)) {
    return null;
  }

  const { chunkIndex, totalChunks, chunkData, envelope, filename, fileId, messageId, chunkMac, recoveryProbe } = payload as FileChunkPayload;
  const from = isCanonicalAuthUsername(message?.from) ? message.from : '';
  const rawTo = (message as any)?.to;
  const toUser = isCanonicalAuthUsername(rawTo) ? rawTo : undefined;
  if (!from || !toUser || payload.from !== from || payload.to !== toUser) return null;
  const safeFilename = sanitizeFilename(filename);
  const safeMessageId = sanitizeMessageId(fileId);
  const transportMessageId = sanitizeMessageId(message?.transportMessageId);
  const transport = message?.transport;
  const payloadTransportMessageId = sanitizeMessageId(messageId);
  if (
    !safeMessageId ||
    !chunkMac ||
    !transportMessageId ||
    transportMessageId !== payloadTransportMessageId ||
    messageId !== `${safeMessageId}:chunk:${chunkIndex}` ||
    (transport !== 'websocket' && transport !== 'p2p' && transport !== 'relay')
  ) return null;
  const fileKey = `${from}\0${safeMessageId}`;

  return {
    from,
    toUser,
    safeFilename,
    fileKey,
    chunkIndex,
    totalChunks,
    chunkData,
    envelope,
    messageId: safeMessageId,
    transportMessageId,
    fileSize: payload.fileSize!,
    chunkSize: payload.chunkSize!,
    chunkMac,
    recoveryProbe,
    transport,
  };
};

// Validate new transfer metadata
export const validateNewTransfer = (
  data: ChunkValidationResult,
  store: Record<string, ExtendedFileState>,
  setLoginError: (err: string) => void
): NewTransferValidation => {
  if (!enforceConcurrentLimit(store, data.from)) {
    setLoginError('Too many simultaneous file transfers');
    dispatchCanceledEvent({ from: data.from, filename: data.safeFilename, reason: 'concurrency-limit' });
    return 'busy';
  }

  if (!Number.isInteger(data.totalChunks) || data.totalChunks <= 0 || data.totalChunks > MAX_TOTAL_CHUNKS) {
    console.error('[chunk-validation] totalChunks out of bounds');
    setLoginError('File transfer rejected (invalid metadata)');
    return 'invalid';
  }

  if (!Number.isInteger(data.fileSize) || data.fileSize <= 0 || data.fileSize > MAX_FILE_SIZE_BYTES) {
    console.error('[chunk-validation] fileSize invalid');
    setLoginError('File too large or invalid');
    return 'invalid';
  }

  if (!Number.isInteger(data.chunkSize) || data.chunkSize <= 0 || data.chunkSize > MAX_CHUNK_SIZE_BYTES) {
    console.error('[chunk-validation] chunkSize invalid');
    setLoginError('Invalid file transfer metadata');
    return 'invalid';
  }
  
  const expectedMaxBytes = data.chunkSize * data.totalChunks;
  if (expectedMaxBytes > MAX_FILE_SIZE_BYTES + MAX_CHUNK_SIZE_BYTES) {
    console.error('[chunk-validation] transfer exceeds safety cap');
    setLoginError('File transfer rejected (unsafe size)');
    return 'invalid';
  }

  if (data.totalChunks !== Math.ceil(data.fileSize / data.chunkSize)) {
    setLoginError('File transfer rejected (inconsistent metadata)');
    return 'invalid';
  }

  return 'valid';
};

// Create new file entry
export const createFileEntry = (data: ChunkValidationResult): ExtendedFileState => {
  return {
    decryptedChunks: Array(data.totalChunks).fill(null),
    totalChunks: data.totalChunks,
    receivedCount: 0,
    fileSize: data.fileSize,
    chunkSize: data.chunkSize,
    bytesReceivedApprox: 0,
    receivedSet: new Set<number>(),
    rateBucket: { windowStart: Date.now(), count: 0 },
    safeFilename: data.safeFilename,
    messageId: data.messageId,
    transport: data.transport,
  };
};

// Validate chunk index bounds
export const isValidChunkIndex = (chunkIndex: number, totalChunks: number): boolean => {
  return Number.isInteger(chunkIndex) && Number.isInteger(totalChunks) && chunkIndex >= 0 && chunkIndex < totalChunks;
};
