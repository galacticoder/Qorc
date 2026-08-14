import type { SecureDB } from '../database/secureDB';

// Extended file state for incoming transfers
export interface ExtendedFileState {
  decryptedChunks: Array<Uint8Array | null>;
  totalChunks: number;
  aesKey?: CryptoKey;
  receivedCount: number;
  chunkSize?: number;
  fileSize?: number;
  bytesReceivedApprox?: number;
  receivedSet?: Set<number>;
  rateBucket?: { windowStart: number; count: number };
  safeFilename: string;
  messageId?: string;
  transport: 'websocket' | 'p2p' | 'relay';
  transportAckedIndices?: Set<number>;
  transportAckInFlight?: { chunkIndex: number; ackFor: string };
  transportAckPending?: Map<number, string>;
  transportAckCanceled?: boolean;
  transportAckDurablyCommitted?: boolean;
  persistenceFailureCount?: number;
  persistenceRetryAt?: number;
}

// File chunk payload from sender
export interface FileChunkPayload {
  chunkIndex: number;
  totalChunks: number;
  chunkData: string;
  envelope: Record<string, unknown>;
  filename: string;
  fileSize: number;
  chunkSize: number;
  chunkMac: string;
  isLastChunk: boolean;
  fileId: string;
  fileTransferId: string;
  messageId: string;
  recoveryProbe: boolean;
  type: string;
  from: string;
  to: string;
  timestamp: number;
}

export type FilePreviewKind = 'image' | 'audio' | 'video' | 'voice';

// useFileUrl hook options
export interface UseFileUrlOptions {
  secureDB: SecureDB | null;
  fileId: string | undefined;
  mimeType?: string;
  enabled?: boolean;
  previewKind?: FilePreviewKind;
}

// useFileUrl hook return type
export interface UseFileUrlReturn {
  url: string | null;
  loading: boolean;
  error: string | null;
}
