import type { Message } from '../../components/chat/messaging/types';
import type { SecureDB } from '../database/secureDB';

// Extended file state for incoming transfers
export interface ExtendedFileState {
  decryptedChunks: Blob[];
  totalChunks: number;
  encryptedAESKey: string;
  ephemeralX25519Public?: string;
  kyberCiphertext?: string;
  filename: string;
  aesKey?: CryptoKey;
  receivedCount: number;
  chunkSize?: number;
  fileSize?: number;
  startedAt?: number;
  lastUpdated?: number;
  paused?: boolean;
  bytesReceivedApprox?: number;
  receivedSet?: Set<number>;
  rateBucket?: { windowStart: number; count: number };
  safeFilename: string;
  originalFilename: string;
  messageId?: string;
}

// File chunk payload from sender
export interface FileChunkPayload {
  chunkIndex: number;
  totalChunks: number;
  chunkData: string;
  envelope?: any;
  encryptedAESKey?: string;
  ephemeralX25519Public?: string;
  kyberCiphertext?: string;
  filename?: string;
  fileSize?: number;
  chunkSize?: number;
  chunkMac?: string;
  messageId?: string;
}

// useFileUrl hook options
export interface UseFileUrlOptions {
  secureDB: SecureDB | null;
  fileId: string | undefined;
  mimeType?: string;
  initialUrl?: string;
  originalBase64Data?: string | null;
}

// useFileUrl hook return type
export interface UseFileUrlReturn {
  url: string | null;
  loading: boolean;
  error: string | null;
}

// useFileHandler hook props
export interface UseFileHandlerProps {
  getKeysOnDemand: () => Promise<{
    x25519: { private: any; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>;
  onNewMessage: (message: Message) => void;
  setLoginError: (err: string) => void;
  secureDBRef?: React.RefObject<any | null>;
}

// useFileHandler hook return type
export interface UseFileHandlerReturn {
  handleFileMessageChunk: (payload: any, message: any) => Promise<void>;
  cancelIncomingFile: (from: string, filename: string) => void;
  pauseIncomingFile: (from: string, filename: string) => void;
  resumeIncomingFile: (from: string, filename: string) => void;
  cleanup: () => void;
}

// File content component props
export interface FileContentProps {
  readonly message: Message;
  readonly isCurrentUser: boolean;
  readonly secureDB?: any;
}

// File message component props
export interface FileMessageProps {
  readonly message: Message;
  readonly isCurrentUser?: boolean;
  readonly onReply?: (message: Message) => void;
  readonly onDelete?: (message: Message) => void;
  readonly onEdit?: (message: Message) => void;
  readonly secureDB?: any;
}
