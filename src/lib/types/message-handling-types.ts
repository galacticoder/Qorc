import type { Message } from '../../components/chat/messaging/types';

// Rate limiting state
export interface RateState {
  windowStart: number;
  count: number;
}

// Pending retry message entry
export interface PendingRetryEntry {
  message: any;
  timestamp: number;
  retryCount: number;
}

// Failed delivery receipt entry
export interface FailedDeliveryReceipt {
  messageId: string;
  peerUsername: string;
  timestamp: number;
  attempts: number;
}

// Attempts ledger entry for retry tracking
export interface AttemptsLedgerEntry {
  attempts: number;
  lastTriedKyberFp: string | null;
  nextAt: number;
}

// Reset counter entry
export interface ResetCounterEntry {
  count: number;
  windowStart: number;
}

// Hybrid keys structure
export interface HybridKeys {
  kyberPublicBase64?: string;
  dilithiumPublicBase64?: string;
  x25519PublicBase64?: string;
}

// Resolved sender keys result
export interface ResolvedSenderKeys {
  kyber: string | null;
  hybrid: HybridKeys | null;
  retried: boolean;
}

// Encrypted message envelope
export interface EncryptedEnvelope {
  kemCiphertext?: string;
  ciphertext?: string;
  chunkData?: string;
  [key: string]: unknown;
}

// Decryption result
export interface DecryptResult {
  success: boolean;
  plaintext?: string;
  error?: string;
  code?: string;
  requiresKeyRefresh?: boolean;
  sessionInfo?: unknown;
}

// Encryption result
export interface EncryptResult {
  success: boolean;
  encryptedPayload?: unknown;
  error?: string;
}

// Local message handler props
export interface LocalMessageHandlerProps {
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  saveMessageWithContext: (message: Message) => Promise<any> | void;
  secureDBRef: React.RefObject<any>;
  allowEvent: (eventType: string) => boolean;
}

// Encrypted message handler options
export interface EncryptedMessageHandlerOptions {
  rateLimit?: {
    windowMs?: number;
    max?: number;
  };
}

// User with hybrid keys
export interface UserWithHybridKeys {
  username: string;
  hybridPublicKeys?: HybridKeys;
  [key: string]: unknown;
}
