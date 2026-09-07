import { Message } from '../../components/chat/messaging/types';

// Receipt event detail for message delivery/read receipts
export interface ReceiptEventDetail {
  account: string;
  messageId: string;
  from: string;
}

// Hybrid public keys structure
export interface HybridPublicKeys {
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
}

// User with hybrid keys
export interface UserWithKeys {
  username: string;
  hybridPublicKeys?: HybridPublicKeys;
  peerCertificateFingerprint?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
}

// Pending retry message structure
export interface PendingRetryMessage {
  user: UserWithKeys;
  content: string;
  replyTo?: string | { id: string; sender?: string; content?: string };
  messageSignalType: string;
  retryId: string;
  originalMessageId: string;
  editMessageId?: string;
  retryCount: number;
  queuedAt: number;
}

// Receipt pending info
export interface PendingReceiptInfo {
  messageId: string;
  kind: 'delivered' | 'read';
  addedAt: number;
  attempts: number;
  /** Peer that sent the receipt — must be the recipient of the target message. */
  from: string;
}

// Rate limit bucket
export interface RateLimitBucket {
  windowStart: number;
  count: number;
}

// ID cache interface
export interface IdCache {
  add(id: string): void;
  isStale(id: string): boolean;
}

// Session API interface
export interface SessionApi {
  hasSession(args: { selfUsername: string; peerUsername: string }): Promise<{ hasSession: boolean }>;
}

// Message receipt updater function type
export type ReceiptUpdater = (receipt: Message['receipt'] | undefined) => Message['receipt'] | undefined;

export interface DbQueuedReceipt {
  messageId: string;
  kind: 'delivered' | 'read';
  from: string;
  addedAt: number;
  attempts: number;
}
