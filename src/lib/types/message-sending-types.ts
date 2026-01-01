import React from 'react';
import { Message } from '../../components/chat/messaging/types';

// Receipt event detail for message delivery/read receipts
export interface ReceiptEventDetail {
  messageId: string;
  from: string;
}

// Hybrid public keys structure
export interface HybridPublicKeys {
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64?: string;
}

// User with hybrid keys
export interface UserWithKeys {
  username: string;
  hybridPublicKeys?: HybridPublicKeys;
}

// Signing keys for session establishment
export interface SigningKeys {
  secretKey: Uint8Array;
  publicKeyBase64: string;
}

// Pending retry message structure
export interface PendingRetryMessage {
  user: UserWithKeys;
  content: string;
  replyTo?: string | { id: string; sender?: string; content?: string };
  fileData?: string;
  messageSignalType?: string;
  originalMessageId?: string;
  editMessageId?: string;
  retryCount: number;
}

// Receipt pending info
export interface PendingReceiptInfo {
  kind: 'delivered' | 'read';
  addedAt: number;
  attempts: number;
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
  hasSession(args: { selfUsername: string; peerUsername: string; deviceId: number }): Promise<{ hasSession: boolean }>;
}

// Message receipt updater function type
export type ReceiptUpdater = (receipt: Message['receipt'] | undefined) => Message['receipt'] | undefined;

// Unacknowledged message structure for session reset retry
export interface UnacknowledgedMessage {
  user: UserWithKeys;
  content: string;
  replyTo?: string | { id: string; sender?: string; content?: string };
  fileData?: string;
  messageSignalType?: string;
  originalMessageId?: string;
  editMessageId?: string;
  timestamp: number;
}
