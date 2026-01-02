export interface RateLimitConfig {
  windowMs: number;
  maxEvents: number;
}

export interface QueuedMessage {
  ciphertext: string;
  nonce: string;
  queuedAt: number;
  expiresAt: number;
}

export interface PersistedQueue {
  version: number;
  messages: QueuedMessage[];
}

export interface StoredSessionKey {
  key: string;
}

export interface BlockedUser {
  username: string;
  blockedAt: number;
}

export interface EncryptedBlockList {
  version: number;
  encryptedData: string;
  salt: string;
  lastUpdated: number;
}

export interface BlockToken {
  tokenHash: string;
  blockerHash: string;
  blockedHash: string;
  expiresAt?: number;
}

export type KeyMaterial = { passphrase?: string; kyberSecret?: Uint8Array };
