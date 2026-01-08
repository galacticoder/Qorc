import type { Message } from '../../components/chat/messaging/types';
import type { User } from '../../components/chat/messaging/UserList';

// SecureDB hook props
export interface UseSecureDBProps {
  Authentication: any;
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
}

// SecureDB hook return type
export interface UseSecureDBReturn {
  users: User[];
  setUsers: React.Dispatch<React.SetStateAction<User[]>>;
  dbInitialized: boolean;
  secureDBRef: React.RefObject<any>;
  saveMessageToLocalDB: (message: Message, activeConversationPeer?: string) => Promise<void>;
  loadMoreConversationMessages: (peerUsername: string, currentOffset: number, limit?: number) => Promise<Message[]>;
  flushPendingSaves: () => Promise<void>;
}

// Username display hook props
export interface UseUnifiedUsernameDisplayProps {
  username: string;
  getDisplayUsername?: (username: string) => Promise<string>;
  fallbackToOriginal?: boolean;
  resolveTimeoutMs?: number;
}

// Username display hook return type
export interface UseUnifiedUsernameDisplayReturn {
  displayName: string;
  isLoading: boolean;
  error: string | null;
  retry: () => void;
}

// Username display component props
export interface UsernameDisplayProps {
  username: string;
  getDisplayUsername?: (username: string) => Promise<string>;
  fallbackToOriginal?: boolean;
  className?: string;
  loadingText?: string;
  errorText?: string;
  showRetry?: boolean;
  onRetry?: () => void;
}

// Mapping payload for username mappings
export interface MappingPayload {
  hashed: string;
  original: string;
}

// Resolve cache entry
export interface ResolveCache {
  displayName: string;
  expiresAt: number;
}

// Rate limit bucket
export interface RateLimitBucket {
  windowStart: number;
  count: number;
}

// Key manager types --
export interface EncryptedKeyData {
  bundleCiphertext: string;
  bundleNonce: string;
  bundleTag: string;
  bundleAad: string;
  bundleMac: string;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
  salt: string;
  version: number;
  argon2Params: {
    version: number;
    algorithm: string;
    memoryCost: number;
    timeCost: number;
    parallelism: number;
  };
  createdAt: number;
  expiresAt: number;
  sequence: number;
  payloadSize: number;
}

export interface DecryptedKeys {
  kyber: {
    publicKeyBase64: string;
    secretKey: Uint8Array;
  };
  dilithium: {
    publicKeyBase64: string;
    secretKey: Uint8Array;
  };
  x25519: {
    publicKeyBase64: string;
    private: Uint8Array;
  };
}

// SecureDB --
export interface EphemeralConfig {
  enabled: boolean;
  defaultTTL: number;
  maxTTL: number;
  cleanupInterval: number;
}

export interface EphemeralData {
  data: any;
  createdAt: number;
  expiresAt: number;
  ttl: number;
  autoDelete: boolean;
}

export interface StoredMessage {
  id?: string;
  timestamp?: number;
  [key: string]: unknown;
}

export interface StoredUser {
  id?: string;
  username?: string;
  [key: string]: unknown;
}

export interface ConversationMetadata {
  peerUsername: string;
  lastMessage: StoredMessage;
  unreadCount: number;
  lastReadTimestamp: number;
}

export type PostQuantumAEADLike = {
  encrypt(plaintext: Uint8Array, key: Uint8Array, aad?: Uint8Array, nonce?: Uint8Array): {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    tag: Uint8Array;
  };
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, tag: Uint8Array, key: Uint8Array, aad?: Uint8Array): Uint8Array;
};