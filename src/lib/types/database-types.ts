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
