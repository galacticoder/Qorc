import type { Message, MessageReceipt, MessageReply } from '../../components/chat/messaging/types';
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
  initialDataLoaded: boolean;
  dbInitError: string | null;
  retryInitializeDB: () => void;
  secureDBRef: React.RefObject<any>;
  saveMessageToLocalDB: (message: Message, activeConversationPeer?: string) => Promise<void>;
  loadMoreConversationMessages: (peerUsername: string, currentOffset: number, limit?: number) => Promise<Message[]>;
  hydratePreloadedConversationMessages: (peerUsername: string) => number;
  discardPreloadedConversationMessages: (peerUsername: string) => void;
  flushPendingSaves: () => Promise<void>;
}

// SecureDB
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
  wireMessageId?: string;
  timestamp?: number;
  content?: string;
  secureContentId?: string;
  sender?: string;
  recipient?: string;
  isDeliberateUserAction?: true;
  replyTo?: MessageReply;
  receipt?: MessageReceipt;
  [key: string]: unknown;
}

export type StoredUser = User;

export interface ConversationMetadata {
  peerUsername: string;
  lastMessage: StoredMessage;
  lastReadTimestamp: number;
  firstSegment: number;
  lastSegment: number;
  isPinned?: boolean;
  pinnedAt?: number;
}
