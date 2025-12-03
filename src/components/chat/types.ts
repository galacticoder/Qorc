export interface MessageReply {
  id: string;
  sender?: string;
  content?: string;
}

export interface FileInfo {
  name: string;
  type: string;
  size: number;
  data: ArrayBuffer;
}

export interface MessageReceipt {
  delivered: boolean;
  read: boolean;
  deliveredAt?: Date;
  readAt?: Date;
}

export interface TypingIndicator {
  id: string;
  type: 'typing-start' | 'typing-stop';
  fromUsername: string;
  toUsername: string;
  timestamp: number;
  isTypingIndicator: true;
}

export interface Message {
  id: string;
  content: string;
  sender: string;
  recipient?: string;
  timestamp: Date;
  isCurrentUser?: boolean;
  isSystemMessage?: boolean;
  isDeleted?: boolean;
  isEdited?: boolean;
  shouldPersist?: boolean;
  replyTo?: MessageReply;
  fileInfo?: FileInfo;
  filename?: string;
  fileSize?: number;
  type?: string;
  mimeType?: string;
  originalBase64Data?: string;
  receipt?: MessageReceipt;
  p2p?: boolean;
  encrypted?: boolean;
  transport?: 'websocket' | 'p2p' | 'relay';
  version: string;
  envelopeVersion?: string;
  ciphertext?: string;
  nonce?: string;
  tag?: string;
  mac?: string;
  aad?: string;
  kemCiphertext?: string;
  recipientDeviceId?: string;
  senderDeviceId?: string;
  pqContext?: {
    aadLabel?: string;
    timestamp?: number;
    sender?: string;
    recipient?: string;
  };
  reactions?: Record<string, string[]>;
  rateLimitBypass?: boolean;
}

export interface ChatMessageProps {
  message: Message;
  smartReceipt?: MessageReceipt;
  onReply?: (message: Message) => void;
  previousMessage?: Message;
  onDelete?: (message: Message) => void;
  onEdit?: (message: Message) => void;
  onReact?: (message: Message, emoji: string) => void;
  currentUsername?: string;
  secureDB?: any;
}