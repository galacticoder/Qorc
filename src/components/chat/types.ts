export interface MessageReply {
  id: string;
  sender: string;
  content: string;
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
  mimeType?: string; // MIME type for file messages
  receipt?: MessageReceipt;
  p2p?: boolean; // Indicates if message was sent via P2P
  encrypted?: boolean; // Indicates if message is encrypted
  transport?: 'websocket' | 'p2p' | 'relay'; // Transport method used
}

export interface ChatMessageProps {
  message: Message;
  onReply?: (message: Message) => void;
  previousMessage?: Message;
  onDelete?: (message: Message) => void;
  onEdit?: (newContent: string) => void;
}
