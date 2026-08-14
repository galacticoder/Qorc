export interface MessageReply {
  id: string;
  sender?: string;
  content?: string;
  secureContentId?: string;
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
  sending?: boolean;
  deliveredAt?: Date;
  readAt?: Date;
}

export interface Message {
  id: string;
  wireMessageId?: string;
  content: string;
  secureContentId?: string;
  sender: string;
  recipient?: string;
  timestamp: Date;
  isCurrentUser?: boolean;
  isDeliberateUserAction?: true;
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
  receipt?: MessageReceipt;
  p2p?: boolean;
  encrypted?: boolean;
  transport?: 'websocket' | 'p2p' | 'relay';
  reactions?: Record<string, string[]>;
  controlState?: {
    editOperationId?: string;
    deleteOperationId?: string;
    reactionOperations?: Array<{ actor: string; operationId: string }>;
  };
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
  onReplyClick?: (replyId: string) => void;
  currentUsername?: string;
  secureDB?: any;
}
