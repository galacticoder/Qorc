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

export interface Message {
  id: string;
  content: string;
  sender: string;
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
}

export interface ChatMessageProps {
  message: Message;
  onReply?: (message: Message) => void;
  previousMessage?: Message;
  onDelete?: (message: Message) => void;
  onEdit?: (message: Message) => void;
}
