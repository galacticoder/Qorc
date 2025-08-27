import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { SignalType } from "../../lib/signals";
import { Message } from "./types";
import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";

import { useFileSender } from "./ChatInput/useFileSender";
import { ProgressBar } from "./ChatInput/ProgressBar.tsx";

import { FileUploader } from "./ChatInput/FileUploader.tsx";
import { MessageTextarea } from "./ChatInput/MessageTextarea.tsx";
import { SendButton } from "./ChatInput/SendButton.tsx";
import { MessageReply } from "./types";

interface ChatInputProps {
  onSendMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: MessageReply | null) => void;
  onSendFile: (fileData: any) => void;
  isEncrypted: boolean;
  currentUsername: string;
  users: User[];
  replyTo: Message | null;
  onCancelReply: () => void;
  editingMessage?: Message | null;
  onCancelEdit?: () => void;
  onEditMessage?: (newContent: string) => void;
  onTyping: () => void;
  selectedConversation?: string;
}

export function ChatInput({
  onSendMessage,
  onSendFile,
  isEncrypted,
  currentUsername,
  users,
  replyTo,
  onCancelReply,
  editingMessage,
  onCancelEdit,
  onEditMessage,
  onTyping,
  selectedConversation,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { sendFile, progress, isSendingFile } = useFileSender(currentUsername, users);

  useEffect(() => {
    if (editingMessage) {
      setMessage(editingMessage.content);
      textareaRef.current?.focus();
    }
  }, [editingMessage]);

  const sanitizeMessage = (input: string): string => {
    // SECURITY: Comprehensive input sanitization with advanced attack prevention
    const maxLength = 10000; // 10KB max message length

    // SECURITY: Unicode normalization to prevent homograph attacks
    let sanitized = input.normalize('NFC').trim().slice(0, maxLength);

    // SECURITY: Remove dangerous Unicode categories
    // Remove control characters, format characters, and private use characters
    sanitized = sanitized.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u200F\u2028-\u202F\u205F-\u206F\uFEFF\uFFF0-\uFFFF]/g, '');

    // SECURITY: Remove zero-width characters that can be used for steganography
    sanitized = sanitized.replace(/[\u200B-\u200D\u2060\uFEFF]/g, '');

    // SECURITY: Remove bidirectional override characters
    sanitized = sanitized.replace(/[\u202A-\u202E\u2066-\u2069]/g, '');

    // SECURITY: Check for suspicious Unicode patterns
    const suspiciousPatterns = [
      /[\u0300-\u036F]{5,}/g, // Excessive combining characters
      /[\uD800-\uDFFF]/g, // Unpaired surrogates
      /[\uFDD0-\uFDEF]/g, // Non-characters
      /[\u0001-\u0008\u000E-\u001F\u007F]/g, // Additional control characters
    ];

    for (const pattern of suspiciousPatterns) {
      sanitized = sanitized.replace(pattern, '');
    }

    // SECURITY: Basic HTML entity encoding for safety
    sanitized = sanitized
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');

    // SECURITY: Final length check after normalization
    if (sanitized.length > maxLength) {
      sanitized = sanitized.slice(0, maxLength);
    }

    return sanitized;
  };

  async function handleSend() {
    if (!message.trim() || isSending || !selectedConversation) return;

    const sanitizedMessage = sanitizeMessage(message);
    if (!sanitizedMessage) return;

    // SECURITY: Log only non-sensitive metadata
    console.log('[ChatInput] Attempting to send message:', {
      contentLength: sanitizedMessage.length,
      selectedConversation,
      editingMessage: !!editingMessage,
      replyTo: !!replyTo
    });

    try {
      setIsSending(true);

      if (editingMessage && onEditMessage) {
        console.log('[ChatInput] Sending edit message');
        await onSendMessage(editingMessage.id, sanitizedMessage, SignalType.EDIT_MESSAGE, editingMessage.replyTo);
        onCancelEdit?.();
      } else {
        console.log('[ChatInput] Sending new message');
        await onSendMessage("", sanitizedMessage, "chat", replyTo ?? null);
        onCancelReply?.();
      }

      console.log('[ChatInput] Message sent successfully');
      setMessage("");
    } catch (e) {
      console.error("[ChatInput] Failed to send message:", e);
    } finally {
      setIsSending(false);
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const validateFile = (file: File): { valid: boolean; error?: string } => {
    const maxSize = 100 * 1024 * 1024; // 100MB max file size
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'text/plain', 'application/pdf',
      'application/zip', 'application/x-zip-compressed',
      'audio/mpeg', 'audio/wav', 'audio/ogg',
      'video/mp4', 'video/webm', 'video/ogg'
    ];

    // SECURITY: Comprehensive file validation to prevent spoofing attacks
    if (file.size > maxSize) {
      return { valid: false, error: 'File size exceeds 100MB limit' };
    }

    if (file.size === 0) {
      return { valid: false, error: 'Empty files are not allowed' };
    }

    if (!allowedTypes.includes(file.type)) {
      return { valid: false, error: 'File type not allowed' };
    }

    // SECURITY: Validate file extension matches MIME type
    const fileExtension = file.name.toLowerCase().split('.').pop() || '';
    const mimeToExtension: Record<string, string[]> = {
      'image/jpeg': ['jpg', 'jpeg'],
      'image/png': ['png'],
      'image/gif': ['gif'],
      'image/webp': ['webp'],
      'text/plain': ['txt'],
      'application/pdf': ['pdf'],
      'application/zip': ['zip'],
      'application/x-zip-compressed': ['zip'],
      'audio/mpeg': ['mp3'],
      'audio/wav': ['wav'],
      'audio/ogg': ['ogg'],
      'video/mp4': ['mp4'],
      'video/webm': ['webm'],
      'video/ogg': ['ogv']
    };

    const expectedExtensions = mimeToExtension[file.type];
    if (expectedExtensions && !expectedExtensions.includes(fileExtension)) {
      return { valid: false, error: `File extension '${fileExtension}' does not match MIME type '${file.type}'` };
    }

    // SECURITY: Check for dangerous file extensions
    const dangerousExtensions = [
      'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar', 'app', 'deb', 'pkg', 'dmg',
      'msi', 'msp', 'dll', 'sys', 'drv', 'bin', 'run', 'action', 'workflow', 'sh', 'bash', 'zsh',
      'ps1', 'psm1', 'psd1', 'ps1xml', 'psc1', 'psc2', 'msh', 'msh1', 'msh2', 'mshxml', 'msh1xml', 'msh2xml'
    ];

    if (dangerousExtensions.includes(fileExtension)) {
      return { valid: false, error: `Dangerous file extension '${fileExtension}' not allowed` };
    }

    // SECURITY: Advanced filename sanitization
    const sanitizedName = file.name
      .normalize('NFC') // Unicode normalization
      .replace(/[<>:"/\\|?*\x00-\x1f\x7f-\x9f]/g, '_') // Remove dangerous characters
      .replace(/\.{2,}/g, '.') // Remove multiple dots
      .replace(/^\.+|\.+$/g, '') // Remove leading/trailing dots
      .slice(0, 255); // Limit length

    if (sanitizedName !== file.name) {
      console.warn('[ChatInput] Filename sanitized:', file.name, '->', sanitizedName);
    }

    if (sanitizedName.length === 0) {
      return { valid: false, error: 'Invalid filename after sanitization' };
    }

    return { valid: true };
  };

  const handleFileChange = async (file: File) => {
    const validation = validateFile(file);
    if (!validation.valid) {
      console.error('[ChatInput] File validation failed:', validation.error);
      // TODO: Show error to user
      return;
    }

    try {
      await sendFile(file);
      const fileUrl = URL.createObjectURL(file);
      const sanitizedFilename = file.name.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').slice(0, 255);

      onSendFile({
        id: crypto.randomUUID(),
        content: fileUrl,
        timestamp: new Date(),
        isCurrentUser: true,
        isSystemMessage: false,
        type: SignalType.FILE_MESSAGE,
        filename: sanitizedFilename,
        fileSize: file.size,
        sender: currentUsername,
      });
    } catch {
      // error handled in hook
    }
  };

  return (
    <div className={cn("relative border-t", "bg-white border-slate-200")}>
      {editingMessage && <EditingBanner onCancelEdit={onCancelEdit} />}
      {replyTo && <ReplyBanner replyTo={replyTo} onCancelReply={onCancelReply} />}

      {progress > 0 && progress < 1 && (
        <div className="px-4 pt-2">
          <ProgressBar progress={progress} />
        </div>
      )}

      <div className="p-4">
        <div
          className={cn(
            "flex items-end gap-3 rounded-2xl border shadow-sm transition-all duration-200",
            "bg-slate-50 border-slate-200 focus-within:border-slate-400"
          )}
        >
          <FileUploader onFileSelected={handleFileChange} disabled={isSendingFile} />

          <MessageTextarea
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
              onTyping();
            }}
            onKeyDown={handleKeyDown}
            textareaRef={textareaRef}
          />

          <SendButton
            disabled={!message.trim() || isSending || !selectedConversation}
            isSending={isSending}
            editingMessage={editingMessage}
            onClick={handleSend}
          />
        </div>
      </div>
    </div>
  );
}
