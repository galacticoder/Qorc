import React, { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { SignalType } from "../../lib/signals";
import { Message } from "./types";
import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";
import { VoiceRecorder } from "./VoiceRecorder";

import { useFileSender } from "./ChatInput/useFileSender";
import { ProgressBar } from "./ChatInput/ProgressBar.tsx";

import { FileUploader } from "./ChatInput/FileUploader.tsx";
import { MessageTextarea } from "./ChatInput/MessageTextarea.tsx";
import { SendButton } from "./ChatInput/SendButton.tsx";
import { VoiceRecorderButton } from "./ChatInput/VoiceRecorderButton.tsx";
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
  getDisplayUsername?: (username: string) => Promise<string>;
}

export function ChatInput({
  onSendMessage,
  onSendFile,

  currentUsername,
  users,
  replyTo,
  onCancelReply,
  editingMessage,
  onCancelEdit,
  onEditMessage,
  onTyping,
  selectedConversation,
  getDisplayUsername,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showVoiceRecorder, setShowVoiceRecorder] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { sendFile, progress, isSendingFile } = useFileSender(currentUsername, selectedConversation, users);

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

  const validateFile = async (file: File): Promise<{ valid: boolean; error?: string }> => {
    // Basic validation - allow any file type

    if (file.size === 0) {
      return { valid: false, error: 'Empty files are not allowed' };
    }

    // Optional: Set a reasonable file size limit (e.g., 100MB)
    const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    if (file.size > MAX_FILE_SIZE) {
      return { valid: false, error: `File too large. Maximum size is ${Math.round(MAX_FILE_SIZE / (1024 * 1024))}MB` };
    }

    // Basic filename sanitization - only reject truly dangerous patterns
    const dangerousPatterns = [
      /\x00/, // Null bytes
      /[\x01-\x1f\x7f-\x9f]/, // Control characters
    ];

    const hasDangerousChars = dangerousPatterns.some(pattern => pattern.test(file.name));
    if (hasDangerousChars) {
      return { valid: false, error: 'Filename contains invalid characters' };
    }

    // Reject files with no name or extension
    if (!file.name || file.name.trim().length === 0) {
      return { valid: false, error: 'File must have a valid name' };
    }

    // Reject files with extremely long names
    if (file.name.length > 255) {
      return { valid: false, error: 'Filename too long (maximum 255 characters)' };
    }

    return { valid: true };
  };

  const handleFileChange = async (file: File) => {
    const validation = await validateFile(file);
    if (!validation.valid) {
      console.error('[ChatInput] File validation failed:', validation.error);
      alert(`File upload failed: ${validation.error}`);
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
        mimeType: file.type,
        sender: currentUsername,
      });
    } catch {
      // error handled in hook
    }
  };

  // Efficiently convert a Blob/File to base64 using FileReader
  const blobToBase64 = (blob: Blob): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        try {
          const result = reader.result as string;
          const commaIndex = result.indexOf(',');
          resolve(commaIndex >= 0 ? result.substring(commaIndex + 1) : result);
        } catch (err) {
          reject(err);
        }
      };
      reader.onerror = () => reject(reader.error);
      try {
        reader.readAsDataURL(blob);
      } catch (err) {
        reject(err);
      }
    });
  };

  const handleSendVoiceNote = async (audioBlob: Blob) => {
    if (!selectedConversation) {
      console.error('[ChatInput] No conversation selected for voice note');
      return;
    }

    try {
      setIsSending(true);

      // Create a file from the audio blob
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `voice-note-${timestamp}.webm`;
      const file = new File([audioBlob], filename, { type: 'audio/webm' });

      // Validate file size using the same validation as regular file uploads
      const validation = await validateFile(file);
      if (!validation.valid) {
        console.error('[ChatInput] Voice note validation failed:', validation.error);
        alert('Voice note too large: ' + validation.error);
        setIsSending(false);
        return;
      }

      console.log('[ChatInput] Sending voice note file:', {
        filename: filename,
        size: file.size,
        type: file.type,
        selectedConversation,
        usersCount: users.length,
        users: users.map(u => u.username)
      });

      try {
        await sendFile(file);
        console.log('[ChatInput] Voice note file sent successfully');
      } catch (error) {
        console.error('[ChatInput] Failed to send voice note:', error);
        alert('Failed to send voice note: ' + (error instanceof Error ? error.message : 'Unknown error'));
        setIsSending(false);
        setShowVoiceRecorder(false);
        return;
      }

      // Add voice note to sender's UI immediately (like regular files)
      const fileUrl = URL.createObjectURL(file);
      console.log('[ChatInput] Created blob URL for voice note:', fileUrl);

      let originalBase64Data: string = '';
      try {
        originalBase64Data = await blobToBase64(file);
        if (!originalBase64Data) {
          throw new Error('Empty base64 data produced');
        }
      } catch (err) {
        console.error('[ChatInput] Failed to convert voice note to base64:', err);
        alert('Failed to process voice note for sending. Please try again.');
        setIsSending(false);
        setShowVoiceRecorder(false);
        return; // Abort sending on failed conversion
      }

      onSendFile({
        id: crypto.randomUUID(),
        content: fileUrl,
        timestamp: new Date(),
        isCurrentUser: true,
        isSystemMessage: false,
        type: 'file-message', // Normalize to file-message for consistent handling
        filename: filename,
        fileSize: file.size,
        mimeType: file.type || 'audio/webm',
        sender: currentUsername,
        originalBase64Data,
      });

      console.log('[ChatInput] Voice note added to UI');

      setShowVoiceRecorder(false);
      console.log('[ChatInput] Voice note sent successfully');
    } catch (error) {
      console.error('[ChatInput] Failed to send voice note:', error);
      alert('Failed to send voice note: ' + (error as Error).message);
    } finally {
      setIsSending(false);
    }
  };

  return (
    <>
      {editingMessage && <EditingBanner onCancelEdit={onCancelEdit} />}
      {replyTo && <ReplyBanner replyTo={replyTo} onCancelReply={onCancelReply} getDisplayUsername={getDisplayUsername} />}

      {progress > 0 && progress < 1 && (
        <div className="px-4 pt-2">
          <ProgressBar progress={progress} />
        </div>
      )}

      {showVoiceRecorder && (
        <div className="px-4 pt-2">
          <VoiceRecorder
            onSendVoiceNote={handleSendVoiceNote}
            onCancel={() => setShowVoiceRecorder(false)}
            disabled={isSending || isSendingFile}
          />
        </div>
      )}

      <div className="flex items-center gap-2 px-4 py-3 transition-all duration-200">
        <FileUploader onFileSelected={handleFileChange} disabled={isSendingFile} />

        <VoiceRecorderButton
          onClick={() => setShowVoiceRecorder(true)}
          disabled={isSendingFile || showVoiceRecorder}
        />

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
    </>
  );
}