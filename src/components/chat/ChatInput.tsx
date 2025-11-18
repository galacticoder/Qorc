import React, { useState, useRef, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { SignalType } from "../../lib/signal-types";
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

interface HybridKeys {
  readonly x25519: { readonly private: Uint8Array; readonly publicKeyBase64: string };
  readonly kyber: { readonly publicKeyBase64: string; readonly secretKey: Uint8Array };
  readonly dilithium: { readonly publicKeyBase64: string; readonly secretKey: Uint8Array };
}

interface P2PConnector {
  readonly connectToPeer?: (peer: string) => Promise<void>;
  readonly getConnectedPeers?: () => readonly string[];
}

interface FileData {
  readonly id: string;
  readonly content: string;
  readonly timestamp: Date;
  readonly isCurrentUser: boolean;
  readonly isSystemMessage: boolean;
  readonly type: string;
  readonly filename: string;
  readonly fileSize: number;
  readonly mimeType: string;
  readonly sender: string;
  readonly originalBase64Data: string;
  readonly size?: number;
  readonly url?: string;
}

interface ChatInputProps {
  readonly onSendMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: MessageReply | null) => void;
  readonly onSendFile: (fileData: FileData) => void;
  readonly isEncrypted: boolean;
  readonly currentUsername: string;
  readonly users: readonly User[];
  readonly replyTo: Message | null;
  readonly onCancelReply: () => void;
  readonly editingMessage?: Message | null;
  readonly onCancelEdit?: () => void;
  readonly onEditMessage?: (newContent: string) => void;
  readonly onTyping: () => void;
  readonly selectedConversation?: string;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly disabled?: boolean;
  readonly p2pConnector?: P2PConnector;
  readonly getKeysOnDemand?: () => Promise<HybridKeys | null>;
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
  disabled = false,
  p2pConnector,
  getKeysOnDemand,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showVoiceRecorder, setShowVoiceRecorder] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { sendFile, progress, isSendingFile } = useFileSender(
    currentUsername,
    selectedConversation,
    users,
    p2pConnector,
    getKeysOnDemand,
  );

  useEffect(() => {
    if (editingMessage) {
      setMessage(editingMessage.content);
      textareaRef.current?.focus();
    }
  }, [editingMessage]);

  const sanitizeMessage = useCallback((input: string): string => {
    const MAX_LENGTH = 10000;

    let sanitized = input.normalize('NFC').trim();
    if (sanitized.length > MAX_LENGTH) {
      sanitized = sanitized.slice(0, MAX_LENGTH);
    }

    sanitized = sanitized
      .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u2000-\u200F\u2028-\u202F\u205F-\u206F\uFEFF\uFFF0-\uFFFF]/g, '')
      .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '')
      .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
      .replace(/[\u0300-\u036F]{5,}/g, '')
      .replace(/[\uD800-\uDFFF]/g, '')
      .replace(/[\uFDD0-\uFDEF]/g, '')
      .replace(/[\u0001-\u0008\u000E-\u001F\u007F]/g, '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');

    return sanitized;
  }, []);

  const handleSend = useCallback(async () => {
    if (!message.trim() || isSending || !selectedConversation || disabled) return;

    const sanitizedMessage = sanitizeMessage(message);
    if (!sanitizedMessage) return;

    try {
      setIsSending(true);

      if (editingMessage && onEditMessage) {
        await onSendMessage(editingMessage.id, sanitizedMessage, SignalType.EDIT_MESSAGE, editingMessage.replyTo);
        onCancelEdit?.();
      } else {
        await onSendMessage("", sanitizedMessage, "chat", replyTo ?? null);
        onCancelReply?.();
      }

      setMessage("");
    } catch {
    } finally {
      setIsSending(false);
    }
  }, [message, isSending, selectedConversation, disabled, sanitizeMessage, editingMessage, onEditMessage, onSendMessage, onCancelEdit, replyTo, onCancelReply]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  const validateFile = useCallback(async (file: File): Promise<{ valid: boolean; error?: string }> => {
    const MAX_FILE_SIZE = 100 * 1024 * 1024;
    const MAX_FILENAME_LENGTH = 255;

    if (file.size === 0) {
      return { valid: false, error: 'Empty files are not allowed' };
    }

    if (file.size > MAX_FILE_SIZE) {
      return { valid: false, error: `File too large. Maximum size is ${Math.round(MAX_FILE_SIZE / (1024 * 1024))}MB` };
    }

    if (/\x00|[\x01-\x1f\x7f-\x9f]/.test(file.name)) {
      return { valid: false, error: 'Filename contains invalid characters' };
    }

    if (!file.name || file.name.trim().length === 0) {
      return { valid: false, error: 'File must have a valid name' };
    }

    if (file.name.length > MAX_FILENAME_LENGTH) {
      return { valid: false, error: 'Filename too long (maximum 255 characters)' };
    }

    return { valid: true };
  }, []);

  const handleFileChange = useCallback(async (file: File) => {
    const validation = await validateFile(file);
    if (!validation.valid) {
      alert(`File upload failed: ${validation.error}`);
      return;
    }

    try {
      await sendFile(file);
    } catch {
    }
  }, [validateFile, sendFile]);

  const blobToBase64 = useCallback((blob: Blob): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        try {
          const result = reader.result as string;
          const commaIndex = result.indexOf(',');
          resolve(commaIndex >= 0 ? result.substring(commaIndex + 1) : result);
        } catch (_err) {
          reject(_err);
        }
      };
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(blob);
    });
  }, []);

  const handleSendVoiceNote = useCallback(async (audioBlob: Blob) => {
    if (!selectedConversation) return;

    try {
      setIsSending(true);

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `voice-note-${timestamp}.webm`;
      const file = new File([audioBlob], filename, { type: 'audio/webm' });

      const validation = await validateFile(file);
      if (!validation.valid) {
        alert('Voice note too large: ' + validation.error);
        setIsSending(false);
        return;
      }

      try {
        await sendFile(file);
      } catch (_error) {
        const msg = _error instanceof Error ? _error.message : 'Unknown error';
        alert('Failed to send voice note: ' + msg);
        setIsSending(false);
        setShowVoiceRecorder(false);
        return;
      }

      const fileUrl = URL.createObjectURL(file);
      let originalBase64Data: string = '';
      
      try {
        originalBase64Data = await blobToBase64(file);
        if (!originalBase64Data) {
          throw new Error('Empty base64 data produced');
        }
      } catch {
        alert('Failed to process voice note for sending. Please try again.');
        setIsSending(false);
        setShowVoiceRecorder(false);
        return;
      }

      onSendFile({
        id: crypto.randomUUID(),
        content: fileUrl,
        timestamp: new Date(),
        isCurrentUser: true,
        isSystemMessage: false,
        type: 'file-message',
        filename,
        fileSize: file.size,
        mimeType: file.type || 'audio/webm',
        sender: currentUsername,
        originalBase64Data,
        size: file.size,
        url: fileUrl,
      });

      setShowVoiceRecorder(false);
    } catch (_error) {
      const msg = _error instanceof Error ? _error.message : 'Unknown error';
      alert('Failed to send voice note: ' + msg);
    } finally {
      setIsSending(false);
    }
  }, [selectedConversation, validateFile, sendFile, blobToBase64, onSendFile, currentUsername]);

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

      <div className={cn(
        "flex items-center gap-2 px-4 py-3 transition-all duration-200",
        disabled && "opacity-50 pointer-events-none"
      )}>
        <FileUploader onFileSelected={handleFileChange} disabled={isSendingFile || disabled} />

        <VoiceRecorderButton
          onClick={() => setShowVoiceRecorder(true)}
          disabled={isSendingFile || showVoiceRecorder || disabled}
        />

        <MessageTextarea
          value={message}
          onChange={useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
            setMessage(e.target.value);
            onTyping();
          }, [onTyping])}
          onKeyDown={handleKeyDown}
          textareaRef={textareaRef}
          disabled={disabled}
        />

        <SendButton
          disabled={!message.trim() || isSending || !selectedConversation || disabled}
          isSending={isSending}
          editingMessage={editingMessage}
          onClick={handleSend}
        />
      </div>
    </>
  );
}