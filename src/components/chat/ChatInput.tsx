import React, { useState, useRef, useEffect, useCallback } from "react";
import { User } from "./messaging/UserList";
import { SignalType } from "../../lib/types/signal-types";
import { Message } from "./messaging/types";
import { useFileSender } from "./ChatInput/useFileSender";
import { ProgressBar } from "./ChatInput/ProgressBar";
import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";
import { VoiceRecorder } from "./calls/VoiceRecorder";
import { VoiceRecorderButton } from "./ChatInput/VoiceRecorderButton";
import { MessageReply } from "./messaging/types";
import { MAX_FILE_SIZE } from "@/lib/constants";
import { sanitizeMessage } from "@/lib/sanitizers";
import { messageVault } from "@/lib/security/message-vault";

interface HybridKeys {
  x25519: { private: Uint8Array; publicKeyBase64: string };
  kyber: { publicKeyBase64: string; secretKey: Uint8Array };
  dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
}

interface FileData {
  id: string;
  content: string;
  timestamp: Date;
  isCurrentUser: boolean;
  isSystemMessage: boolean;
  type: string;
  filename: string;
  fileSize: number;
  mimeType: string;
  sender: string;
  originalBase64Data: string;
  size?: number;
  url?: string;
}

interface ChatInputProps {
  onSendMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: Message | MessageReply | null) => void;
  onSendFile: (fileData: FileData) => void;
  isEncrypted: boolean;

  currentUsername: string;
  users: ReadonlyArray<User>;
  replyTo?: Message | null;
  onCancelReply?: () => void;
  editingMessage?: Message | null;
  onCancelEdit?: () => void;
  onEditMessage?: (messageId: string, newContent: string) => void;
  onTyping: () => void;
  selectedConversation?: string;
  getDisplayUsername?: (username: string) => Promise<string>;
  disabled?: boolean;
  getKeysOnDemand?: () => Promise<HybridKeys | null>;
  getPeerHybridKeys?: (peerUsername: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>;
}

// Main chat input component for sending messages and files
export function ChatInput({
  onSendMessage,
  onSendFile: _onSendFile,
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
  getKeysOnDemand,
  getPeerHybridKeys,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showVoiceRecorder, setShowVoiceRecorder] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageInputRef = useRef<HTMLInputElement>(null);

  const { sendFile, progress, isSendingFile } = useFileSender(
    currentUsername,
    selectedConversation,
    users,
    getKeysOnDemand,
    getPeerHybridKeys,
  );

  useEffect(() => {
    const loadEditingContent = async () => {
      if (editingMessage) {
        const contentId = editingMessage.secureContentId || editingMessage.id;
        const vaultContent = await messageVault.retrieve(contentId);

        setMessage(vaultContent || "");
        messageInputRef.current?.focus();
      }
    };

    loadEditingContent();
  }, [editingMessage]);

  // Handle sending text messages or edits
  const handleSend = useCallback(() => {
    if (!message.trim() || !selectedConversation || disabled) {
      return;
    }

    const sanitizedMessage = sanitizeMessage(message);
    if (!sanitizedMessage) return;
    setMessage("");

    const isEdit = !!(editingMessage && onEditMessage);
    const sendPromise = isEdit
      ? onSendMessage(editingMessage!.id, sanitizedMessage, SignalType.EDIT_MESSAGE, editingMessage!.replyTo)
      : onSendMessage("", sanitizedMessage, "chat", replyTo ?? null);

    if (isEdit) { onCancelEdit?.(); } else { onCancelReply?.(); }

    Promise.resolve(sendPromise).catch((error) => {
      console.error('Failed to send message:', error);
    });
  }, [message, selectedConversation, disabled, editingMessage, onEditMessage, onSendMessage, onCancelEdit, replyTo, onCancelReply, sanitizeMessage]);

  // Validate file size and type
  const validateFile = useCallback((file: File): string | null => {
    if (file.size > MAX_FILE_SIZE) {
      return 'File is too large. Maximum size is ' + MAX_FILE_SIZE + 'MB.';
    }
    return null;
  }, []);

  // Handle file selection and upload
  const handleFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const validationError = validateFile(file);
    if (validationError) {
      alert(validationError);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      return;
    }

    try {
      setIsSending(true);
      await sendFile(file);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      alert('Failed to send file: ' + errorMessage);
    } finally {
      setIsSending(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  }, [validateFile, sendFile]);

  // Handle sending voice notes as audio files
  const handleSendVoiceNote = useCallback(async (audioBlob: Blob, durationSec: number) => {
    if (!selectedConversation) return;

    try {
      setIsSending(true);

      const timestamp = Date.now();
      
      const seconds = Math.max(1, Math.round(durationSec || 0));
      const filename = `voice-note-${seconds}s-${timestamp}.webm`;
      const file = new File([audioBlob], filename, { type: audioBlob.type || 'audio/webm' });

      const validationError = validateFile(file);
      if (validationError) {
        alert(validationError);
        setIsSending(false);
        setShowVoiceRecorder(false);
        return;
      }

      await sendFile(file);

      setShowVoiceRecorder(false);
    } catch (_error) {
      console.error('Failed to send voice note:', _error);
      const msg = _error instanceof Error ? _error.message : 'Unknown error';
      alert('Failed to send voice note: ' + msg);
    } finally {
      setIsSending(false);
    }
  }, [selectedConversation, validateFile, sendFile]);

  // Handle message input changes and typing indicators
  const handleMessageChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setMessage(e.target.value);
    onTyping();
  }, [onTyping]);

  // Handle keyboard events (Enter to send)
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  return (
    <>
      {progress > 0 && progress < 1 && (
        <div className="qor-chat-progress">
          <ProgressBar progress={progress} />
        </div>
      )}

      <div className="qor-input-shell">
        {editingMessage && <EditingBanner onCancelEdit={onCancelEdit} />}
        {replyTo && <ReplyBanner replyTo={replyTo} onCancelReply={onCancelReply} getDisplayUsername={getDisplayUsername} />}

        {showVoiceRecorder ? (
          <VoiceRecorder
            onSendVoiceNote={handleSendVoiceNote}
            onCancel={() => setShowVoiceRecorder(false)}
            disabled={isSendingFile || isSending}
          />
        ) : (
          <div
            className={`qor-message-box ${editingMessage || replyTo ? 'has-banner' : ''}`}
          >
            {/* File Upload */}
            <div className="qor-file-upload-wrapper">
              <label
                htmlFor="file-input"
                className="qor-composer-icon-btn"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 337 337"
                  aria-hidden="true"
                >
                  <circle
                    strokeWidth={20}
                    stroke="hsl(var(--muted-foreground))"
                    fill="none"
                    r="158.5"
                    cy="168.5"
                    cx="168.5"
                  />
                  <path
                    strokeLinecap="round"
                    strokeWidth={25}
                    stroke="hsl(var(--muted-foreground))"
                    d="M167.759 79V259"
                  />
                  <path
                    strokeLinecap="round"
                    strokeWidth={25}
                    stroke="hsl(var(--muted-foreground))"
                    d="M79 167.138H259"
                  />
                </svg>
              </label>
              <input
                ref={fileInputRef}
                type={SignalType.FILE}
                id="file-input"
                style={{ display: 'none' }}
                onChange={handleFileChange}
                disabled={disabled || isSendingFile}
              />
            </div>

            {/* Voice Recorder Button */}
            <div className="qor-voice-button-wrap">
              <VoiceRecorderButton
                onClick={() => setShowVoiceRecorder(true)}
                disabled={isSendingFile || isSending || showVoiceRecorder || disabled}
              />
            </div>

            {/* Message Input */}
            <input
              ref={messageInputRef}
              placeholder="Message..."
              type="text"
              id="messageInput"
              value={message}
              onChange={handleMessageChange}
              onKeyDown={handleKeyDown}
              disabled={disabled}
              className="qor-message-input"
            />

            {/* Send Button */}
            <button
              id="sendButton"
              onClick={handleSend}
              disabled={!message.trim() || !selectedConversation || disabled}
              className="qor-send-button"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 664 663"
                style={{ height: '18px', width: '18px' }}
              >
                <path fill="none" d="M646.293 331.888L17.7538 17.6187L155.245 331.888M646.293 331.888L17.753 646.157L155.245 331.888M646.293 331.888L318.735 330.228L155.245 331.888" />
                <path
                  strokeLinejoin="round"
                  strokeLinecap="round"
                  strokeWidth="33.67"
                  stroke={message.trim() ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))'}
                  fill={message.trim() ? 'hsl(var(--primary) / 0.2)' : 'none'}
                  d="M646.293 331.888L17.7538 17.6187L155.245 331.888M646.293 331.888L17.753 646.157L155.245 331.888M646.293 331.888L318.735 330.228L155.245 331.888"
                />
              </svg>
            </button>
          </div>
        )}
      </div>
    </>
  );
}
