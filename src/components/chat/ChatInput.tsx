import React, { useState, useRef, useEffect, useCallback } from "react";
import { User } from "./messaging/UserList";
import { SignalType } from "../../lib/signal-types";
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

interface HybridKeys {
  x25519: { private: Uint8Array; publicKeyBase64: string };
  kyber: { publicKeyBase64: string; secretKey: Uint8Array };
  dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
}

interface P2PConnector {
  connectToPeer?: (peer: string) => Promise<void>;
  getConnectedPeers?: () => string[];
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
  p2pConnector?: P2PConnector;
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
  p2pConnector,
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
    p2pConnector,
    getKeysOnDemand,
    getPeerHybridKeys,
  );

  useEffect(() => {
    if (editingMessage) {
      setMessage(editingMessage.content);
      messageInputRef.current?.focus();
    }
  }, [editingMessage]);

  // Handle sending text messages or edits
  const handleSend = useCallback(async () => {
    if (!message.trim() || isSending || !selectedConversation || disabled) {
      return;
    }

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
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message. Please try again.');
    } finally {
      setIsSending(false);
    }
  }, [message, isSending, selectedConversation, disabled, editingMessage, onEditMessage, onSendMessage, onCancelEdit, replyTo, onCancelReply, sanitizeMessage]);

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
  const handleSendVoiceNote = useCallback(async (audioBlob: Blob) => {
    if (!selectedConversation) return;

    try {
      setIsSending(true);

      const timestamp = Date.now();
      const filename = `voice-note-${timestamp}.webm`;
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
        <div className="px-4 pt-2">
          <ProgressBar progress={progress} />
        </div>
      )}

      <div className="px-4 py-3">
        {editingMessage && <EditingBanner onCancelEdit={onCancelEdit} />}
        {replyTo && <ReplyBanner replyTo={replyTo} onCancelReply={onCancelReply} getDisplayUsername={getDisplayUsername} />}

        {showVoiceRecorder ? (
          <VoiceRecorder
            onSendVoiceNote={handleSendVoiceNote}
            onCancel={() => setShowVoiceRecorder(false)}
            disabled={isSending || isSendingFile}
          />
        ) : (
          <div
            className="messageBox"
            style={{
              width: '100%',
              height: '40px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              backgroundColor: "var(--chat-background)",
              padding: '0 15px',
              borderRadius: editingMessage || replyTo ? '0 0 10px 10px' : '10px',
              border: '1px solid hsl(var(--border))',
              borderTop: editingMessage || replyTo ? 'none' : '1px solid hsl(var(--border))',
              minWidth: 0,
              userSelect: 'none',
            }}
          >
            {/* File Upload */}
            <div
              className="fileUploadWrapper"
              style={{
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <label
                htmlFor="file-input"
                style={{
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 337 337"
                  style={{ height: '18px', width: '20px' }}
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
            <div style={{ flexShrink: 0 }}>
              <VoiceRecorderButton
                onClick={() => setShowVoiceRecorder(true)}
                disabled={isSendingFile || showVoiceRecorder || disabled}
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
              style={{
                flex: 1,
                minWidth: 0,
                height: '100%',
                backgroundColor: 'transparent',
                outline: 'none',
                border: 'none',
                color: 'hsl(var(--foreground))',
                userSelect: 'text',
              }}
            />

            {/* Send Button */}
            <button
              id="sendButton"
              onClick={handleSend}
              disabled={!message.trim() || isSending || !selectedConversation || disabled}
              style={{
                flexShrink: 0,
                width: 'fit-content',
                height: '100%',
                backgroundColor: 'transparent',
                outline: 'none',
                border: 'none',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: disabled || !message.trim() ? 'not-allowed' : 'pointer',
                opacity: disabled || !message.trim() ? 0.5 : 1,
              }}
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