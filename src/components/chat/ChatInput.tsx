import React, { useState, useRef, useEffect, useLayoutEffect, useCallback } from "react";
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
import { MAX_FILE_SIZE, MAX_VOICE_NOTE_DURATION_SECONDS } from "@/lib/constants";
import { sanitizeMessage } from "@/lib/sanitizers";
import type { HybridKeys } from "@/lib/types/auth-types";
import type { HybridPublicKeys } from '@/lib/types/message-sending-types';
import { toast } from "sonner";

interface ChatInputProps {
  onSendMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: Message | MessageReply | null) => void;
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
  getPeerHybridKeys?: (peerUsername: string) => Promise<HybridPublicKeys | null>;
  findUser?: (handle: string) => Promise<any>;
  secureDB?: any;
  ensurePeerSession?: (peerUsername: string) => Promise<void>;
}

// Main chat input component for sending messages and files
export function ChatInput({
  onSendMessage,
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
  findUser,
  secureDB,
  ensurePeerSession,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showVoiceRecorder, setShowVoiceRecorder] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageInputRef = useRef<HTMLInputElement>(null);
  const editingMessageIdRef = useRef<string | null>(null);

  const { sendFile, progress, isSendingFile, fileSendPhase, cancelCurrent } = useFileSender(
    currentUsername,
    selectedConversation,
    users,
    getKeysOnDemand,
    getPeerHybridKeys,
    findUser,
    secureDB,
    ensurePeerSession,
  );

  useEffect(() => {
    if (!editingMessage) {
      if (editingMessageIdRef.current) setMessage("");
      editingMessageIdRef.current = null;
      return;
    }

    editingMessageIdRef.current = editingMessage.id;
    setMessage("");
    messageInputRef.current?.focus();
  }, [editingMessage, selectedConversation, currentUsername]);

  useLayoutEffect(() => {
    editingMessageIdRef.current = null;
    setMessage("");
    setShowVoiceRecorder(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, [selectedConversation, currentUsername]);

  // Handle sending text messages or edits
  const handleSend = useCallback(() => {
    if (!message.trim() || !selectedConversation || disabled) {
      return;
    }

    const sanitizedMessage = sanitizeMessage(message);
    if (!sanitizedMessage) return;
    setMessage("");

    const isEdit = !!(editingMessage && onEditMessage);
    const outboundReply = replyTo
      ? { ...replyTo, id: replyTo.wireMessageId || replyTo.id }
      : null;
    const sendPromise = isEdit
      ? onSendMessage(
          editingMessage!.wireMessageId || editingMessage!.id,
          sanitizedMessage,
          SignalType.EDIT_MESSAGE,
          editingMessage!.replyTo,
        )
      : onSendMessage("", sanitizedMessage, SignalType.MESSAGE, outboundReply);

    if (isEdit) { onCancelEdit?.(); } else { onCancelReply?.(); }

    Promise.resolve(sendPromise).catch((error) => {
      console.error('Failed to send message:', error);
    });
  }, [message, selectedConversation, disabled, editingMessage, onEditMessage, onSendMessage, onCancelEdit, replyTo, onCancelReply, sanitizeMessage]);

  // Validate file size and type
  const validateFile = useCallback((file: File): string | null => {
    if (file.size === 0) {
      return 'File is empty.';
    }
    if (file.size > MAX_FILE_SIZE) {
      return 'File is too large. Maximum size is ' + Math.floor(MAX_FILE_SIZE / (1024 * 1024)) + ' MB.';
    }
    return null;
  }, []);

  // Handle file selection and upload
  const handleFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const validationError = validateFile(file);
    if (validationError) {
      toast.error(validationError);
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
      toast.error('Failed to send file: ' + errorMessage);
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
      const seconds = Math.round(durationSec);
      if (
        !Number.isSafeInteger(seconds) ||
        seconds < 1 ||
        seconds > MAX_VOICE_NOTE_DURATION_SECONDS
      ) {
        throw new Error('Voice note duration is invalid');
      }

      const mimeType = audioBlob.type.split(';', 1)[0].trim().toLowerCase();
      const extensionByMime: Readonly<Record<string, string>> = {
        'audio/webm': 'webm',
        'audio/ogg': 'ogg',
        'audio/mp4': 'm4a',
        'audio/mpeg': 'mp3',
      };
      const extension = extensionByMime[mimeType];
      if (!extension) throw new Error('Voice note format is unsupported');

      const filename = `voice-note-${seconds}s-${timestamp}.${extension}`;
      const file = new File([audioBlob], filename, { type: mimeType });

      const validationError = validateFile(file);
      if (validationError) {
        toast.error(validationError);
        setIsSending(false);
        setShowVoiceRecorder(false);
        return;
      }

      await sendFile(file);

      setShowVoiceRecorder(false);
    } catch (_error) {
      console.error('Failed to send voice note:', _error);
      const msg = _error instanceof Error ? _error.message : 'Unknown error';
      toast.error('Failed to send voice note: ' + msg);
    } finally {
      setIsSending(false);
    }
  }, [selectedConversation, validateFile, sendFile]);

  // Handle message input changes and typing indicators
  const handleMessageChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setMessage(e.target.value);
    onTyping();
  }, [onTyping]);

  // Handle keyboard events
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  return (
    <>
      {isSendingFile && (
        <div className="qor-chat-progress" role="status" aria-live="polite">
          <div className="qor-chat-progress-label">
            <span>{fileSendPhase === 'preparing' ? 'Preparing encrypted file…' : 'Sending file…'}</span>
            <div className="qor-chat-progress-right">
              {fileSendPhase === 'sending' && progress > 0 && (
                <span>{Math.round(Math.max(0, Math.min(1, progress)) * 100)}%</span>
              )}
              <button
                type="button"
                className="qor-chat-progress-cancel"
                onClick={() => cancelCurrent()}
                aria-label="Cancel file transfer"
              >
                Cancel
              </button>
            </div>
          </div>
          <ProgressBar
            progress={progress}
            indeterminate={fileSendPhase !== 'sending' || progress <= 0}
          />
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
              placeholder={editingMessage ? "Type the complete replacement message…" : "Message..."}
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
