import React, { useState, useRef, useEffect, useLayoutEffect, useCallback } from "react";
import { User } from "./messaging/UserList";
import { SignalType } from "../../lib/types/signal-types";
import { Message } from "./messaging/types";
import { useFileSender } from "./ChatInput/useFileSender";
import type { FileSenderController } from "./ChatInput/useFileSender";
import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";
import { VoiceRecorder } from "./calls/VoiceRecorder";
import { VoiceRecorderButton } from "./ChatInput/VoiceRecorderButton";
import { MessageReply } from "./messaging/types";
import { HEX_PATTERN, MAX_FILE_SIZE, MAX_VOICE_NOTE_DURATION_SECONDS } from "@/lib/constants";
import { sanitizeMessage } from "@/lib/sanitizers";
import type { HybridKeys } from "@/lib/types/auth-types";
import type { HybridPublicKeys } from '@/lib/types/message-sending-types';
import { toast } from "sonner";
import { Paperclip, SendHorizontal } from "lucide-react";
import { Cross2Icon } from "./assets/icons";
import { MaterialFileIcon } from "../ui/MaterialFileIcon";

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
  disabledPlaceholder?: string;
  getKeysOnDemand?: () => Promise<HybridKeys | null>;
  getPeerHybridKeys?: (peerUsername: string) => Promise<HybridPublicKeys | null>;
  findUser?: (handle: string) => Promise<any>;
  secureDB?: any;
  checkPeerSession?: (peerUsername: string) => Promise<void>;
  fileSenderOverride?: FileSenderController;
}

const safeReplyDisplayName = (value: string): string => {
  const trimmed = value.trim();
  return !trimmed || HEX_PATTERN.test(trimmed) ? 'User' : trimmed;
};

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
  disabledPlaceholder,
  getKeysOnDemand,
  getPeerHybridKeys,
  findUser,
  secureDB,
  checkPeerSession: checkPeerSession,
  fileSenderOverride,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showVoiceRecorder, setShowVoiceRecorder] = useState(false);
  const [replyDisplaySender, setReplyDisplaySender] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageInputRef = useRef<HTMLInputElement>(null);
  const editingMessageIdRef = useRef<string | null>(null);

  const networkFileSender = useFileSender(
    currentUsername,
    selectedConversation,
    users,
    getKeysOnDemand,
    getPeerHybridKeys,
    findUser,
    secureDB,
    checkPeerSession,
  );
  const {
    sendFile,
    progress,
    isSendingFile,
    fileSendPhase,
    fileName,
    cancelCurrent,
  } = fileSenderOverride ?? networkFileSender;

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

  useEffect(() => {
    const sender = replyTo?.sender;
    if (!sender) {
      setReplyDisplaySender('');
      return;
    }

    let cancelled = false;
    const fallback = safeReplyDisplayName(sender);
    setReplyDisplaySender(fallback);
    if (getDisplayUsername) {
      void getDisplayUsername(sender)
        .then((resolved) => {
          if (!cancelled) setReplyDisplaySender(safeReplyDisplayName(resolved));
        })
        .catch(() => {
          if (!cancelled) setReplyDisplaySender(fallback);
        });
    }
    return () => {
      cancelled = true;
    };
  }, [getDisplayUsername, replyTo?.sender]);

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
          null,
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
    if (disabled || isSendingFile || isSending) {
      e.target.value = '';
      return;
    }

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
  }, [disabled, isSending, isSendingFile, validateFile, sendFile]);

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

  const fileProgressPercent = Math.round(Math.max(0, Math.min(1, progress)) * 100);
  const fileProgressStyle = {
    '--qor-file-send-progress': `${fileProgressPercent}%`,
  } as React.CSSProperties;

  return (
    <>
      <div className="qor-input-shell">
        {isSendingFile && (
          <div
            className="qor-file-send-banner"
            style={fileProgressStyle}
            role="progressbar"
            aria-live="polite"
            aria-label={fileSendPhase === 'preparing' ? 'Preparing encrypted file' : 'Sending file'}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={fileProgressPercent}
          >
            <span className="qor-file-send-banner-fill" aria-hidden="true" />
            <MaterialFileIcon fileName={fileName} className="qor-file-send-banner-icon" />
            <span className="qor-file-send-banner-name" title={fileName || 'File'}>
              {fileName || 'File'}
            </span>
            <span className="qor-file-send-banner-percent">{fileProgressPercent}%</span>
            <button
              type="button"
              className="qor-file-send-banner-cancel"
              onClick={cancelCurrent}
              aria-label="Cancel file transfer"
              title="Cancel file transfer"
            >
              <Cross2Icon aria-hidden="true" />
            </button>
          </div>
        )}
        {editingMessage && (
          <EditingBanner editingMessage={editingMessage} onCancelEdit={onCancelEdit} />
        )}
        {replyTo && (
          <ReplyBanner
            replyTo={replyTo}
            onCancelReply={onCancelReply}
            displaySender={replyDisplaySender || 'User'}
          />
        )}

        {showVoiceRecorder && (
          <VoiceRecorder
            onSendVoiceNote={handleSendVoiceNote}
            onCancel={() => setShowVoiceRecorder(false)}
            disabled={isSendingFile || isSending}
          />
        )}
        <div
          className={`qor-message-box ${isSendingFile || editingMessage || replyTo || showVoiceRecorder ? 'has-banner' : ''}`}
        >
            {/* File Upload */}
            <div className="qor-file-upload-wrapper">
              <button
                type="button"
                className="qor-composer-icon-btn"
                title="Add a file"
                aria-label="Add a file"
                disabled={disabled || isSendingFile || isSending}
                onClick={() => fileInputRef.current?.click()}
              >
                <Paperclip aria-hidden="true" />
              </button>
              <input
                ref={fileInputRef}
                type={SignalType.FILE}
                style={{ display: 'none' }}
                onChange={handleFileChange}
                disabled={disabled || isSendingFile || isSending}
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
              placeholder={disabledPlaceholder || (editingMessage
                ? "Editing message..."
                : replyTo
                  ? `Replying to ${replyDisplaySender || 'User'}...`
                  : "Message...")}
              type="text"
              id="messageInput"
              value={disabledPlaceholder ? '' : message}
              onChange={handleMessageChange}
              onKeyDown={handleKeyDown}
              disabled={disabled}
              className={`qor-message-input${disabledPlaceholder ? ' is-blocked-placeholder' : ''}`}
            />

            {/* Send Button */}
            <button
              id="sendButton"
              onClick={handleSend}
              disabled={!message.trim() || !selectedConversation || disabled}
              className="qor-send-button"
              title="Send message"
              aria-label="Send message"
            >
              <SendHorizontal aria-hidden="true" />
            </button>
        </div>
      </div>
    </>
  );
}
