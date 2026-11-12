import React, { useState, useRef, useEffect, useLayoutEffect, useCallback } from "react";
import { User } from "./messaging/UserList";
import { SignalType } from "../../lib/types/signal-types";
import { Message, MessageReply } from './messaging/types';
import { useFileSender } from "./ChatInput/useFileSender";
import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";
import { VoiceRecorder } from "./calls/VoiceRecorder";
import { VoiceRecorderButton } from "./ChatInput/VoiceRecorderButton";
import { HEX_PATTERN, MAX_FILE_SIZE, MAX_VOICE_NOTE_DURATION_SECONDS } from "@/lib/constants";
import { sanitizeMessage } from "@/lib/sanitizers";
import type { HybridKeys } from "@/lib/types/auth-types";
import type { SecureDB } from '@/lib/database/secureDB';
import { toast } from "sonner";
import { Paperclip, SendHorizontal } from "lucide-react";
import { Cross2Icon } from "./assets/icons";
import { MaterialFileIcon } from "../ui/MaterialFileIcon";

interface ChatInputProps {
  onSendMessage: (messageId: string, content: string, messageSignalType: string, replyTo?: Message | MessageReply | null) => void | Promise<void>;

  currentUsername: string;
  users: ReadonlyArray<User>;
  replyTo?: Message | null;
  onCancelReply: () => void;
  editingMessage?: Message | null;
  onCancelEdit: () => void;
  onTyping: () => void;
  selectedConversation: string;
  getDisplayUsername: (username: string) => Promise<string>;
  disabled?: boolean;
  disabledPlaceholder?: string;
  getKeysOnDemand: () => Promise<HybridKeys | null>;
  findUser: (handle: string) => Promise<any>;
  secureDB: SecureDB;
  checkPeerSession: (peerUsername: string) => Promise<void>;
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
  onTyping,
  selectedConversation,
  getDisplayUsername,
  disabled = false,
  disabledPlaceholder,
  getKeysOnDemand,
  findUser,
  secureDB,
  checkPeerSession: checkPeerSession,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showVoiceRecorder, setShowVoiceRecorder] = useState(false);
  const [replyDisplaySender, setReplyDisplaySender] = useState('');
  const messageRef = useRef('');
  const inputScopeRef = useRef(`${currentUsername}:${selectedConversation}`);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageInputRef = useRef<HTMLTextAreaElement>(null);
  const editingMessageIdRef = useRef<string | null>(null);

  const networkFileSender = useFileSender(
    currentUsername,
    selectedConversation,
    users,
    getKeysOnDemand,
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
  } = networkFileSender;

  useEffect(() => {
    if (!editingMessage) {
      if (editingMessageIdRef.current) { messageRef.current = ''; setMessage(''); }
      editingMessageIdRef.current = null;
      return;
    }

    editingMessageIdRef.current = editingMessage.id;
    messageRef.current = '';
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
    setReplyDisplaySender('');
    void getDisplayUsername(sender)
      .then((resolved) => {
        if (!cancelled) setReplyDisplaySender(safeReplyDisplayName(resolved));
      })
      .catch((error) => {
        console.error('[ChatInput] Reply display-name lookup failed', error);
      });
    return () => {
      cancelled = true;
    };
  }, [getDisplayUsername, replyTo?.sender]);

  useLayoutEffect(() => {
    editingMessageIdRef.current = null;
    inputScopeRef.current = `${currentUsername}:${selectedConversation}`;
    messageRef.current = '';
    setMessage("");
    setShowVoiceRecorder(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
    return () => { messageRef.current = ''; inputScopeRef.current = ''; };
  }, [selectedConversation, currentUsername]);

  useLayoutEffect(() => {
    const input = messageInputRef.current;
    if (!input) return;

    const resize = () => {
      input.style.height = 'auto';
      input.style.height = `${input.scrollHeight}px`;
    };
    let width = input.clientWidth;
    const observer = new ResizeObserver(() => {
      if (input.clientWidth === width) return;
      width = input.clientWidth;
      resize();
    });
    resize();
    observer.observe(input);
    return () => observer.disconnect();
  }, [message, disabledPlaceholder]);

  const handleSend = useCallback(() => {
    const text = messageRef.current;
    if (inputScopeRef.current !== `${currentUsername}:${selectedConversation}` || !text.trim() || !selectedConversation || disabled || showVoiceRecorder) return;
    const sanitizedMessage = sanitizeMessage(text);
    if (!sanitizedMessage) return;
    const isEdit = !!editingMessage;
    const targetId = isEdit ? editingMessage!.wireMessageId || editingMessage!.id : '';
    const outboundReply = replyTo ? { ...replyTo, id: replyTo.wireMessageId || replyTo.id } : null;
    messageRef.current = '';
    setMessage('');
    if (isEdit) { editingMessageIdRef.current = null; onCancelEdit(); } else onCancelReply();
    try {
      const result = onSendMessage(targetId, sanitizedMessage, isEdit ? SignalType.EDIT_MESSAGE : SignalType.MESSAGE, isEdit ? null : outboundReply);
      void Promise.resolve(result).catch(error => console.error('[ChatInput] Message send failed', error));
    } catch (error) {
      console.error('[ChatInput] Message send failed', error);
    }
  }, [currentUsername, selectedConversation, disabled, showVoiceRecorder, editingMessage, replyTo, onSendMessage, onCancelEdit, onCancelReply]);

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

      setShowVoiceRecorder(false);
      await sendFile(file);
    } catch (_error) {
      console.error('Failed to send voice note:', _error);
      const msg = _error instanceof Error ? _error.message : 'Unknown error';
      toast.error('Failed to send voice note: ' + msg);
    } finally {
      setIsSending(false);
    }
  }, [selectedConversation, validateFile, sendFile]);

  // Handle message input changes and typing indicators
  const handleMessageChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    if (inputScopeRef.current !== `${currentUsername}:${selectedConversation}`) return;
    messageRef.current = e.target.value;
    setMessage(e.target.value);
    onTyping();
  }, [onTyping, currentUsername, selectedConversation]);

  // Handle keyboard events
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  const composerBusy = disabled || isSendingFile || isSending;
  const hasDraft = !!message.trim();

  const fileProgressPercent = Math.max(0, Math.min(1, progress)) * 100;
  const fileProgressLabel = fileSendPhase === 'preparing'
    ? 'Preparing'
    : fileProgressPercent > 0 && fileProgressPercent < 1
      ? `${fileProgressPercent.toFixed(2)}%`
      : `${Math.round(fileProgressPercent)}%`;
  const fileProgressStyle = {
    '--qorc-file-send-progress': `${fileProgressPercent}%`,
  } as React.CSSProperties;

  return (
    <>
      <div className="qorc-input-shell">
        {isSendingFile && (
          <div
            className="qorc-file-send-banner"
            style={fileProgressStyle}
            role="progressbar"
            aria-live="polite"
            aria-label={fileSendPhase === 'preparing' ? 'Preparing encrypted file' : 'Sending file'}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={fileSendPhase === 'preparing' ? undefined : Math.round(fileProgressPercent)}
          >
            <span className="qorc-file-send-banner-fill" aria-hidden="true" />
            <MaterialFileIcon fileName={fileName} className="qorc-file-send-banner-icon" />
            <span className="qorc-file-send-banner-name" title={fileName || 'File'}>
              {fileName || 'File'}
            </span>
            <span className="qorc-file-send-banner-percent">{fileProgressLabel}</span>
            <button
              type="button"
              className="qorc-file-send-banner-cancel"
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
          className={`qorc-message-box ${isSendingFile || editingMessage || replyTo || showVoiceRecorder ? 'has-banner' : ''}`}
        >
            <div className="qorc-file-upload-wrapper">
              <button type="button" className="qorc-composer-icon-btn" title="Attach a file" aria-label="Attach a file" disabled={composerBusy || showVoiceRecorder} onClick={() => fileInputRef.current?.click()}>
                <Paperclip aria-hidden="true" />
              </button>
              <input ref={fileInputRef} type={SignalType.FILE} style={{ display: 'none' }} onChange={handleFileChange} disabled={composerBusy} />
            </div>

            {/* Message Input */}
            <textarea
              ref={messageInputRef}
              placeholder={disabledPlaceholder || (editingMessage
                ? "Editing message..."
                : replyTo
                  ? "Reply…"
                  : "Message…")}
              rows={1}
              id="messageInput"
              aria-label="Message"
              value={disabledPlaceholder ? '' : message}
              onChange={handleMessageChange}
              onKeyDown={handleKeyDown}
              disabled={disabled}
              className={`qorc-message-input${disabledPlaceholder ? ' is-blocked-placeholder' : ''}`}
            />

            <div className="qorc-composer-action">
              {hasDraft ? <button
                id="sendButton" type="button"
                onMouseDown={event => {
                  const input = messageInputRef.current;
                  if (event.button === 0 && input && document.activeElement === input) event.preventDefault();
                }}
                onClick={() => { void handleSend(); }}
                disabled={!hasDraft || !selectedConversation || disabled || showVoiceRecorder}
                className="qorc-send-button" title="Send message" aria-label="Send message"
              ><SendHorizontal aria-hidden="true" /></button> : <VoiceRecorderButton onClick={() => setShowVoiceRecorder(true)} disabled={composerBusy || showVoiceRecorder} />}
            </div>
        </div>
      </div>
    </>
  );
}
