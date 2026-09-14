import React, { useRef, useMemo, useCallback, useEffect, useState } from "react";
import { cn } from "../../../lib/utils/shared-utils";
import { format, isSameMinute } from "date-fns";
import { EmojiPicker } from "../../ui/EmojiPicker";
import { useEmojiPicker } from "../../../contexts/EmojiPickerContext";
import { ChatMessageProps } from "./types";
import { SystemMessage } from "./ChatMessage/SystemMessage";
import { recordEmojiUsage } from "../../../lib/system-emoji";
import { DeletedMessage } from "./ChatMessage/DeletedMessage";
import { FileContent } from "./ChatMessage/FileMessage";
import { VoiceMessage } from "../calls/VoiceMessage";
import { MessageReceipt } from "./MessageReceipt";
import { useDisplayUsername } from "../../../hooks/database/useDisplayUsername";
import { MessageContextMenu } from "./MessageContextMenu";
import { UserAvatar } from "../../ui/UserAvatar";
import { SecureCanvasText } from "./SecureCanvasText";
import { BannerMessagePreview } from "../ChatInput/BannerMessagePreview";
import { createDownloadLink, parseCurrentVoiceNoteFilename } from "../../../lib/utils/file-utils";
import { nativeMessageContent } from "../../../lib/tauri-bindings";
import { MessageLinkPreviews } from "./MessageLinkPreview";
import { formatMessageTimestamp } from '../../../lib/utils/date-utils';
import { EventType } from '../../../lib/types/event-types';
import { SignalType } from '../../../lib/types/signal-types';

interface SystemAction {
  readonly label: string;
  readonly onClick: () => void;
}

interface MessageAnchorRect {
  readonly top: number;
  readonly right: number;
  readonly bottom: number;
  readonly left: number;
}

// Check if string is valid JSON
const isValidJson = (str: string): boolean => {
  if (typeof str !== 'string' || str.length === 0) return false;
  const trimmed = str.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
};

// Parse system message content
const parseSystemMessage = (content: string, message: any, currentUsername?: string): { label: string; actions?: SystemAction[]; isError?: boolean; callType?: 'audio' | 'video'; showCallIcon?: boolean } => {
  if (!isValidJson(content)) {
    return { label: content };
  }

  try {
    const parsed = JSON.parse(content);
    if (!parsed || typeof parsed !== 'object' || !parsed.label) {
      return { label: content };
    }

    const label = typeof parsed.label === 'string' ? parsed.label : content;
    const callType = parsed.callType === 'video' || parsed.callType === 'audio' ? parsed.callType : undefined;
    const showCallIcon = parsed.showCallIcon === true;
    let actions: SystemAction[] | undefined;

    if (parsed.actionsType === 'callback' && message) {
      const peer = message.sender === 'System' ? (message.recipient || '') : message.sender;
      if (typeof peer === 'string' && peer.length > 0) {
        actions = [{
          label: 'Call back',
          onClick: () => {
            try {
              window.dispatchEvent(new CustomEvent(EventType.UI_CALL_REQUEST, {
                detail: { account: currentUsername, peer, type: 'audio' }
              }));
            } catch { }
          }
        }];
        return { label, actions, isError: parsed.isError, callType, showCallIcon };
      }
    }

    return { label, actions, isError: parsed.isError, callType, showCallIcon };
  } catch {
    return { label: content };
  }
};

export const ChatMessage = React.memo<ChatMessageProps>(({ message, smartReceipt, onReply, previousMessage, onDelete, onEdit, onReact, onReplyClick, currentUsername, secureDB }) => {
  const { content, sender, timestamp, isCurrentUser, isSystemMessage, isDeleted, type } = message;
  const effectiveReceipt = smartReceipt;

  const displaySender = useDisplayUsername({ username: sender });
  const displayReplyToSender = useDisplayUsername({ username: message.replyTo?.sender || '' });

  // Group messages within 3 minutes from same sender
  const isGrouped = useMemo(() => {
    if (!previousMessage) return false;
    if (previousMessage.sender !== sender) return false;
    if (!(previousMessage.timestamp instanceof Date) || !(timestamp instanceof Date)) return false;
    const diff = Math.abs(timestamp.getTime() - previousMessage.timestamp.getTime());
    const GROUP_GAP_MS = 3 * 60 * 1000;
    return diff <= GROUP_GAP_MS || isSameMinute(previousMessage.timestamp, timestamp);
  }, [previousMessage, sender, timestamp]);

  const safeIsCurrentUser = useMemo(() => isCurrentUser || false, [isCurrentUser]);

  const bubbleRef = useRef<HTMLDivElement | null>(null);
  const { openPicker, openPickerOrigin, closePicker, isPickerOpen } = useEmojiPicker();

  const messageTriggerIdRef = useRef<string | null>(null);
  if (!messageTriggerIdRef.current) {
    const safeId = message.id || `msg-${timestamp instanceof Date ? timestamp.getTime() : Date.now()}`;
    messageTriggerIdRef.current = `message-${safeId}`;
  }
  const messageTriggerId = messageTriggerIdRef.current;
  const pickerOpen = isPickerOpen(messageTriggerId);

  const [contextMenu, setContextMenu] = useState<{ anchorRect: MessageAnchorRect } | null>(null);
  const [isContentRendered, setIsContentRendered] = useState(false);
  const downloadGenerationRef = useRef(0);
  useEffect(() => {
    downloadGenerationRef.current += 1;
    return () => { downloadGenerationRef.current += 1; };
  }, [message.id, secureDB]);

  const { systemLabel, systemActions, systemIsError, systemCallType, systemShowCallIcon } = useMemo(() => {
    if (!isSystemMessage) return { systemLabel: '', systemActions: undefined, systemIsError: undefined, systemCallType: undefined, systemShowCallIcon: undefined };
    const { label, actions, isError, callType, showCallIcon } = parseSystemMessage(content, message, currentUsername);
    return { systemLabel: label, systemActions: actions, systemIsError: isError, systemCallType: callType, systemShowCallIcon: showCallIcon };
  }, [isSystemMessage, content, message, currentUsername]);

  const isFileMessageType =
    type === SignalType.FILE_MESSAGE ||
    type === SignalType.FILE;

  const isVoiceNote = useMemo(() => {
    if (!isFileMessageType) return false;
    const metadata = parseCurrentVoiceNoteFilename(message.filename);
    return metadata !== null && metadata.mimeType === message.mimeType;
  }, [isFileMessageType, message.filename, message.mimeType]);

  const [loadFile, setLoadFile] = useState(false);
  useEffect(() => {
    if (!isFileMessageType) return;
    const node = bubbleRef.current;
    if (!node) return;
    const observer = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      setLoadFile(true);
      observer.disconnect();
    }, { rootMargin: '600px 0px' });
    observer.observe(node);
    return () => observer.disconnect();
  }, [isFileMessageType, message.id]);

  const timestampDisplay = useMemo(() => formatMessageTimestamp(timestamp), [timestamp]);

  // Handle emoji selection
  const handlePickEmoji = useCallback((emoji: string) => {
    if (!onReact) return;
    void recordEmojiUsage(emoji, secureDB);
    if (currentUsername && message.reactions) {
      for (const [e, users] of Object.entries(message.reactions)) {
        if (users.includes(currentUsername) && e !== emoji) {
          onReact?.(message, e);
        }
      }
    }
    onReact?.(message, emoji);
  }, [currentUsername, message, onReact, secureDB]);

  useEffect(() => {
    if (onReact || !pickerOpen) return;
    closePicker();
  }, [closePicker, onReact, pickerOpen]);

  // Handle message copy
  const handleCopyMessage = useCallback(() => {
    const contentId = message.secureContentId || message.id;
    void nativeMessageContent.copy(contentId).catch(() => { });
  }, [message.id, message.secureContentId]);

  // Handle message reply
  const handleReply = useCallback(() => {
    onReply?.(message);
  }, [onReply, message]);

  // Handle message deletion
  const handleDelete = useCallback(() => {
    onDelete?.(message);
  }, [onDelete, message]);

  // Handle message editing
  const handleEdit = useCallback(() => {
    onEdit?.(message);
  }, [onEdit, message]);

  // Handle file download
  const handleDownload = useCallback(async () => {
    const generation = downloadGenerationRef.current;
    const database = secureDB;
    try {
      if (!database || !message.id) throw new Error('Encrypted file storage is unavailable');
      const blob = await database.getFile(message.id);
      if (
        generation !== downloadGenerationRef.current ||
        !blob
      ) return;
      const typedBlob = new Blob([blob], { type: message.mimeType || 'application/octet-stream' });
      const url = URL.createObjectURL(typedBlob);
      try {
        createDownloadLink(url, message.filename || `file-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}`);
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 0);
      }
    } catch (error) {
      console.error('Failed to download file:', error);
      alert('Failed to download file');
    }
  }, [message, secureDB, timestamp]);

  // Handle context menu
  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (contextMenu) {
      setContextMenu(null);
      return;
    }

    const anchor = bubbleRef.current ?? e.currentTarget;
    const rect = anchor.getBoundingClientRect();
    setContextMenu({
      anchorRect: {
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
        left: rect.left,
      },
    });
  }, [contextMenu]);

  const isDownloadable = useMemo(() => {
    return !!(isFileMessageType && secureDB && message.id);
  }, [isFileMessageType, message.id, secureDB]);

  const reactionEntries = useMemo(() => (
    Object.entries(message.reactions || {}).filter(([, users]) => users.length > 0)
  ), [message.reactions]);

  const messageReactions = reactionEntries.length > 0 ? (
    <div
      className={cn(
        "qorc-message-reactions",
        safeIsCurrentUser ? "is-mine" : "is-received",
      )}
      role="group"
      aria-label="Message reactions"
    >
      {reactionEntries.map(([emoji, users], index) => {
        const hasReacted = currentUsername ? users.includes(currentUsername) : false;
        return (
          <button
            key={emoji}
            type="button"
            className="qorc-message-reaction"
            style={{ '--qorc-reaction-stack': reactionEntries.length - index } as React.CSSProperties}
            onClick={() => onReact?.(message, emoji)}
            disabled={!onReact}
            aria-label={`${emoji} reaction, ${users.length} user${users.length !== 1 ? 's' : ''}`}
            aria-pressed={hasReacted}
          >
            <span className="qorc-message-reaction-emoji" aria-hidden="true">{emoji}</span>
            {users.length > 1 && (
              <span className="qorc-message-reaction-count" aria-hidden="true">{users.length}</span>
            )}
          </button>
        );
      })}
    </div>
  ) : null;

  if (isSystemMessage) {
    return <SystemMessage content={systemLabel} actions={systemActions} isError={systemIsError} callType={systemCallType} showCallIcon={systemShowCallIcon} timestamp={systemCallType ? timestampDisplay : undefined} />;
  }

  if (isDeleted) {
    return (
      <DeletedMessage
        senderUsername={sender}
        displayName={displaySender}
        timestamp={timestamp}
        isCurrentUser={safeIsCurrentUser}
      />
    );
  }

  return (
    <div
      data-emoji-trigger={messageTriggerId}
      className={cn(
        "flex gap-3 mb-4",
        safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
      )}
      style={{
        marginBottom: reactionEntries.length > 0
          ? `calc(${isGrouped ? 'var(--spacing-xxs)' : 'var(--spacing-sm)'} + 10px)`
          : isGrouped ? 'var(--spacing-xxs)' : 'var(--spacing-sm)'
      }}
    >
      <div className="flex-shrink-0 w-10">
        {!isGrouped && (
          <UserAvatar
            username={sender}
            isCurrentUser={safeIsCurrentUser}
            size="md"
          />
        )}
      </div>

      {/* Message Content */}
      <div
        className={cn(
          "flex flex-col min-w-0 group",
          safeIsCurrentUser ? "items-end" : "items-start"
        )}
        style={{
          maxWidth: 'var(--message-bubble-max-width)'
        }}
      >
        {!isGrouped && (
          <div
            className={cn(
              "flex items-center gap-2 mb-1",
              safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
            )}
          >
            <span
              className="text-sm font-medium"
              style={{ color: 'var(--color-text-primary)' }}
            >
              {displaySender}
            </span>
            <span
              className="text-xs select-none"
              style={{ color: 'var(--color-text-secondary)' }}
              role="time"
              aria-label={`Message sent at ${timestampDisplay}`}
            >
              {timestampDisplay}
            </span>
          </div>
        )}

        {/* Message body container (bubbles, previews, etc) */}
        <div
          style={{
            visibility: isContentRendered ? 'visible' : 'hidden',
            width: '100%',
            display: 'contents'
          }}
        >
          {message.replyTo && (
            <div
              className="qorc-message-reply-preview mb-1 select-none"
              role="note"
              aria-label={`Replying to ${displayReplyToSender}`}
              onClick={() => onReplyClick?.(message.replyTo!.id)}
            >
              <UserAvatar
                username={message.replyTo.sender || ''}
                size="xs"
                className="qorc-message-reply-preview-avatar"
              />
              <div className="qorc-message-reply-preview-copy">
                <span className="qorc-message-reply-preview-name">{displayReplyToSender}</span>
                <div className="qorc-message-reply-preview-text">
                  {message.replyTo.isDeleted ? (
                    <span className="qorc-message-reply-preview-deleted">Message deleted</span>
                  ) : (
                    <BannerMessagePreview
                      messageId={message.replyTo.secureContentId || message.replyTo.id}
                      contentVersion={message.replyTo.contentVersion}
                      maxWidth={800}
                      maxLines={2}
                    />
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Message bubble */}
          <div className={cn("flex items-end gap-2", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")}>
            {/* Render file content or text content */}
            {isFileMessageType ? (
              <div className="relative" ref={bubbleRef} onContextMenu={handleContextMenu}>
                {isVoiceNote ? (
                  <VoiceMessage
                    timestamp={timestamp}
                    isCurrentUser={safeIsCurrentUser}
                    filename={message.filename!}
                    mimeType={message.mimeType!}
                    messageId={message.id}
                    secureDB={secureDB}
                    onRendered={() => setIsContentRendered(true)}
                    loadFile={loadFile}
                  />
                ) : (
                  <FileContent
                    message={message}
                    secureDB={secureDB}
                    onRendered={() => setIsContentRendered(true)}
                    loadFile={loadFile}
                  />
                )}
                {messageReactions}
              </div>
            ) : (
                <div
                  className={cn(
                    "relative flex max-w-full flex-col",
                    safeIsCurrentUser ? "items-end" : "items-start"
                  )}
                  ref={bubbleRef}
                >
                  <MessageLinkPreviews
                    messageId={message.secureContentId || message.id}
                    contentVersion={message.controlState?.editOperationId}
                    secureDB={secureDB}
                    onContextMenu={handleContextMenu}
                  />
                  <div
                    className="px-4 py-3 text-sm transition-opacity duration-200"
                    style={{
                      backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--chat-bubble-received-text-bg, var(--chat-bubble-received-bg))',
                      borderRadius: 'var(--message-bubble-radius)',
                      minWidth: '3rem',
                      maxWidth: '100%'
                    }}
                    onContextMenu={handleContextMenu}
                  >
                    <SecureCanvasText
                      messageId={message.secureContentId || message.id}
                      contentVersion={message.controlState?.editOperationId}
                      maxWidth={350}
                      fontSize={14}
                      color={safeIsCurrentUser ? 'var(--color-on-accent)' : 'var(--chat-bubble-received-text)'}
                      isCurrentUser={safeIsCurrentUser}
                      onRendered={() => setIsContentRendered(true)}
                      onContextMenu={handleContextMenu}
                    />
                  </div>
                  {messageReactions}
                </div>
              )}
          </div>
        </div>

        <div
          className={cn(
            "flex items-center gap-2 mt-1 text-xs",
            safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
          )}>

          {message.isEdited && (
            <span
              className="qorc-message-edited italic"
              role="status"
              aria-label="Message edited"
            >
              (edited)
            </span>
          )}
        </div>

        <MessageReceipt
          receipt={effectiveReceipt}
          isCurrentUser={safeIsCurrentUser}
          className="mt-1"
        />
      </div>

      {pickerOpen && (
        <EmojiPicker
          onEmojiSelect={handlePickEmoji}
          onClose={closePicker}
          triggerId={messageTriggerId}
          isCurrentUser={safeIsCurrentUser}
          secureDB={secureDB}
          origin={openPickerOrigin}
        />
      )}

      {contextMenu && (
        <MessageContextMenu
          anchorRect={contextMenu.anchorRect}
          triggerId={messageTriggerId}
          isCurrentUser={safeIsCurrentUser}
          onClose={() => setContextMenu(null)}
          onCopy={!isFileMessageType ? handleCopyMessage : undefined}
          onEdit={!isFileMessageType && safeIsCurrentUser && onEdit ? handleEdit : undefined}
          onReply={onReply ? handleReply : undefined}
          onDelete={safeIsCurrentUser ? handleDelete : undefined}
          onReact={onReact ? (origin) => openPicker(messageTriggerId, origin) : undefined}
          onReactionSelect={onReact ? handlePickEmoji : undefined}
          onDownload={isDownloadable ? handleDownload : undefined}
          canEdit={!isFileMessageType && safeIsCurrentUser && !!onEdit}
          canDelete={safeIsCurrentUser}
          isFile={isFileMessageType}
        />
      )}
    </div>
  );
});
