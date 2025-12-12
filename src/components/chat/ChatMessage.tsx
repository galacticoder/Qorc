import React, { useRef, useMemo, useCallback, useState } from "react";
import { cn } from "../../lib/utils";
import { format, isSameMinute, isToday, isYesterday, isThisYear } from "date-fns";
import { EmojiPicker } from "../ui/EmojiPicker";
import { useEmojiPicker } from "../../contexts/EmojiPickerContext";
import { ChatMessageProps } from "./types.ts";
import { SystemMessage } from "./ChatMessage/SystemMessage.tsx";
import { recordEmojiUsage } from "../../lib/system-emoji";
import { DeletedMessage } from "./ChatMessage/DeletedMessage.tsx";
import { FileContent } from "./ChatMessage/FileMessage.tsx";
import { VoiceMessage } from "./VoiceMessage";
import { MessageReceipt } from "./MessageReceipt.tsx";
import { useUnifiedUsernameDisplay } from "../../hooks/useUnifiedUsernameDisplay";
import { LinkifyWithPreviews } from "./LinkifyWithPreviews.tsx";
import { LinkExtractor } from "../../lib/link-extraction.ts";
import { MarkdownRenderer } from "../ui/MarkdownRenderer";
import { isMarkdownMessage, extractMarkdownContent } from "../../lib/markdown-parser";
import { copyTextToClipboard } from "../../lib/clipboard";
import { MessageContextMenu } from "./MessageContextMenu";
import { UserAvatar } from "../ui/UserAvatar";

interface ExtendedChatMessageProps extends ChatMessageProps {
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

interface SystemAction {
  readonly label: string;
  readonly onClick: () => void;
}

const isValidJson = (str: string): boolean => {
  if (typeof str !== 'string' || str.length === 0) return false;
  const trimmed = str.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
};

const parseSystemMessage = (content: string, message: any): { label: string; actions?: SystemAction[]; isError?: boolean } => {
  if (!isValidJson(content)) {
    return { label: content };
  }

  try {
    const parsed = JSON.parse(content);
    if (!parsed || typeof parsed !== 'object' || !parsed.label) {
      return { label: content };
    }

    const label = typeof parsed.label === 'string' ? parsed.label : content;
    let actions: SystemAction[] | undefined;

    if (parsed.actionsType === 'callback' && message) {
      const peer = message.sender === 'System' ? (message.recipient || '') : message.sender;
      if (typeof peer === 'string' && peer.length > 0) {
        actions = [{
          label: 'Call back',
          onClick: () => {
            try {
              window.dispatchEvent(new CustomEvent('ui-call-request', { detail: { peer, type: 'audio' } }));
            } catch { }
          }
        }];
        return { label, actions, isError: parsed.isError };
      }
    }

    return { label, actions, isError: parsed.isError };
  } catch {
    return { label: content };
  }
};

const formatTimestamp = (timestamp: Date): string => {
  try {
    if (!(timestamp instanceof Date) || isNaN(timestamp.getTime())) {
      return '';
    }
    // Today: show time only
    if (isToday(timestamp)) {
      return format(timestamp, 'h:mm a');
    }
    // Yesterday: prefix
    if (isYesterday(timestamp)) {
      return `Yesterday ${format(timestamp, 'h:mm a')}`;
    }
    // This year: Month day, time
    if (isThisYear(timestamp)) {
      return format(timestamp, 'MMM d, h:mm a');
    }
    // Other years: include year
    return format(timestamp, 'MMM d, yyyy, h:mm a');
  } catch {
    return '';
  }
};

export const ChatMessage = React.memo<ExtendedChatMessageProps>(({ message, smartReceipt, onReply, previousMessage, onDelete, onEdit, onReact, onReplyClick, getDisplayUsername, currentUsername, secureDB }) => {
  const { content, sender, timestamp, isCurrentUser, isSystemMessage, isDeleted, type } = message;
  const effectiveReceipt = smartReceipt;

  const senderKey = useMemo(() => sender, [sender]);
  const { displayName: displaySender } = useUnifiedUsernameDisplay({
    username: senderKey,
    getDisplayUsername,
    fallbackToOriginal: true
  });

  const replyToSenderKey = useMemo(() => message.replyTo?.sender || '', [message.replyTo?.sender]);
  const { displayName: displayReplyToSender } = useUnifiedUsernameDisplay({
    username: replyToSenderKey,
    getDisplayUsername,
    fallbackToOriginal: true
  });

  const isGrouped = useMemo(() => {
    if (!previousMessage) return false;
    if (previousMessage.sender !== sender) return false;
    if (!(previousMessage.timestamp instanceof Date) || !(timestamp instanceof Date)) return false;
    const diff = Math.abs(timestamp.getTime() - previousMessage.timestamp.getTime());
    const GROUP_GAP_MS = 3 * 60 * 1000; // group messages within 3 minutes from same sender
    return diff <= GROUP_GAP_MS || isSameMinute(previousMessage.timestamp, timestamp);
  }, [previousMessage, sender, timestamp]);

  const safeIsCurrentUser = useMemo(() => isCurrentUser || false, [isCurrentUser]);

  const bubbleRef = useRef<HTMLDivElement | null>(null);
  const { openPicker, closePicker, isPickerOpen } = useEmojiPicker();

  const messageTriggerIdRef = useRef<string | null>(null);
  if (!messageTriggerIdRef.current) {
    const safeId = message.id || `msg-${timestamp instanceof Date ? timestamp.getTime() : Date.now()}`;
    messageTriggerIdRef.current = `message-${safeId}`;
  }
  const messageTriggerId = messageTriggerIdRef.current;
  const pickerOpen = isPickerOpen(messageTriggerId);

  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null);

  const { isUrlOnly, urls, isMarkdown, markdownContent } = useMemo(() => {
    const urlOnly = LinkExtractor.isUrlOnlyMessage(content);
    const extractedUrls = LinkExtractor.extractUrlStrings(content);
    const hasMarkdown = isMarkdownMessage(content);
    const mdContent = hasMarkdown ? extractMarkdownContent(content) : '';

    return {
      isUrlOnly: urlOnly,
      urls: extractedUrls,
      isMarkdown: hasMarkdown,
      markdownContent: mdContent
    };
  }, [content]);

  const { systemLabel, systemActions, systemIsError } = useMemo(() => {
    if (!isSystemMessage) return { systemLabel: '', systemActions: undefined, systemIsError: undefined };
    const { label, actions, isError } = parseSystemMessage(content, message);
    return { systemLabel: label, systemActions: actions, systemIsError: isError };
  }, [isSystemMessage, content, message]);

  const isFileMessageType =
    type === "FILE_MESSAGE" ||
    type === "file" ||
    type === "file-message";

  const isVoiceNote = useMemo(() => {
    if (!isFileMessageType) return false;
    const name = (message.filename || '').toLowerCase();
    return name.includes('voice-note');
  }, [isFileMessageType, message.filename]);

  const timestampDisplay = useMemo(() => formatTimestamp(timestamp), [timestamp]);

  const handlePickEmoji = useCallback((emoji: string) => {
    recordEmojiUsage(emoji, secureDB);
    if (currentUsername && message.reactions) {
      for (const [e, users] of Object.entries(message.reactions)) {
        if (users.includes(currentUsername) && e !== emoji) {
          onReact?.(message, e);
        }
      }
    }
    onReact?.(message, emoji);
  }, [currentUsername, message, onReact, secureDB]);

  const handleCopyMessage = useCallback(() => {
    void copyTextToClipboard(content);
  }, [content]);

  const handleReply = useCallback(() => {
    onReply?.(message);
  }, [onReply, message]);

  const handleDelete = useCallback(() => {
    onDelete?.(message);
  }, [onDelete, message]);

  const handleEdit = useCallback(() => {
    onEdit?.(message);
  }, [onEdit, message]);

  const handleTogglePicker = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (pickerOpen) {
      closePicker();
    } else {
      openPicker(messageTriggerId);
    }
  }, [pickerOpen, closePicker, openPicker, messageTriggerId]);



  const handleDownload = useCallback(async () => {
    try {
      const { originalBase64Data, mimeType, filename } = message;
      const audioUrl = typeof content === 'string' ? content : '';

      if (originalBase64Data) {
        try {
          const cleanBase64 = originalBase64Data.trim().replace(/[^A-Za-z0-9+/=]/g, '');
          const binaryString = atob(cleanBase64);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
          const blob = new Blob([bytes], { type: mimeType || 'application/octet-stream' });
          const downloadUrl = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = filename || `file-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}`;
          link.style.display = 'none';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
          return;
        } catch (_base64Error) {
        }
      }

      if (!audioUrl || audioUrl === 'File' || audioUrl === 'voice-note') {
        alert('Cannot download file: Invalid data');
        return;
      }

      const link = document.createElement('a');
      link.href = audioUrl;
      link.download = filename || `file-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}`;
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (error) {
      console.error('Failed to download file:', error);
      alert('Failed to download file');
    }
  }, [message, content, timestamp]);

  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    const rect = e.currentTarget.getBoundingClientRect();
    const x = safeIsCurrentUser ? rect.right : rect.left;
    const y = rect.bottom + 5;

    setContextMenu({ x, y });
  }, [safeIsCurrentUser]);

  const isDownloadable = useMemo(() => {
    if (!isFileMessageType) return false;
    const { originalBase64Data } = message;
    const audioUrl = typeof content === 'string' ? content : '';
    if (originalBase64Data) return true;
    if (!audioUrl || audioUrl === 'File' || audioUrl === 'voice-note') return false;
    return true;
  }, [isFileMessageType, message, content]);



  if (isSystemMessage) {
    return <SystemMessage content={systemLabel} actions={systemActions} isError={systemIsError} />;
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
      className={cn(
        "flex gap-3 mb-4",
        safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
      )}
      style={{
        marginBottom: isGrouped ? 'var(--spacing-xs)' : 'var(--spacing-md)'
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

        {message.replyTo && (
          <div
            className="mb-1 p-3 rounded text-sm max-w-full select-none cursor-pointer hover:opacity-90 transition-opacity relative overflow-hidden"
            style={{
              backgroundColor: 'hsl(var(--secondary))',
              borderLeft: `4px solid ${safeIsCurrentUser ? 'hsl(var(--primary-foreground))' : 'hsl(var(--primary))'}`,
            }}
            role="note"
            aria-label={`Reply to ${displayReplyToSender}`}
            onClick={() => onReplyClick?.(message.replyTo!.id)}
          >
            <div className="flex items-center gap-2 mb-0.5">
              <span className="font-medium text-xs text-foreground/80">{displayReplyToSender}</span>
            </div>
            <div className="text-xs text-muted-foreground truncate opacity-90">
              {message.replyTo.content}
            </div>
          </div>
        )}

        {message.encrypted && (message.ciphertext || message.mac || message.kemCiphertext) && (
          <details className="mb-2 w-full">
            <summary className="text-[11px] text-accent cursor-pointer select-none">
              Encryption details
            </summary>
            <div className="mt-1 p-2 rounded-md bg-[var(--color-muted-panel)] text-[10px] leading-relaxed break-words" role="region" aria-label="Encryption metadata">
              {message.kemCiphertext && typeof message.kemCiphertext === 'string' && (
                <div><strong>KEM</strong>: {message.kemCiphertext.slice(0, 32)}…</div>
              )}
              {message.ciphertext && typeof message.ciphertext === 'string' && (
                <div><strong>CT</strong>: {message.ciphertext.slice(0, 32)}…</div>
              )}
              {message.nonce && typeof message.nonce === 'string' && (
                <div><strong>Nonce</strong>: {message.nonce}</div>
              )}
              {message.tag && typeof message.tag === 'string' && (
                <div><strong>Tag</strong>: {message.tag}</div>
              )}
              {message.mac && typeof message.mac === 'string' && (
                <div><strong>MAC</strong>: {message.mac}</div>
              )}
              {message.aad && typeof message.aad === 'string' && (
                <div><strong>AAD</strong>: {message.aad}</div>
              )}
              {message.pqContext && typeof message.pqContext === 'object' && (
                <div><strong>Context</strong>: {JSON.stringify(message.pqContext)}</div>
              )}
            </div>
          </details>
        )}

        {!isUrlOnly && !isSystemMessage && !isDeleted && urls.length > 0 && type !== "FILE_MESSAGE" && type !== "file" && type !== "file-message" && (
          <div
            className="mb-3 w-full flex self-stretch"
            style={{
              justifyContent: safeIsCurrentUser ? 'flex-end' : 'flex-start',
              alignSelf: safeIsCurrentUser ? 'flex-end' : 'flex-start',
              maxWidth: 'min(var(--message-bubble-max-width), 320px)',
              width: '100%',
              flex: '0 1 auto'
            }}
          >
            <LinkifyWithPreviews
              options={{ rel: "noopener noreferrer" }}
              showPreviews={true}
              isCurrentUser={safeIsCurrentUser}
              previewsOnly={true}
              urls={urls}
            >
              {content}
            </LinkifyWithPreviews>
          </div>
        )}

        {/* Message bubble */}
        <div className={cn("flex items-end gap-2", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")}>
          {/* Render file content or text content */}
          {isFileMessageType ? (
            <div className="relative" ref={bubbleRef} onContextMenu={handleContextMenu}>
              {isVoiceNote ? (
                <VoiceMessage
                  audioUrl={typeof content === 'string' ? content : ''}
                  timestamp={timestamp}
                  isCurrentUser={safeIsCurrentUser}
                  filename={message.filename}
                  originalBase64Data={message.originalBase64Data}
                  mimeType={message.mimeType}
                  messageId={message.id}
                  secureDB={secureDB}
                />
              ) : (
                <FileContent message={message} isCurrentUser={safeIsCurrentUser} secureDB={secureDB} />
              )}
            </div>
          ) : (() => {
            const showPreviews = !isSystemMessage && !isDeleted;

            if (isUrlOnly && showPreviews) {
              return (
                <div
                  className="relative self-start w-full flex"
                  style={{
                    alignSelf: safeIsCurrentUser ? 'flex-end' : 'flex-start',
                    maxWidth: 'min(var(--message-bubble-max-width), 320px)',
                    width: '100%',
                    flex: '0 1 auto',
                    justifyContent: safeIsCurrentUser ? 'flex-end' : 'flex-start'
                  }}
                  ref={bubbleRef}
                  onContextMenu={handleContextMenu}
                >
                  <LinkifyWithPreviews
                    options={{ rel: "noopener noreferrer" }}
                    showPreviews={true}
                    isCurrentUser={safeIsCurrentUser}
                    urls={urls}
                  >
                    {content}
                  </LinkifyWithPreviews>
                </div>
              );
            }

            return (
              <div className="relative max-w-full" ref={bubbleRef}>
                <div
                  className={`px-4 py-3 ${isMarkdown ? 'text-base' : 'text-sm'
                    } ${isMarkdown ? '' : 'whitespace-pre-wrap'
                    } break-words`}
                  style={{
                    backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--chat-bubble-received-bg)',
                    color: safeIsCurrentUser ? 'white' : 'var(--color-text-primary)',
                    borderRadius: 'var(--message-bubble-radius)',
                    wordBreak: "break-word",
                    whiteSpace: isMarkdown ? "normal" : "pre-wrap",
                    minWidth: '3rem',
                    maxWidth: '100%'
                  }}
                  onContextMenu={handleContextMenu}
                >
                  {isMarkdown ? (
                    <MarkdownRenderer
                      content={content}
                      isCurrentUser={safeIsCurrentUser}
                      className="compact"
                      preCalculatedContent={markdownContent}
                    />
                  ) : (
                    <LinkifyWithPreviews
                      options={{ rel: "noopener noreferrer" }}
                      showPreviews={false}
                      isCurrentUser={safeIsCurrentUser}
                      urls={urls}
                    >
                      {content}
                    </LinkifyWithPreviews>
                  )}
                </div>
              </div>
            );
          })()}
        </div>

        <div
          className={cn(
            "flex items-center gap-2 mt-1 text-xs",
            safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
          )}>

          {message.isEdited && (
            <span
              className="italic"
              style={{ color: 'var(--color-text-secondary)' }}
              role="status"
              aria-label="Message edited"
            >
              (edited)
            </span>
          )}
        </div>

        {message.reactions && Object.keys(message.reactions).length > 0 && (
          <div
            className="flex flex-wrap gap-1 mt-1"
            role="group"
            aria-label="Message reactions"
            style={{ userSelect: 'none' }}
          >
            {Object.entries(message.reactions).map(([emoji, users]) => {
              const hasReacted = currentUsername ? users.includes(currentUsername) : false;
              return (
                <button
                  key={emoji}
                  className={cn(
                    "px-2 py-0.5 rounded-full text-xs border",
                    hasReacted && "font-semibold"
                  )}
                  style={{
                    backgroundColor: hasReacted ? 'var(--color-accent-primary)' : 'var(--color-surface)',
                    borderColor: hasReacted ? 'var(--color-accent-primary)' : 'rgba(255,255,255,0.22)',
                    color: hasReacted ? 'var(--color-on-accent)' : 'var(--color-text-primary)',
                    userSelect: 'none'
                  }}
                  onClick={() => onReact?.(message, emoji)}
                  aria-label={`${emoji} reaction, ${users.length} user${users.length !== 1 ? 's' : ''}`}
                >
                  <span className="mr-1" aria-hidden="true">{emoji}</span>
                  <span>{users.length}</span>
                </button>
              );
            })}
          </div>
        )}

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
        />
      )}

      {contextMenu && (
        <MessageContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          onClose={() => setContextMenu(null)}
          onEdit={!isFileMessageType && safeIsCurrentUser ? handleEdit : undefined}
          onReply={handleReply}
          onDelete={safeIsCurrentUser ? handleDelete : undefined}
          onReact={() => openPicker(messageTriggerId)}
          onReactionSelect={handlePickEmoji}
          onDownload={isDownloadable ? handleDownload : undefined}
          canEdit={!isFileMessageType && safeIsCurrentUser}
          canDelete={safeIsCurrentUser}
          isFile={isFileMessageType}
        />
      )}
    </div>
  );
});
