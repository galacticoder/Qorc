import React, { useRef, useMemo, useCallback } from "react";
import { cn } from "../../lib/utils";
import { format, isSameMinute, isToday, isYesterday, isThisYear } from "date-fns";
import { TrashIcon, Pencil1Icon, DownloadIcon } from "./icons.tsx";
import { EmojiPicker } from "../ui/EmojiPicker";
import { useEmojiPicker } from "../../contexts/EmojiPickerContext";
import { ChatMessageProps } from "./types.ts";
import { SystemMessage } from "./ChatMessage/SystemMessage.tsx";
import { DeletedMessage } from "./ChatMessage/DeletedMessage.tsx";
import { FileContent } from "./ChatMessage/FileMessage.tsx";
import { VoiceMessage } from "./VoiceMessage";
import { MessageReceipt } from "./MessageReceipt.tsx";
import { useUnifiedUsernameDisplay } from "../../hooks/useUnifiedUsernameDisplay";
import { LinkifyWithPreviews } from "./LinkifyWithPreviews.tsx";
import { LinkExtractor } from "../../lib/link-extraction.ts";
import { MarkdownRenderer } from "../ui/MarkdownRenderer";
import { isMarkdownMessage } from "../../lib/markdown-parser";
import { copyTextToClipboard } from "../../lib/clipboard";

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

const parseSystemMessage = (content: string, message: any): { label: string; actions?: SystemAction[] } => {
  if (!isValidJson(content)) {
    return { label: content };
  }

  try {
    const parsed = JSON.parse(content);
    if (!parsed || typeof parsed !== 'object' || !parsed.label) {
      return { label: content };
    }

    const label = typeof parsed.label === 'string' ? parsed.label : content;

    if (parsed.actionsType === 'callback' && message) {
      const peer = message.sender === 'System' ? (message.recipient || '') : message.sender;
      if (typeof peer === 'string' && peer.length > 0) {
        const actions: SystemAction[] = [{
          label: 'Call back',
          onClick: () => {
            try {
              window.dispatchEvent(new CustomEvent('ui-call-request', { detail: { peer, type: 'audio' } }));
            } catch { }
          }
        }];
        return { label, actions };
      }
    }

    return { label };
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

export const ChatMessage = React.memo<ExtendedChatMessageProps>(({ message, onReply, previousMessage, onDelete, onEdit, onReact, getDisplayUsername, currentUsername }) => {
  const { content, sender, timestamp, isCurrentUser, isSystemMessage, isDeleted, type } = message;

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


  const isUrlOnly = useMemo(() => LinkExtractor.isUrlOnlyMessage(content), [content]);
  const urls = useMemo(() => LinkExtractor.extractUrlStrings(content), [content]);
  const isMarkdown = useMemo(() => isMarkdownMessage(content), [content]);

  const isFileMessageType =
    type === "FILE_MESSAGE" ||
    type === "file" ||
    type === "file-message";

  const isVoiceNote = useMemo(() => {
    if (!isFileMessageType) return false;
    const name = (message.filename || '').toLowerCase();
    return name.includes('voice-note');
  }, [isFileMessageType, message.filename]);

  const isImage = useMemo(() => {
    if (!isFileMessageType) return false;
    const name = (message.filename || '').toLowerCase();
    const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    return imageExtensions.some(ext => name.endsWith('.' + ext));
  }, [isFileMessageType, message.filename]);

  const timestampDisplay = useMemo(() => formatTimestamp(timestamp), [timestamp]);
  const avatarLetter = useMemo(() => displaySender.charAt(0).toUpperCase(), [displaySender]);

  const handlePickEmoji = useCallback((emoji: string) => {
    if (currentUsername && message.reactions) {
      for (const [e, users] of Object.entries(message.reactions)) {
        if (users.includes(currentUsername) && e !== emoji) {
          onReact?.(message, e);
        }
      }
    }
    onReact?.(message, emoji);
  }, [currentUsername, message, onReact]);

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
    onEdit?.(message.content);
  }, [onEdit, message.content]);

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
    } catch (_error) {
      alert('Failed to download file.');
    }
  }, [message, content, timestamp]);

  if (isSystemMessage) {
    const { label, actions } = parseSystemMessage(content, message);
    return <SystemMessage content={label} actions={actions} />;
  }

  if (isDeleted) {
    return <DeletedMessage sender={displaySender} timestamp={timestamp} isCurrentUser={safeIsCurrentUser} />;
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
          <div
            className="w-10 h-10 rounded-full flex items-center justify-center font-medium text-sm select-none"
            style={{
              backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-accent-secondary)',
              color: 'white'
            }}
            aria-hidden="true"
          >
            {avatarLetter}
          </div>
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
            className="mb-2 p-3 rounded-lg text-sm max-w-full"
            style={{
              backgroundColor: 'var(--color-muted-panel)',
              borderLeft: '3px solid var(--color-accent-primary)',
              color: 'var(--color-text-secondary)'
            }}
            role="note"
            aria-label={`Reply to ${displayReplyToSender}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
              </svg>
              <span className="font-semibold">{displayReplyToSender}</span>
            </div>
            <div className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>
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
          <div className="mb-3">
            <LinkifyWithPreviews
              options={{ rel: "noopener noreferrer" }}
              showPreviews={true}
              isCurrentUser={safeIsCurrentUser}
              previewsOnly={true}
            >
              {content}
            </LinkifyWithPreviews>
          </div>
        )}

        {/* Message bubble */}
        <div className={cn("flex items-end gap-2", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")}>
          {/* Render file content or text content */}
          {isFileMessageType ? (
            <div className="max-w-[60%] relative" ref={bubbleRef}>
              {isImage ? (
                <FileContent message={message} isCurrentUser={safeIsCurrentUser} />
              ) : (
                <div
                  className="px-2 py-2"
                  style={{
                    backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-surface)',
                    color: safeIsCurrentUser ? 'white' : 'var(--color-text-primary)',
                    borderRadius: 'var(--message-bubble-radius)',
                    overflow: 'hidden'
                  }}
                >
                  {isVoiceNote ? (
                    <VoiceMessage
                      audioUrl={typeof content === 'string' ? content : ''}
                      timestamp={timestamp}
                      isCurrentUser={safeIsCurrentUser}
                      filename={message.filename}
                      originalBase64Data={message.originalBase64Data}
                      mimeType={message.mimeType}
                    />
                  ) : (
                    <FileContent message={message} isCurrentUser={safeIsCurrentUser} />
                  )}
                </div>
              )}
            </div>
          ) : (() => {
            const showPreviews = !isSystemMessage && !isDeleted;

            if (isUrlOnly && showPreviews) {
              // For URL-only messages, render LinkifyWithPreviews without bubble styling
              return (
                <div className="max-w-[80%] relative" ref={bubbleRef}>
                  <LinkifyWithPreviews
                    options={{ rel: "noopener noreferrer" }}
                    showPreviews={true}
                    isCurrentUser={safeIsCurrentUser}
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
                    backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-surface)',
                    color: safeIsCurrentUser ? 'white' : 'var(--color-text-primary)',
                    borderRadius: 'var(--message-bubble-radius)',
                    wordBreak: "break-word",
                    whiteSpace: isMarkdown ? "normal" : "pre-wrap",
                    minWidth: '3rem',
                    maxWidth: '100%'
                  }}
                >
                  {isMarkdown ? (
                    <MarkdownRenderer
                      content={content}
                      isCurrentUser={safeIsCurrentUser}
                      className="compact"
                    />
                  ) : (
                    <LinkifyWithPreviews
                      options={{ rel: "noopener noreferrer" }}
                      showPreviews={false}
                      isCurrentUser={safeIsCurrentUser}
                    >
                      {content}
                    </LinkifyWithPreviews>
                  )}
                </div>
              </div>
            );
          })()}

          <div className="flex items-end">
            <button
              data-emoji-add-button
              data-emoji-trigger={messageTriggerId}
              className={`w-5 h-5 rounded-full text-[11px] flex items-center justify-center border transition-opacity duration-200 ${pickerOpen ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
                }`}
              style={{
                backgroundColor: 'var(--color-surface)',
                borderColor: 'var(--color-border)',
                color: 'var(--color-text-secondary)',
                boxShadow: 'var(--shadow-elevation-low)',
                userSelect: 'none'
              }}
              onClick={handleTogglePicker}
              aria-label="Add reaction"
              title="Add reaction"
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
                e.currentTarget.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--color-surface)';
                e.currentTarget.style.color = 'var(--color-text-secondary)';
              }}
            >
              +
            </button>
          </div>

          <div
            className={cn(
              "flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
              "p-1 rounded"
            )}
            style={{
              backgroundColor: 'var(--color-surface)',
              boxShadow: 'var(--shadow-elevation-low)'
            }}
            role="toolbar"
            aria-label="Message actions"
          >
            <button
              onClick={handleCopyMessage}
              aria-label="Copy message"
              className="p-1 rounded hover:bg-opacity-80 transition-colors"
              style={{ color: 'var(--color-text-secondary)' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
                e.currentTarget.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'var(--color-text-secondary)';
              }}
            >
              <svg
                width="15"
                height="15"
                viewBox="0 0 15 15"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M1 9.50006C1 10.3285 1.67157 11.0001 2.5 11.0001H4L4 10.0001H2.5C2.22386 10.0001 2 9.7762 2 9.50006L2 2.50006C2 2.22392 2.22386 2.00006 2.5 2.00006L9.5 2.00006C9.77614 2.00006 10 2.22392 10 2.50006V4.00002H5.5C4.67158 4.00002 4 4.67159 4 5.50002V12.5C4 13.3284 4.67158 14 5.5 14H12.5C13.3284 14 14 13.3284 14 12.5V5.50002C14 4.67159 13.3284 4.00002 12.5 4.00002H11V2.50006C11 1.67163 10.3284 1.00006 9.5 1.00006H2.5C1.67157 1.00006 1 1.67163 1 2.50006V9.50006ZM5 5.50002C5 5.22388 5.22386 5.00002 5.5 5.00002H12.5C12.7761 5.00002 13 5.22388 13 5.50002V12.5C13 12.7762 12.7761 13 12.5 13H5.5C5.22386 13 5 12.7762 5 12.5V5.50002Z"
                  fill="currentColor"
                  fillRule="evenodd"
                  clipRule="evenodd"
                />
              </svg>
            </button>

            <button
              onClick={handleReply}
              aria-label="Reply to message"
              className="p-1 rounded hover:bg-opacity-80 transition-colors"
              style={{ color: 'var(--color-text-secondary)' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
                e.currentTarget.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'var(--color-text-secondary)';
              }}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth={1.5}
                stroke="currentColor"
                className="w-4 h-4"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 15 3 9m0 0 6-6M3 9h12a6 6 0 0 1 0 12h-3" />
              </svg>
            </button>

            {safeIsCurrentUser && !isSystemMessage && (
              <button
                onClick={handleDelete}
                aria-label="Delete message"
                className="p-1 rounded hover:bg-opacity-80 transition-colors"
                style={{ color: 'var(--color-text-secondary)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = '#ef4444';
                  e.currentTarget.style.color = 'white';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = 'var(--color-text-secondary)';
                }}
              >
                <TrashIcon className="w-4 h-4" />
              </button>
            )}

            {safeIsCurrentUser && !message.isDeleted && !isFileMessageType && (
              <button
                onClick={handleEdit}
                aria-label="Edit message"
                className="p-1 rounded hover:bg-opacity-80 transition-colors"
                style={{ color: 'var(--color-text-secondary)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
                  e.currentTarget.style.color = 'white';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = 'var(--color-text-secondary)';
                }}
              >
                <Pencil1Icon className="w-4 h-4" />
              </button>
            )}

            {isFileMessageType && (
              <button
                onClick={handleDownload}
                aria-label="Download file"
                className="p-1 rounded hover:bg-opacity-80 transition-colors"
                style={{ color: 'var(--color-text-secondary)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
                  e.currentTarget.style.color = 'white';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = 'var(--color-text-secondary)';
                }}
              >
                <DownloadIcon className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        <div
          className={cn(
            "flex items-center gap-2 mt-1 text-xs",
            safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
          )}>
          {/* No per-bubble bottom timestamp when grouped; only header on first bubble */}

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
            {Object.entries(message.reactions).map(([emoji, users]) => (
              <button
                key={emoji}
                className="px-2 py-0.5 rounded-full text-xs border"
                style={{
                  backgroundColor: 'var(--color-surface)',
                  borderColor: 'var(--color-border)',
                  color: 'var(--color-text-primary)',
                  userSelect: 'none'
                }}
                onClick={() => onReact?.(message, emoji)}
                aria-label={`${emoji} reaction, ${users.length} user${users.length !== 1 ? 's' : ''}`}
              >
                <span className="mr-1" aria-hidden="true">{emoji}</span>
                <span>{users.length}</span>
              </button>
            ))}
          </div>
        )}

        <MessageReceipt
          receipt={message.receipt}
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
        />
      )}
    </div>
  );
});
