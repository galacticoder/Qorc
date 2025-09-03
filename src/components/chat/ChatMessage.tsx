import React, { useState, useEffect } from "react";
import { cn } from "../../lib/utils";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { format, isSameMinute } from "date-fns";
import Linkify from "linkify-react";
import { TrashIcon, Pencil1Icon } from "./icons.tsx";

import { ChatMessageProps } from "./types.ts";
import { SystemMessage } from "./ChatMessage/SystemMessage.tsx";
import { DeletedMessage } from "./ChatMessage/DeletedMessage.tsx";
import { FileMessage } from "./ChatMessage/FileMessage.tsx";
import { VoiceMessage } from "./VoiceMessage.tsx";
import { MessageReceipt } from "./MessageReceipt.tsx";

interface ExtendedChatMessageProps extends ChatMessageProps {
  getDisplayUsername?: (username: string) => Promise<string>;
}

export function ChatMessage({ message, onReply, previousMessage, onDelete, onEdit, getDisplayUsername }: ExtendedChatMessageProps) {
  const { content, sender, timestamp, isCurrentUser, isSystemMessage, isDeleted, type } = message;
  const [displaySender, setDisplaySender] = useState(sender);
  const [displayReplyToSender, setDisplayReplyToSender] = useState(message.replyTo?.sender || "");

  // Load display usernames
  useEffect(() => {
    if (getDisplayUsername) {
      getDisplayUsername(sender)
        .then(setDisplaySender)
        .catch((error) => {
          console.error('Failed to get display username for sender:', error);
          setDisplaySender(sender);
        });
      if (message.replyTo?.sender) {
        getDisplayUsername(message.replyTo.sender)
          .then(setDisplayReplyToSender)
          .catch((error) => {
            console.error('Failed to get display username for reply sender:', error);
            setDisplayReplyToSender(message.replyTo?.sender || "");
          });
      }
    }
  }, [sender, message.replyTo?.sender, getDisplayUsername]);

  const isGrouped =
    previousMessage &&
    previousMessage.sender === sender &&
    isSameMinute(previousMessage.timestamp, timestamp);

  // Ensure isCurrentUser is always boolean
  const safeIsCurrentUser = isCurrentUser || false;

  if (isSystemMessage) {
    return <SystemMessage content={content} />;
  }

  if (isDeleted) {
    return <DeletedMessage sender={displaySender} timestamp={timestamp} isCurrentUser={isCurrentUser || false} />;
  }

  if (type === "FILE_MESSAGE" || type === "file" || type === "file-message") {
    // Check if it's a voice note (audio file)
    const isVoiceNote = message.filename?.includes('voice-note') ||
                       (message.mimeType && message.mimeType.startsWith('audio/')) ||
                       (message.filename && /\.(webm|mp3|wav|ogg|m4a)$/i.test(message.filename));

    if (isVoiceNote) {
      return (
        <VoiceMessage
          audioUrl={message.content}
          sender={displaySender}
          timestamp={message.timestamp}
          isCurrentUser={isCurrentUser || false}
          filename={message.filename}
          originalBase64Data={message.originalBase64Data}
          mimeType={message.mimeType}
        />
      );
    }

    return <FileMessage message={message} isCurrentUser={isCurrentUser || false} />;
  }

  return (
    <div 
      className={cn(
        "flex gap-3 mb-4 group",
        safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
      )}
      style={{ 
        marginBottom: isGrouped ? 'var(--spacing-xs)' : 'var(--spacing-md)'
      }}
    >
      {/* Avatar - only show for non-grouped messages */}
      <div className={cn("flex-shrink-0", isGrouped ? "w-10" : "w-10")}>
        {!isGrouped && (
          <div 
            className="w-10 h-10 rounded-full flex items-center justify-center font-medium text-sm"
            style={{
              backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-accent-secondary)',
              color: 'white'
            }}
          >
            {displaySender.charAt(0).toUpperCase()}
          </div>
        )}
      </div>

      {/* Message Content */}
      <div
        className={cn(
          "flex flex-col min-w-0",
          safeIsCurrentUser ? "items-end" : "items-start"
        )}
        style={{ maxWidth: 'var(--message-bubble-max-width)' }}
      >
        {/* Sender name and timestamp - only for non-grouped messages */}
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
              className="text-xs"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              {format(timestamp, "h:mm a")}
            </span>
          </div>
        )}

        {/* Reply indicator */}
        {message.replyTo && (
          <div 
            className="mb-2 p-3 rounded-lg text-sm max-w-full"
            style={{
              backgroundColor: 'var(--color-muted-panel)',
              borderLeft: '3px solid var(--color-accent-primary)',
              color: 'var(--color-text-secondary)'
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
              </svg>
              <span className="font-semibold">{displayReplyToSender}</span>
            </div>
            <p className="line-clamp-2">
              {message.replyTo.content === "Message deleted"
                ? "Message deleted"
                : message.replyTo.content.slice(0, 100) +
                (message.replyTo.content.length > 100 ? "..." : "")}
            </p>
          </div>
        )}

        {/* Message bubble */}
        <div className={cn("flex items-end gap-2", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")}>
          <div
            className="px-4 py-3 text-sm whitespace-pre-wrap break-words"
            style={{
              backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-surface)',
              color: safeIsCurrentUser ? 'white' : 'var(--color-text-primary)',
              borderRadius: 'var(--message-bubble-radius)',
              wordBreak: "break-word",
              whiteSpace: "pre-wrap",
              minWidth: '3rem',
              maxWidth: '100%'
            }}
          >
            <Linkify options={{ target: "_blank", rel: "noopener noreferrer" }}>{content}</Linkify>
          </div>

          {/* Action Buttons */}
          <div
            className={cn(
              "flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
              "p-1 rounded"
            )}
            style={{
              backgroundColor: 'var(--color-surface)',
              boxShadow: 'var(--shadow-elevation-low)'
            }}
          >
            <button
              onClick={() => navigator.clipboard.writeText(content)}
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
              onClick={() => onReply?.(message)}
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
                onClick={() => onDelete?.(message)} 
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

            {safeIsCurrentUser && !message.isDeleted && (
              <button 
                onClick={() => onEdit?.(message.content)} 
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
          </div>
        </div>

        {/* Message metadata */}
        <div 
          className={cn(
            "flex items-center gap-2 mt-1 text-xs",
            safeIsCurrentUser ? "flex-row-reverse" : "flex-row"
          )}>
          {/* Timestamp for grouped messages */}
          {isGrouped && (
            <span style={{ color: 'var(--color-text-secondary)' }}>
              {format(timestamp, "h:mm a")}
            </span>
          )}
          
          {/* Edited indicator */}
          {message.isEdited && (
            <span 
              className="italic"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              (edited)
            </span>
          )}
        </div>

        {/* Message Receipt */}
        <MessageReceipt
          receipt={message.receipt}
          isCurrentUser={isCurrentUser || false}
          className="mt-1"
        />
      </div>
    </div>
  );
}