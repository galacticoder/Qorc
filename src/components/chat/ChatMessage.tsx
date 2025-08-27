import React from "react";
import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { format, isSameMinute } from "date-fns";
import Linkify from "linkify-react";
import { TrashIcon, Pencil1Icon } from "./icons.tsx";

import { ChatMessageProps } from "./types.ts";
import { SystemMessage } from "./ChatMessage/SystemMessage.tsx";
import { DeletedMessage } from "./ChatMessage/DeletedMessage.tsx";
import { FileMessage } from "./ChatMessage/FileMessage.tsx";
import { MessageReceipt } from "./MessageReceipt.tsx";

export function ChatMessage({ message, onReply, previousMessage, onDelete, onEdit }: ChatMessageProps) {
  const { content, sender, timestamp, isCurrentUser, isSystemMessage, isDeleted, type } = message;

  const isGrouped =
    previousMessage &&
    previousMessage.sender === sender &&
    isSameMinute(previousMessage.timestamp, timestamp);

  if (isSystemMessage) {
    return <SystemMessage content={content} />;
  }

  if (isDeleted) {
    return <DeletedMessage sender={sender} timestamp={timestamp} isCurrentUser={isCurrentUser} />;
  }

  if (type === "FILE_MESSAGE") {
    return <FileMessage message={message} isCurrentUser={isCurrentUser} />;
  }

  return (
    <div className={cn("flex items-start gap-2 mb-4", isCurrentUser ? "flex-row-reverse" : "")}>
      <div className={cn("w-9 h-9", isGrouped ? "invisible" : "mb-5")}>
        {!isGrouped && (
          <Avatar className="w-9 h-9">
            <AvatarFallback className={cn(isCurrentUser ? "bg-blue-500 text-white" : "bg-muted")}>
              {sender.charAt(0).toUpperCase()}
            </AvatarFallback>
          </Avatar>
        )}
      </div>

      <div
        className={cn("flex flex-col min-w-0", isCurrentUser ? "items-end" : "items-start")}
        style={{ maxWidth: "75%" }}
      >
        {!isGrouped && (
          <div className="flex items-center gap-2 mt-1">
            <span className="text-sm font-medium">{sender}</span>
            <span className="text-xs text-muted-foreground">{format(timestamp, "h:mm a")}</span>
          </div>
        )}

        {message.replyTo && (
          <div className="mb-1 p-2 border-l-2 border-blue-500 bg-blue-50 text-xs text-gray-500 rounded max-w-full truncate">
            <span className="font-medium">{message.replyTo.sender}</span>:{" "}
            <span className="italic">
              {message.replyTo.content === "Message deleted"
                ? "Message deleted"
                : message.replyTo.content.slice(0, 100) +
                (message.replyTo.content.length > 100 ? "..." : "")}
            </span>
          </div>
        )}



        <div className={cn("group flex items-center gap-2", isCurrentUser ? "flex-row-reverse" : "")}>
          <div
            className={cn(
              "rounded-lg px-3 py-2 text-sm min-w-[5rem] whitespace-pre-wrap break-words",
              isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
            )}
            style={{ wordBreak: "break-word", whiteSpace: "pre-wrap" }}
          >
            <Linkify options={{ target: "_blank", rel: "noopener noreferrer" }}>{content}</Linkify>
          </div>

          {/* Action Buttons */}
          <div
            className={cn(
              "flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
              isCurrentUser ? "mr-1 flex-row-reverse" : "ml-1"
            )}
          >
            <button
              onClick={() => navigator.clipboard.writeText(content)}
              aria-label="Copy message"
              className="hover:text-primary"
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
              className="hover:text-primary"
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

            {isCurrentUser && !isSystemMessage && (
              <button onClick={() => onDelete?.(message)} aria-label="Delete message" className="hover:text-destructive">
                <TrashIcon className="w-4 h-4" />
              </button>
            )}

            {message.isEdited && <span className="text-xs text-muted-foreground italic">(edited)</span>}

            {isCurrentUser && !message.isDeleted && (
              <button onClick={() => onEdit?.(message.content)} aria-label="Edit message" className="hover:text-primary">
                <Pencil1Icon className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Message Receipt */}
        <MessageReceipt
          receipt={message.receipt}
          isCurrentUser={isCurrentUser}
          className="mt-1"
        />
      </div>
    </div>
  );
}
