import React from "react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";
import { UserAvatar } from "../../ui/UserAvatar";

interface DeletedMessageProps {
  sender: string;
  timestamp: Date;
  isCurrentUser?: boolean;
}

export function DeletedMessage({ sender, timestamp, isCurrentUser }: DeletedMessageProps) {
  const safeIsCurrentUser = isCurrentUser || false;

  return (
    <div className={cn("flex gap-3 mb-4 group", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")} style={{ marginBottom: 'var(--spacing-md)' }}>
      {/* Avatar*/}
      <div className="flex-shrink-0 w-10">
        <UserAvatar
          username={sender}
          isCurrentUser={safeIsCurrentUser}
          size="md"
        />
      </div>

      {/* Message Content */}
      <div className={cn("flex flex-col min-w-0", safeIsCurrentUser ? "items-end" : "items-start")} style={{ maxWidth: 'var(--message-bubble-max-width)' }}>
        <div className={cn("flex items-center gap-2 mb-1", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")}>
          <span
            className="text-sm font-medium"
            style={{ color: 'var(--color-text-primary)' }}
          >
            {sender}
          </span>
          <span
            className="text-xs"
            style={{ color: 'var(--color-text-secondary)' }}
          >
            {format(timestamp, "h:mm a")}
          </span>
        </div>

        <div
          className="px-4 py-3 text-sm whitespace-pre-wrap break-words italic"
          style={{
            backgroundColor: 'var(--color-surface)',
            color: 'var(--color-text-secondary)',
            borderRadius: 'var(--message-bubble-radius)',
            border: '1px dashed var(--color-border)',
            minWidth: '3rem',
            userSelect: 'none'
          }}
        >
          Message deleted
        </div>
      </div>
    </div >
  );
}