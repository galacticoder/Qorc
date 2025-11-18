import React from "react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";

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
        <div 
          className="w-10 h-10 rounded-full flex items-center justify-center font-medium text-sm"
          style={{
            backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-accent-secondary)',
            color: 'white'
          }}
        >
          {sender.charAt(0).toUpperCase()}
        </div>
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
            backgroundColor: safeIsCurrentUser ? 'var(--color-accent-primary)' : 'var(--color-surface)',
            color: safeIsCurrentUser ? 'white' : 'var(--color-text-secondary)',
            borderRadius: 'var(--message-bubble-radius)',
            opacity: 0.7,
            minWidth: '3rem'
          }}
        >
          Message deleted
        </div>
      </div>
    </div>
  );
}