import { cn } from "../../../../lib/utils/shared-utils";
import { format } from "date-fns";
import { useEffect, useState } from 'react';

interface DeletedMessageProps {
  senderUsername: string;
  timestamp: Date;
  isCurrentUser?: boolean;
}

export function DeletedMessage({ senderUsername, timestamp, isCurrentUser }: DeletedMessageProps) {
  const safeIsCurrentUser = isCurrentUser || false;
  const [showSentTime, setShowSentTime] = useState(false);
  useEffect(() => setShowSentTime(false), [senderUsername, timestamp]);

  return (
    <div className={cn("flex gap-3 mb-4 group", safeIsCurrentUser ? "flex-row-reverse" : "flex-row")} style={{ marginBottom: safeIsCurrentUser ? '14px' : '18px' }}>
      {/* Message Content */}
      <div className={cn("flex flex-col min-w-0", safeIsCurrentUser ? "items-end" : "items-start")} style={{ maxWidth: 'min(var(--message-bubble-max-width), 100%)' }}>
        <div
          className="qorc-deleted-message-bubble qorc-text-bubble whitespace-pre-wrap break-words italic"
          role="button"
          tabIndex={0}
          aria-label={`Deleted message; ${showSentTime ? 'hide' : 'show'} sent time`}
          onClick={() => setShowSentTime(value => !value)}
          onKeyDown={event => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            setShowSentTime(value => !value);
          }}
          style={{
            borderRadius: 'var(--message-bubble-radius)',
            minWidth: '3rem',
            userSelect: 'none'
          }}
        >
          Message deleted
        </div>
        {showSentTime && <time className="qorc-message-sent-time text-xs mt-1" dateTime={timestamp.toISOString()}>{format(timestamp, 'h:mm a')}</time>}
      </div>
    </div >
  );
}
