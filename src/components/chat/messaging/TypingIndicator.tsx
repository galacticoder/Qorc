import React, { memo } from "react";
import { cn } from "../../../lib/utils";
import { useUnifiedUsernameDisplay } from "../../../hooks/database/useUnifiedUsernameDisplay";

interface TypingIndicatorProps {
  username: string;
  className?: string;
  getDisplayUsername?: (username: string) => Promise<string>;
}

export const TypingIndicator = memo(function TypingIndicator({ username, className, getDisplayUsername }: TypingIndicatorProps) {
  const { displayName } = useUnifiedUsernameDisplay({
    username,
    getDisplayUsername,
    fallbackToOriginal: true
  });

  return (
    <div className={cn("flex items-center gap-2 mb-2", className)} style={{ marginLeft: '50px' }} aria-live="polite" aria-atomic="true">
      <div
        className="px-4 py-3 rounded-2xl rounded-tl-none select-none"
        style={{
          backgroundColor: 'var(--color-typing-bubble)',
          borderTopLeftRadius: '4px'
        }}
      >
        <div className="flex items-center gap-1 h-4" aria-hidden="true">
          <div className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: 'var(--color-typing-dot)', animationDelay: '0ms', animationDuration: '1.4s' }} />
          <div className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: 'var(--color-typing-dot)', animationDelay: '200ms', animationDuration: '1.4s' }} />
          <div className="w-2 h-2 rounded-full animate-bounce" style={{ backgroundColor: 'var(--color-typing-dot)', animationDelay: '400ms', animationDuration: '1.4s' }} />
        </div>
        <span className="sr-only">{displayName} is typing</span>
      </div>
    </div>
  );
});