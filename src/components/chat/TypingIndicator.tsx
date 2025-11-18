import React, { memo } from "react";
import { cn } from "../../lib/utils";
import { useUnifiedUsernameDisplay } from "../../hooks/useUnifiedUsernameDisplay";

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
    <div className={cn("flex items-center gap-2 text-sm text-muted-foreground", className)} aria-live="polite" aria-atomic="true">
      <span className="font-medium text-foreground">{displayName}</span>
      <span>is typing</span>
      <div className="flex items-center gap-1" aria-hidden="true">
        <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: '0ms', animationDuration: '1s' }} />
        <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: '150ms', animationDuration: '1s' }} />
        <div className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce" style={{ animationDelay: '300ms', animationDuration: '1s' }} />
      </div>
    </div>
  );
});