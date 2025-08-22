import React, { memo } from "react";
import { cn } from "@/lib/utils";

interface TypingIndicatorProps {
  username: string;
  className?: string;
}

// Memoized component to prevent unnecessary re-renders
export const TypingIndicator = memo(function TypingIndicator({ username, className }: TypingIndicatorProps) {
  return (
    <div className={cn("flex items-center gap-2 text-sm text-muted-foreground animate-in fade-in duration-200", className)}>
      <span className="font-medium text-foreground">{username}</span>
      <span>is typing</span>
      <div className="flex items-center gap-1">
        <div
          className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce"
          style={{ animationDelay: '0ms', animationDuration: '1s' }}
        />
        <div
          className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce"
          style={{ animationDelay: '150ms', animationDuration: '1s' }}
        />
        <div
          className="w-1.5 h-1.5 bg-primary rounded-full animate-bounce"
          style={{ animationDelay: '300ms', animationDuration: '1s' }}
        />
      </div>
    </div>
  );
});
