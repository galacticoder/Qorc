import React from "react";
import { cn } from "@/lib/utils";

interface TypingIndicatorProps {
  username: string;
  className?: string;
}

export function TypingIndicator({ username, className }: TypingIndicatorProps) {
  return (
    <div className={cn("flex items-center gap-2 text-sm text-muted-foreground", className)}>
      <span className="font-medium">{username}</span>
      <span>is typing</span>
      <div className="flex items-center gap-1">
        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
      </div>
    </div>
  );
}
