import { memo } from "react";
import { cn } from "../../../lib/utils/shared-utils";
import { useDisplayUsername } from "../../../hooks/database/useDisplayUsername";

interface TypingIndicatorProps {
  username: string;
  className?: string;
}

export const TypingBubble = memo(function TypingBubble({ compact = false }: { compact?: boolean }) {
  return (
    <span className={cn('qorc-typing-bubble', compact && 'is-compact')} aria-hidden="true">
      <span className="qorc-typing-bubble-dots">
        <span />
        <span />
        <span />
      </span>
    </span>
  );
});

export const TypingIndicator = memo(function TypingIndicator({ username, className }: TypingIndicatorProps) {
  const displayName = useDisplayUsername({ username });

  return (
    <div className={cn("flex items-center gap-2 mb-2", className)} style={{ marginLeft: '50px' }} aria-live="polite" aria-atomic="true">
      <TypingBubble />
      <span className="sr-only">{displayName} is typing</span>
    </div>
  );
});
