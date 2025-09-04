import { Button } from "../../ui/button";
import { Mic } from "lucide-react";
import { cn } from "@/lib/utils";

interface VoiceRecorderButtonProps {
  onClick: () => void;
  disabled?: boolean;
}

export function VoiceRecorderButton({ onClick, disabled }: VoiceRecorderButtonProps) {
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn(
        "h-8 w-8 rounded-full transition-all duration-200 flex items-center justify-center flex-shrink-0",
        "focus:outline-none focus:ring-0 focus-visible:ring-0 focus-visible:ring-offset-0",
        disabled && "opacity-50 cursor-not-allowed"
      )}
      style={{
        color: 'var(--color-text-secondary)',
        backgroundColor: 'transparent'
      }}
      onMouseEnter={(e) => {
        if (!disabled) {
          e.currentTarget.style.backgroundColor = 'var(--color-surface)';
          e.currentTarget.style.color = 'var(--color-text-primary)';
        }
      }}
      onMouseLeave={(e) => {
        if (!disabled) {
          e.currentTarget.style.backgroundColor = 'transparent';
          e.currentTarget.style.color = 'var(--color-text-secondary)';
        }
      }}
      onClick={onClick}
      disabled={disabled}
      type="button"
      title="Record voice note"
    >
      <Mic className="h-5 w-5" />
    </Button>
  );
}