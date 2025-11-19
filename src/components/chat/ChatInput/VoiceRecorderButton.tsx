import { useCallback } from "react";
import { Button } from "../../ui/button";
import { Mic } from "lucide-react";
import { cn } from "@/lib/utils";

interface VoiceRecorderButtonProps {
  readonly onClick: () => void;
  readonly disabled?: boolean;
}

export function VoiceRecorderButton({ onClick, disabled }: VoiceRecorderButtonProps) {


  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn(
        "h-8 w-8 rounded-full transition-all duration-200 flex items-center justify-center flex-shrink-0",
        "focus:outline-none focus:ring-0 focus-visible:ring-0 focus-visible:ring-offset-0",
        "text-muted-foreground hover:bg-muted hover:text-foreground",
        disabled && "opacity-50 cursor-not-allowed"
      )}
      onClick={onClick}
      disabled={disabled}
      type="button"
      title="Record voice note"
    >
      <Mic className="h-5 w-5" />
    </Button>
  );
}