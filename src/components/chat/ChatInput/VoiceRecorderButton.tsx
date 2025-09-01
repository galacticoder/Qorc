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
        "h-10 w-10 rounded-full transition-all duration-200",
        disabled && "opacity-50 cursor-not-allowed",
        "hover:bg-slate-200 text-slate-500 hover:text-slate-700"
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
