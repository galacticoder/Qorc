import { useMemo } from "react";
import { Button } from "../../ui/button.tsx";
import { PaperPlaneIcon } from "../icons.tsx";
import { cn } from "@/lib/utils";
import { Message } from "../types";

interface SendButtonProps {
  readonly disabled: boolean;
  readonly isSending: boolean;
  readonly editingMessage?: Message | null;
  readonly onClick: () => void;
}

export function SendButton({ disabled, isSending, editingMessage, onClick }: SendButtonProps) {
  const buttonStyle = useMemo(() => ({
    backgroundColor: disabled ? 'var(--color-disabled)' : 
      editingMessage ? 'var(--color-warning)' : 'var(--color-accent-primary)',
    color: 'white'
  }), [disabled, editingMessage]);

  const buttonContent = useMemo(() => {
    if (isSending) {
      return (
        <svg className="h-5 w-5 animate-spin" fill="none" viewBox="0 0 24 24" aria-label="Sending">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          ></path>
        </svg>
      );
    }
    if (editingMessage) {
      return (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-label="Save edit">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
          />
        </svg>
      );
    }
    return <PaperPlaneIcon className="h-5 w-5" />;
  }, [isSending, editingMessage]);

  return (
    <Button
      onClick={onClick}
      size="sm"
      disabled={disabled}
      className={cn(
        "h-8 w-8 rounded-full text-white shadow-md transition-all duration-200 flex items-center justify-center flex-shrink-0",
        "focus:outline-none focus:ring-0 focus-visible:ring-0 focus-visible:ring-offset-0",
        disabled ? "opacity-50 cursor-not-allowed" : ""
      )}
      style={buttonStyle}
      aria-label={isSending ? "Sending message" : editingMessage ? "Save edit" : "Send message"}
    >
      {buttonContent}
    </Button>
  );
}