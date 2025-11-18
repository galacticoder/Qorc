import { useEffect } from "react";
import { Textarea } from "../../ui/textarea";
import { cn } from "@/lib/utils";

interface MessageTextareaProps {
  readonly value: string;
  readonly onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  readonly onKeyDown: (e: React.KeyboardEvent) => void;
  readonly textareaRef: React.RefObject<HTMLTextAreaElement>;
  readonly disabled?: boolean;
}

const MAX_TEXTAREA_HEIGHT = 120;

export function MessageTextarea({ value, onChange, onKeyDown, textareaRef, disabled = false }: MessageTextareaProps) {
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, MAX_TEXTAREA_HEIGHT) + "px";
    }
  }, [value, textareaRef]);

  return (
    <Textarea
      ref={textareaRef}
      value={value}
      onChange={onChange}
      onKeyDown={onKeyDown}
      placeholder={disabled ? "Messages disabled" : "Type a message..."}
      disabled={disabled}
      className={cn(
        "min-h-[39px] max-h-[100px] resize-none border-0 bg-transparent px-0 py-2 text-sm",
        "focus-visible:ring-0 focus-visible:ring-offset-0 focus:outline-none focus:ring-0 focus:border-transparent",
        disabled && "opacity-50 cursor-not-allowed"
      )}
      aria-label="Message input"
      style={{
        color: 'var(--composer-text-color)',
        backgroundColor: 'transparent'
      }}
      rows={1}
    />
  );
}