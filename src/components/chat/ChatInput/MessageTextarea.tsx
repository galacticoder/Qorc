import { useEffect } from "react";
import { Textarea } from "../../ui/textarea";
import { cn } from "@/lib/utils";

interface MessageTextareaProps {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  onKeyDown: (e: React.KeyboardEvent) => void;
  textareaRef: React.RefObject<HTMLTextAreaElement>;
}

export function MessageTextarea({ value, onChange, onKeyDown, textareaRef }: MessageTextareaProps) {
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 120) + "px";
    }
  }, [value]);

  return (
    <Textarea
      ref={textareaRef}
      value={value}
      onChange={onChange}
      onKeyDown={onKeyDown}
      placeholder="Type a message..."
      className={cn(
        "min-h-[39px] max-h-[100px] resize-none border-0 bg-transparent px-0 py-2 text-sm",
        "focus-visible:ring-0 focus-visible:ring-offset-0",
        "text-slate-900 placeholder:text-slate-500"
      )}
      rows={1}
    />
  );
}