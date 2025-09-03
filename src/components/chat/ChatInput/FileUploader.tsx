import { useRef } from "react";
import { Button } from "../../ui/button";
import { PaperclipIcon } from "../icons.tsx";
import { cn } from "@/lib/utils";

interface FileUploaderProps {
  onFileSelected: (file: File) => void;
  disabled?: boolean;
}

export function FileUploader({ onFileSelected, disabled }: FileUploaderProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onFileSelected(file);
    }
    e.target.value = "";
  };

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className={cn(
          "h-8 w-8 rounded-full transition-all duration-200 flex items-center justify-center flex-shrink-0",
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
        onClick={() => !disabled && fileInputRef.current?.click()}
        disabled={disabled}
        type="button"
      >
        <PaperclipIcon className="h-5 w-5" />
      </Button>
      <input ref={fileInputRef} type="file" className="hidden" onChange={handleChange} />
    </>
  );
}