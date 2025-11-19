import { useRef, useCallback } from "react";
import { Button } from "../../ui/button";
import { PaperclipIcon } from "../icons.tsx";
import { cn } from "@/lib/utils";

interface FileUploaderProps {
  readonly onFileSelected: (file: File) => void;
  readonly disabled?: boolean;
}

export function FileUploader({ onFileSelected, disabled }: FileUploaderProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>): void => {
    const file = e.target.files?.[0];
    if (file) {
      onFileSelected(file);
    }
    e.target.value = "";
  }, [onFileSelected]);

  const handleClick = useCallback((): void => {
    if (!disabled) {
      fileInputRef.current?.click();
    }
  }, [disabled]);



  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className={cn(
          "h-8 w-8 rounded-full transition-all duration-200 flex items-center justify-center flex-shrink-0",
          "focus:outline-none focus:ring-0 focus-visible:ring-0 focus-visible:ring-offset-0",
          "text-muted-foreground hover:bg-muted hover:text-foreground",
          disabled && "opacity-50 cursor-not-allowed"
        )}
        onClick={handleClick}
        disabled={disabled}
        type="button"
      >
        <PaperclipIcon className="h-5 w-5" />
      </Button>
      <input ref={fileInputRef} type="file" className="hidden" onChange={handleChange} />
    </>
  );
}