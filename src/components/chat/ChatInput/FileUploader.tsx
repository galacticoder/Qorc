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
          "h-10 w-10 rounded-full transition-all duration-200",
          disabled && "opacity-50 cursor-not-allowed",
          "hover:bg-slate-200 text-slate-500 hover:text-slate-700"
        )}
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