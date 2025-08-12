import { Button } from "../../ui/button.tsx";
import { PaperPlaneIcon } from "../icons.tsx";
import { cn } from "@/lib/utils";
import { Message } from "../types";

interface SendButtonProps {
  disabled: boolean;
  isSending: boolean;
  editingMessage?: Message | null;
  onClick: () => void;
}

export function SendButton({ disabled, isSending, editingMessage, onClick }: SendButtonProps) {
  return (
    <Button
      onClick={onClick}
      size="sm"
      disabled={disabled}
      className={cn(
        "h-10 w-10 rounded-full text-white shadow-md transition-all duration-200",
        disabled ? "opacity-50 cursor-not-allowed bg-gray-400" :
          editingMessage ? "bg-yellow-500 hover:bg-yellow-600" : "bg-slate-600 hover:bg-slate-700"
      )}
    >
      {isSending ? (
        <svg className="h-5 w-5 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          ></path>
        </svg>
      ) : editingMessage ? (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
          />
        </svg>
      ) : (
        <PaperPlaneIcon className="h-5 w-5" />
      )}
    </Button>
  );
}
