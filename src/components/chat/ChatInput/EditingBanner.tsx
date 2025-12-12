import { Cross2Icon } from "../icons";
import { Pencil } from "lucide-react";

interface EditingBannerProps {
  readonly onCancelEdit?: () => void;
}

export function EditingBanner({ onCancelEdit }: EditingBannerProps) {
  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-background border-b border-yellow-500/20 rounded-t-xl relative select-none" style={{ backgroundColor: 'var(--chat-background)' }}>
      <div className="absolute inset-0 bg-yellow-500/10 pointer-events-none rounded-t-xl" />
      <div className="relative flex items-center gap-2 flex-1 min-w-0 text-yellow-600 dark:text-yellow-500">
        <Pencil className="w-3.5 h-3.5 flex-shrink-0" />
        <span className="text-xs font-medium flex-1">Editing message</span>
        <button
          className="flex-shrink-0 w-5 h-5 rounded hover:bg-yellow-500/20 flex items-center justify-center transition-colors"
          onClick={onCancelEdit}
          aria-label="Cancel edit"
        >
          <Cross2Icon className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}