import { Cross2Icon } from "../icons";
import { Pencil } from "lucide-react";

interface EditingBannerProps {
  readonly onCancelEdit?: () => void;
}

export function EditingBanner({ onCancelEdit }: EditingBannerProps) {
  return (
    <div className="px-4 py-2">
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-yellow-500/10 text-yellow-600 dark:text-yellow-500">
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