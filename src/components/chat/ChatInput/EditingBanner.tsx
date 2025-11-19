import { Button } from "../../ui/button";
import { cn } from "@/lib/utils";
import { Cross2Icon } from "../icons";

interface EditingBannerProps {
  readonly onCancelEdit?: () => void;
}

export function EditingBanner({ onCancelEdit }: EditingBannerProps) {
  return (
    <div className="px-4 pt-3 pb-0">
      <div
        className={cn(
          "flex items-center justify-between p-3 border-l-4 rounded-lg shadow-sm",
          "bg-muted/50 border-yellow-500/50 text-foreground"
        )}
      >
        <span className="text-sm font-medium text-yellow-600 dark:text-yellow-500">Editing message</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground"
          onClick={onCancelEdit}
        >
          <Cross2Icon className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}