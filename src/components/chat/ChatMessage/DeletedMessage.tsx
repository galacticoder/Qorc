import React from "react";
import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "../../ui/avatar";
import { format } from "date-fns";

interface DeletedMessageProps {
  sender: string;
  timestamp: Date;
  isCurrentUser?: boolean;
}

export function DeletedMessage({ sender, timestamp, isCurrentUser }: DeletedMessageProps) {
  return (
    <div className={cn("flex items-start gap-2 mb-4", isCurrentUser ? "flex-row-reverse" : "")}>
      <Avatar className="w-8 h-8">
        <AvatarFallback className={cn(isCurrentUser ? "bg-blue-500 text-white" : "bg-muted")}>
          {sender.charAt(0).toUpperCase()}
        </AvatarFallback>
      </Avatar>

      <div className={cn("flex flex-col min-w-0", isCurrentUser ? "items-end" : "items-start")} style={{ maxWidth: "75%" }}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium">{sender}</span>
          <span className="text-xs text-muted-foreground">{format(timestamp, "h:mm a")}</span>
        </div>

        <div
          className={cn(
            "rounded-lg px-3 py-2 text-sm min-w-[5rem] whitespace-pre-wrap break-words",
            isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted",
            "italic text-gray-500"
          )}
        >
          Message deleted
        </div>
      </div>
    </div>
  );
}
