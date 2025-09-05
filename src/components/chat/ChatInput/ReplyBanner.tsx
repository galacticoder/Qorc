import React, { useState, useEffect } from "react";
import { Button } from "../../ui/button";
import { Cross2Icon } from "../icons";
import { cn } from "@/lib/utils";
import * as cm from "../ChatMessage";
import { Message } from "../types"

interface ReplyBannerProps {
  replyTo: Message;
  onCancelReply: () => void;
  getDisplayUsername?: (username: string) => Promise<string>;
}

export function ReplyBanner({ replyTo, onCancelReply, getDisplayUsername }: ReplyBannerProps) {
  const [displaySender, setDisplaySender] = useState(replyTo.sender);

  // Load display username
  useEffect(() => {
    if (getDisplayUsername) {
      getDisplayUsername(replyTo.sender)
        .then(setDisplaySender)
        .catch((error) => {
          console.error('Failed to get display username for reply banner:', error);
          setDisplaySender(replyTo.sender);
        });
    }
  }, [replyTo.sender, getDisplayUsername]);
  return (
    <div className="px-4 pt-3 pb-0">
      <div
        className={cn(
          "flex items-start gap-3 p-3 border-l-4 rounded-lg shadow-sm transition-colors duration-200",
          "bg-gradient-to-r from-slate-50 to-slate-100 border-slate-400 text-slate-900"
        )}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <svg
              className={cn("w-4 h-4", "text-slate-500")}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"
              />
            </svg>
            <span className="text-sm font-semibold text-slate-700">
              {displaySender}
            </span>
          </div>
          <p className="text-sm line-clamp-2 text-slate-600">
            {replyTo.content.slice(0, 100)}
            {replyTo.content.length > 100 && "..."}
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 transition-colors hover:bg-slate-200 text-slate-500 hover:text-slate-700"
          onClick={onCancelReply}
        >
          <Cross2Icon className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}