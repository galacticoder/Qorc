import React from "react";

interface SystemMessageProps {
  content: string;
}

export function SystemMessage({ content }: SystemMessageProps) {
  return (
    <div className="flex items-center justify-center my-2">
      <div className="bg-muted text-muted-foreground text-xs rounded-full px-3 py-1">
        {content}
      </div>
    </div>
  );
}
