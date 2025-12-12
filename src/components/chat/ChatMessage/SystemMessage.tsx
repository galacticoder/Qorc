import React from "react";

interface SystemMessageProps {
  content: string;
  actions?: Array<{ label: string; onClick: () => void }>;
  isError?: boolean;
}

export function SystemMessage({ content, actions, isError }: SystemMessageProps) {
  return (
    <div className="flex items-center justify-center my-2">
      <div className={`text-xs rounded-full px-3 py-1 flex items-center gap-2 ${isError
        ? 'bg-red-900/20 text-red-600 dark:text-red-400 font-medium'
        : 'bg-muted text-muted-foreground'
        }`}>
        <span>{content}</span>
        {Array.isArray(actions) && actions.length > 0 && (
          <span className="flex items-center gap-1">
            {actions.map((a, i) => (
              <button
                key={i}
                onClick={a.onClick}
                className="ml-1 px-2 py-0.5 rounded-full bg-foreground text-background hover:opacity-90 transition-opacity"
                style={{ fontSize: '0.7rem' }}
              >
                {a.label}
              </button>
            ))}
          </span>
        )}
      </div>
    </div>
  );
}