import { Phone, Video } from 'lucide-react';
import { cn } from '../../../../lib/utils/shared-utils';

interface SystemMessageProps {
  content: string;
  actions?: Array<{ label: string; onClick: () => void }>;
  isError?: boolean;
  callType?: 'audio' | 'video';
  showCallIcon?: boolean;
  timestamp?: string;
}

export function SystemMessage({ content, actions, isError, callType, showCallIcon, timestamp }: SystemMessageProps) {
  const CallIcon = callType === 'video' ? Video : Phone;

  return (
    <div className="flex items-center justify-center my-2 select-none">
      <div className={cn(
        'text-xs rounded-lg px-3 py-1.5 flex items-center gap-2',
        isError
          ? 'bg-red-500 text-white font-medium'
          : 'bg-zinc-200 text-zinc-700 dark:bg-zinc-700 dark:text-zinc-100'
        )}>
        {(isError || showCallIcon) && callType && <CallIcon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />}
        <span>{content}</span>
        {timestamp && (
          <time className="ml-1 whitespace-nowrap text-[10px] opacity-70" aria-label={`Call event at ${timestamp}`}>
            {timestamp}
          </time>
        )}
        {Array.isArray(actions) && actions.length > 0 && (
          <span className="flex items-center gap-1">
            {actions.map((a, i) => (
              <button
                key={i}
                onClick={a.onClick}
                className={cn(
                  'ml-1 cursor-pointer px-2 py-0.5 rounded-md font-semibold transition-colors',
                  isError
                    ? 'bg-red-600 text-white hover:bg-red-500'
                    : 'border border-border bg-background text-foreground hover:bg-accent'
                )}
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
