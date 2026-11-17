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
        'text-xs rounded-lg px-3 py-1.5 flex flex-wrap items-center justify-center gap-2 min-w-0 max-w-full',
        isError
          ? 'qorc-danger-surface text-white font-medium'
          : 'qorc-system-message-call text-zinc-100'
        )}>
        {(isError || showCallIcon) && callType && <CallIcon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />}
        <span className="min-w-0 break-words">{content}</span>
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
                  'qorc-system-message-action ml-1 cursor-pointer px-2 py-0.5 rounded-md font-semibold',
                  isError
                    ? 'qorc-system-message-action--error qorc-danger-button text-white'
                    : 'qorc-button-primary'
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
