import { memo } from 'react';

interface UnreadIndicatorProps {
    readonly count: number;
}

export const UnreadIndicator = memo<UnreadIndicatorProps>(({ count }) => {
    if (!Number.isSafeInteger(count) || count <= 0) return null;

    return (
        <span
            className="qorc-conversation-unread-badge"
            aria-label={`${count} unread ${count === 1 ? 'message' : 'messages'}`}
        >
            {count > 99 ? '99+' : count}
        </span>
    );
});

UnreadIndicator.displayName = 'UnreadIndicator';
