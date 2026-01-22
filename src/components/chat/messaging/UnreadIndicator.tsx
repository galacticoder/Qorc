import React, { memo, useMemo } from 'react';

interface UnreadIndicatorProps {
    readonly count: number;
    readonly isSelected?: boolean;
}

/**
 * Displays unread message count as text.
 * Shows "1 unread message", "2 unread messages", or "9+ unread messages" for counts > 9.
 */
export const UnreadIndicator = memo<UnreadIndicatorProps>(({ count, isSelected = false }) => {
    const displayText = useMemo(() => {
        if (count <= 0) return null;
        if (count === 1) return '1 unread message';
        if (count <= 9) return `${count} unread messages`;
        return '9+ unread messages';
    }, [count]);

    if (!displayText) return null;

    return (
        <span
            className="text-xs font-semibold select-none"
            style={{
                color: isSelected ? 'rgba(255, 255, 255, 0.95)' : 'var(--color-accent-primary)',
            }}
        >
            {displayText}
        </span>
    );
});

UnreadIndicator.displayName = 'UnreadIndicator';

export default UnreadIndicator;
