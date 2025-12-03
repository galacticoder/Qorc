import React, { useMemo, useEffect, useRef } from 'react';
import { useTypingIndicatorContext } from '@/contexts/TypingIndicatorContext';
import { TypingIndicator } from './TypingIndicator';

interface TypingIndicatorListProps {
    selectedConversation?: string;
    getDisplayUsername?: (username: string) => Promise<string>;
    onUpdate?: () => void;
}

export const TypingIndicatorList = React.memo(({ selectedConversation, getDisplayUsername, onUpdate }: TypingIndicatorListProps) => {
    const { typingUsers: allTypingUsers } = useTypingIndicatorContext();

    const typingUsers = useMemo(() => {
        if (!selectedConversation) return [];
        return allTypingUsers.filter(username => username === selectedConversation);
    }, [allTypingUsers, selectedConversation]);

    const prevCountRef = useRef(typingUsers.length);

    useEffect(() => {
        if (typingUsers.length !== prevCountRef.current) {
            prevCountRef.current = typingUsers.length;
            onUpdate?.();
        }
    }, [typingUsers.length, onUpdate]);

    if (typingUsers.length === 0) return null;

    return (
        <div className="flex flex-col gap-2 mt-2">
            {typingUsers.map((username) => (
                <TypingIndicator
                    key={username}
                    username={username}
                    getDisplayUsername={getDisplayUsername}
                />
            ))}
        </div>
    );
});
