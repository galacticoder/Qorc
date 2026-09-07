import { useEffect, useMemo, useState } from 'react';
import type { Conversation } from '../../components/chat/messaging/ConversationList';
import { preloadAvatarImage } from '../../lib/avatar/image-readiness';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import type { SecureDB } from '../../lib/database/secureDB';
import { generateDefaultAvatar } from '../../lib/utils/avatar-utils';

interface StartupAvatarReadinessProps {
    secureDB: SecureDB | null;
    currentUsername: string;
    conversations: ReadonlyArray<Conversation>;
    avatarDataLoaded: boolean;
    conversationsLoaded: boolean;
}

const preloadForUsername = async (username: string, isCurrentUser: boolean): Promise<void> => {
    const defaultAvatar = generateDefaultAvatar(username);
    const preferred = isCurrentUser
        ? profilePictureSystem.getOwnAvatar()
        : profilePictureSystem.getPeerAvatar(username);
    if (preferred && await preloadAvatarImage(preferred)) return;
    await preloadAvatarImage(defaultAvatar);
};

export const useStartupAvatarReadiness = ({
    secureDB,
    currentUsername,
    conversations,
    avatarDataLoaded,
    conversationsLoaded,
}: StartupAvatarReadinessProps): boolean => {
    const [readyDatabase, setReadyDatabase] = useState<SecureDB | null>(null);
    const orderedUsernames = useMemo(() => {
        const pinned = conversations
            .filter((conversation) => conversation.isPinned)
            .sort((left, right) => (right.pinnedAt || 0) - (left.pinnedAt || 0));
        const unpinned = conversations.filter((conversation) => !conversation.isPinned);
        const visibleRows = Math.max(12, Math.min(40, Math.ceil((window.innerHeight - 78) / 74) + 4));
        return [...pinned, ...unpinned]
            .slice(0, visibleRows)
            .map((conversation) => conversation.username);
    }, [conversations]);

    useEffect(() => {
        if (
            !secureDB ||
            !currentUsername ||
            !avatarDataLoaded ||
            !conversationsLoaded ||
            readyDatabase === secureDB
        ) {
            return;
        }
        let cancelled = false;
        const peerUsernames = Array.from(new Set(orderedUsernames))
            .filter((username) => username !== currentUsername);
        const avatars = [
            { username: currentUsername, isCurrentUser: true },
            ...peerUsernames.map((username) => ({ username, isCurrentUser: false })),
        ];
        const load = async () => {
            let cursor = 0;
            const workers = Array.from({ length: Math.min(6, avatars.length) }, async () => {
                while (!cancelled) {
                    const position = cursor;
                    cursor += 1;
                    if (position >= avatars.length) return;
                    const avatar = avatars[position];
                    await preloadForUsername(avatar.username, avatar.isCurrentUser);
                }
            });
            await Promise.all(workers);
            if (!cancelled) setReadyDatabase(secureDB);
        };
        void load();
        return () => { cancelled = true; };
    }, [secureDB, currentUsername, orderedUsernames, avatarDataLoaded, conversationsLoaded, readyDatabase]);

    return Boolean(
        secureDB &&
        avatarDataLoaded &&
        conversationsLoaded &&
        readyDatabase === secureDB
    );
};
