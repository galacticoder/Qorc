import React, { useState, useEffect, useCallback, memo } from 'react';
import { profilePictureSystem } from '../../lib/profile-picture-system';

interface UserAvatarProps {
    username: string;
    isCurrentUser?: boolean;
    size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
    className?: string;
    showFallback?: boolean;
}

const SIZE_MAP = {
    xs: 24,
    sm: 32,
    md: 40,
    lg: 48,
    xl: 80
} as const;

export const UserAvatar = memo(function UserAvatar({
    username,
    isCurrentUser = false,
    size = 'md',
    className = '',
    showFallback = true
}: UserAvatarProps) {
    const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
    const [requested, setRequested] = useState(false);
    const currentUrlRef = React.useRef<string | null>(null);

    const loadAvatar = useCallback(() => {
        if (isCurrentUser) {
            const own = profilePictureSystem.getOwnAvatar();


            // Only update if the URL is actually different
            if (own !== currentUrlRef.current) {
                currentUrlRef.current = own;
                setAvatarUrl(own);
            }

            if (!own && !requested) {
                setRequested(true);
                profilePictureSystem.fetchOwnFromServer().catch(() => { });
            }


        } else {
            const peer = profilePictureSystem.getPeerAvatar(username);

            // Only update if the URL is actually different
            if (peer !== currentUrlRef.current) {
                if (peer === null && currentUrlRef.current !== null) {
                } else {
                    currentUrlRef.current = peer;
                    setAvatarUrl(peer);
                }
            }

            if (!peer && !requested) {
                setRequested(true);
                profilePictureSystem.requestPeerAvatar(username);
            }
        }
    }, [username, isCurrentUser, requested]);

    useEffect(() => {
        loadAvatar();

        const handleUpdate = (e: CustomEvent) => {
            const { type, username: updatedUser, notFound } = e.detail || {};

            if (type === 'own' && isCurrentUser) {
                loadAvatar();
            } else if (type === 'peer' && updatedUser === username) {
                if (notFound) {
                    setTimeout(() => setRequested(false), 5000);
                } else {
                    loadAvatar();
                }
            }
        };

        window.addEventListener('profile-picture-updated', handleUpdate as EventListener);
        return () => {
            window.removeEventListener('profile-picture-updated', handleUpdate as EventListener);
        };
    }, [loadAvatar, username, isCurrentUser]);

    // Periodic refresh for peer avatars
    useEffect(() => {
        if (isCurrentUser) return;

        const refreshInterval = setInterval(() => {
            const peer = profilePictureSystem.getPeerAvatar(username);
            if (!peer && currentUrlRef.current) {
                setRequested(false);
            }
        }, 30000);

        return () => clearInterval(refreshInterval);
    }, [username, isCurrentUser]);

    const pixelSize = SIZE_MAP[size];
    const skeletonColor = 'var(--color-secondary)';

    return (
        <div
            className={`relative rounded-full overflow-hidden flex-shrink-0 select-none ${className}`}
            style={{
                width: pixelSize,
                height: pixelSize,
                minWidth: pixelSize,
                minHeight: pixelSize,
                maxWidth: pixelSize,
                maxHeight: pixelSize,
                backgroundColor: avatarUrl ? 'transparent' : skeletonColor
            }}
        >
            {avatarUrl ? (
                <img
                    src={avatarUrl}
                    alt=""
                    className="w-full h-full object-cover"
                    loading="lazy"
                    onError={() => setAvatarUrl(null)}
                    draggable={false}
                    onDragStart={(e) => e.preventDefault()}
                />
            ) : (
                <div
                    className="w-full h-full animate-pulse"
                    style={{ backgroundColor: skeletonColor }}
                    aria-hidden="true"
                />
            )}
        </div>
    );
});

export default UserAvatar;
