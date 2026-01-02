import React, { useState, useEffect, useCallback, memo } from 'react';
import { profilePictureSystem } from '../../lib/profile-picture-system';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';
import { sanitizeEventText } from '../../lib/sanitizers';
import { EventType } from '../../lib/types/event-types';
import {
    DEFAULT_EVENT_RATE_WINDOW_MS,
    DEFAULT_EVENT_RATE_MAX,
    MAX_EVENT_TYPE_LENGTH,
    MAX_EVENT_USERNAME_LENGTH
} from '../../lib/constants';

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
    const [avatarUrl, setAvatarUrl] = useState<string | null>(() => {
        if (isCurrentUser) {
            return profilePictureSystem.getOwnAvatar();
        } else {
            return profilePictureSystem.getPeerAvatar(username);
        }
    });
    const [requested, setRequested] = useState(false);
    const [isLoaded, setIsLoaded] = useState(false);
    const currentUrlRef = React.useRef<string | null>(avatarUrl);
    const profilePictureEventRateRef = React.useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

    const loadAvatar = useCallback(() => {
        if (isCurrentUser) {
            const own = profilePictureSystem.getOwnAvatar();
            if (own !== currentUrlRef.current) {
                currentUrlRef.current = own;
                setAvatarUrl(own);
                setIsLoaded(false);
            }

            if (!own && !requested) {
                setRequested(true);
                profilePictureSystem.fetchOwnFromServer().catch(() => { });
            }

        } else {
            const peer = profilePictureSystem.getPeerAvatar(username);
            if (peer !== currentUrlRef.current) {
                if (peer === null && currentUrlRef.current !== null) {
                } else {
                    currentUrlRef.current = peer;
                    setAvatarUrl(peer);
                    setIsLoaded(false);
                }
            }

            if (!requested) {
                const isStale = profilePictureSystem.isPeerAvatarStale(username);
                if (isStale) {
                    setRequested(true);
                    profilePictureSystem.requestPeerAvatar(username);
                }
            }
        }
    }, [username, isCurrentUser, requested]);

    useEffect(() => {
        loadAvatar();

        const handleUpdate = (event: Event) => {
            try {
                if (event.type === EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED) {
                    loadAvatar();
                    return;
                }

                const now = Date.now();
                const bucket = profilePictureEventRateRef.current;
                if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
                    bucket.windowStart = now;
                    bucket.count = 0;
                }
                bucket.count += 1;
                if (bucket.count > DEFAULT_EVENT_RATE_MAX) {
                    return;
                }

                if (!(event instanceof CustomEvent)) return;
                const detail = event.detail;
                if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

                const type = sanitizeEventText((detail as any).type, MAX_EVENT_TYPE_LENGTH);
                if (!type) return;

                if (type === 'all') {
                    setAvatarUrl(profilePictureSystem.getPeerAvatar(username));
                } else if (type === 'single') {
                    const updatedUser = sanitizeEventText((detail as any).username, MAX_EVENT_USERNAME_LENGTH);
                    if (!updatedUser) return;
                    const notFound = (detail as any).notFound === true;

                    if (updatedUser === username) {
                        if (notFound) {
                            setTimeout(() => setRequested(false), 5000);
                        } else {
                            loadAvatar();
                        }
                    }
                }
            } catch { }
        };

        window.addEventListener(EventType.PROFILE_PICTURE_UPDATED, handleUpdate as EventListener);
        window.addEventListener(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED, handleUpdate as EventListener);
        return () => {
            window.removeEventListener(EventType.PROFILE_PICTURE_UPDATED, handleUpdate as EventListener);
            window.removeEventListener(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED, handleUpdate as EventListener);
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
                backgroundColor: 'transparent'
            }}
        >
            {avatarUrl && (
                <img
                    src={avatarUrl}
                    alt=""
                    className={`w-full h-full object-cover transition-opacity duration-200 ${isLoaded ? 'opacity-100' : 'opacity-0'}`}
                    loading="lazy"
                    onLoad={() => setIsLoaded(true)}
                    onError={() => {
                        setAvatarUrl(null);
                        setIsLoaded(true);
                    }}
                    draggable={false}
                    onDragStart={(e) => e.preventDefault()}
                />
            )}

            {/* Show skeleton if no URL or not yet loaded */}
            {showFallback && (!avatarUrl || !isLoaded) && (
                <div
                    className="absolute inset-0 w-full h-full animate-pulse"
                    style={{ backgroundColor: skeletonColor }}
                    aria-hidden="true"
                />
            )}
        </div>
    );
});

export default UserAvatar;
