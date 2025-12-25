import React, { useState, useEffect, useCallback, memo } from 'react';
import { profilePictureSystem } from '../../lib/profile-picture-system';

const PROFILE_PICTURE_EVENT_RATE_WINDOW_MS = 10_000;
const PROFILE_PICTURE_EVENT_RATE_MAX = 200;
const MAX_PROFILE_PICTURE_EVENT_TYPE_LENGTH = 32;
const MAX_PROFILE_PICTURE_EVENT_USERNAME_LENGTH = 256;

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
    if (typeof value !== 'object' || value === null) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
    if (obj == null || typeof obj !== 'object') return false;
    const keys = Object.keys(obj as Record<string, unknown>);
    return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const sanitizeEventText = (value: unknown, maxLen: number): string | null => {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    if (!trimmed) return null;
    const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
    if (!cleaned) return null;
    return cleaned.slice(0, maxLen);
};

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
    const [isLoaded, setIsLoaded] = useState(false);
    const currentUrlRef = React.useRef<string | null>(null);
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
                const now = Date.now();
                const bucket = profilePictureEventRateRef.current;
                if (now - bucket.windowStart > PROFILE_PICTURE_EVENT_RATE_WINDOW_MS) {
                    bucket.windowStart = now;
                    bucket.count = 0;
                }
                bucket.count += 1;
                if (bucket.count > PROFILE_PICTURE_EVENT_RATE_MAX) {
                    return;
                }

                if (!(event instanceof CustomEvent)) return;
                const detail = event.detail;
                if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

                const type = sanitizeEventText((detail as any).type, MAX_PROFILE_PICTURE_EVENT_TYPE_LENGTH);
                if (!type) return;

                if (type === 'own') {
                    if (isCurrentUser) {
                        loadAvatar();
                    }
                    return;
                }

                if (type === 'peer') {
                    const updatedUser = sanitizeEventText((detail as any).username, MAX_PROFILE_PICTURE_EVENT_USERNAME_LENGTH);
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
