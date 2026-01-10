import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import { AVATAR_CACHE_TTL_MS } from '../constants';
import type { CachedAvatar } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';

// Persist avatar cache to database
export async function persistCache(state: AvatarSystemState): Promise<void> {
    if (!state.secureDB) return;

    try {
        const cacheObj: Record<string, CachedAvatar> = {};
        const now = Date.now();

        for (const [username, avatar] of state.avatarCache.entries()) {
            if (avatar.expiresAt > now) {
                cacheObj[username] = avatar;
            }
        }

        await state.secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, 'cache', cacheObj);
    } catch { }
}

// Clear avatar cache
export function clearPeerCache(state: AvatarSystemState, username?: string): void {
    if (username) {
        state.avatarCache.delete(username);
    } else {
        state.avatarCache.clear();
    }
    void persistCache(state);
}

// Cache avatar for peer
export async function cachePeerAvatar(
    state: AvatarSystemState,
    username: string,
    data: string,
    mimeType: string,
    hash: string
): Promise<void> {
    const cached: CachedAvatar = {
        data,
        hash,
        cachedAt: Date.now(),
        expiresAt: Date.now() + AVATAR_CACHE_TTL_MS
    };

    state.avatarCache.set(username, cached);
    await persistCache(state);

    window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
        detail: { type: 'peer', username, fromServer: true }
    }));
}
