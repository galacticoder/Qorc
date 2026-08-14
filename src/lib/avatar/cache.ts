import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import { AVATAR_CACHE_TTL_MS, MAX_PEER_AVATAR_CACHE_ENTRIES } from '../constants';
import { isCanonicalAuthUsername } from '../sanitizers';
import { hashAvatarData, isValidAvatarData, isValidCachedAvatar } from '../utils/avatar-utils';
import type { CachedAvatar } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';

// Persist avatar cache to database
export async function persistCache(
    state: AvatarSystemState,
    isCurrent: () => boolean
): Promise<void> {
    if (!state.secureDB || !isCurrent()) return;
    state.cacheSavePending = true;
    if (state.cacheSaveInFlight) return state.cacheSaveInFlight;

    const secureDB = state.secureDB;
    const operation = (async () => {
        do {
            state.cacheSavePending = false;
            if (!isCurrent() || state.secureDB !== secureDB) return;
            const cacheObj = Object.create(null) as Record<string, CachedAvatar>;
            const now = Date.now();
            let retained = 0;
            for (const [username, avatar] of state.avatarCache.entries()) {
                if (retained >= MAX_PEER_AVATAR_CACHE_ENTRIES) break;
                if (
                    isCanonicalAuthUsername(username) &&
                    avatar.expiresAt > now &&
                    isValidCachedAvatar(avatar)
                ) {
                    cacheObj[username] = avatar;
                    retained += 1;
                }
            }
            await secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_CACHE, cacheObj);
            if (!isCurrent() || state.secureDB !== secureDB) return;
        } while (state.cacheSavePending && isCurrent() && state.secureDB === secureDB);
    })();
    state.cacheSaveInFlight = operation;
    try {
        await operation;
    } catch { }
    finally {
        if (state.cacheSaveInFlight === operation) state.cacheSaveInFlight = null;
    }
}

// Clear avatar cache
export function clearPeerCache(
    state: AvatarSystemState,
    username: string | undefined,
    isCurrent: () => boolean
): void {
    if (!isCurrent()) return;
    if (username) {
        state.avatarCache.delete(username);
    } else {
        state.avatarCache.clear();
    }
    void persistCache(state, isCurrent);
}

// Cache avatar for peer
export async function cachePeerAvatar(
    state: AvatarSystemState,
    username: string,
    data: string,
    mimeType: string,
    hash: string,
    isDefault: boolean,
    isCurrent: () => boolean
): Promise<void> {
    if (!isCurrent()) return;
    if (!isCanonicalAuthUsername(username)) return;
    const candidate = { data, mimeType, hash, isDefault };
    if (!isValidAvatarData(candidate)) return;
    if (await hashAvatarData(data) !== hash) return;
    if (!isCurrent()) return;

    if (isDefault) {
        const existing = state.avatarCache.get(username);
        if (existing && existing.isDefault !== true) {
            return;
        }
    }

    const cached: CachedAvatar = {
        data,
        hash,
        cachedAt: Date.now(),
        expiresAt: Date.now() + AVATAR_CACHE_TTL_MS,
        isDefault
    };

    if (!state.avatarCache.has(username) && state.avatarCache.size >= MAX_PEER_AVATAR_CACHE_ENTRIES) {
        const now = Date.now();
        for (const [peer, entry] of state.avatarCache) {
            if (entry.expiresAt <= now || !isValidCachedAvatar(entry)) state.avatarCache.delete(peer);
        }
        while (state.avatarCache.size >= MAX_PEER_AVATAR_CACHE_ENTRIES) {
            let oldestPeer: string | null = null;
            let oldestAt = Number.POSITIVE_INFINITY;
            for (const [peer, entry] of state.avatarCache) {
                if (entry.cachedAt < oldestAt) {
                    oldestAt = entry.cachedAt;
                    oldestPeer = peer;
                }
            }
            if (!oldestPeer) break;
            state.avatarCache.delete(oldestPeer);
        }
    }
    if (!isCurrent()) return;
    state.avatarCache.set(username, cached);
    await persistCache(state, isCurrent);
    if (!isCurrent()) return;

    window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
        detail: { type: 'peer', username, fromServer: true }
    }));
}
