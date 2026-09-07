import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import { generateDefaultAvatar, hashAvatarData, isValidAvatarData, isValidCachedAvatar } from '../utils/avatar-utils';
import type { SecureDB } from '../database/secureDB';
import type { CachedAvatar } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';
import { MAX_PEER_AVATAR_CACHE_ENTRIES } from '../constants';
import { isCanonicalAuthUsername, isPlainObject } from '../sanitizers';

// Set database
export function setSecureDB(state: AvatarSystemState, db: SecureDB | null): void {
    state.secureDB = db;
    state.initialized = false;
    state.ownAvatar = null;
    state.avatarCache.clear();
    state.cacheSaveInFlight = null;
    state.cacheSavePending = false;
}

// Initialize avatar system
export async function initialize(
    state: AvatarSystemState,
    isCurrent: () => boolean
): Promise<void> {
    if (state.initialized) return;
    if (!state.secureDB) throw new Error('Profile picture storage is not initialized');

    const secureDB = state.secureDB;
    const username = websocketClient.getUsername();
    if (!isCanonicalAuthUsername(username)) {
        throw new Error('Profile picture account is unavailable');
    }
    let ownAvatar: AvatarSystemState['ownAvatar'] = null;
    const avatarCache = new Map<string, CachedAvatar>();
    let generatedOwnAvatar = false;

    const storedAvatar = await secureDB.retrieve(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_OWN);
    if (!isCurrent()) return;
    if (storedAvatar !== null) {
        if (!isValidAvatarData(storedAvatar)) throw new Error('Invalid stored avatar');
        ownAvatar = storedAvatar;
    }

    if (!ownAvatar) {
        const defaultAvatarUrl = generateDefaultAvatar(username);
        const hash = await hashAvatarData(defaultAvatarUrl);
        if (!isCurrent()) return;
        ownAvatar = {
            data: defaultAvatarUrl,
            mimeType: 'image/svg+xml',
            hash,
            isDefault: true
        };
        await secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_OWN, ownAvatar);
        if (!isCurrent()) return;
        generatedOwnAvatar = true;
    }

    const cachedAvatars = await secureDB.retrieve(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_CACHE);
    if (!isCurrent()) return;
    if (cachedAvatars !== null) {
        if (
            !isPlainObject(cachedAvatars) ||
            Object.keys(cachedAvatars).length > MAX_PEER_AVATAR_CACHE_ENTRIES
        ) {
            throw new Error('Invalid peer avatar cache');
        }
        const cache = cachedAvatars as Record<string, CachedAvatar>;
        for (const [peerUsername, avatar] of Object.entries(cache)) {
            if (!isCanonicalAuthUsername(peerUsername) || !isValidCachedAvatar(avatar)) {
                throw new Error('Invalid peer avatar cache');
            }
            avatarCache.set(peerUsername, avatar);
        }
    }

    if (!isCurrent()) return;
    state.ownAvatar = ownAvatar;
    state.avatarCache = avatarCache;
    state.initialized = true;
    if (generatedOwnAvatar) {
        window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
            detail: { type: 'own' }
        }));
    }
    window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED));
}
