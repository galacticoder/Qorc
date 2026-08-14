import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import { generateDefaultAvatar, hashAvatarData, isValidAvatarData, isValidCachedAvatar } from '../utils/avatar-utils';
import type { SecureDB } from '../database/secureDB';
import type { CachedAvatar } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';
import { MAX_PEER_AVATAR_CACHE_ENTRIES } from '../constants';
import { isCanonicalAuthUsername, isPlainObject } from '../sanitizers';

function isValidProfileSettings(value: unknown): value is AvatarSystemState['settings'] {
    if (
        !value || typeof value !== 'object' || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).sort().join(',') !== 'lastUpdated,shareWithOthers'
    ) return false;
    const settings = value as Record<string, unknown>;
    return typeof settings.shareWithOthers === 'boolean' &&
        Number.isSafeInteger(settings.lastUpdated) &&
        (settings.lastUpdated as number) >= 0 &&
        (settings.lastUpdated as number) <= Date.now() + 60_000;
}

// Set database
export function setSecureDB(state: AvatarSystemState, db: SecureDB | null): void {
    state.secureDB = db;
    state.initialized = false;
    state.ownAvatar = null;
    state.avatarCache.clear();
    state.cacheSaveInFlight = null;
    state.cacheSavePending = false;
    state.settings = { shareWithOthers: false, lastUpdated: 0 };
}

// Initialize avatar system
export async function initialize(
    state: AvatarSystemState,
    ensureHandlerFn: () => void,
    isCurrent: () => boolean = () => true
): Promise<void> {
    if (state.initialized || !state.secureDB) return;

    const secureDB = state.secureDB;
    const username = websocketClient?.getUsername() || '';
    let ownAvatar: AvatarSystemState['ownAvatar'] = null;
    let settings: AvatarSystemState['settings'] = { shareWithOthers: false, lastUpdated: 0 };
    const avatarCache = new Map<string, CachedAvatar>();
    let generatedOwnAvatar = false;

    try {
        ensureHandlerFn();

        try {
            const storedAvatar = await secureDB.retrieve(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_OWN);
            if (!isCurrent()) return;
            if (storedAvatar && isValidAvatarData(storedAvatar)) {
                ownAvatar = storedAvatar;
            }
        } catch (avatarError: any) {
            if (!isCurrent()) return;
            if (/decrypt|BLAKE3|MAC/i.test(avatarError?.message)) {
                await secureDB.clearStore(STORAGE_KEYS.PROFILE_AVATARS).catch(() => { });
                if (!isCurrent()) return;
            }
        }

        if (!ownAvatar && username) {
            const defaultAvatarUrl = generateDefaultAvatar(username);
            const hash = await hashAvatarData(defaultAvatarUrl);
            if (!isCurrent()) return;
            ownAvatar = {
                data: defaultAvatarUrl,
                mimeType: 'image/svg+xml',
                hash,
                isDefault: true
            };
            await secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_OWN, ownAvatar).catch(() => { });
            if (!isCurrent()) return;
            generatedOwnAvatar = true;
        }

        // Load settings
        try {
            const storedSettings = await secureDB.retrieve(STORAGE_KEYS.PROFILE_SETTINGS, STORAGE_KEYS.PROFILE_SETTINGS_RECORD);
            if (!isCurrent()) return;
            if (isValidProfileSettings(storedSettings)) {
                settings = { ...storedSettings };
            }
        } catch (settingsError: any) {
            if (!isCurrent()) return;
            if (/decrypt|BLAKE3|MAC/i.test(settingsError?.message)) {
                await secureDB.clearStore(STORAGE_KEYS.PROFILE_SETTINGS).catch(() => { });
                if (!isCurrent()) return;
            }
        }

        // Load cached avatars
        try {
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
                for (const [username, avatar] of Object.entries(cache)) {
                    if (isCanonicalAuthUsername(username) && isValidCachedAvatar(avatar)) {
                        avatarCache.set(username, avatar);
                    }
                }
            }
        } catch {
            avatarCache.clear();
        }

        if (!isCurrent()) return;
        state.ownAvatar = ownAvatar;
        state.settings = settings;
        state.avatarCache = avatarCache;
        state.initialized = true;
        if (generatedOwnAvatar) {
            window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
                detail: { type: 'own' }
            }));
        }
        window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED));
    } catch (error) {
        if (isCurrent()) console.error('[ProfilePictureSystem] Initialize failed:', error);
    }
}
