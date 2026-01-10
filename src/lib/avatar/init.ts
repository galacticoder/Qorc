import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import { generateDefaultAvatar, hashAvatarData, isValidAvatarData, isValidCachedAvatar } from '../utils/avatar-utils';
import type { SecureDB } from '../database/secureDB';
import type { CachedAvatar } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';

// Set database
export function setSecureDB(state: AvatarSystemState, db: SecureDB | null): void {
    state.secureDB = db;
    state.initialized = false;
    state.ownAvatar = null;
    state.avatarCache.clear();
}

// Set kyber keys
export function setKeys(state: AvatarSystemState, kyberPublicBase64: string, kyberSecretKey: Uint8Array): void {
    state.ownKyberPublicKey = kyberPublicBase64;
    state.ownKyberSecretKey = kyberSecretKey;
}

// Initialize avatar system
export async function initialize(
    state: AvatarSystemState,
    ensureHandlerFn: () => void
): Promise<void> {
    if (state.initialized || !state.secureDB) return;

    try {
        ensureHandlerFn();

        try {
            const storedAvatar = await state.secureDB.retrieve(STORAGE_KEYS.PROFILE_AVATARS, 'own');
            if (storedAvatar && isValidAvatarData(storedAvatar)) {
                state.ownAvatar = storedAvatar;
            }
        } catch (avatarError: any) {
            if (/decrypt|BLAKE3|MAC/i.test(avatarError?.message)) {
                await state.secureDB.clearStore(STORAGE_KEYS.PROFILE_AVATARS).catch(() => { });
            }
        }

        if (!state.ownAvatar) {
            const username = websocketClient?.getUsername() || '';
            if (username) {
                const defaultAvatarUrl = generateDefaultAvatar(username);
                const hash = await hashAvatarData(defaultAvatarUrl);
                state.ownAvatar = {
                    data: defaultAvatarUrl,
                    mimeType: 'image/svg+xml',
                    hash,
                    updatedAt: Date.now(),
                    isDefault: true
                };
                await state.secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, 'own', state.ownAvatar).catch(() => { });
                window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
                    detail: { type: 'own' }
                }));
            }
        }

        // Load settings
        try {
            const storedSettings = await state.secureDB.retrieve(STORAGE_KEYS.PROFILE_SETTINGS, 'profile');
            if (storedSettings && typeof storedSettings === 'object') {
                const s = storedSettings as any;
                if (typeof s.shareWithOthers === 'boolean') {
                    state.settings = {
                        shareWithOthers: s.shareWithOthers,
                        lastUpdated: s.lastUpdated || Date.now()
                    };
                }
            }
        } catch (settingsError: any) {
            if (/decrypt|BLAKE3|MAC/i.test(settingsError?.message)) {
                await state.secureDB.clearStore(STORAGE_KEYS.PROFILE_SETTINGS).catch(() => { });
            }
        }

        // Load cached avatars
        try {
            const cachedAvatars = await state.secureDB.retrieve(STORAGE_KEYS.PROFILE_AVATARS, 'cache');
            if (cachedAvatars && typeof cachedAvatars === 'object') {
                const cache = cachedAvatars as Record<string, CachedAvatar>;
                for (const [username, avatar] of Object.entries(cache)) {
                    if (isValidCachedAvatar(avatar)) {
                        state.avatarCache.set(username, avatar);
                    }
                }
            }
        } catch (cacheError: any) {
            state.avatarCache.clear();
        }

        state.initialized = true;
        window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED));
    } catch (error) {
        console.error('[ProfilePictureSystem] Initialize failed:', error);
    }
}
