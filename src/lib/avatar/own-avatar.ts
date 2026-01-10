import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import type { AvatarData } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';
import {
    generateDefaultAvatar,
    validateImageData,
    compressImage,
    hashAvatarData
} from '../utils/avatar-utils';

// Set own avatar
export async function setOwnAvatar(
    state: AvatarSystemState,
    imageDataUrl: string,
    isDefault: boolean = false,
    uploadFn: () => Promise<any>
): Promise<{ success: boolean; error?: string }> {
    if (!state.secureDB) {
        return { success: false, error: 'Not initialized' };
    }

    const validation = validateImageData(imageDataUrl);
    if (!validation.valid) {
        return { success: false, error: validation.error };
    }

    try {
        const compressed = await compressImage(imageDataUrl);
        const hash = await hashAvatarData(compressed);

        const avatarData: AvatarData = {
            data: compressed,
            mimeType: 'image/webp',
            hash,
            updatedAt: Date.now(),
            isDefault
        };

        await state.secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, 'own', avatarData);
        state.ownAvatar = avatarData;

        await uploadFn();

        window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
            detail: { type: 'own' }
        }));

        return { success: true };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

// Remove own avatar
export async function removeOwnAvatar(
    state: AvatarSystemState,
    usernameOverride?: string,
    setAvatarFn?: (url: string, isDefault: boolean) => Promise<any>
): Promise<void> {
    if (!state.secureDB) return;

    try {
        const username = usernameOverride || websocketClient?.getUsername() || 'unknown';
        const defaultAvatarUrl = generateDefaultAvatar(username);

        if (setAvatarFn) {
            await setAvatarFn(defaultAvatarUrl, true);
        }
    } catch { }
}

// Get own avatar
export function getOwnAvatar(state: AvatarSystemState): string | null {
    return state.ownAvatar?.data || null;
}

// Get own avatar hash
export function getOwnAvatarHash(state: AvatarSystemState): string | null {
    return state.ownAvatar?.hash || null;
}

// Check if own avatar is default
export function isOwnAvatarDefault(state: AvatarSystemState): boolean {
    return !!state.ownAvatar?.isDefault;
}

// Set share with others
export async function setShareWithOthers(
    state: AvatarSystemState,
    share: boolean,
    uploadFn: () => Promise<any>
): Promise<void> {
    if (!state.secureDB) return;

    const previousState = state.settings.shareWithOthers;
    state.settings = { shareWithOthers: share, lastUpdated: Date.now() };

    try {
        await state.secureDB.store(STORAGE_KEYS.PROFILE_SETTINGS, 'profile', state.settings);

        window.dispatchEvent(new CustomEvent(EventType.PROFILE_SETTINGS_UPDATED, {
            detail: { shareWithOthers: share }
        }));

        if (state.ownAvatar && previousState !== share) {
            await uploadFn();
        }
    } catch { }
}

// Get share with others
export function getShareWithOthers(state: AvatarSystemState): boolean {
    return state.settings.shareWithOthers;
}
