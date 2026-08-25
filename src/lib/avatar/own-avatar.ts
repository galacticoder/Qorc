import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';
import { EventType } from '../types/event-types';
import { MAX_AVATAR_DIMENSION } from '../constants';
import type { AvatarData } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';
import {
    generateDefaultAvatar,
    validateImageData,
    compressImage,
    hashAvatarData
} from '../utils/avatar-utils';

const MAX_AVATAR_SOURCE_DIMENSION = 8192;

// Set own avatar
export async function setOwnAvatar(
    state: AvatarSystemState,
    imageDataUrl: string,
    isDefault: boolean,
    isCurrent: () => boolean
): Promise<{ success: boolean; error?: string }> {
    const secureDB = state.secureDB;
    if (!secureDB || !isCurrent()) {
        return { success: false, error: 'Not initialized' };
    }

    const validation = validateImageData(imageDataUrl, {
        allowGeneratedDefaultSvg: isDefault,
        maxDimension: MAX_AVATAR_SOURCE_DIMENSION
    });
    if (!validation.valid) {
        return { success: false, error: validation.error };
    }

    try {
        const compressed = await compressImage(imageDataUrl);
        if (!isCurrent() || state.secureDB !== secureDB) {
            return { success: false, error: 'Account changed' };
        }
        const compressedValidation = validateImageData(compressed, {
            maxDimension: MAX_AVATAR_DIMENSION
        });
        if (!compressedValidation.valid) {
            return { success: false, error: 'Processed avatar failed validation' };
        }
        const hash = await hashAvatarData(compressed);
        if (!isCurrent() || state.secureDB !== secureDB) {
            return { success: false, error: 'Account changed' };
        }

        const avatarData: AvatarData = {
            data: compressed,
            mimeType: 'image/webp',
            hash,
            isDefault
        };

        await secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, STORAGE_KEYS.AVATAR_OWN, avatarData);
        if (!isCurrent() || state.secureDB !== secureDB) {
            return { success: false, error: 'Account changed' };
        }
        state.ownAvatar = avatarData;

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
    setAvatarFn?: (url: string, isDefault: boolean) => Promise<any>,
    isCurrent: () => boolean = () => false
): Promise<void> {
    if (!state.secureDB || !isCurrent()) return;

    try {
        const username = usernameOverride || websocketClient?.getUsername() || 'unknown';
        const defaultAvatarUrl = generateDefaultAvatar(username);

        if (setAvatarFn && isCurrent()) {
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
