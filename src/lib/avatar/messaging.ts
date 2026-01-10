import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { unifiedSignalTransport } from '../transport/unified-signal-transport';
import { MAX_AVATAR_SIZE_BYTES, AVATAR_CACHE_TTL_MS } from '../constants';
import { generateDefaultAvatar, validateImageData, hashAvatarData } from '../utils/avatar-utils';
import { persistCache } from './cache';
import type { ProfilePictureMessage, CachedAvatar } from '../types/avatar-types';
import type { AvatarSystemState } from '../types/avatar-types';

// Create profile picture request
export function createProfilePictureRequest(): ProfilePictureMessage {
    return { type: 'profile-picture-request' };
}

// Create profile picture response
export function createProfilePictureResponse(state: AvatarSystemState): ProfilePictureMessage | null {
    if (!state.settings.shareWithOthers) {
        return { type: 'profile-picture-response' };
    }
    if (!state.ownAvatar) {
        return { type: 'profile-picture-response' };
    }

    return {
        type: 'profile-picture-response',
        hash: state.ownAvatar.hash,
        data: state.ownAvatar.data,
        mimeType: state.ownAvatar.mimeType
    };
}

// Handle incoming message
export async function handleIncomingMessage(
    state: AvatarSystemState,
    message: ProfilePictureMessage,
    fromUsername: string
): Promise<ProfilePictureMessage | null> {
    if (!message || typeof message.type !== 'string') return null;

    if (message.type === 'profile-picture-request') {
        const response = createProfilePictureResponse(state);
        if (response) {
            await unifiedSignalTransport.send(fromUsername, response, SignalType.SIGNAL).catch(() => { });
        }
        return response;
    }

    if (message.type === 'profile-picture-response') {
        state.pendingRequests.delete(fromUsername);

        if (!message.data || !message.hash) {
            const defaultAvatar = generateDefaultAvatar(fromUsername);
            const defaultHash = await hashAvatarData(defaultAvatar);

            state.avatarCache.set(fromUsername, {
                data: defaultAvatar,
                hash: defaultHash,
                cachedAt: Date.now(),
                expiresAt: Date.now() + AVATAR_CACHE_TTL_MS
            });

            window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
                detail: { type: 'peer', username: fromUsername, fromServer: false, usedDefault: true }
            }));
            return null;
        }

        if (typeof message.data !== 'string' || message.data.length > MAX_AVATAR_SIZE_BYTES * 1.4) {
            return null;
        }

        if (typeof message.hash !== 'string' || message.hash.length !== 64) {
            return null;
        }

        const validation = validateImageData(message.data);
        if (!validation.valid) {
            return null;
        }

        const computedHash = await hashAvatarData(message.data);
        if (computedHash !== message.hash) {
            return null;
        }

        const cached: CachedAvatar = {
            data: message.data,
            hash: message.hash,
            cachedAt: Date.now(),
            expiresAt: Date.now() + AVATAR_CACHE_TTL_MS
        };

        state.avatarCache.set(fromUsername, cached);
        await persistCache(state);

        window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
            detail: { type: 'peer', username: fromUsername }
        }));
    }

    return null;
}
