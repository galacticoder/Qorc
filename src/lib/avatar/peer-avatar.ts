import type { AvatarSystemState } from '../types/avatar-types';

// Get peer avatar
export function getPeerAvatar(state: AvatarSystemState, username: string): string | null {
    const cached = state.avatarCache.get(username);
    if (cached && cached.data) {
        return cached.data;
    }
    return null;
}

// Get peer avatar hash
export function getPeerAvatarHash(state: AvatarSystemState, username: string): string | null {
    const cached = state.avatarCache.get(username);
    if (cached && cached.hash) {
        return cached.hash;
    }
    return null;
}
