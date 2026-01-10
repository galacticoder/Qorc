import { SignalType } from '../types/signal-types';
import { unifiedSignalTransport } from '../transport/unified-signal-transport';
import { AVATAR_PENDING_REQUEST_TIMEOUT_MS } from '../constants';
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

// Check if peer avatar is stale
export function isPeerAvatarStale(state: AvatarSystemState, username: string): boolean {
    const cached = state.avatarCache.get(username);
    if (!cached) {
        return true;
    }
    return cached.expiresAt <= Date.now();
}

// Request peer avatar
export async function requestPeerAvatar(
    state: AvatarSystemState,
    username: string,
    fetchFromServerFn: (username: string) => Promise<void>
): Promise<void> {
    if (state.pendingRequests.has(username)) {
        return;
    }

    // Check for cached avatar
    const cached = state.avatarCache.get(username);

    // If cached and not stale, don't fetch
    if (cached && cached.expiresAt > Date.now()) {
        return;
    }

    state.pendingRequests.add(username);

    try {
        await unifiedSignalTransport.send(username, { type: 'profile-picture-request' }, SignalType.SIGNAL);
    } catch (p2pError) {
        await fetchFromServerFn(username);
    } finally {
        setTimeout(() => {
            if (state.pendingRequests.has(username)) {
                state.pendingRequests.delete(username);
            }
        }, AVATAR_PENDING_REQUEST_TIMEOUT_MS);
    }
}
