import { SignalType } from '../types/signal-types';
import { unifiedSignalTransport } from '../transport/unified-signal-transport';
import type { AvatarSystemState } from '../types/avatar-types';
import { createProfilePictureRequest } from './messaging';
import { AVATAR_PENDING_REQUEST_TIMEOUT_MS } from '../constants';

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
    if (!username) return;

    const now = Date.now();
    const last = state.serverFetchTimestamps.get(username) || 0;
    if (now - last < 5000) {
        return;
    }

    if (state.pendingRequests.has(username)) {
        return;
    }

    state.serverFetchTimestamps.set(username, now);
    state.pendingRequests.add(username);
    setTimeout(() => {
        state.pendingRequests.delete(username);
    }, AVATAR_PENDING_REQUEST_TIMEOUT_MS);

    let sent = false;
    try {
        const request = createProfilePictureRequest();
        const result = await unifiedSignalTransport.send(username, request, SignalType.SIGNAL);
        sent = !!result?.success;
    } catch {
    }

    try {
        await fetchFromServerFn(username);
    } catch {
    }

    if (!sent) {
        state.pendingRequests.delete(username);
    }
}
