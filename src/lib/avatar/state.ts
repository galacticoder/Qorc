import type { AvatarSystemState } from '../types/avatar-types';

export function createInitialState(): AvatarSystemState {
    return {
        secureDB: null,
        ownAvatar: null,
        settings: { shareWithOthers: true, lastUpdated: 0 },
        avatarCache: new Map(),
        pendingRequests: new Set(),
        initialized: false,
        handlerRegistered: false,
        serverFetchTimestamps: new Map(),
        ownKyberPublicKey: null,
        ownKyberSecretKey: null,
        ownAvatarFetchTimestamp: 0
    };
}
