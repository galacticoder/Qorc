import type { AvatarSystemState } from '../types/avatar-types';

export function createInitialState(): AvatarSystemState {
    return {
        secureDB: null,
        ownAvatar: null,
        settings: { shareWithOthers: false, lastUpdated: 0 },
        avatarCache: new Map(),
        cacheSaveInFlight: null,
        cacheSavePending: false,
        initialized: false
    };
}
