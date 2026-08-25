import type { SecureDB } from '../database/secureDB';

export interface AvatarData {
    data: string;
    mimeType: string;
    hash: string;
    isDefault: boolean;
}

export interface CachedAvatar {
    data: string;
    hash: string;
    cachedAt: number;
    expiresAt: number;
    isDefault: boolean;
}

export interface AvatarSystemState {
    secureDB: SecureDB | null;
    ownAvatar: AvatarData | null;
    avatarCache: Map<string, CachedAvatar>;
    cacheSaveInFlight: Promise<void> | null;
    cacheSavePending: boolean;
    initialized: boolean;
}
