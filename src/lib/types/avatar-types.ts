import type { SecureDB } from '../database/secureDB';

export interface AvatarData {
    data: string;
    mimeType: string;
    hash: string;
    updatedAt: number;
    isDefault?: boolean;
}

export interface ProfileSettings {
    shareWithOthers: boolean;
    lastUpdated: number;
}

export interface CachedAvatar {
    data: string;
    hash: string;
    cachedAt: number;
    expiresAt: number;
}

export interface ProfilePictureMessage {
    type: 'profile-picture-request' | 'profile-picture-response';
    hash?: string;
    data?: string;
    mimeType?: string;
}

export interface AvatarSystemState {
    secureDB: SecureDB | null;
    ownAvatar: AvatarData | null;
    settings: ProfileSettings;
    avatarCache: Map<string, CachedAvatar>;
    pendingRequests: Set<string>;
    initialized: boolean;
    handlerRegistered: boolean;
    serverFetchTimestamps: Map<string, number>;
    ownKyberPublicKey: string | null;
    ownKyberSecretKey: Uint8Array | null;
    ownAvatarFetchTimestamp: number;
}