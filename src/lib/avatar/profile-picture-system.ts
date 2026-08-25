import type { SecureDB } from '../database/secureDB';
import type { AvatarData } from '../types/avatar-types';
import { createInitialState } from './state';
import { AvatarSystemState } from '../types/avatar-types';
import { setSecureDB, initialize } from './init';
import { clearPeerCache, cachePeerAvatar } from './cache';
import { setOwnAvatar, removeOwnAvatar, getOwnAvatar, getOwnAvatarHash, isOwnAvatarDefault } from './own-avatar';
import { getPeerAvatar, getPeerAvatarHash } from './peer-avatar';

class ProfilePictureSystem {
    private static instance: ProfilePictureSystem | null = null;
    private state: AvatarSystemState;
    private generation = 0;
    private initializationPromise: Promise<void> | null = null;

    private constructor() {
        this.state = createInitialState();
    }

    private captureAccountOperation(): () => boolean {
        const generation = this.generation;
        const secureDB = this.state.secureDB;
        return () => this.generation === generation && this.state.secureDB === secureDB;
    }

    // Get instance
    static getInstance(): ProfilePictureSystem {
        if (!ProfilePictureSystem.instance) {
            ProfilePictureSystem.instance = new ProfilePictureSystem();
        }
        return ProfilePictureSystem.instance;
    }

    // Set secure DB
    setSecureDB(db: SecureDB | null): void {
        if (this.state.secureDB === db) return;
        this.generation += 1;
        this.initializationPromise = null;
        setSecureDB(this.state, db);
    }

    // Initialize
    async initialize(): Promise<void> {
        if (this.state.initialized || !this.state.secureDB) return;
        if (this.initializationPromise) return this.initializationPromise;

        const generation = this.generation;
        const secureDB = this.state.secureDB;
        const operation = initialize(
            this.state,
            () => { },
            () => this.generation === generation && this.state.secureDB === secureDB
        );
        this.initializationPromise = operation;
        try {
            await operation;
        } finally {
            if (this.initializationPromise === operation) {
                this.initializationPromise = null;
            }
        }
    }

    // Set own avatar
    async setOwnAvatar(imageDataUrl: string, isDefault: boolean = false): Promise<{ success: boolean; error?: string }> {
        return setOwnAvatar(this.state, imageDataUrl, isDefault, this.captureAccountOperation());
    }

    // Remove own avatar
    async removeOwnAvatar(usernameOverride?: string): Promise<void> {
        const isCurrent = this.captureAccountOperation();
        return removeOwnAvatar(
            this.state,
            usernameOverride,
            (url, def) => this.setOwnAvatar(url, def),
            isCurrent
        );
    }

    // Get own avatar
    getOwnAvatar(): string | null {
        return getOwnAvatar(this.state);
    }

    // Get own avatar data
    getOwnAvatarData(): AvatarData | null {
        if (!this.state.ownAvatar) return null;
        return { ...this.state.ownAvatar };
    }

    // Get own avatar hash
    getOwnAvatarHash(): string | null {
        return getOwnAvatarHash(this.state);
    }

    // Check if own avatar is default
    isOwnAvatarDefault(): boolean {
        return isOwnAvatarDefault(this.state);
    }

    // Get peer avatar
    getPeerAvatar(username: string): string | null {
        return getPeerAvatar(this.state, username);
    }

    // Get peer avatar hash
    getPeerAvatarHash(username: string): string | null {
        return getPeerAvatarHash(this.state, username);
    }

    // Clear peer cache
    clearPeerCache(username?: string): void {
        clearPeerCache(this.state, username, this.captureAccountOperation());
    }

    // Cache peer avatar
    async cachePeerAvatar(username: string, data: string, mimeType: string, hash: string, isDefault: boolean = false): Promise<void> {
        return cachePeerAvatar(
            this.state,
            username,
            data,
            mimeType,
            hash,
            isDefault,
            this.captureAccountOperation()
        );
    }

}

export const profilePictureSystem = ProfilePictureSystem.getInstance();
export type { AvatarData };
