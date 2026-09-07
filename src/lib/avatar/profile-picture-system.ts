import type { SecureDB } from '../database/secureDB';
import type { AvatarData } from '../types/avatar-types';
import { createInitialState } from './state';
import { AvatarSystemState } from '../types/avatar-types';
import { setSecureDB, initialize } from './init';
import { cachePeerAvatar } from './cache';
import { setOwnAvatar, getOwnAvatar } from './own-avatar';
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
        if (this.state.initialized) return;
        if (!this.state.secureDB) throw new Error('Profile picture storage is not initialized');
        if (this.initializationPromise) return this.initializationPromise;

        const generation = this.generation;
        const secureDB = this.state.secureDB;
        const operation = initialize(
            this.state,
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

    // Get own avatar
    getOwnAvatar(): string | null {
        return getOwnAvatar(this.state);
    }

    // Get own avatar data
    getOwnAvatarData(): AvatarData | null {
        if (!this.state.ownAvatar) return null;
        return { ...this.state.ownAvatar };
    }

    // Get peer avatar
    getPeerAvatar(username: string): string | null {
        return getPeerAvatar(this.state, username);
    }

    // Get peer avatar hash
    getPeerAvatarHash(username: string): string | null {
        return getPeerAvatarHash(this.state, username);
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
