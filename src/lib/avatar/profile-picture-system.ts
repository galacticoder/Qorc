import type { SecureDB } from '../database/secureDB';
import type { ProfilePictureMessage, AvatarData } from '../types/avatar-types';
import { createInitialState } from './state';
import { AvatarSystemState } from '../types/avatar-types';
import { setSecureDB, setKeys, initialize } from './init';
import { clearPeerCache, cachePeerAvatar } from './cache';
import { setOwnAvatar, removeOwnAvatar, getOwnAvatar, getOwnAvatarHash, getOwnProfileVersion, isOwnAvatarDefault, setShareWithOthers, getShareWithOthers } from './own-avatar';
import { getPeerAvatar, getPeerAvatarHash, isPeerAvatarStale, requestPeerAvatar } from './peer-avatar';
import { createProfilePictureRequest, createProfilePictureResponse, handleIncomingMessage } from './messaging';

class ProfilePictureSystem {
    private static instance: ProfilePictureSystem | null = null;
    private state: AvatarSystemState;

    private constructor() {
        this.state = createInitialState();
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
        setSecureDB(this.state, db);
    }

    // Set keys
    setKeys(kyberPublicBase64: string, kyberSecretKey: Uint8Array): void {
        setKeys(this.state, kyberPublicBase64, kyberSecretKey);
    }

    // Initialize
    async initialize(): Promise<void> {
        await initialize(this.state, () => { });
    }

    // Set own avatar
    async setOwnAvatar(imageDataUrl: string, isDefault: boolean = false): Promise<{ success: boolean; error?: string }> {
        return setOwnAvatar(this.state, imageDataUrl, isDefault, () => Promise.resolve());
    }

    // Remove own avatar
    async removeOwnAvatar(usernameOverride?: string): Promise<void> {
        return removeOwnAvatar(this.state, usernameOverride, (url, def) => this.setOwnAvatar(url, def));
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

    // Get own profile version
    getOwnProfileVersion(): number {
        return getOwnProfileVersion(this.state);
    }

    // Check if own avatar is default
    isOwnAvatarDefault(): boolean {
        return isOwnAvatarDefault(this.state);
    }

    // Set share with others
    async setShareWithOthers(share: boolean): Promise<void> {
        return setShareWithOthers(this.state, share, () => Promise.resolve());
    }

    // Get share with others
    getShareWithOthers(): boolean {
        return getShareWithOthers(this.state);
    }

    // Get peer avatar
    getPeerAvatar(username: string): string | null {
        return getPeerAvatar(this.state, username);
    }

    // Get peer avatar hash
    getPeerAvatarHash(username: string): string | null {
        return getPeerAvatarHash(this.state, username);
    }

    // Check if peer avatar is stale
    isPeerAvatarStale(username: string): boolean {
        return isPeerAvatarStale(this.state, username);
    }

    // Request peer avatar
    async requestPeerAvatar(username: string): Promise<void> {
        return requestPeerAvatar(this.state, username, async () => { });
    }

    // Clear peer cache
    clearPeerCache(username?: string): void {
        clearPeerCache(this.state, username);
    }

    // Cache peer avatar
    async cachePeerAvatar(username: string, data: string, mimeType: string, hash: string, isDefault: boolean = false): Promise<void> {
        return cachePeerAvatar(this.state, username, data, mimeType, hash, isDefault);
    }

    // Create profile picture request
    createProfilePictureRequest(): ProfilePictureMessage {
        return createProfilePictureRequest();
    }

    // Create profile picture response
    createProfilePictureResponse(): ProfilePictureMessage | null {
        return createProfilePictureResponse(this.state);
    }

    // Handle incoming message
    async handleIncomingMessage(message: ProfilePictureMessage, fromUsername: string): Promise<ProfilePictureMessage | null> {
        return handleIncomingMessage(this.state, message, fromUsername);
    }
}

export const profilePictureSystem = ProfilePictureSystem.getInstance();
export type { ProfilePictureMessage, AvatarData };
