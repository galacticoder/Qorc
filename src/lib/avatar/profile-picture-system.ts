import websocketClient from '../websocket/websocket';
import type { SecureDB } from '../database/secureDB';
import type { ProfilePictureMessage, AvatarData } from '../types/avatar-types';
import { createInitialState } from './state';
import { AvatarSystemState } from '../types/avatar-types';
import { setSecureDB, setKeys, initialize } from './init';
import { clearPeerCache, cachePeerAvatar } from './cache';
import { setOwnAvatar, removeOwnAvatar, getOwnAvatar, getOwnAvatarHash, isOwnAvatarDefault, setShareWithOthers, getShareWithOthers } from './own-avatar';
import { getPeerAvatar, getPeerAvatarHash, isPeerAvatarStale, requestPeerAvatar } from './peer-avatar';
import { uploadToServer, fetchOwnFromServer, fetchPeerFromServer, handleServerAvatarResponse } from './server-sync';
import { createProfilePictureRequest, createProfilePictureResponse, handleIncomingMessage } from './messaging';

export type { LongTermEnvelope } from './server-sync';

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
        await initialize(this.state, () => this.ensureHandlerRegistered());
    }

    // Set own avatar
    async setOwnAvatar(imageDataUrl: string, isDefault: boolean = false): Promise<{ success: boolean; error?: string }> {
        return setOwnAvatar(this.state, imageDataUrl, isDefault, () => this.uploadToServer());
    }

    // Remove own avatar
    async removeOwnAvatar(usernameOverride?: string): Promise<void> {
        return removeOwnAvatar(this.state, usernameOverride, (url, def) => this.setOwnAvatar(url, def));
    }

    // Get own avatar
    getOwnAvatar(): string | null {
        return getOwnAvatar(this.state);
    }

    // Get own avatar hash
    getOwnAvatarHash(): string | null {
        return getOwnAvatarHash(this.state);
    }

    // Check if own avatar is default
    isOwnAvatarDefault(): boolean {
        return isOwnAvatarDefault(this.state);
    }

    // Set share with others
    async setShareWithOthers(share: boolean): Promise<void> {
        return setShareWithOthers(this.state, share, () => this.uploadToServer());
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
        return requestPeerAvatar(this.state, username, (u) => this.fetchPeerFromServer(u));
    }

    // Clear peer cache
    clearPeerCache(username?: string): void {
        clearPeerCache(this.state, username);
    }

    // Cache peer avatar
    async cachePeerAvatar(username: string, data: string, mimeType: string, hash: string): Promise<void> {
        return cachePeerAvatar(this.state, username, data, mimeType, hash);
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

    // Upload to server
    async uploadToServer(): Promise<{ success: boolean; error?: string }> {
        return uploadToServer(this.state);
    }

    // Fetch own from server
    async fetchOwnFromServer(): Promise<{ success: boolean; error?: string }> {
        this.ensureHandlerRegistered();
        return fetchOwnFromServer(this.state);
    }

    // Fetch peer from server
    async fetchPeerFromServer(username: string): Promise<void> {
        this.ensureHandlerRegistered();
        return fetchPeerFromServer(this.state, username);
    }

    // Handle server avatar response
    public async handleServerAvatarResponse(response: {
        target: string;
        envelope?: any;
        found: boolean;
        isDefault?: boolean;
        publicData?: any;
    }): Promise<void> {
        return handleServerAvatarResponse(this.state, response, () => this.removeOwnAvatar());
    }

    // Ensure handler registered
    public ensureHandlerRegistered(): void {
        if (this.state.handlerRegistered) return;

        try {
            websocketClient.registerMessageHandler('avatar-fetch-response', (msg: any) => {
                if (msg && typeof msg.target === 'string') {
                    this.handleServerAvatarResponse({
                        target: msg.target,
                        envelope: msg.envelope,
                        found: !!msg.found,
                        isDefault: !!msg.isDefault
                    }).catch(() => { });
                }
            });

            this.state.handlerRegistered = true;
        } catch { }
    }
}

export const profilePictureSystem = ProfilePictureSystem.getInstance();
export type { ProfilePictureMessage, AvatarData };

try {
    profilePictureSystem.ensureHandlerRegistered();
    if (typeof window !== 'undefined') {
        const onPQSessionEstablished = () => {
            profilePictureSystem.ensureHandlerRegistered();
        };
        window.addEventListener('pq-session-established', onPQSessionEstablished, { once: true });
    }
} catch {
}
