import { SecureDB } from './secureDB';
import { encryptLongTerm, decryptLongTerm, LongTermEnvelope } from './long-term-encryption';
import websocketClient from './websocket';
import { generateDefaultAvatar } from './utils';
import { SignalType } from './signal-types';

const MAX_AVATAR_SIZE_BYTES = 512 * 1024;
const MAX_AVATAR_DIMENSION = 512;
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'];
const AVATAR_STORE_KEY = 'profile_avatars';
const SETTINGS_KEY = 'profile_settings';
const AVATAR_CACHE_TTL = 1 * 60 * 1000; // 1 minute for avatar updates
const SERVER_FETCH_DEBOUNCE = 3000; // 3 seconds between server fetch attempts

interface AvatarData {
    data: string;
    mimeType: string;
    hash: string;
    updatedAt: number;
    isDefault?: boolean;
}

interface ProfileSettings {
    shareWithOthers: boolean;
    lastUpdated: number;
}

interface CachedAvatar {
    data: string;
    hash: string;
    cachedAt: number;
    expiresAt: number;
}

interface ProfilePictureMessage {
    type: 'profile-picture-request' | 'profile-picture-response';
    hash?: string;
    data?: string;
    mimeType?: string;
}

class ProfilePictureSystem {
    private static instance: ProfilePictureSystem | null = null;
    private secureDB: SecureDB | null = null;
    private ownAvatar: AvatarData | null = null;
    private settings: ProfileSettings = { shareWithOthers: false, lastUpdated: 0 };
    private avatarCache: Map<string, CachedAvatar> = new Map();
    private pendingRequests: Set<string> = new Set();
    private initialized = false;

    private constructor() { }

    static getInstance(): ProfilePictureSystem {
        if (!ProfilePictureSystem.instance) {
            ProfilePictureSystem.instance = new ProfilePictureSystem();
        }
        return ProfilePictureSystem.instance;
    }

    setSecureDB(db: SecureDB | null): void {
        this.secureDB = db;
        this.initialized = false;
        this.ownAvatar = null;
        this.avatarCache.clear();
    }

    async initialize(): Promise<void> {
        if (this.initialized || !this.secureDB) return;

        try {
            this.ensureHandlerRegistered();

            try {
                const storedAvatar = await this.secureDB.retrieve(AVATAR_STORE_KEY, 'own');
                if (storedAvatar && this.isValidAvatarData(storedAvatar)) {
                    this.ownAvatar = storedAvatar as AvatarData;
                }
            } catch (avatarError: any) {
                if (/decrypt|BLAKE3|MAC/i.test(avatarError?.message)) {
                    console.warn('[ProfilePictureSystem] Clearing corrupted avatar data');
                    await this.secureDB.clearStore(AVATAR_STORE_KEY).catch(() => { });
                }
            }

            if (!this.ownAvatar) {
                const username = websocketClient?.getUsername() || '';
                if (username) {
                    const defaultAvatarUrl = generateDefaultAvatar(username);
                    const hash = await this.hashData(defaultAvatarUrl);
                    this.ownAvatar = {
                        data: defaultAvatarUrl,
                        mimeType: 'image/svg+xml',
                        hash,
                        updatedAt: Date.now(),
                        isDefault: true
                    };
                    await this.secureDB.store(AVATAR_STORE_KEY, 'own', this.ownAvatar).catch(() => { });
                    window.dispatchEvent(new CustomEvent('profile-picture-updated', {
                        detail: { type: 'own' }
                    }));
                }
            }

            // Load settings
            try {
                const storedSettings = await this.secureDB.retrieve(SETTINGS_KEY, 'profile');
                if (storedSettings && typeof storedSettings === 'object') {
                    const s = storedSettings as any;
                    if (typeof s.shareWithOthers === 'boolean') {
                        this.settings = {
                            shareWithOthers: s.shareWithOthers,
                            lastUpdated: s.lastUpdated || Date.now()
                        };
                    }
                }
            } catch (settingsError: any) {
                if (/decrypt|BLAKE3|MAC/i.test(settingsError?.message)) {
                    console.warn('[ProfilePictureSystem] Clearing corrupted settings data');
                    await this.secureDB.clearStore(SETTINGS_KEY).catch(() => { });
                }
            }

            // Load cached avatars
            try {
                const cachedAvatars = await this.secureDB.retrieve(AVATAR_STORE_KEY, 'cache');
                if (cachedAvatars && typeof cachedAvatars === 'object') {
                    const cache = cachedAvatars as Record<string, CachedAvatar>;
                    const now = Date.now();
                    for (const [username, avatar] of Object.entries(cache)) {
                        const recalculatedExpiresAt = avatar.cachedAt + AVATAR_CACHE_TTL;
                        if (recalculatedExpiresAt > now && this.isValidCachedAvatar(avatar)) {
                            avatar.expiresAt = recalculatedExpiresAt;
                            this.avatarCache.set(username, avatar);
                        }
                    }
                }
            } catch (cacheError: any) {
                if (/decrypt|BLAKE3|MAC/i.test(cacheError?.message)) {
                    console.warn('[ProfilePictureSystem] Clearing corrupted avatar cache');
                }
                this.avatarCache.clear();
            }

            this.initialized = true;
            window.dispatchEvent(new CustomEvent('profile-picture-system-initialized'));
        } catch (error) {
            console.error('[ProfilePictureSystem] Initialize failed:', error);
        }
    }

    private isValidAvatarData(data: unknown): data is AvatarData {
        if (!data || typeof data !== 'object') return false;
        const d = data as any;
        return (
            typeof d.data === 'string' &&
            typeof d.mimeType === 'string' &&
            typeof d.hash === 'string' &&
            typeof d.updatedAt === 'number' &&
            ALLOWED_MIME_TYPES.includes(d.mimeType) &&
            d.data.length <= MAX_AVATAR_SIZE_BYTES * 1.4 &&
            d.hash.length === 64
        );
    }

    private isValidCachedAvatar(data: unknown): data is CachedAvatar {
        if (!data || typeof data !== 'object') return false;
        const d = data as any;
        return (
            typeof d.data === 'string' &&
            typeof d.hash === 'string' &&
            typeof d.cachedAt === 'number' &&
            typeof d.expiresAt === 'number' &&
            d.data.length <= MAX_AVATAR_SIZE_BYTES * 1.4 &&
            d.hash.length === 64
        );
    }

    private async hashData(data: string): Promise<string> {
        const { blake3 } = await import('@noble/hashes/blake3.js');
        const bytes = new TextEncoder().encode(data);
        const hash = blake3(bytes, { dkLen: 32 });
        return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    private validateImageData(dataUrl: string): { valid: boolean; mimeType: string; error?: string } {
        if (!dataUrl || typeof dataUrl !== 'string') {
            return { valid: false, mimeType: '', error: 'Invalid data URL' };
        }

        const match = dataUrl.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,/i);
        if (!match) {
            return { valid: false, mimeType: '', error: 'Invalid data URL format' };
        }

        const mimeType = match[1].toLowerCase();
        if (!ALLOWED_MIME_TYPES.includes(mimeType)) {
            return { valid: false, mimeType, error: `Unsupported image type: ${mimeType}` };
        }

        const base64Data = dataUrl.slice(dataUrl.indexOf(',') + 1);

        try {
            const binaryString = atob(base64Data);
            const bytes = binaryString.length;

            if (bytes > MAX_AVATAR_SIZE_BYTES) {
                return { valid: false, mimeType, error: `Image too large: ${Math.round(bytes / 1024)}KB (max ${MAX_AVATAR_SIZE_BYTES / 1024}KB)` };
            }

            if (bytes < 100) {
                return { valid: false, mimeType, error: 'Image too small or corrupted' };
            }

            const header = new Uint8Array(12);
            for (let i = 0; i < Math.min(12, binaryString.length); i++) {
                header[i] = binaryString.charCodeAt(i);
            }

            const isJpeg = header[0] === 0xFF && header[1] === 0xD8 && header[2] === 0xFF;
            const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
            const isWebp = header[0] === 0x52 && header[1] === 0x49 && header[2] === 0x46 && header[3] === 0x46 &&
                header[8] === 0x57 && header[9] === 0x45 && header[10] === 0x42 && header[11] === 0x50;
            const isSvg = mimeType === 'image/svg+xml' && (binaryString.includes('<svg') || binaryString.includes('<?xml'));

            if (!isJpeg && !isPng && !isWebp && !isSvg) {
                return { valid: false, mimeType, error: 'Invalid image magic bytes' };
            }

            if ((mimeType === 'image/jpeg' && !isJpeg) ||
                (mimeType === 'image/png' && !isPng) ||
                (mimeType === 'image/webp' && !isWebp) ||
                (mimeType === 'image/svg+xml' && !isSvg)) {
                return { valid: false, mimeType, error: 'MIME type mismatch with file content' };
            }
        } catch {
            return { valid: false, mimeType, error: 'Invalid base64 encoding' };
        }

        return { valid: true, mimeType };
    }

    async compressImage(dataUrl: string, maxSize: number = MAX_AVATAR_DIMENSION): Promise<string> {
        return new Promise((resolve, reject) => {
            const img = new Image();
            img.onload = () => {
                try {
                    let width = img.width;
                    let height = img.height;

                    if (width > maxSize || height > maxSize) {
                        if (width > height) {
                            height = Math.round((height * maxSize) / width);
                            width = maxSize;
                        } else {
                            width = Math.round((width * maxSize) / height);
                            height = maxSize;
                        }
                    }

                    const canvas = document.createElement('canvas');
                    canvas.width = width;
                    canvas.height = height;
                    const ctx = canvas.getContext('2d');
                    if (!ctx) {
                        reject(new Error('Canvas context unavailable'));
                        return;
                    }

                    ctx.drawImage(img, 0, 0, width, height);

                    let quality = 0.9;
                    let result = canvas.toDataURL('image/webp', quality);

                    while (result.length > MAX_AVATAR_SIZE_BYTES * 1.4 && quality > 0.3) {
                        quality -= 0.1;
                        result = canvas.toDataURL('image/webp', quality);
                    }

                    if (result.length > MAX_AVATAR_SIZE_BYTES * 1.4) {
                        reject(new Error('Unable to compress image to acceptable size'));
                        return;
                    }

                    resolve(result);
                } catch (e) {
                    reject(e);
                }
            };
            img.onerror = () => reject(new Error('Failed to load image'));
            img.src = dataUrl;
        });
    }

    async setOwnAvatar(imageDataUrl: string, isDefault: boolean = false): Promise<{ success: boolean; error?: string }> {
        if (!this.secureDB) {
            return { success: false, error: 'Not initialized' };
        }

        const validation = this.validateImageData(imageDataUrl);
        if (!validation.valid) {
            return { success: false, error: validation.error };
        }

        try {
            const compressed = await this.compressImage(imageDataUrl);
            const hash = await this.hashData(compressed);

            const avatarData: AvatarData = {
                data: compressed,
                mimeType: 'image/webp',
                hash,
                updatedAt: Date.now(),
                isDefault
            };

            await this.secureDB.store(AVATAR_STORE_KEY, 'own', avatarData);
            this.ownAvatar = avatarData;

            await this.uploadToServer();

            window.dispatchEvent(new CustomEvent('profile-picture-updated', {
                detail: { type: 'own' }
            }));

            return { success: true };
        } catch (error) {
            return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
        }
    }

    async removeOwnAvatar(usernameOverride?: string): Promise<void> {
        if (!this.secureDB) return;

        try {
            const username = usernameOverride || websocketClient?.getUsername() || 'unknown';
            const defaultAvatarUrl = generateDefaultAvatar(username);

            await this.setOwnAvatar(defaultAvatarUrl, true);
        } catch { }
    }

    getOwnAvatar(): string | null {
        return this.ownAvatar?.data || null;
    }

    getOwnAvatarHash(): string | null {
        return this.ownAvatar?.hash || null;
    }

    isOwnAvatarDefault(): boolean {
        return !!this.ownAvatar?.isDefault;
    }

    async setShareWithOthers(share: boolean): Promise<void> {
        if (!this.secureDB) return;

        const previousState = this.settings.shareWithOthers;
        this.settings = { shareWithOthers: share, lastUpdated: Date.now() };

        try {
            await this.secureDB.store(SETTINGS_KEY, 'profile', this.settings);

            window.dispatchEvent(new CustomEvent('profile-settings-updated', {
                detail: { shareWithOthers: share }
            }));

            if (this.ownAvatar && previousState !== share) {
                await this.uploadToServer();
            }
        } catch { }
    }

    getShareWithOthers(): boolean {
        return this.settings.shareWithOthers;
    }

    getPeerAvatar(username: string): string | null {
        const cached = this.avatarCache.get(username);
        if (cached) {
            return cached.data;
        }
        return null;
    }

    getPeerAvatarHash(username: string): string | null {
        const cached = this.avatarCache.get(username);
        if (cached) {
            return cached.hash;
        }
        return null;
    }

    isPeerAvatarStale(username: string): boolean {
        const cached = this.avatarCache.get(username);
        if (!cached) {
            return true;
        }
        return cached.expiresAt <= Date.now();
    }

    async requestPeerAvatar(username: string): Promise<void> {
        if (this.pendingRequests.has(username)) {
            return;
        }

        // Check for cached avatar
        const cached = this.avatarCache.get(username);

        // If cached and not stale, don't fetch
        if (cached && cached.expiresAt > Date.now()) {
            return;
        }

        this.pendingRequests.add(username);

        try {
            await this.fetchPeerFromServer(username);
        } finally {
            setTimeout(() => this.pendingRequests.delete(username), 30000);
        }
    }

    createProfilePictureRequest(): ProfilePictureMessage {
        return { type: 'profile-picture-request' };
    }

    createProfilePictureResponse(): ProfilePictureMessage | null {
        if (!this.settings.shareWithOthers || !this.ownAvatar) {
            return { type: 'profile-picture-response' };
        }

        return {
            type: 'profile-picture-response',
            hash: this.ownAvatar.hash,
            data: this.ownAvatar.data,
            mimeType: this.ownAvatar.mimeType
        };
    }

    async handleIncomingMessage(
        message: ProfilePictureMessage,
        fromUsername: string
    ): Promise<ProfilePictureMessage | null> {
        if (!message || typeof message.type !== 'string') return null;

        if (message.type === 'profile-picture-request') {
            return this.createProfilePictureResponse();
        }

        if (message.type === 'profile-picture-response') {
            this.pendingRequests.delete(fromUsername);

            if (!message.data || !message.hash) {
                return null;
            }

            if (typeof message.data !== 'string' || message.data.length > MAX_AVATAR_SIZE_BYTES * 1.4) {
                return null;
            }

            if (typeof message.hash !== 'string' || message.hash.length !== 64) {
                return null;
            }

            const validation = this.validateImageData(message.data);
            if (!validation.valid) {
                return null;
            }

            const computedHash = await this.hashData(message.data);
            if (computedHash !== message.hash) {
                return null;
            }

            const cached: CachedAvatar = {
                data: message.data,
                hash: message.hash,
                cachedAt: Date.now(),
                expiresAt: Date.now() + AVATAR_CACHE_TTL
            };

            this.avatarCache.set(fromUsername, cached);
            await this.persistCache();

            window.dispatchEvent(new CustomEvent('profile-picture-updated', {
                detail: { type: 'peer', username: fromUsername }
            }));
        }

        return null;
    }

    private async persistCache(): Promise<void> {
        if (!this.secureDB) return;

        try {
            const cacheObj: Record<string, CachedAvatar> = {};
            const now = Date.now();

            for (const [username, avatar] of this.avatarCache.entries()) {
                if (avatar.expiresAt > now) {
                    cacheObj[username] = avatar;
                }
            }

            await this.secureDB.store(AVATAR_STORE_KEY, 'cache', cacheObj);
        } catch { }
    }

    clearPeerCache(username?: string): void {
        if (username) {
            this.avatarCache.delete(username);
        } else {
            this.avatarCache.clear();
        }
        void this.persistCache();
    }

    private serverFetchTimestamps: Map<string, number> = new Map();
    private ownKyberPublicKey: string | null = null;
    private ownKyberSecretKey: Uint8Array | null = null;

    /**
     * Set cryptographic keys for server storage
     */
    setKeys(kyberPublicBase64: string, kyberSecretKey: Uint8Array): void {
        this.ownKyberPublicKey = kyberPublicBase64;
        this.ownKyberSecretKey = kyberSecretKey;
    }

    /**
     * Upload own avatar to server
     */
    async uploadToServer(): Promise<{ success: boolean; error?: string }> {
        if (!this.ownAvatar || !this.ownKyberPublicKey) {
            return { success: false, error: 'No avatar or keys available' };
        }

        try {
            const envelope = await encryptLongTerm(
                JSON.stringify({
                    data: this.ownAvatar.data,
                    mimeType: this.ownAvatar.mimeType,
                    hash: this.ownAvatar.hash
                }),
                this.ownKyberPublicKey
            );

            if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
                return { success: false, error: 'Not connected to server' };
            }

            const uploadMessage: any = {
                type: SignalType.AVATAR_UPLOAD,
                envelope,
                shareWithOthers: this.settings.shareWithOthers
            };

            if (this.settings.shareWithOthers) {
                uploadMessage.publicData = {
                    data: this.ownAvatar.data,
                    mimeType: this.ownAvatar.mimeType,
                    hash: this.ownAvatar.hash
                };
            }

            await websocketClient.sendSecureControlMessage(uploadMessage);

            return { success: true };
        } catch (error) {
            return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
        }
    }

    private handlerRegistered = false;

    public ensureHandlerRegistered(): void {
        if (this.handlerRegistered) return;

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

            this.handlerRegistered = true;
        } catch { }
    }

    private ownAvatarFetchTimestamp = 0;

    /**
     * Fetch own avatar from server (for new device login).
     */
    async fetchOwnFromServer(): Promise<{ success: boolean; error?: string }> {
        const timeSinceLastFetch = Date.now() - this.ownAvatarFetchTimestamp;
        if (timeSinceLastFetch < SERVER_FETCH_DEBOUNCE) {
            return { success: false, error: 'Debounced' };
        }
        this.ownAvatarFetchTimestamp = Date.now();

        if (!this.ownKyberSecretKey) {
            return { success: false, error: 'No keys available' };
        }

        try {
            this.ensureHandlerRegistered();
            if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
                return { success: false, error: 'Not connected to server' };
            }

            await websocketClient.sendSecureControlMessage({
                type: SignalType.AVATAR_FETCH,
                target: 'own'
            });

            return { success: true };
        } catch (error) {
            return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
        }
    }

    /**
     * Fetch a peer's avatar from server.
     */
    async fetchPeerFromServer(username: string): Promise<void> {
        const lastFetch = this.serverFetchTimestamps.get(username) || 0;
        const timeSinceLastFetch = Date.now() - lastFetch;

        if (timeSinceLastFetch < SERVER_FETCH_DEBOUNCE) {
            return;
        }
        this.serverFetchTimestamps.set(username, Date.now());

        try {
            this.ensureHandlerRegistered();
            const isConnected = websocketClient?.isConnectedToServer();
            const isPQReady = websocketClient?.isPQSessionEstablished();

            if (!isConnected || !isPQReady) {
                return;
            }

            await websocketClient.sendSecureControlMessage({
                type: SignalType.AVATAR_FETCH,
                target: username
            });
        } catch { }
    }

    /**
     * Cache a peer's avatar.
     */
    async cachePeerAvatar(username: string, data: string, mimeType: string, hash: string): Promise<void> {
        const cached: CachedAvatar = {
            data,
            hash,
            cachedAt: Date.now(),
            expiresAt: Date.now() + AVATAR_CACHE_TTL
        };

        this.avatarCache.set(username, cached);
        await this.persistCache();

        window.dispatchEvent(new CustomEvent('profile-picture-updated', {
            detail: { type: 'peer', username, fromServer: true }
        }));
    }

    /**
     * Handle avatar response from server.
     */
    public async handleServerAvatarResponse(response: {
        target: string;
        envelope?: LongTermEnvelope | any;
        found: boolean;
        isDefault?: boolean;
        publicData?: any;
    }): Promise<void> {
        if (!response.found || !response.envelope) {
        }

        const isOwn = response.target === 'own';
        const isDefault = !!response.isDefault;

        try {
            let avatarData: { data: string; mimeType: string; hash: string } | null = null;

            if (!response.found) {
                if (isOwn) {
                    await this.removeOwnAvatar();
                }
            } else if (isOwn && !isDefault && this.ownKyberSecretKey) {
                if (response.envelope.version !== 'lt-v1') {
                    await this.removeOwnAvatar();
                    return;
                }

                const result = await decryptLongTerm(response.envelope, this.ownKyberSecretKey);
                if (result.json && typeof result.json === 'object') {
                    avatarData = result.json as any;
                }
            } else {
                avatarData = response.envelope as any;
            }

            if (avatarData && typeof avatarData.data === 'string') {
                const validation = this.validateImageData(avatarData.data);
                if (!validation.valid) {
                    return;
                }

                if (isOwn) {
                    this.ownAvatar = {
                        data: avatarData.data,
                        mimeType: avatarData.mimeType || 'image/webp',
                        hash: avatarData.hash || '',
                        updatedAt: Date.now()
                    };
                    if (this.secureDB) {
                        await this.secureDB.store(AVATAR_STORE_KEY, 'own', this.ownAvatar);
                    }
                    window.dispatchEvent(new CustomEvent('profile-picture-updated', {
                        detail: { type: 'own', fromServer: true }
                    }));
                } else {
                    // Cache peer avatar
                    await this.cachePeerAvatar(
                        response.target,
                        avatarData.data,
                        avatarData.mimeType || 'image/webp',
                        avatarData.hash
                    );
                }
            } else if (!response.found) {
                if (isOwn) {
                    if (this.secureDB) {
                        await this.secureDB.delete(AVATAR_STORE_KEY, 'own');
                    }
                    this.ownAvatar = null;
                    window.dispatchEvent(new CustomEvent('profile-picture-updated', { detail: { type: 'own', fromServer: true } }));
                } else {
                    try {
                        const defaultAvatar = generateDefaultAvatar(response.target);
                        const fallbackHash = await this.hashData(defaultAvatar);

                        await this.cachePeerAvatar(
                            response.target,
                            defaultAvatar,
                            'image/svg+xml',
                            fallbackHash
                        );

                        window.dispatchEvent(new CustomEvent('profile-picture-updated', {
                            detail: { type: 'peer', username: response.target, fromServer: false, isDefault: true }
                        }));

                    } catch {
                        window.dispatchEvent(new CustomEvent('profile-picture-updated', {
                            detail: { type: 'peer', username: response.target, notFound: true }
                        }));
                    }
                }
            } else {
            }

        } catch {
            if (response.envelope) {
            }
        }
    }
}

export const profilePictureSystem = ProfilePictureSystem.getInstance();
export type { ProfilePictureMessage, AvatarData, LongTermEnvelope };

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

