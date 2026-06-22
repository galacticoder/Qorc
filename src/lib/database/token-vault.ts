/**
 * Token Vault
 * 
 * Stores Privacy Pass tokens encrypted with the OPAQUE export key
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { storage } from '../tauri-bindings';
import type { AnonymousToken } from '../cryptography/privacy-pass-client';
import { TokenSerializer } from '../cryptography/privacy-pass-client';
import { Base64 } from '../cryptography/base64';

// Vault configuration
const VAULT_CONFIG = {
    STORAGE_KEY: 'qor_token_vault',
    NONCE_SIZE: 24,
    LOW_TOKEN_THRESHOLD: 50,
    REFRESH_TRIGGER_THRESHOLD: 25,
    VERSION: 1,
};

// Vault labels for key derivation
const VAULT_LABELS = {
    ENCRYPTION_KEY: 'TokenVault-Encryption-v1',
    AUTH_KEY: 'TokenVault-Auth-v1',
};

/**
 * Vault metadata stored alongside encrypted tokens
 */
interface VaultMetadata {
    version: number;
    createdAt: number;
    lastUpdated: number;
    tokenCount: number;
    encryptedData: string;
    nonce: string;
    authTag: string;
}

/**
 * Token Vault
 * 
 * Manages encrypted storage of anonymous authentication tokens
 */
export class TokenVault {
    private encryptionKey: Uint8Array | null = null;
    private tokens: AnonymousToken[] = [];
    private isUnlocked = false;

    /**
     * Initialize vault with OPAQUE export key
     */
    async initialize(exportKey: Uint8Array): Promise<void> {
        // Derive vault encryption key from OPAQUE export key
        this.encryptionKey = hkdf(
            blake3,
            exportKey,
            new Uint8Array(0),
            new TextEncoder().encode(VAULT_LABELS.ENCRYPTION_KEY),
            32
        );

        await this.loadFromStorage();
        this.isUnlocked = true;
    }

    /**
     * Lock vault
     */
    lock(): void {
        if (this.encryptionKey) {
            this.encryptionKey.fill(0);
            this.encryptionKey = null;
        }

        // Clear token secrets from memory
        for (const token of this.tokens) {
            if (token.tokenSecret) token.tokenSecret.fill(0);
            if (token.blindingFactor) token.blindingFactor.fill(0);
            if (token.unblindedToken) token.unblindedToken.fill(0);
        }

        this.tokens = [];
        this.isUnlocked = false;
    }

    /**
     * Store a batch of new tokens
     */
    async storeTokens(newTokens: AnonymousToken[]): Promise<void> {
        this.ensureUnlocked();

        this.tokens.push(...newTokens);

        await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0)));
        await this.saveToStorage();
    }

    /**
     * Get tokens that are pending issuance
     */
    getPendingTokens(): AnonymousToken[] {
        return this.tokens.filter(t => !t.unblindedToken && !t.used);
    }

    /**
     * Update a batch of tokens
     */
    async updateTokens(updatedTokens: AnonymousToken[]): Promise<void> {
        this.ensureUnlocked();

        for (const updated of updatedTokens) {
            const index = this.tokens.findIndex(t => t.id === updated.id);
            if (index !== -1) {
                this.tokens[index] = updated;
            } else {
                this.tokens.push(updated);
            }

            // Yield every 50 tokens to keep UI alive
            if (updatedTokens.indexOf(updated) % 50 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }

        await this.saveToStorage();
    }

    /**
     * Get next available token for redemption
     */
    async getToken(): Promise<AnonymousToken | null> {
        if (!this.isUnlocked || !this.encryptionKey) {
            return null;
        }

        const token = this.tokens.find(t => !t.used && !t.pending && t.unblindedToken);

        if (!token) return null;

        token.pending = true;
        await this.saveToStorage();

        return token;
    }

    /**
     * Confirm token was successfully used
     */
    async confirmUsed(tokenId: string): Promise<void> {
        this.ensureUnlocked();

        const token = this.tokens.find(t => t.id === tokenId);
        if (token) {
            token.used = true;
            token.pending = false;

            if (token.tokenSecret) token.tokenSecret.fill(0);
            if (token.unblindedToken) token.unblindedToken.fill(0);

            await this.saveToStorage();
        }
    }

    /**
     * Rollback pending token if auth failed
     */
    async rollbackToken(tokenId: string): Promise<void> {
        this.ensureUnlocked();

        const token = this.tokens.find(t => t.id === tokenId);
        if (token && token.pending) {
            token.pending = false;
            await this.saveToStorage();
        }
    }

    /**
     * Get count of remaining usable tokens
     */
    getRemainingCount(): number {
        return this.tokens.filter(t => !t.used && !t.pending && t.unblindedToken).length;
    }

    async reserveResumeTokens(count: number): Promise<AnonymousToken[]> {
        if (!this.isUnlocked || !this.encryptionKey || count <= 0) {
            return [];
        }
        const reserved: AnonymousToken[] = [];
        this.tokens = this.tokens.filter((t) => {
            if (reserved.length < count && !t.used && !t.pending && t.unblindedToken) {
                reserved.push(t);
                // remove from the vault
                return false; 
            }
            return true;
        });
        if (reserved.length > 0) {
            await this.saveToStorage();
        }
        return reserved;
    }

    /**
     * Check if token refresh is needed
     */
    needsRefresh(): boolean {
        return this.getRemainingCount() <= VAULT_CONFIG.REFRESH_TRIGGER_THRESHOLD;
    }

    /**
     * Check if tokens are running low
     */
    isLow(): boolean {
        return this.getRemainingCount() <= VAULT_CONFIG.LOW_TOKEN_THRESHOLD;
    }

    /**
     * Remove used tokens to free storage
     */
    async pruneUsedTokens(): Promise<number> {
        this.ensureUnlocked();

        const initialCount = this.tokens.length;
        this.tokens = this.tokens.filter(t => !t.used);
        const prunedCount = initialCount - this.tokens.length;

        if (prunedCount > 0) {
            await this.saveToStorage();
        }

        return prunedCount;
    }

    /**
     * Load tokens from encrypted storage
     */
    private async loadFromStorage(): Promise<void> {
        if (!this.encryptionKey) {
            throw new Error('Vault not unlocked');
        }

        try {
            const stored = await storage.get(VAULT_CONFIG.STORAGE_KEY);
            if (!stored) {
                this.tokens = [];
                return;
            }

            const metadata: VaultMetadata = JSON.parse(stored);

            if (metadata.version !== VAULT_CONFIG.VERSION) {
                console.warn('[TokenVault] Version mismatch, clearing vault');
                this.tokens = [];
                return;
            }

            // Decrypt token data
            const nonce = Base64.base64ToUint8Array(metadata.nonce);
            const encryptedData = Base64.base64ToUint8Array(metadata.encryptedData);

            const cipher = xchacha20poly1305(this.encryptionKey, nonce);
            const decrypted = cipher.decrypt(encryptedData);

            const tokenData = new TextDecoder().decode(decrypted);
            this.tokens = await TokenSerializer.deserializeBatch(tokenData);

        } catch (error) {
            console.error('[TokenVault] Failed to load tokens:', error);
            this.tokens = [];
        }
    }

    /**
     * Save tokens to encrypted storage
     */
    private async saveToStorage(): Promise<void> {
        if (!this.encryptionKey) {
            throw new Error('Vault not unlocked');
        }

        try {
            // Serialize tokens
            await new Promise(resolve => setTimeout(resolve, 0));
            const tokenData = await TokenSerializer.serializeBatch(this.tokens);
            
            await new Promise(resolve => setTimeout(resolve, 0));
            const dataBytes = new TextEncoder().encode(tokenData);

            // Encrypt
            const nonce = randomBytes(VAULT_CONFIG.NONCE_SIZE);
            const cipher = xchacha20poly1305(this.encryptionKey, nonce);
            
            await new Promise(resolve => setTimeout(resolve, 0));
            const encrypted = cipher.encrypt(dataBytes);

            // Create metadata
            const metadata: VaultMetadata = {
                version: VAULT_CONFIG.VERSION,
                createdAt: this.tokens.length > 0
                    ? Math.min(...this.tokens.map(t => t.issuedAt))
                    : Date.now(),
                lastUpdated: Date.now(),
                tokenCount: this.tokens.filter(t => !t.used).length,
                encryptedData: Base64.arrayBufferToBase64(encrypted),
                nonce: Base64.arrayBufferToBase64(nonce),
                authTag: '',
            };

            await storage.set(VAULT_CONFIG.STORAGE_KEY, JSON.stringify(metadata));
        } catch (error) {
            console.error('[TokenVault] Failed to save tokens:', error);
            throw error;
        }
    }

    /**
     * Ensure vault is unlocked before operations
     */
    private ensureUnlocked(): void {
        if (!this.isUnlocked || !this.encryptionKey) {
            throw new Error('Vault is locked');
        }
    }

    /**
     * Check if vault is unlocked
     */
    isVaultUnlocked(): boolean {
        return this.isUnlocked;
    }

    /**
     * Clear all tokens
     */
    async clearAll(): Promise<void> {
        this.lock();
        await storage.remove(VAULT_CONFIG.STORAGE_KEY);
    }
}

export const tokenVault = new TokenVault();

export { VAULT_CONFIG };
