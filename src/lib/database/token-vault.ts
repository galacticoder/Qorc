/**
 * Token Vault
 */

import { account } from '../tauri-bindings';
import type { AnonymousToken } from '../cryptography/privacy-pass-client';
import { getPrivacyPassBatchEpoch, isPrivacyPassTokenEpochUsable, isPrivacyPassTokenUsable, PrivacyPassClient, TokenSerializer } from '../cryptography/privacy-pass-client';
import { Base64 } from '../cryptography/base64';
import { getCurrentServerScope } from '../security/local-account-scope';
import { wipeAnonymousToken as wipeToken } from '../cryptography/wipe';
import { ACCOUNT_AUTH_PURPOSE } from '../config/audiences';

// Vault configuration
const VAULT_CONFIG = {
    MAX_STORED_CHARS: 7 * 1024 * 1024,
    MAX_TOKENS: 250,
};

function cloneToken(token: AnonymousToken): AnonymousToken {
    return {
        ...token,
        tokenSecret: new Uint8Array(token.tokenSecret),
        blindingFactor: token.blindingFactor ? new Uint8Array(token.blindingFactor) : undefined,
        blindedElement: token.blindedElement ? new Uint8Array(token.blindedElement) : undefined,
        unblindedToken: token.unblindedToken ? new Uint8Array(token.unblindedToken) : undefined,
    };
}

/**
 * Token Vault
 * 
 * Manages encrypted storage of anonymous authentication tokens
 */
export class TokenVault {
    private tokens: AnonymousToken[] = [];
    private isUnlocked = false;
    private serverScope: string | null = null;
    private mutationTail: Promise<void> = Promise.resolve();
    private generation = 0;

    private assertGeneration(expectedGeneration: number): void {
        if (this.generation !== expectedGeneration) {
            throw new Error('Token vault operation was superseded');
        }
    }

    private async withMutation<T>(
        operation: (generation: number) => Promise<T>,
        changesGeneration = false
    ): Promise<T> {
        const requestedGeneration = this.generation;
        const previous = this.mutationTail;
        let release!: () => void;
        this.mutationTail = new Promise<void>((resolve) => {
            release = resolve;
        });
        await previous;
        try {
            this.assertGeneration(requestedGeneration);
            const result = await operation(requestedGeneration);
            if (!changesGeneration) this.assertGeneration(requestedGeneration);
            return result;
        } finally {
            release();
        }
    }

    /** Activate the account-bound native token vault after native account unlock. */
    async initialize(): Promise<void> {
        await this.withMutation(() => this.initializeInternal(), true);
    }

    private async initializeInternal(): Promise<void> {
        this.lock();
        const generation = this.generation;
        let loadedTokens: AnonymousToken[] = [];
        const serverScope = await getCurrentServerScope();
        this.assertGeneration(generation);
        this.serverScope = serverScope;

        try {
            loadedTokens = await this.loadFromStorage(generation);
            this.assertGeneration(generation);
            if (await getCurrentServerScope() !== serverScope) {
                throw new Error('Token-vault server changed during initialization');
            }
            this.assertGeneration(generation);
            this.tokens = loadedTokens;
            loadedTokens = [];
            this.isUnlocked = true;
        } catch (error) {
            for (const token of loadedTokens) wipeToken(token);
            if (this.generation === generation) this.lock();
            throw error;
        }
    }

    /**
     * Lock vault
     */
    lock(): string | null {
        const serverScope = this.serverScope;
        this.generation += 1;

        // Clear token secrets from memory
        for (const token of this.tokens) wipeToken(token);

        this.tokens = [];
        this.isUnlocked = false;
        this.serverScope = null;
        return serverScope;
    }

    /**
     * Store a batch of new tokens
     */
    async storeTokens(newTokens: AnonymousToken[]): Promise<void> {
        await this.withMutation((generation) => this.storeTokensInternal(newTokens, generation));
    }

    async replaceTokens(newTokens: AnonymousToken[]): Promise<void> {
        await this.withMutation((generation) => this.replaceTokensInternal(newTokens, generation));
    }

    private async replaceTokensInternal(newTokens: AnonymousToken[], generation: number): Promise<void> {
        await this.validateCurrentOwner(generation);
        if (!Array.isArray(newTokens) || newTokens.length !== VAULT_CONFIG.MAX_TOKENS) {
            throw new Error('Invalid replacement token batch');
        }

        const ids = new Set<string>();
        const replacement: AnonymousToken[] = [];
        const originalTokens = this.tokens;
        try {
            for (const token of newTokens) {
                if (
                    !token ||
                    typeof token.id !== 'string' ||
                    ids.has(token.id) ||
                    !isPrivacyPassTokenEpochUsable(token.tokenSecret)
                ) {
                    throw new Error('Invalid replacement token');
                }
                ids.add(token.id);
                replacement.push(cloneToken(token));
            }

            this.tokens = replacement;
            await this.saveToStorage(generation);
            this.assertGeneration(generation);
            for (const token of originalTokens) wipeToken(token);
        } catch (error) {
            if (this.generation === generation) {
                this.tokens = originalTokens;
            } else {
                for (const token of originalTokens) wipeToken(token);
            }
            for (const token of replacement) wipeToken(token);
            throw error;
        }
    }

    private async storeTokensInternal(newTokens: AnonymousToken[], generation: number): Promise<void> {
        await this.validateCurrentOwner(generation);
        if (!Array.isArray(newTokens) || newTokens.length > 250) throw new Error('Invalid token batch');
        const originalTokens = this.tokens;
        const discarded = originalTokens.filter((token) => !isPrivacyPassTokenEpochUsable(token.tokenSecret));
        const nextTokens = originalTokens.filter((token) => isPrivacyPassTokenEpochUsable(token.tokenSecret));
        const added: AnonymousToken[] = [];
        const existingIds = new Set(nextTokens.map((token) => token.id));
        try {
            for (const token of newTokens) {
                if (
                    !token ||
                    typeof token.id !== 'string' ||
                    existingIds.has(token.id) ||
                    !isPrivacyPassTokenEpochUsable(token.tokenSecret)
                ) {
                    throw new Error('Invalid new token');
                }
                const owned = cloneToken(token);
                nextTokens.push(owned);
                added.push(owned);
                existingIds.add(token.id);
            }
            if (nextTokens.length > VAULT_CONFIG.MAX_TOKENS) {
                throw new Error('Token vault capacity exceeded');
            }

            this.tokens = nextTokens;

            await new Promise(resolve => setTimeout(resolve, 0));
            this.assertGeneration(generation);
            await this.saveToStorage(generation);
            this.assertGeneration(generation);
            for (const token of discarded) wipeToken(token);
        } catch (error) {
            if (this.generation === generation) {
                this.tokens = originalTokens;
            } else {
                for (const token of originalTokens) wipeToken(token);
            }
            for (const token of added) wipeToken(token);
            throw error;
        }
    }

    /** Whether the native account-bound token vault is active. */
    isVaultUnlocked(): boolean {
        return this.isUnlocked;
    }

    /**
     * Prepare single credential that replaces the one consumed to authorize the current anonymous socket.
     */
    async prepareAuthorizedRefresh(batchSize: number = 1): Promise<{ blindedTokens: string[]; tokenEpoch: number }> {
        if (batchSize !== 1) throw new Error('Invalid account-auth replacement batch size');
        const existing = await this.getPendingTokens(2);
        if (existing.length > 0) {
            if (existing.length !== 1 || existing[0].blindedElement?.length !== 32) {
                for (const token of existing) wipeToken(token);
                throw new Error('Invalid pending account-auth replacement');
            }
            try {
                return {
                    blindedTokens: [Base64.arrayBufferToBase64(existing[0].blindedElement)],
                    tokenEpoch: getPrivacyPassBatchEpoch(existing)
                };
            } finally {
                wipeToken(existing[0]);
            }
        }
        const ppClient = new PrivacyPassClient(ACCOUNT_AUTH_PURPOSE);
        const generated = await ppClient.generateTokenBatch(batchSize);
        try {
            await this.storeTokens(generated.tokenSecrets);
            return {
                blindedTokens: generated.blindedTokens.map((token) => Base64.arrayBufferToBase64(token)),
                tokenEpoch: getPrivacyPassBatchEpoch(generated.tokenSecrets)
            };
        } finally {
            for (const token of generated.blindedTokens) token.fill(0);
            for (const token of generated.tokenSecrets) wipeToken(token);
        }
    }

    /**
     * Complete onefor one replacement and fold into the working pool
     */
    async finalizeAuthorizedRefresh(
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array,
        issuerEpoch: number
    ): Promise<void> {
        const pendingTokens = await this.getPendingTokens(signedBlindedTokens.length);
        if (pendingTokens.length !== signedBlindedTokens.length) {
            throw new Error('Account-auth refresh batch size mismatch');
        }
        const ppClient = new PrivacyPassClient(ACCOUNT_AUTH_PURPOSE);
        const completed = await ppClient.unblindTokens(
            pendingTokens,
            signedBlindedTokens,
            proof,
            serverPublicKey,
            issuerEpoch
        );
        try {
            await this.updateTokens(completed);
        } finally {
            for (const token of pendingTokens) wipeToken(token);
        }
    }

    /**
     * Get tokens that are pending issuance
     */
    async getPendingTokens(limit: number = 250): Promise<AnonymousToken[]> {
        return this.withMutation(async (generation) => {
            await this.validateCurrentOwner(generation);
            if (!Number.isSafeInteger(limit) || limit < 1 || limit > 250) {
                throw new Error('Invalid pending token limit');
            }
            return this.tokens
                .filter(t => !t.unblindedToken && !t.used && isPrivacyPassTokenEpochUsable(t.tokenSecret))
                .slice(0, limit)
                .map(cloneToken);
        });
    }

    async discardPendingTokens(): Promise<void> {
        await this.withMutation(async (generation) => {
            await this.validateCurrentOwner(generation);
            const originalTokens = this.tokens;
            const discarded = originalTokens.filter(token => !token.unblindedToken && !token.used);
            if (discarded.length === 0) return;
            this.tokens = originalTokens.filter(token => token.unblindedToken || token.used);
            try {
                await this.saveToStorage(generation);
                this.assertGeneration(generation);
                for (const token of discarded) wipeToken(token);
            } catch (error) {
                if (this.generation === generation) {
                    this.tokens = originalTokens;
                } else {
                    for (const token of originalTokens) wipeToken(token);
                }
                throw error;
            }
        });
    }

    /**
     * Update a batch of tokens
     */
    async updateTokens(updatedTokens: AnonymousToken[]): Promise<void> {
        await this.withMutation((generation) => this.updateTokensInternal(updatedTokens, generation));
    }

    private async updateTokensInternal(updatedTokens: AnonymousToken[], generation: number): Promise<void> {
        await this.validateCurrentOwner(generation);
        if (!Array.isArray(updatedTokens) || updatedTokens.length > 250) {
            throw new Error('Invalid token update batch');
        }

        const updateIds = new Set<string>();
        const originalTokens = this.tokens;
        const nextTokens = originalTokens.slice();
        const indexById = new Map(nextTokens.map((token, index) => [token.id, index]));
        const ownedUpdates: AnonymousToken[] = [];
        const replacedTokens: AnonymousToken[] = [];
        try {
            for (let i = 0; i < updatedTokens.length; i++) {
                const updated = updatedTokens[i];
                if (updateIds.has(updated.id)) throw new Error('Duplicate token update');
                updateIds.add(updated.id);

                const owned = cloneToken(updated);
                ownedUpdates.push(owned);
                const index = indexById.get(updated.id);
                if (index !== undefined) {
                    replacedTokens.push(nextTokens[index]);
                    nextTokens[index] = owned;
                } else {
                    indexById.set(updated.id, nextTokens.length);
                    nextTokens.push(owned);
                }

                if (i > 0 && i % 50 === 0) {
                    await new Promise(resolve => setTimeout(resolve, 0));
                    this.assertGeneration(generation);
                }
            }
            if (nextTokens.length > VAULT_CONFIG.MAX_TOKENS) {
                throw new Error('Token vault capacity exceeded');
            }

            this.tokens = nextTokens;
            await this.saveToStorage(generation);
            this.assertGeneration(generation);
            for (const token of replacedTokens) wipeToken(token);
        } catch (error) {
            if (this.generation === generation) {
                this.tokens = originalTokens;
            } else {
                for (const token of originalTokens) wipeToken(token);
            }
            for (const token of ownedUpdates) wipeToken(token);
            throw error;
        }
    }

    async reserveResumeTokens(count: number): Promise<AnonymousToken[]> {
        return this.withMutation((generation) => this.reserveResumeTokensInternal(count, generation));
    }

    private async reserveResumeTokensInternal(count: number, generation: number): Promise<AnonymousToken[]> {
        if (!Number.isSafeInteger(count) || count <= 0) {
            throw new Error('Invalid resume-token reservation count');
        }
        await this.validateCurrentOwner(generation);
        const originalTokens = this.tokens;
        const reserved: AnonymousToken[] = [];
        const retained = this.tokens.filter((t) => {
            if (reserved.length < count && !t.pending && isPrivacyPassTokenUsable(t, ACCOUNT_AUTH_PURPOSE)) {
                reserved.push(t);
                return false;
            }
            return true;
        });
        if (reserved.length > 0) {
            this.tokens = retained;
            try {
                await this.saveToStorage(generation);
                this.assertGeneration(generation);
            } catch (error) {
                if (this.generation === generation) {
                    this.tokens = originalTokens;
                } else {
                    for (const token of originalTokens) wipeToken(token);
                }
                throw error;
            }
        }
        return reserved;
    }

    /**
     * Load tokens from encrypted storage
     */
    private async loadFromStorage(generation: number): Promise<AnonymousToken[]> {
        this.assertGeneration(generation);
        const serverScope = this.serverScope;
        if (!serverScope) {
            throw new Error('Vault not unlocked');
        }

        let loadedTokens: AnonymousToken[] = [];
        try {
            const stored = await account.tokenVaultLoad(serverScope, 'working');
            this.assertGeneration(generation);
            if (stored === null) {
                return [];
            }
            if (typeof stored !== 'string' || stored.length > VAULT_CONFIG.MAX_STORED_CHARS) {
                throw new Error('Token vault record is oversized');
            }

            loadedTokens = await TokenSerializer.deserializeBatch(stored);
            this.assertGeneration(generation);
            let removedAmbiguousToken = false;
            loadedTokens = loadedTokens.filter((token) => {
                if (!token.pending && !token.used) return true;
                wipeToken(token);
                removedAmbiguousToken = true;
                return false;
            });
            if (loadedTokens.length > VAULT_CONFIG.MAX_TOKENS) {
                throw new Error('Token vault exceeds its fixed capacity');
            }
            if (removedAmbiguousToken) {
                await this.saveTokenSnapshot(loadedTokens, generation, serverScope);
            }
            this.assertGeneration(generation);
            const result = loadedTokens;
            loadedTokens = [];
            return result;
        } catch (error) {
            for (const token of loadedTokens) wipeToken(token);
            loadedTokens = [];
            if (this.generation !== generation) throw error;
            throw new Error(`Token vault could not be opened: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Save tokens to encrypted storage
     */
    private async saveToStorage(generation: number): Promise<void> {
        this.assertGeneration(generation);
        const serverScope = this.serverScope;
        if (!serverScope) {
            throw new Error('Vault not unlocked');
        }
        await this.saveTokenSnapshot(this.tokens, generation, serverScope);
    }

    private async saveTokenSnapshot(
        tokens: AnonymousToken[],
        generation: number,
        serverScope: string
    ): Promise<void> {
        try {
            // Serialize tokens
            await new Promise(resolve => setTimeout(resolve, 0));
            this.assertGeneration(generation);
            const tokenData = await TokenSerializer.serializeBatch(tokens);
            this.assertGeneration(generation);

            if (tokenData.length > VAULT_CONFIG.MAX_STORED_CHARS) {
                throw new Error('Token vault record is oversized');
            }
            if (!await account.tokenVaultStore(serverScope, 'working', tokenData)) {
                throw new Error('Native secure storage rejected the token-vault update');
            }
            this.assertGeneration(generation);
        } catch (error) {
            console.error('[TokenVault] Failed to save tokens:', error);
            throw error;
        }
    }

    private checkUnlocked(): void {
        if (!this.isUnlocked || !this.serverScope) {
            throw new Error('Vault is locked');
        }
    }

    private async validateCurrentOwner(generation: number): Promise<void> {
        this.assertGeneration(generation);
        this.checkUnlocked();
        const owner = this.serverScope;
        const currentOwner = await getCurrentServerScope();
        this.assertGeneration(generation);
        if (!owner || currentOwner !== owner) {
            this.lock();
            throw new Error('Token vault belongs to a different server');
        }
    }

    /**
     * Clear all tokens
     */
    async clearAll(): Promise<void> {
        const serverScope = this.serverScope;
        await this.withMutation(async () => {
            if (this.serverScope === serverScope) this.lock();
            if (serverScope) {
                if (!await account.tokenVaultRemove(serverScope, 'working')) {
                    throw new Error('Token vault deletion could not be verified');
                }
            }
        }, true);
    }
}

export const tokenVault = new TokenVault();

export { VAULT_CONFIG };
