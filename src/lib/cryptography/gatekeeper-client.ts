/**
 * Total Blind Gatekeeper Client
 */

import { OPAQUEClient, OPAQUEClientHelpers } from './opaque-client';
import { PrivacyPassClient, TokenSerializer, AnonymousToken } from './privacy-pass-client';
import { SignalType } from '../types/signal-types';
import { Base64 } from './base64';
import { storage } from '../tauri-bindings';

export class GatekeeperClient {
    private static readonly MAX_ACTIVE_TOKENS = 400;
    private static readonly QUOTA_RETRY_CAPS = [200, 100, 50, 20];
    private opaqueClient: OPAQUEClient;
    private ppClient: PrivacyPassClient;
    private storedTokens: AnonymousToken[] = [];
    private storageKey: string;
    private initPromise: Promise<void> | null = null;

    constructor(serverId: string) {
        this.opaqueClient = new OPAQUEClient();
        this.ppClient = new PrivacyPassClient('server-entry');
        this.storageKey = `pp_tokens_${serverId}`;
        this.initPromise = this.loadTokens();
    }

    /**
     * Ensure tokens are loaded from storage
     */
    async ensureReady(): Promise<void> {
        if (this.initPromise) {
            await this.initPromise;
        }
    }

    /**
     * Start the server entry flow by blinding the server password
     */
    async startEntryRequest(password: string): Promise<Record<string, any>> {
        // Clear any old pending tokens from failed attempts
        this.storedTokens = this.storedTokens.filter(t => t.unblindedToken);
        
        const passwordBytes = new TextEncoder().encode(password);
        const { blindedElement } = await this.opaqueClient.startLogin(passwordBytes);
        return {
            type: SignalType.SERVER_ENTRY_REQUEST,
            ...OPAQUEClientHelpers.encodeRequest({ blindedElement })
        };
    }

    async prepareTokenIssuance(
        password: string,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverNonce: Uint8Array;
            envelope: Uint8Array;
            maskedResponse: Uint8Array;
            salt?: Uint8Array;
        },
        batchSize: number = 250
    ): Promise<Record<string, any>> {
        await this.ensureReady();

        const passwordBytes = new TextEncoder().encode(password);
        const proof = await this.opaqueClient.finishLogin(passwordBytes, serverResponse);

        if (!proof.success || !proof.authMessage) {
            console.error('[GATEKEEPER] prepareTokenIssuance proof failed:', proof.error);
            throw new Error(`Failed to derive server entry proof - incorrect password? ${proof.error || ''}`);
        }

        // Generate blinded tokens for Privacy Pass
        const { blindedTokens, tokenSecrets } = await this.ppClient.generateTokenBatch(batchSize);

        // Store secrets temporarily until unblinded
        this.storedTokens = [...this.storedTokens, ...tokenSecrets];

        return {
            type: SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
            blindedTokens: blindedTokens.map(t => Base64.arrayBufferToBase64(t)),
            proofOfKnowledge: Base64.arrayBufferToBase64(proof.authMessage)
        };
    }

    /**
     * Unblind and store tokens
     */
    async finalizeEntry(
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array
    ): Promise<void> {
        await this.ensureReady();

        const completed = await this.ppClient.unblindTokens(
            this.storedTokens.filter(t => !t.unblindedToken),
            signedBlindedTokens,
            proof,
            serverPublicKey
        );

        // Update stored tokens
        this.storedTokens = [
            ...this.storedTokens.filter(t => t.unblindedToken),
            ...completed
        ];

        await this.saveTokens();
        console.log('[AUTOLOGIN] gatekeeper finalizeEntry saved', {
            completed: completed.length, stored: this.storedTokens.length, usable: this.tokenCount
        });
    }

    /**
     * Get a token for redemption during connection
     */
    async getRedemptionPayload(): Promise<Record<string, any> | null> {
        await this.ensureReady();

        const availableToken = this.storedTokens.find(t => t.unblindedToken && !t.used && !t.pending);
        if (!availableToken) return null;

        // Mark as pending and save state
        availableToken.pending = true;
        await this.saveTokens();

        const redemption = await this.ppClient.prepareRedemption(availableToken);
        (availableToken as any).currentNullifier = Base64.arrayBufferToBase64(redemption.nullifier);

        return {
            type: SignalType.PRIVACY_PASS_REDEMPTION,
            ...OPAQUEClientHelpers.encodeRequest(redemption)
        };
    }

    /**
     * Mark token as successfully used by its nullifier
     */
    async commitTokenUsageByNullifier(nullifierB64: string): Promise<void> {
        await this.ensureReady();
        
        // Find the specific token that matches this nullifier
        const token = this.storedTokens.find(t => (t as any).currentNullifier === nullifierB64);
        
        if (token) {
            token.used = true;
            token.pending = false;
            delete (token as any).currentNullifier;
            await this.saveTokens();
        } else {
            // If nullifier mapping lost then mark oldest pending as used
            const fallbackToken = this.storedTokens.find(t => t.pending && !t.used);
            if (fallbackToken) {
                fallbackToken.used = true;
                fallbackToken.pending = false;
                await this.saveTokens();
            }
        }
    }

    /**
     * Mark token as successfully used
     */
    async commitTokenUsage(tokenId: string): Promise<void> {
        await this.ensureReady();

        const token = this.storedTokens.find(t => t.id === tokenId);
        if (token) {
            token.used = true;
            token.pending = false;
            await this.saveTokens();
        }
    }

    async commitPendingTokenUsage(): Promise<void> {
        await this.ensureReady();

        const pendingTokens = this.storedTokens
            .filter(t => t.unblindedToken && !t.used && t.pending)
            .sort((a, b) => a.issuedAt - b.issuedAt);

        const token = pendingTokens[0];
        if (!token) return;

        token.used = true;
        token.pending = false;
        delete (token as any).currentNullifier;
        await this.saveTokens();
    }

    /**
     * Release pending tokens without consuming them
     */
    async releasePendingTokenUsage(): Promise<void> {
        await this.ensureReady();

        let changed = false;
        for (const token of this.storedTokens) {
            if (token.pending && !token.used) {
                token.pending = false;
                delete (token as any).currentNullifier;
                changed = true;
            }
        }
        if (changed) await this.saveTokens();
    }

    private async loadTokens(): Promise<void> {
        try {
            await storage.init();
            const data = await storage.get(this.storageKey);
            if (data) {
                this.storedTokens = await TokenSerializer.deserializeBatch(data);
            } else {
                this.storedTokens = [];
            }
            const rawCount = this.storedTokens.length;
            this.storedTokens = this.storedTokens.filter(t => t.purpose === 'server-entry');
            const afterPurpose = this.storedTokens.length;
            this.discardPersistedPendingTokens();
            this.pruneTokensForStorage();
            console.log('[AUTOLOGIN] gatekeeper loadTokens', {
                hadData: !!data, rawCount, afterPurpose, usableAfter: this.tokenCount
            });
        } catch (e) {
            console.error('[GATEKEEPER] Failed to load tokens', e);
            this.storedTokens = [];
        } finally {
            this.initPromise = null;
        }
    }

    private async saveTokens(): Promise<void> {
        this.pruneTokensForStorage();

        try {
            const serialized = await TokenSerializer.serializeBatch(this.storedTokens);
            await storage.init();
            await storage.set(this.storageKey, serialized);
        } catch (e) {
            if (this.isQuotaExceededError(e)) {
                for (const cap of GatekeeperClient.QUOTA_RETRY_CAPS) {
                    this.pruneTokensForStorage(cap);
                    try {
                        const serialized = await TokenSerializer.serializeBatch(this.storedTokens);
                        await storage.set(this.storageKey, serialized);
                        return;
                    } catch (retryError) {
                        if (!this.isQuotaExceededError(retryError)) {
                            console.error('[GATEKEEPER] Failed to save tokens', retryError);
                            return;
                        }
                    }
                }
            }
            console.error('[GATEKEEPER] Failed to save tokens', e);
        }
    }

    private pruneTokensForStorage(maxActive: number = GatekeeperClient.MAX_ACTIVE_TOKENS): void {
        const activeTokens = this.storedTokens
            .filter(t => t.unblindedToken && !t.used)
            .sort((a, b) => b.issuedAt - a.issuedAt)
            .slice(0, maxActive);

        for (const token of activeTokens) {
            if (!token.pending) {
                delete (token as any).currentNullifier;
            }
        }

        this.storedTokens = activeTokens.sort((a, b) => a.issuedAt - b.issuedAt);
    }

    private discardPersistedPendingTokens(): void {
        let discardedCount = 0;

        for (const token of this.storedTokens) {
            if (!token.pending || token.used) {
                continue;
            }

            token.used = true;
            token.pending = false;
            delete (token as any).currentNullifier;
            discardedCount += 1;
        }

        if (discardedCount > 0) {
            console.warn('[GATEKEEPER] Discarded stale pending entry tokens', {
                count: discardedCount
            });
        }
    }

    private isQuotaExceededError(error: unknown): boolean {
        return error instanceof DOMException && error.name === 'QuotaExceededError';
    }

    get hasTokens(): boolean {
        return this.storedTokens.some(t => t.unblindedToken && !t.used && !t.pending);
    }

    get tokenCount(): number {
        return this.storedTokens.filter(t => t.unblindedToken && !t.used && !t.pending).length;
    }
}
