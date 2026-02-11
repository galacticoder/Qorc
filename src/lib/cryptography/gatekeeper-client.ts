/**
 * Total Blind Gatekeeper Client
 */

import { OPAQUEClient, OPAQUEClientHelpers } from './opaque-client';
import { PrivacyPassClient, TokenSerializer, AnonymousToken } from './privacy-pass-client';
import { SignalType } from '../types/signal-types';
import { Base64 } from './base64';

export class GatekeeperClient {
    private opaqueClient: OPAQUEClient;
    private ppClient: PrivacyPassClient;
    private storedTokens: AnonymousToken[] = [];
    private storageKey: string;
    private initPromise: Promise<void> | null = null;

    constructor(serverId: string) {
        this.opaqueClient = new OPAQUEClient();
        this.ppClient = new PrivacyPassClient();
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
            throw new Error('Failed to derive server entry proof - incorrect password?');
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

    private async loadTokens(): Promise<void> {
        try {
            const data = localStorage.getItem(this.storageKey);
            if (data) {
                this.storedTokens = await TokenSerializer.deserializeBatch(data);
            } else {
                this.storedTokens = [];
            }
        } catch (e) {
            console.error('[GATEKEEPER] Failed to load tokens', e);
            this.storedTokens = [];
        } finally {
            this.initPromise = null;
        }
    }

    private async saveTokens(): Promise<void> {
        try {
            localStorage.setItem(this.storageKey, await TokenSerializer.serializeBatch(this.storedTokens));
        } catch (e) {
            console.error('[GATEKEEPER] Failed to save tokens', e);
        }
    }

    get hasTokens(): boolean {
        return this.storedTokens.some(t => t.unblindedToken && !t.used);
    }

    get tokenCount(): number {
        return this.storedTokens.filter(t => t.unblindedToken && !t.used).length;
    }
}
