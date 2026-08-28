/**
 * Total Blind Gatekeeper Client
 */

import { OPAQUEClient, OPAQUEClientHelpers } from './opaque-client';
import { PrivacyPassClient, TokenSerializer, AnonymousToken, getPrivacyPassBatchEpoch, isPrivacyPassTokenUsable } from './privacy-pass-client';
import { SignalType } from '../types/signal-types';
import { Base64 } from './base64';
import { solvePowChallenge, PowChallenge } from './proof-of-work';
import { storage } from '../tauri-bindings';
import { PostQuantumWorker } from './worker-bridge';
import { blake3 } from '@noble/hashes/blake3.js';
import { wipeAnonymousToken } from './wipe';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { SERVER_ENTRY_PURPOSE } from '../config/audiences';

const GATEKEEPER_KDF_SALT = blake3(new TextEncoder().encode(PROTOCOL_KEYS.GATEKEEPER_KDF), { dkLen: 32 });

export class GatekeeperClient {
    private static readonly MAX_ACTIVE_TOKENS = 1000;
    private opaqueClient: OPAQUEClient;
    private ppClient: PrivacyPassClient;
    private storedTokens: AnonymousToken[] = [];
    private storageKey: string;
    private initPromise: Promise<void> | null = null;
    private pendingEntrySecret: Uint8Array | null = null;
    private mutationTail: Promise<void> = Promise.resolve();

    constructor(serverId: string) {
        this.opaqueClient = new OPAQUEClient();
        this.ppClient = new PrivacyPassClient(SERVER_ENTRY_PURPOSE);
        const storageId = blake3(
            new TextEncoder().encode(`${STORAGE_KEY_DOMAINS.GATEKEEPER_TOKEN_STORE}\0${serverId}`),
            { dkLen: 32 }
        );
        this.storageKey = `${STORAGE_PREFIXES.PRIVACY_PASS_TOKEN}${Array.from(storageId)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('')}`;
        storageId.fill(0);
        this.initPromise = this.loadTokens();
    }

    async checkReady(): Promise<void> {
        if (this.initPromise) {
            await this.initPromise;
        }
    }

    private withMutation<T>(operation: () => Promise<T>): Promise<T> {
        const run = this.mutationTail.catch(() => { }).then(operation);
        this.mutationTail = run.then(() => undefined, () => undefined);
        return run;
    }

    /**
     * Start the server entry flow by blinding the server password
     */
    async startEntryRequest(password: string): Promise<Record<string, any>> {
        return this.withMutation(async () => {
        await this.checkReady();
        this.storedTokens = this.storedTokens.filter((token) => {
            if (token.unblindedToken) return true;
            wipeAnonymousToken(token);
            return false;
        });
        
        if (this.pendingEntrySecret) this.pendingEntrySecret.fill(0);
        this.pendingEntrySecret = null;
        this.opaqueClient.clear();
        const passwordBytes = new TextEncoder().encode(password);
        let workerHash: Uint8Array | null = null;
        try {
            const derived = await PostQuantumWorker.argon2Hash({
                pass: passwordBytes,
                salt: GATEKEEPER_KDF_SALT,
                time: 3,
                mem: 64 * 1024,
                parallelism: 1,
                type: 2,
                version: 0x13,
                hashLen: 32
            });
            workerHash = derived.hash instanceof Uint8Array ? derived.hash : null;
            if (!workerHash || workerHash.length !== 32) throw new Error('Invalid server entry KDF result');
            this.pendingEntrySecret = new Uint8Array(workerHash);
            const { blindedElement } = await this.opaqueClient.startLogin(this.pendingEntrySecret);
            try {
                return {
                    type: SignalType.SERVER_ENTRY_REQUEST,
                    ...OPAQUEClientHelpers.encodeRequest({ blindedElement })
                };
            } finally {
                blindedElement.fill(0);
            }
        } catch (error) {
            this.pendingEntrySecret?.fill(0);
            this.pendingEntrySecret = null;
            this.opaqueClient.clear();
            throw error;
        } finally {
            passwordBytes.fill(0);
            workerHash?.fill(0);
        }
        });
    }

    async prepareTokenIssuance(
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverNonce: Uint8Array;
            envelope: Uint8Array;
            salt: Uint8Array;
            powChallenge?: PowChallenge;
            authChannelBinding: Uint8Array;
        },
        abortSignal?: AbortSignal
    ): Promise<Record<string, any>> {
        return this.withMutation(async () => {
        await this.checkReady();
        if (!this.pendingEntrySecret) throw new Error('Server entry request not started');
        let proof: Awaited<ReturnType<OPAQUEClient['finishLogin']>> | null = null;
        let generated: Awaited<ReturnType<PrivacyPassClient['generateTokenBatch']>> | null = null;
        let tokensCommitted = false;
        try {
            try {
                proof = await this.opaqueClient.finishLogin(
                    this.pendingEntrySecret,
                    serverResponse,
                    serverResponse.authChannelBinding
                );
            } finally {
                this.pendingEntrySecret.fill(0);
                this.pendingEntrySecret = null;
            }

            if (!proof.success || !proof.authMessage) {
                console.error('[GATEKEEPER] prepareTokenIssuance proof failed:', proof.error);
                throw new Error(`Failed to derive server entry proof - incorrect password? ${proof.error || ''}`);
            }

            const powSolution = await solvePowChallenge(serverResponse.powChallenge, abortSignal);

            const staleSecrets = this.storedTokens.filter(t => !t.unblindedToken);
            if (staleSecrets.length > 0) {
                console.warn(`[GATEKEEPER] Purging ${staleSecrets.length} stale pending token secrets from previous failed attempts`);
                this.storedTokens = this.storedTokens.filter(t => t.unblindedToken);
                for (const token of staleSecrets) wipeAnonymousToken(token);
            }

            generated = await this.ppClient.generateTokenBatch(GatekeeperClient.MAX_ACTIVE_TOKENS);
            this.storedTokens = [...this.storedTokens, ...generated.tokenSecrets];
            tokensCommitted = true;

            return {
                type: SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
                blindedTokens: generated.blindedTokens.map(t => Base64.arrayBufferToBase64(t)),
                tokenEpoch: getPrivacyPassBatchEpoch(generated.tokenSecrets),
                proofOfKnowledge: Base64.arrayBufferToBase64(proof.authMessage),
                powSolution
            };
        } finally {
            proof?.exportKey?.fill(0);
            proof?.authMessage?.fill(0);
            if (generated) {
                for (const token of generated.blindedTokens) token.fill(0);
            }
            if (generated && !tokensCommitted) {
                for (const token of generated.tokenSecrets) wipeAnonymousToken(token);
            }
        }
        });
    }

    /**
     * Unblind and store tokens
     */
    async finalizeEntry(
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array,
        issuerEpoch: number
    ): Promise<void> {
        return this.withMutation(async () => {
        await this.checkReady();

        const originalTokens = this.storedTokens;
        const pendingTokens = originalTokens.filter(t => !t.unblindedToken);
        const completed = await this.ppClient.unblindTokens(
            pendingTokens,
            signedBlindedTokens,
            proof,
            serverPublicKey,
            issuerEpoch
        );

        this.storedTokens = [
            ...originalTokens.filter(t => t.unblindedToken),
            ...completed
        ];
        try {
            await this.saveTokens();
        } catch (error) {
            this.storedTokens = originalTokens;
            for (const token of completed) wipeAnonymousToken(token);
            throw error;
        }

        for (const token of pendingTokens) wipeAnonymousToken(token);
        });
    }

    /**
     * Get a token for redemption during connection
     */
    async getRedemptionPayload(): Promise<Record<string, any> | null> {
        return this.withMutation(async () => {
        await this.checkReady();

        const ambiguousTokens = this.storedTokens.filter(token => token.pending && !token.used);
        if (ambiguousTokens.length > 0) {
            for (const token of ambiguousTokens) {
                token.used = true;
                token.pending = false;
            }
            await this.saveTokens();
        }

        const availableToken = this.storedTokens.find(t => !t.pending && isPrivacyPassTokenUsable(t, SERVER_ENTRY_PURPOSE));
        if (!availableToken) return null;

        // Mark as pending and save state
        availableToken.pending = true;
        await this.saveTokens();

        let redemption: Awaited<ReturnType<PrivacyPassClient['prepareRedemption']>> | null = null;
        try {
            redemption = await this.ppClient.prepareRedemption(availableToken);
            return {
                type: SignalType.PRIVACY_PASS_REDEMPTION,
                ...OPAQUEClientHelpers.encodeRequest(redemption)
            };
        } catch (error) {
            availableToken.pending = false;
            await this.saveTokens();
            throw error;
        } finally {
            redemption?.nullifier.fill(0);
            redemption?.mac.fill(0);
        }
        });
    }

    async commitPendingTokenUsage(): Promise<void> {
        return this.withMutation(async () => {
        await this.checkReady();

        const pendingTokens = this.storedTokens
            .filter(t => t.unblindedToken && !t.used && t.pending)
            .sort((a, b) => a.issuedAt - b.issuedAt);

        const token = pendingTokens[0];
        if (!token) return;

        token.used = true;
        token.pending = false;
        await this.saveTokens();
        });
    }

    async cancelPendingEntry(): Promise<void> {
        return this.withMutation(async () => {
            try { await this.checkReady(); } catch { }
            this.pendingEntrySecret?.fill(0);
            this.pendingEntrySecret = null;
            this.opaqueClient.clear();
            this.storedTokens = this.storedTokens.filter((token) => {
                if (token.unblindedToken) return true;
                wipeAnonymousToken(token);
                return false;
            });
        });
    }

    /**
     * Permanently reserve one entry proof before an HTTP request
     */
    async reserveRedemptionPayload(): Promise<Record<string, any> | null> {
        return this.withMutation(async () => {
            await this.checkReady();

            let storeChanged = false;
            for (const token of this.storedTokens) {
                if (token.pending && !token.used) {
                    token.used = true;
                    token.pending = false;
                    storeChanged = true;
                }
            }

            const availableToken = this.storedTokens.find(
                token => !token.pending && isPrivacyPassTokenUsable(token, SERVER_ENTRY_PURPOSE)
            );
            if (!availableToken) {
                if (storeChanged) await this.saveTokens();
                return null;
            }

            let redemption: Awaited<ReturnType<PrivacyPassClient['prepareRedemption']>> | null = null;
            const originalTokens = this.storedTokens;
            try {
                redemption = await this.ppClient.prepareRedemption(availableToken);
                const payload = OPAQUEClientHelpers.encodeRequest(redemption);
                this.storedTokens = originalTokens.filter(token => token !== availableToken);
                await this.saveTokens();
                wipeAnonymousToken(availableToken);
                return payload;
            } catch (error) {
                this.storedTokens = originalTokens;
                throw error;
            } finally {
                redemption?.nullifier.fill(0);
                redemption?.mac.fill(0);
            }
        });
    }

    private async loadTokens(): Promise<void> {
        let storageReadCompleted = false;
        try {
            const data = await storage.get(this.storageKey);
            storageReadCompleted = true;
            if (data !== null) {
                this.storedTokens = await TokenSerializer.deserializeBatch(data);
            } else {
                this.storedTokens = [];
            }
            if (
                this.storedTokens.length > GatekeeperClient.MAX_ACTIVE_TOKENS ||
                this.storedTokens.some(t => t.purpose !== SERVER_ENTRY_PURPOSE)
            ) {
                throw new Error('Invalid gatekeeper token store');
            }
            const discardedPending = this.discardPersistedPendingTokens();
            if (discardedPending) await this.saveTokens();
        } catch (e) {
            for (const token of this.storedTokens) wipeAnonymousToken(token);
            this.storedTokens = [];
            
            if (storageReadCompleted) {
                if (!await storage.remove(this.storageKey) || await storage.has(this.storageKey)) {
                    throw new Error('Invalid gatekeeper token store could not be removed');
                }
                return;
            }
            throw new Error(`Gatekeeper token store could not be opened: ${e instanceof Error ? e.message : String(e)}`);
        } finally {
            this.initPromise = null;
        }
    }

    private async saveTokens(): Promise<void> {
        const selected = this.selectTokensForStorage(GatekeeperClient.MAX_ACTIVE_TOKENS);
        const serialized = await TokenSerializer.serializeBatch(selected);
        if (!await storage.set(this.storageKey, serialized)) {
            throw new Error('Native secure storage rejected the gatekeeper token update');
        }
        if (await storage.get(this.storageKey) !== serialized) {
            throw new Error('Native secure storage could not verify the gatekeeper token update');
        }
        this.commitTokenSelection(selected);
    }

    private selectTokensForStorage(maxActive: number): AnonymousToken[] {
        return this.storedTokens
            .filter(t => isPrivacyPassTokenUsable(t, SERVER_ENTRY_PURPOSE))
            .sort((a, b) => b.issuedAt - a.issuedAt)
            .slice(0, maxActive)
            .sort((a, b) => a.issuedAt - b.issuedAt);
    }

    private commitTokenSelection(selected: AnonymousToken[]): void {
        const retained = new Set(selected);
        const unfinished: AnonymousToken[] = [];
        for (const token of this.storedTokens) {
            if (retained.has(token)) continue;
            if (!token.unblindedToken && !token.used) {
                unfinished.push(token);
                continue;
            }
            wipeAnonymousToken(token);
        }
        this.storedTokens = [...selected, ...unfinished];
    }

    private discardPersistedPendingTokens(): boolean {
        let discardedCount = 0;

        for (const token of this.storedTokens) {
            if (!token.pending || token.used) {
                continue;
            }

            token.used = true;
            token.pending = false;
            discardedCount += 1;
        }

        if (discardedCount > 0) {
            console.warn('[GATEKEEPER] Discarded stale pending entry tokens', {
                count: discardedCount
            });
        }
        return discardedCount > 0;
    }

    get hasTokens(): boolean {
        return this.storedTokens.some(t => !t.pending && isPrivacyPassTokenUsable(t, SERVER_ENTRY_PURPOSE));
    }

    get tokenCount(): number {
        return this.storedTokens.filter(t => !t.pending && isPrivacyPassTokenUsable(t, SERVER_ENTRY_PURPOSE)).length;
    }

    async dispose(): Promise<void> {
        return this.withMutation(async () => {
            try { await this.checkReady(); } catch { }
            for (const token of this.storedTokens) wipeAnonymousToken(token);
            this.storedTokens = [];
            this.pendingEntrySecret?.fill(0);
            this.pendingEntrySecret = null;
            this.opaqueClient.clear();
        });
    }
}
