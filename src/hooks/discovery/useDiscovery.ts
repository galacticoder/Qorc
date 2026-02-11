/**
 * OPRF peer discovery hook
 */

import { useState, useCallback, useEffect, useRef, RefObject } from 'react';
import { SignalType } from '@/lib/types/signal-types';
import { EventType } from '@/lib/types/event-types';
import websocketClient from '@/lib/websocket/websocket';
import { profilePictureSystem } from '@/lib/avatar/profile-picture-system';
import {
    oprfDiscoveryClient,
    OPRFBlindResult,
    OPRFServerResponse,
    OPRFDiscoveryMaterial
} from '@/lib/crypto/oprf-discovery-crypto';
import { signal } from '@/lib/tauri-bindings';
import { getBlindRoutingClient } from '@/lib/transport/blind-routing-client';
import { computeBlindUserId } from '@/lib/utils/auth-utils';
import { CryptoUtils } from '@/lib/utils/crypto-utils';
import { generateDefaultAvatar, hashAvatarData, isValidAvatarData } from '@/lib/utils/avatar-utils';
import type { AvatarData } from '@/lib/types/avatar-types';
import type { HybridKeys } from '@/lib/types/auth-types';
import type { PeerCertificateBundle } from '@/lib/types/p2p-types';
import { P2P_PEER_CERT_TTL_MS } from '@/lib/constants';
import { blake3 } from '@noble/hashes/blake3.js';
import { shouldAttemptDiscovery } from '@/lib/utils/discovery-utils';

const discoveryTokenCache = new Map<string, Promise<{ token: string; encryptionKey: Uint8Array } | null>>();
const findUserCache = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const discoveryResultCache = new Map<string, { value: OPRFDiscoveryMaterial | null; expiresAt: number }>();

const DISCOVERY_POSITIVE_CACHE_TTL_MS = 5 * 60 * 1000;
const DISCOVERY_NEGATIVE_CACHE_TTL_MS = 30 * 1000;
const DISCOVERY_TIMEOUT_CACHE_TTL_MS = 15 * 1000;
const DISCOVERY_TOKEN_CACHE_TTL_MS = 30 * 1000;
const OPRF_RESPONSE_CACHE_TTL_MS = 30 * 1000;
const OPRF_EVAL_TIMEOUT_MS = 18000;
const DISCOVERY_QUERY_TIMEOUT_MS = 20000;
const OPRF_WAIT_TIMEOUT_MS = 10000;
const PUBLISH_ACK_TIMEOUT_MS = 12000;
const DISCOVERY_LATE_RESULT_GRACE_MS = 30 * 1000;
const MAX_DISCOVERY_TOKEN_OWNER_ENTRIES = 512;

type PendingDiscoveryRequest = {
    requestId: string;
    tokens: string[];
    normalizedHandle: string;
    targetHandle: string;
    encryptionKeys: Uint8Array[];
    resolve: (value: OPRFDiscoveryMaterial | null) => void;
    timeoutId: number;
    settled: boolean;
};

type DiscoveryTokenOwner = {
    normalizedHandle: string;
    targetHandle: string;
    encryptionKeys: Uint8Array[];
    expiresAt: number;
};

const stableStringify = (value: any): string => {
    if (value === null || value === undefined) return 'null';
    if (typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) {
        return `[${value.map(stableStringify).join(',')}]`;
    }
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => `${JSON.stringify(key)}:${stableStringify((value as any)[key])}`);
    return `{${entries.join(',')}}`;
};

const hashDiscoveryMaterial = (material: OPRFDiscoveryMaterial): string => {
    const bytes = new TextEncoder().encode(stableStringify(material));
    const digest = blake3(bytes, { dkLen: 32 });
    return Array.from(digest).map(b => b.toString(16).padStart(2, '0')).join('');
};

export const invalidateDiscoveryCache = (handle: string) => {
    if (!handle) return;
    let normalized = handle;
    if (!/^[a-f0-9]{64}$/i.test(handle)) {
        normalized = computeBlindUserId(handle);
    }
    discoveryResultCache.delete(normalized);
    console.debug('[Discovery] Invalidated cache for', handle.slice(0, 8));
};

export const useDiscovery = (
    handle: string | undefined,
    signalUsername?: string,
    hybridKeysRef?: RefObject<HybridKeys | null>
) => {
    const [isDiscoverable, setIsDiscoverable] = useState(true);
    const oprfStateRef = useRef<{ publicKey?: string; epoch?: number; previousEpoch?: number; epochRotatesAt?: number }>({});
    const lastPublishedRef = useRef<number>(0);
    const pendingOprfRequestsRef = useRef(new Map<string, {
        blindResult: OPRFBlindResult;
        normalizedHandle: string;
        epoch: number;
        resolve: (value: { token: string; encryptionKey: Uint8Array } | null) => void;
        reject: (error: Error) => void;
        timeoutId: number;
    }>());
    const oprfResponseCacheRef = useRef(new Map<string, {
        response: OPRFServerResponse;
        receivedAt: number;
    }>());
    const keysReadyPublishedRef = useRef<boolean>(false);
    const defaultAvatarCacheRef = useRef<Map<string, AvatarData>>(new Map());
    const avatarPublishTimeoutRef = useRef<number | null>(null);
    const pendingAvatarPublishRef = useRef<boolean>(false);
    const lastPublishedAvatarHashRef = useRef<string | null>(null);
    const lastOprfKeyRequestRef = useRef<number>(0);
    const unlinkedReadyRef = useRef<boolean>(false);
    const lastPublishFailureRef = useRef<string | null>(null);
    const publishingRef = useRef<boolean>(false);
    const lastPublishedFingerprintRef = useRef<string | null>(null);
    const lastPublishAttemptRef = useRef<number>(0);
    const lastOprfPublicKeyRef = useRef<string | null>(null);
    const oprfReadyPromiseRef = useRef<Promise<{ publicKey: string; epoch: number; previousEpoch?: number; epochRotatesAt?: number } | null> | null>(null);
    const pendingDiscoveryByTokenRef = useRef(new Map<string, Set<PendingDiscoveryRequest>>());
    const pendingDiscoveryByRequestIdRef = useRef(new Map<string, PendingDiscoveryRequest>());
    const discoveryTokenOwnerRef = useRef(new Map<string, DiscoveryTokenOwner>());
    const discoveryTokenResultCacheRef = useRef(new Map<string, {
        encryptedBlob: string | null;
        exists: boolean;
        receivedAt: number;
    }>());

    const requestOprfKey = useCallback((reason: string | Event = 'auto') => {
        const label = typeof reason === 'string' ? reason : 'event';
        const now = Date.now();
        if (now - lastOprfKeyRequestRef.current < 5000) return;
        if (websocketClient.isUnlinkedMode?.() && !unlinkedReadyRef.current) return;
        lastOprfKeyRequestRef.current = now;
        websocketClient.send({ type: SignalType.OPRF_DISCOVERY_PUBLIC_KEY, reason: label });
    }, []);

    const waitForOprfState = useCallback(async (
        reason: string,
        timeoutMs: number = OPRF_WAIT_TIMEOUT_MS
    ): Promise<{ publicKey: string; epoch: number; previousEpoch?: number; epochRotatesAt?: number } | null> => {
        const current = oprfStateRef.current;
        if (current.publicKey && current.epoch !== undefined) {
            return current as { publicKey: string; epoch: number; previousEpoch?: number; epochRotatesAt?: number };
        }

        if (oprfReadyPromiseRef.current) {
            return oprfReadyPromiseRef.current;
        }

        requestOprfKey(reason);
        oprfReadyPromiseRef.current = new Promise((resolve) => {
            let settled = false;
            const cleanup = () => {
                if (settled) return;
                settled = true;
                window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
                window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
                if (timeoutId) clearTimeout(timeoutId);
                oprfReadyPromiseRef.current = null;
            };

            const handler = (ev: Event) => {
                const detail = (ev as CustomEvent).detail;
                if (detail?.type === SignalType.OPRF_DISCOVERY_PUBLIC_KEY && detail.publicKey && detail.epoch !== undefined) {
                    cleanup();
                    resolve({
                        publicKey: detail.publicKey,
                        epoch: detail.epoch,
                        previousEpoch: detail.previousEpoch,
                        epochRotatesAt: detail.epochRotatesAt
                    });
                }
            };

            const timeoutId = window.setTimeout(() => {
                cleanup();
                resolve(null);
            }, timeoutMs);

            window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        });

        return oprfReadyPromiseRef.current;
    }, [requestOprfKey]);

    const pruneDiscoveryTokenCache = useCallback((epoch?: number, previousEpoch?: number) => {
        const allowed = new Set<number>();
        if (typeof epoch === 'number') allowed.add(epoch);
        if (typeof previousEpoch === 'number') allowed.add(previousEpoch);
        for (const key of Array.from(discoveryTokenCache.keys())) {
            const parts = key.split(':');
            const keyEpoch = Number(parts[parts.length - 1]);
            if (!allowed.has(keyEpoch)) {
                discoveryTokenCache.delete(key);
            }
        }
    }, []);

    const waitForPqSession = useCallback(async (timeoutMs: number = 15000): Promise<boolean> => {
        try {
            if (typeof (websocketClient as any)?.isPQSessionEstablished === 'function') {
                if ((websocketClient as any).isPQSessionEstablished()) return true;
            }
        } catch { }

        return new Promise<boolean>((resolve) => {
            let settled = false;
            const cleanup = () => {
                if (settled) return;
                settled = true;
                window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, handler as EventListener);
                if (timeoutId) clearTimeout(timeoutId);
            };

            const handler = () => {
                cleanup();
                resolve(true);
            };

            const timeoutId = window.setTimeout(() => {
                cleanup();
                try {
                    if (typeof (websocketClient as any)?.isPQSessionEstablished === 'function') {
                        return resolve((websocketClient as any).isPQSessionEstablished());
                    }
                } catch { }
                resolve(false);
            }, timeoutMs);

            window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, handler as EventListener);
        });
    }, []);

    const sendSecureDiscoveryMessage = useCallback(async (
        payload: Record<string, unknown>,
        reason: string,
        readyTimeoutMs: number = 15000
    ): Promise<boolean> => {
        const ready = await waitForPqSession(readyTimeoutMs);
        if (!ready) {
            console.warn(`[OPRF-DISCOVERY] ${reason}: PQ session not ready`);
            return false;
        }
        try {
            await websocketClient.sendSecureControlMessage(payload);
            return true;
        } catch (err) {
            console.warn(`[OPRF-DISCOVERY] ${reason}: send failed`, err);
            return false;
        }
    }, [waitForPqSession]);

    const buildSelfPeerCertificate = async (
        username: string,
        inboxId: string,
        keys: HybridKeys | null | undefined
    ): Promise<PeerCertificateBundle | null> => {
        if (!keys?.dilithium?.secretKey || !keys.dilithium.publicKeyBase64) return null;
        if (!keys.kyber?.publicKeyBase64 || !keys.x25519?.publicKeyBase64) return null;

        const issuedAt = Date.now();
        const expiresAt = issuedAt + P2P_PEER_CERT_TTL_MS;
        const proof = keys.dilithium.publicKeyBase64;

        const canonical = new TextEncoder().encode(JSON.stringify({
            username,
            dilithiumPublicKey: keys.dilithium.publicKeyBase64,
            kyberPublicKey: keys.kyber.publicKeyBase64,
            x25519PublicKey: keys.x25519.publicKeyBase64,
            proof,
            issuedAt,
            expiresAt
        }));

        const signatureBytes = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
        const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureBytes);

        return {
            username,
            inboxId,
            dilithiumPublicKey: keys.dilithium.publicKeyBase64,
            kyberPublicKey: keys.kyber.publicKeyBase64,
            x25519PublicKey: keys.x25519.publicKeyBase64,
            proof,
            issuedAt,
            expiresAt,
            signature
        };
    };

    /**
     * Normalizes a handle to its hashed pseudonym if not already hashed
     */
    const getDiscoveryHandle = useCallback((input: string): string => {
        if (!input) return '';
        if (/^[a-f0-9]{64}$/i.test(input)) {
            return input.toLowerCase();
        }
        return computeBlindUserId(input);
    }, []);

    const getAvatarForDiscovery = useCallback(async (username: string): Promise<AvatarData | null> => {
        const shareWithOthers = profilePictureSystem.getShareWithOthers();
        const ownAvatar = profilePictureSystem.getOwnAvatarData?.() ?? null;

        if (shareWithOthers && ownAvatar && isValidAvatarData(ownAvatar)) {
            return ownAvatar;
        }

        if (!shareWithOthers && ownAvatar?.isDefault && isValidAvatarData(ownAvatar)) {
            return ownAvatar;
        }

        const cacheKey = (username || '').toLowerCase();
        const cached = defaultAvatarCacheRef.current.get(cacheKey);
        if (cached && isValidAvatarData(cached)) {
            return cached;
        }

        const defaultAvatarUrl = generateDefaultAvatar(username);
        const hash = await hashAvatarData(defaultAvatarUrl);
        const defaultAvatar: AvatarData = {
            data: defaultAvatarUrl,
            mimeType: 'image/svg+xml',
            hash,
            updatedAt: Date.now(),
            isDefault: true
        };

        defaultAvatarCacheRef.current.set(cacheKey, defaultAvatar);
        return defaultAvatar;
    }, []);

    const normalizeToken = useCallback((token: unknown): string => {
        if (typeof token !== 'string') return '';
        return token.trim().toLowerCase();
    }, []);

    const normalizeBlindedPoint = useCallback((value: unknown): string => {
        if (typeof value !== 'string') return '';
        return value.trim().toLowerCase();
    }, []);

    const normalizeRequestId = useCallback((value: unknown): string => {
        if (typeof value !== 'string') return '';
        const trimmed = value.trim();
        if (!trimmed) return '';
        return trimmed.slice(0, 128);
    }, []);

    const pruneDiscoveryIndexes = useCallback(() => {
        const now = Date.now();

        for (const [token, owner] of Array.from(discoveryTokenOwnerRef.current.entries())) {
            if (owner.expiresAt <= now) {
                discoveryTokenOwnerRef.current.delete(token);
            }
        }

        for (const [token, cached] of Array.from(discoveryTokenResultCacheRef.current.entries())) {
            if ((now - cached.receivedAt) > DISCOVERY_TOKEN_CACHE_TTL_MS) {
                discoveryTokenResultCacheRef.current.delete(token);
            }
        }

        if (discoveryTokenOwnerRef.current.size > MAX_DISCOVERY_TOKEN_OWNER_ENTRIES) {
            const sorted = Array.from(discoveryTokenOwnerRef.current.entries())
                .sort((a, b) => a[1].expiresAt - b[1].expiresAt);
            while (sorted.length > MAX_DISCOVERY_TOKEN_OWNER_ENTRIES) {
                const [token] = sorted.shift()!;
                discoveryTokenOwnerRef.current.delete(token);
            }
        }
    }, []);

    const unregisterPendingDiscovery = useCallback((pending: PendingDiscoveryRequest) => {
        pendingDiscoveryByRequestIdRef.current.delete(pending.requestId);
        for (const token of pending.tokens) {
            const set = pendingDiscoveryByTokenRef.current.get(token);
            if (!set) continue;
            set.delete(pending);
            if (set.size === 0) {
                pendingDiscoveryByTokenRef.current.delete(token);
            }
        }
    }, []);

    const registerPendingDiscovery = useCallback((pending: PendingDiscoveryRequest) => {
        pruneDiscoveryIndexes();
        pendingDiscoveryByRequestIdRef.current.set(pending.requestId, pending);
        const expiresAt = Date.now() + DISCOVERY_LATE_RESULT_GRACE_MS;
        for (const token of pending.tokens) {
            if (!token) continue;
            let set = pendingDiscoveryByTokenRef.current.get(token);
            if (!set) {
                set = new Set<PendingDiscoveryRequest>();
                pendingDiscoveryByTokenRef.current.set(token, set);
            }
            set.add(pending);
            discoveryTokenOwnerRef.current.set(token, {
                normalizedHandle: pending.normalizedHandle,
                targetHandle: pending.targetHandle,
                encryptionKeys: pending.encryptionKeys,
                expiresAt
            });
        }
    }, [pruneDiscoveryIndexes]);


    const finalizeDiscoveryResult = useCallback((
        normalizedHandle: string,
        targetHandle: string,
        encryptedBlob: string | null,
        exists: boolean,
        encryptionKeys: Uint8Array[]
    ): OPRFDiscoveryMaterial | null => {
        if (!exists || !encryptedBlob) {
            discoveryResultCache.set(normalizedHandle, {
                value: null,
                expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
            });
            return null;
        }

        let decrypted: OPRFDiscoveryMaterial | null = null;
        for (const key of encryptionKeys) {
            if (!key) continue;
            try {
                decrypted = oprfDiscoveryClient.decryptDiscoveryBlob(encryptedBlob, key);
                if (decrypted) break;
            } catch { }
        }

        if (decrypted) {
            const isHashedHandle = /^[a-f0-9]{64}$/i.test(String(targetHandle || ''));
            const cacheUsername = decrypted.peerCertificate?.username || (!isHashedHandle ? String(targetHandle) : null);
            const avatar = decrypted.avatar;

            if (cacheUsername && avatar && isValidAvatarData(avatar)) {
                const currentHash = profilePictureSystem.getPeerAvatarHash(cacheUsername);
                if (currentHash !== avatar.hash || profilePictureSystem.isPeerAvatarStale(cacheUsername)) {
                    void profilePictureSystem.cachePeerAvatar(
                        cacheUsername,
                        avatar.data,
                        avatar.mimeType,
                        avatar.hash
                    );
                }
            }
            discoveryResultCache.set(normalizedHandle, {
                value: decrypted,
                expiresAt: Date.now() + DISCOVERY_POSITIVE_CACHE_TTL_MS
            });
            return decrypted;
        }

        console.warn('[OPRF-DISCOVERY] Decryption failed for discovery blob');
        discoveryResultCache.set(normalizedHandle, {
            value: null,
            expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
        });
        return null;
    }, []);

    const resolvePendingDiscovery = useCallback((
        pending: PendingDiscoveryRequest,
        encryptedBlob: string | null,
        exists: boolean
    ) => {
        if (pending.settled) return;
        pending.settled = true;
        unregisterPendingDiscovery(pending);
        if (pending.timeoutId) clearTimeout(pending.timeoutId);

        const decrypted = finalizeDiscoveryResult(
            pending.normalizedHandle,
            pending.targetHandle,
            encryptedBlob,
            exists,
            pending.encryptionKeys
        );
        pending.resolve(decrypted);
    }, [finalizeDiscoveryResult, unregisterPendingDiscovery]);

    /**
     * Requests OPRF evaluation and derives discovery token for a specific epoch
     */
    const getDiscoveryTokenForEpoch = useCallback(async (
        targetHandle: string,
        epoch: number
    ): Promise<{ token: string; encryptionKey: Uint8Array } | null> => {
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) return null;

        const cacheKey = `${normalizedHandle}:${epoch}`;

        if (discoveryTokenCache.has(cacheKey)) {
            return discoveryTokenCache.get(cacheKey)!;
        }

        const promise = (async () => {
            const oprfState = await waitForOprfState('oprf-token');
            if (!oprfState?.publicKey) {
                throw new Error('OPRF service unavailable');
            }

            const sessionReady = await waitForPqSession();
            if (!sessionReady) {
                console.warn('[OPRF-DISCOVERY] OPRF evaluation aborted - PQ session not ready');
                return null;
            }

            const blindResult = oprfDiscoveryClient.blindHandle(normalizedHandle);
            const blindedHex = Array.from(blindResult.blinded).map(b => b.toString(16).padStart(2, '0')).join('');

            const cachedResponse = oprfResponseCacheRef.current.get(blindedHex);
            if (cachedResponse) {
                if (Date.now() - cachedResponse.receivedAt < OPRF_RESPONSE_CACHE_TTL_MS) {
                    try {
                        const result = oprfDiscoveryClient.finalizeToken(
                            normalizedHandle,
                            blindResult,
                            cachedResponse.response,
                            epoch
                        );
                        return result;
                    } catch {
                        oprfResponseCacheRef.current.delete(blindedHex);
                    }
                } else {
                    oprfResponseCacheRef.current.delete(blindedHex);
                }
            }

            return new Promise<{ token: string; encryptionKey: Uint8Array } | null>((resolve, reject) => {
                pendingOprfRequestsRef.current.set(blindedHex, {
                    blindResult,
                    normalizedHandle,
                    epoch,
                    resolve,
                    reject,
                    timeoutId: 0
                });

                void (async () => {
                    const sent = await sendSecureDiscoveryMessage(
                        {
                            type: SignalType.OPRF_BLIND_EVALUATE,
                            blindedPoint: blindedHex
                        },
                        'oprf-blind-evaluate',
                        OPRF_EVAL_TIMEOUT_MS + 6000
                    );

                    if (!sent) {
                        const pending = pendingOprfRequestsRef.current.get(blindedHex);
                        if (!pending) return;
                        pendingOprfRequestsRef.current.delete(blindedHex);
                        pending.resolve(null);
                        return;
                    }

                    const timeoutId = window.setTimeout(() => {
                        const pending = pendingOprfRequestsRef.current.get(blindedHex);
                        if (!pending) return;
                        pendingOprfRequestsRef.current.delete(blindedHex);
                        console.warn('[OPRF-DISCOVERY] OPRF blind evaluation timed out', { blindedPrefix: blindedHex.slice(0, 8) });
                        pending.resolve(null);
                    }, OPRF_EVAL_TIMEOUT_MS);

                    const pending = pendingOprfRequestsRef.current.get(blindedHex);
                    if (!pending) {
                        clearTimeout(timeoutId);
                        return;
                    }
                    pending.timeoutId = timeoutId;
                })().catch((err) => {
                    const pending = pendingOprfRequestsRef.current.get(blindedHex);
                    if (!pending) return;
                    pendingOprfRequestsRef.current.delete(blindedHex);
                    console.warn('[OPRF-DISCOVERY] Failed to send blind evaluation request', err);
                    pending.resolve(null);
                });
            });
        })();

        discoveryTokenCache.set(cacheKey, promise);
        promise.then(result => { if (!result) discoveryTokenCache.delete(cacheKey); })
               .catch(() => discoveryTokenCache.delete(cacheKey));
        return promise;
    }, [getDiscoveryHandle, sendSecureDiscoveryMessage, waitForOprfState, waitForPqSession]);

    /**
     * Publishes current identity to the billboard using OPRF-derived tokens
     */
    const publishSelf = useCallback(async (force = false): Promise<boolean> => {
        const fail = (reason: string) => {
            lastPublishFailureRef.current = reason;
            return false;
        };

        if (!handle) return fail('missing-handle');
        if (!isDiscoverable) return fail('not-discoverable');
        if (publishingRef.current) return true;

        const now = Date.now();
        const minAttemptDelay = force ? 500 : 1500;
        if (now - lastPublishAttemptRef.current < minAttemptDelay) return true;
        lastPublishAttemptRef.current = now;

        publishingRef.current = true;
        try {
            let inboxId: string | null = null;
            try {
                inboxId = getBlindRoutingClient().getMyInboxId();
            } catch {
                return fail('blind-routing-client-missing');
            }

            if (!inboxId) {
                const waitStart = Date.now();
                while (!inboxId && Date.now() - waitStart < 3000) {
                    await new Promise(resolve => setTimeout(resolve, 250));
                    try { inboxId = getBlindRoutingClient().getMyInboxId(); } catch { break; }
                }
                if (!inboxId) return fail('missing-inbox-id');
            }

            const bundleUsername = signalUsername || handle;
            const bundle = await signal.createPreKeyBundle(bundleUsername);
            if (!bundle) return fail('bundle-create-failed');

            const kyberKey = hybridKeysRef?.current?.kyber?.publicKeyBase64;
            const dilithiumKey = hybridKeysRef?.current?.dilithium?.publicKeyBase64;
            const x25519Key = hybridKeysRef?.current?.x25519?.publicKeyBase64;

            if (!kyberKey || !dilithiumKey || !x25519Key) return fail('missing-hybrid-keys');

            const peerCertificate = await buildSelfPeerCertificate(
                String(bundleUsername),
                inboxId,
                hybridKeysRef?.current
            );

            const avatar = await getAvatarForDiscovery(String(bundleUsername));

            const material: OPRFDiscoveryMaterial = {
                inboxId,
                publicKeys: {
                    kyberPublicBase64: kyberKey,
                    dilithiumPublicBase64: dilithiumKey,
                    x25519PublicBase64: x25519Key
                },
                fullBundle: bundle,
                peerCertificate: peerCertificate || undefined,
                avatar: avatar || undefined
            };

            const materialFingerprint = hashDiscoveryMaterial(material);

            // Get tokens for both current and previous epoch — wait for epoch if not yet available
            const oprfState = await waitForOprfState('publish-missing-epoch');
            if (!oprfState || oprfState.epoch === undefined) {
                return fail('missing-oprf-epoch');
            }
            const { epoch, previousEpoch } = oprfState;

            const currentTokenPromise = getDiscoveryTokenForEpoch(handle, epoch);
            const previousTokenPromise = previousEpoch !== undefined && previousEpoch !== epoch
                ? getDiscoveryTokenForEpoch(handle, previousEpoch)
                : Promise.resolve(null);

            const [currentResult, previousResult] = await Promise.all([currentTokenPromise, previousTokenPromise]);

            if (!currentResult) return fail('oprf-token-missing');

            const publishFingerprint = `${currentResult.token}:${materialFingerprint}`;
            if (lastPublishedFingerprintRef.current === publishFingerprint) {
                return true;
            }

            const encryptedBlob = oprfDiscoveryClient.encryptDiscoveryBlob(material, currentResult.encryptionKey);
            const publishSent = await sendSecureDiscoveryMessage(
                {
                    type: SignalType.PUBLISH_DISCOVERY,
                    token: currentResult.token,
                    previousEpochToken: previousResult?.token,
                    encryptedBlob
                },
                'publish-discovery',
                PUBLISH_ACK_TIMEOUT_MS + 6000
            );
            if (!publishSent) {
                return fail('publish-send-failed');
            }

            const startedAt = Date.now();
            const ackSuccess = await new Promise<boolean>((resolve) => {
                let settled = false;
                const cleanup = () => {
                    if (settled) return;
                    settled = true;
                    window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, ackHandler as EventListener);
                    window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, ackHandler as EventListener);
                    if (timeoutId) clearTimeout(timeoutId);
                };

                const ackHandler = (ev: Event) => {
                    const detail = (ev as CustomEvent).detail;
                    if (detail?.type === SignalType.OK && detail?.op === 'publish-discovery') {
                        cleanup();
                        console.log('[OPRF-DISCOVERY] Publish ack', {
                            tokenPrefix: currentResult.token.slice(0, 8),
                            success: !!detail.success,
                            rttMs: Date.now() - startedAt
                        });
                        resolve(!!detail.success);
                    }
                    if (detail?.type === SignalType.ERROR && typeof detail?.message === 'string') {
                        cleanup();
                        resolve(false);
                    }
                };

                const timeoutId = window.setTimeout(() => {
                    cleanup();
                    resolve(false);
                }, PUBLISH_ACK_TIMEOUT_MS);

                window.addEventListener(EventType.SECURE_SERVER_MESSAGE, ackHandler as EventListener);
                window.addEventListener(EventType.EDGE_SERVER_MESSAGE, ackHandler as EventListener);
            });

            if (!ackSuccess) {
                return fail('publish-ack-failed');
            }

            lastPublishedRef.current = Date.now();
            lastPublishedFingerprintRef.current = publishFingerprint;
            lastPublishedAvatarHashRef.current = avatar?.hash ?? null;
            keysReadyPublishedRef.current = true;
            lastPublishFailureRef.current = null;

            if (avatarPublishTimeoutRef.current) {
                clearTimeout(avatarPublishTimeoutRef.current);
            }
            avatarPublishTimeoutRef.current = null;
            pendingAvatarPublishRef.current = false;

            return true;
        } catch (err) {
            const reason = err instanceof Error ? err.message : String(err);
            console.warn('[OPRF-DISCOVERY] Error during self-publish:', err);
            return fail(reason || 'publish-error');
        } finally {
            publishingRef.current = false;
        }
    }, [handle, isDiscoverable, getDiscoveryTokenForEpoch, signalUsername, hybridKeysRef, getAvatarForDiscovery, sendSecureDiscoveryMessage, waitForOprfState]);

    // Capture OPRF public key and epoch info from server
    useEffect(() => {
        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === SignalType.OPRF_DISCOVERY_PUBLIC_KEY) {
                const { publicKey, epoch, previousEpoch, epochRotatesAt } = detail;
                if (publicKey && epoch !== undefined) {
                    if (lastOprfPublicKeyRef.current && lastOprfPublicKeyRef.current !== publicKey) {
                        discoveryTokenCache.clear();
                    }
                    lastOprfPublicKeyRef.current = publicKey;
                    oprfStateRef.current = { publicKey, epoch, previousEpoch, epochRotatesAt };
                    oprfDiscoveryClient.setServerPublicKey(publicKey);
                    pruneDiscoveryTokenCache(epoch, previousEpoch);
                }
            }
        };

        const onUnlinkedReady = () => {
            unlinkedReadyRef.current = true;
            requestOprfKey('unlinked-ready');
        };
        const onReconnected = () => {
            unlinkedReadyRef.current = false;
            requestOprfKey('ws-reconnected');
        };
        const onHybridKeys = () => {
            void publishSelf(true);
        };

        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.UNLINKED_SESSION_READY, onUnlinkedReady as EventListener);
        window.addEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, requestOprfKey as EventListener);
        window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onHybridKeys as EventListener);
        window.addEventListener(EventType.WS_RECONNECTED, onReconnected as EventListener);

        return () => {
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.UNLINKED_SESSION_READY, onUnlinkedReady as EventListener);
            window.removeEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, requestOprfKey as EventListener);
            window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onHybridKeys as EventListener);
            window.removeEventListener(EventType.WS_RECONNECTED, onReconnected as EventListener);
        };
    }, [requestOprfKey, publishSelf, pruneDiscoveryTokenCache]);

    useEffect(() => {
        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (!detail) return;

            if (detail.type === SignalType.OPRF_BLIND_EVALUATE_RESPONSE) {
                const blindedPoint = normalizeBlindedPoint(detail.blindedPoint);
                if (!blindedPoint) return;

                const pending = pendingOprfRequestsRef.current.get(blindedPoint);
                const serverResponse: OPRFServerResponse = {
                    evaluated: detail.evaluated,
                    proof: detail.proof,
                    publicKey: detail.publicKey
                };

                if (!pending) {
                    oprfResponseCacheRef.current.set(blindedPoint, {
                        response: serverResponse,
                        receivedAt: Date.now()
                    });
                    return;
                }

                pendingOprfRequestsRef.current.delete(blindedPoint);
                if (pending.timeoutId) clearTimeout(pending.timeoutId);

                try {
                    const result = oprfDiscoveryClient.finalizeToken(
                        pending.normalizedHandle,
                        pending.blindResult,
                        serverResponse,
                        pending.epoch
                    );
                    pending.resolve(result);
                } catch (err) {
                    pending.reject(err instanceof Error ? err : new Error(String(err)));
                }
                return;
            }

            if (detail.type === SignalType.ERROR && typeof detail.message === 'string') {
                if (!detail.message.toLowerCase().includes('oprf')) return;
                for (const [blindedPoint, pending] of pendingOprfRequestsRef.current.entries()) {
                    pendingOprfRequestsRef.current.delete(blindedPoint);
                    if (pending.timeoutId) clearTimeout(pending.timeoutId);
                    pending.reject(new Error(detail.message));
                }
            }
        };

        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        return () => {
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        };
    }, [normalizeBlindedPoint]);

    useEffect(() => {
        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            const type = detail?.type;
            if (type !== '__ws_connection_closed' && type !== '__ws_connection_error') return;

            for (const pending of Array.from(pendingDiscoveryByRequestIdRef.current.values())) {
                if (pending.settled) continue;
                pending.settled = true;
                if (pending.timeoutId) clearTimeout(pending.timeoutId);
                unregisterPendingDiscovery(pending);
                discoveryResultCache.set(pending.normalizedHandle, {
                    value: null,
                    expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                });
                pending.resolve(null);
            }

            for (const [blindedPoint, pending] of Array.from(pendingOprfRequestsRef.current.entries())) {
                pendingOprfRequestsRef.current.delete(blindedPoint);
                if (pending.timeoutId) clearTimeout(pending.timeoutId);
                pending.resolve(null);
            }
        };

        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        return () => {
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        };
    }, [unregisterPendingDiscovery]);

    const scheduleAvatarPublish = useCallback((reason: string) => {
        if (!handle || !isDiscoverable) return;
        const ownAvatar = profilePictureSystem.getOwnAvatarData?.() ?? null;
        const ownHash = ownAvatar?.hash ?? null;
        if (ownHash && lastPublishedAvatarHashRef.current === ownHash) {
            return;
        }
        if (pendingAvatarPublishRef.current) return;
        pendingAvatarPublishRef.current = true;

        const jitterMs = 30000 + Math.floor(Math.random() * 90000);
        console.log('[OPRF-DISCOVERY] Scheduling discovery publish for avatar update', {
            reason,
            delayMs: jitterMs
        });

        avatarPublishTimeoutRef.current = window.setTimeout(() => {
            pendingAvatarPublishRef.current = false;
            avatarPublishTimeoutRef.current = null;
            void publishSelf(true);
        }, jitterMs);
    }, [handle, isDiscoverable, publishSelf]);

    /**
     * Watch for hybrid keys becoming available and publish immediately
     */
    useEffect(() => {
        if (!handle) return;
        if (!oprfStateRef.current.publicKey) return;

        const hasKeys = !!(
            hybridKeysRef?.current?.kyber?.publicKeyBase64 &&
            hybridKeysRef?.current?.dilithium?.publicKeyBase64 &&
            hybridKeysRef?.current?.x25519?.publicKeyBase64
        );

        if (hasKeys && !keysReadyPublishedRef.current) {
            void publishSelf(true);
        }
    }, [handle, hybridKeysRef?.current, publishSelf]);

    useEffect(() => {
        if (!handle) return;

        const handler = (ev: Event) => {
            try {
                if (ev.type === EventType.PROFILE_SETTINGS_UPDATED) {
                    scheduleAvatarPublish('profile-settings-updated');
                    return;
                }

                if (ev.type === EventType.PROFILE_PICTURE_UPDATED) {
                    const detail = (ev as CustomEvent).detail;
                    if (detail?.type === 'own') {
                        scheduleAvatarPublish('profile-picture-updated');
                    }
                }
            } catch {
            }
        };

        window.addEventListener(EventType.PROFILE_PICTURE_UPDATED, handler as EventListener);
        window.addEventListener(EventType.PROFILE_SETTINGS_UPDATED, handler as EventListener);

        return () => {
            window.removeEventListener(EventType.PROFILE_PICTURE_UPDATED, handler as EventListener);
            window.removeEventListener(EventType.PROFILE_SETTINGS_UPDATED, handler as EventListener);
            if (avatarPublishTimeoutRef.current) {
                clearTimeout(avatarPublishTimeoutRef.current);
            }
            avatarPublishTimeoutRef.current = null;
            pendingAvatarPublishRef.current = false;
        };
    }, [handle, scheduleAvatarPublish]);

    /**
     * Periodic and state-based publisher
     */
    useEffect(() => {
        if (!handle) return;

        let intervalId: ReturnType<typeof setInterval> | null = null;
        let cancelled = false;

        const startPublishing = async () => {
            if (cancelled) return;

            const success = await publishSelf();
            if (!success) {
                console.log('[OPRF-DISCOVERY] Initial publish failed', { reason: lastPublishFailureRef.current || 'unknown' });
            }

            if (!intervalId) {
                intervalId = setInterval(() => {
                    void publishSelf();
                }, 300000);
            }
        };

        const oprfKeyHandler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === SignalType.OPRF_DISCOVERY_PUBLIC_KEY && detail.publicKey) {
                void startPublishing();
            }
        };

        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, oprfKeyHandler as EventListener);

        return () => {
            cancelled = true;
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, oprfKeyHandler as EventListener);
            if (intervalId) clearInterval(intervalId);
        };
    }, [handle, publishSelf]);

    useEffect(() => {
        if (websocketClient.isUnlinkedMode()) {
            void publishSelf();
        }
    }, [publishSelf]);

    useEffect(() => {
        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type !== SignalType.DISCOVERY_RESULT) return;
            const token = normalizeToken(detail.token);
            const requestId = normalizeRequestId(detail.requestId);
            const encryptedBlob = typeof detail.encryptedBlob === 'string' ? detail.encryptedBlob : null;
            const exists = !!detail.exists;

            pruneDiscoveryIndexes();

            if (token) {
                discoveryTokenResultCacheRef.current.set(token, {
                    encryptedBlob,
                    exists,
                    receivedAt: Date.now()
                });
            }

            const matched = new Set<PendingDiscoveryRequest>();
            if (requestId) {
                const byRequest = pendingDiscoveryByRequestIdRef.current.get(requestId);
                if (byRequest) {
                    matched.add(byRequest);
                }
            }
            if (token) {
                const byToken = pendingDiscoveryByTokenRef.current.get(token);
                if (byToken) {
                    for (const pending of byToken) {
                        matched.add(pending);
                    }
                }
            }

            if (matched.size > 0) {
                for (const pending of matched) {
                    resolvePendingDiscovery(pending, encryptedBlob, exists);
                }
                return;
            }

            if (token) {
                const owner = discoveryTokenOwnerRef.current.get(token);
                if (owner && owner.expiresAt > Date.now()) {
                    finalizeDiscoveryResult(
                        owner.normalizedHandle,
                        owner.targetHandle,
                        encryptedBlob,
                        exists,
                        owner.encryptionKeys
                    );
                }
            }
        };

        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        return () => {
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        };
    }, [finalizeDiscoveryResult, normalizeToken, normalizeRequestId, pruneDiscoveryIndexes, resolvePendingDiscovery]);

    useEffect(() => {
        return () => {
            for (const pending of Array.from(pendingDiscoveryByRequestIdRef.current.values())) {
                pending.settled = true;
                if (pending.timeoutId) clearTimeout(pending.timeoutId);
            }
            pendingDiscoveryByRequestIdRef.current.clear();
            pendingDiscoveryByTokenRef.current.clear();
            discoveryTokenOwnerRef.current.clear();

            for (const [blindedPoint, pending] of Array.from(pendingOprfRequestsRef.current.entries())) {
                pendingOprfRequestsRef.current.delete(blindedPoint);
                if (pending.timeoutId) clearTimeout(pending.timeoutId);
                pending.resolve(null);
            }
        };
    }, []);

    /**
     * Find a user by handle using OPRF-derived tokens
     */
    const findUser = useCallback(async (targetHandle: string): Promise<OPRFDiscoveryMaterial | null> => {
        if (!shouldAttemptDiscovery(targetHandle)) {
            return null;
        }
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) return null;

        const cachedEntry = discoveryResultCache.get(normalizedHandle);
        if (cachedEntry) {
            if (cachedEntry.expiresAt > Date.now()) {
                return cachedEntry.value;
            }
            discoveryResultCache.delete(normalizedHandle);
        }
        if (findUserCache.has(normalizedHandle)) {
            return findUserCache.get(normalizedHandle)!;
        }

        const promise = (async () => {
            try {
                // Get tokens for both current and previous epoch
                const oprfState = await waitForOprfState('find-missing-epoch');
                if (!oprfState || oprfState.epoch === undefined) {
                    console.warn('[OPRF-DISCOVERY] findUser: epoch undefined after waiting for OPRF key');
                    return null;
                }
                const { epoch, previousEpoch } = oprfState;

                const currentTokenPromise = getDiscoveryTokenForEpoch(normalizedHandle, epoch);
                const previousTokenPromise = previousEpoch !== undefined && previousEpoch !== epoch
                    ? getDiscoveryTokenForEpoch(normalizedHandle, previousEpoch)
                    : Promise.resolve(null);

                const [currentResult, previousResult] = await Promise.all([currentTokenPromise, previousTokenPromise]);

                if (!currentResult) {
                    console.warn('[OPRF-DISCOVERY] findUser: OPRF token derivation failed for epoch', epoch);
                    return null;
                }

                return new Promise<OPRFDiscoveryMaterial | null>((resolve) => {
                    const currentToken = normalizeToken(currentResult.token);
                    const previousToken = normalizeToken(previousResult?.token);
                    const now = Date.now();
                    pruneDiscoveryIndexes();

                    const currentCached = currentToken ? discoveryTokenResultCacheRef.current.get(currentToken) : null;
                    const previousCached = previousToken ? discoveryTokenResultCacheRef.current.get(previousToken) : null;
                    const validCurrent = !!currentCached && (now - currentCached.receivedAt) < DISCOVERY_TOKEN_CACHE_TTL_MS;
                    const validPrevious = !!previousCached && (now - previousCached.receivedAt) < DISCOVERY_TOKEN_CACHE_TTL_MS;
                    const cached = validCurrent && validPrevious
                        ? ((currentCached!.receivedAt >= previousCached!.receivedAt) ? currentCached! : previousCached!)
                        : (validCurrent ? currentCached! : (validPrevious ? previousCached! : null));

                    if (cached) {
                        const decrypted = finalizeDiscoveryResult(
                            normalizedHandle,
                            targetHandle,
                            cached.encryptedBlob,
                            cached.exists,
                            [currentResult.encryptionKey, previousResult?.encryptionKey].filter(Boolean) as Uint8Array[]
                        );
                        resolve(decrypted);
                        return;
                    }

                    const requestId = `disc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
                    const tokens = [currentToken];
                    if (previousToken && previousToken !== currentToken) tokens.push(previousToken);
                    const encryptionKeys = [currentResult.encryptionKey];
                    if (previousResult?.encryptionKey) encryptionKeys.push(previousResult.encryptionKey);

                    const pending: PendingDiscoveryRequest = {
                        requestId,
                        tokens,
                        normalizedHandle,
                        targetHandle,
                        encryptionKeys,
                        resolve,
                        timeoutId: 0,
                        settled: false
                    };

                    registerPendingDiscovery(pending);

                    void (async () => {
                        const sent = await sendSecureDiscoveryMessage(
                            {
                                type: SignalType.QUERY_DISCOVERY,
                                token: currentResult.token,
                                previousEpochToken: previousResult?.token,
                                requestId
                            },
                            'query-discovery',
                            DISCOVERY_QUERY_TIMEOUT_MS + 6000
                        );

                        if (!sent) {
                            if (pending.settled) return;
                            pending.settled = true;
                            unregisterPendingDiscovery(pending);
                            discoveryResultCache.set(normalizedHandle, {
                                value: null,
                                expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                            });
                            resolve(null);
                            return;
                        }

                        if (pending.settled) return;

                        const timeoutId = window.setTimeout(() => {
                            if (pending.settled) return;
                            pending.settled = true;
                            console.warn('[OPRF-DISCOVERY] findUser: QUERY_DISCOVERY timed out for', targetHandle.slice(0, 8));
                            unregisterPendingDiscovery(pending);
                            discoveryResultCache.set(normalizedHandle, {
                                value: null,
                                expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                            });
                            resolve(null);
                        }, DISCOVERY_QUERY_TIMEOUT_MS);

                        pending.timeoutId = timeoutId;
                        console.log('[OPRF-DISCOVERY] findUser: sending QUERY_DISCOVERY, tokenPrefix:', currentResult.token.slice(0, 8));
                    })().catch((err) => {
                        if (pending.settled) return;
                        pending.settled = true;
                        console.warn('[OPRF-DISCOVERY] findUser: failed to send QUERY_DISCOVERY', err);
                        unregisterPendingDiscovery(pending);
                        discoveryResultCache.set(normalizedHandle, {
                            value: null,
                            expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                        });
                        resolve(null);
                    });
                });
            } catch (err) {
                console.error('[OPRF-DISCOVERY] Error finding user:', err);
                return null;
            } finally {
                findUserCache.delete(normalizedHandle);
            }
        })();

        findUserCache.set(normalizedHandle, promise);
        return promise;
    }, [getDiscoveryTokenForEpoch, getDiscoveryHandle, waitForOprfState, finalizeDiscoveryResult, normalizeToken, pruneDiscoveryIndexes, registerPendingDiscovery, sendSecureDiscoveryMessage, unregisterPendingDiscovery]);

    return {
        findUser,
        isDiscoverable,
        setIsDiscoverable
    };
};
