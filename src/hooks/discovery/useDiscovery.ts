/**
 * OPRF peer discovery hook
 */

import { useState, useCallback, useEffect, useLayoutEffect, useMemo, useRef, RefObject } from 'react';
import { SignalType } from '@/lib/types/signal-types';
import { EventType } from '@/lib/types/event-types';
import websocketClient from '@/lib/websocket/websocket';
import { profilePictureSystem } from '@/lib/avatar/profile-picture-system';
import {
    oprfDiscoveryClient,
    OPRFBlindResult,
    OPRFServerResponse,
    OPRFDiscoveryMaterial,
    OPRFDiscoveryBlob,
    DISCOVERY_BLOB_BASE64_CHARS
} from '@/lib/crypto/oprf-discovery-crypto';
import { account, signal } from '@/lib/tauri-bindings';
import { anonymousHttpFetch } from '@/lib/transport/pq-anonymous-http';
import { computeBlindUserId } from '@/lib/utils/auth-utils';
import { CryptoUtils } from '@/lib/utils/crypto-utils';
import { isValidAvatarData } from '@/lib/utils/avatar-utils';
import { sanitizeHybridKeys } from '@/lib/utils/messaging-validators';
import {
    computePeerCertificateFingerprint,
    encodePeerCertificateSigningPayload,
    validatePeerCertificateBundle
} from '@/lib/utils/peer-certificate-utils';
import {
    buildCertifiedPeerBundleV3,
    validateCertifiedPeerBundleV3
} from '@/lib/utils/certified-identity-utils';
import type { AvatarData } from '@/lib/types/avatar-types';
import { publishAvatarToStore, fetchAvatarFromStore, validateAvatarCoverBlobs as validateAvatarCoverBlobs, isValidAvatarRef } from '@/lib/avatar/avatar-store-client';
import type { AvatarRef } from '@/lib/crypto/avatar-blob-crypto';
import type { HybridKeys } from '@/lib/types/auth-types';
import type { PeerCertificateBundle } from '@/lib/types/p2p-types';
import {
    AUTH_USERNAME_REGEX,
    DISCOVERY_EPOCH_DURATION_MS,
    P2P_PEER_CERT_PUBLISH_REFRESH_LEAD_MS,
    P2P_PEER_CERT_TTL_MS,
    P2P_PEER_TRUST_REFRESH_INTERVAL_MS,
} from '@/lib/constants';
import { blake3 } from '@noble/hashes/blake3.js';
import { shouldAttemptDiscovery } from '@/lib/utils/discovery-utils';
import {
    DISCOVERY_PUBLICATION_BUCKET_COUNT,
    DISCOVERY_FIXED_BUCKET_COUNT,
    deriveDiscoveryBucketId,
    deriveDiscoveryBucketKey,
    fetchDiscoveryBlobsForTokens,
    requestDiscoveryManifest,
    type DiscoveryBucketFetchResult,
} from '@/lib/discovery/bucket-client';
import { assertCurrentServerContext, captureCurrentServerContext } from '@/lib/security/local-account-scope';
import { solvePowChallenge } from '@/lib/cryptography/proof-of-work';
import { Base64 } from '@/lib/cryptography/base64';
import { createAnonymousHttpPow } from '@/lib/cryptography/anonymous-http-pow';
import { keyTransparencyClient } from '@/lib/key-transparency/client';
import { markKeyTransparencyVerifiedMaterial } from '@/lib/key-transparency/verified-material';
import { createBoundedMapSetter } from '@/lib/utils/message-state-limits';
import { bytesToHex } from '@/lib/utils/byte-utils';
import { savePersistedDiscoveryMaterial } from '@/lib/discovery/persisted-discovery-material';
import { loadTrustedPersistedDiscoveryMaterial } from '@/lib/utils/signal-bundle-utils';
import {
    ownDetectionPublicKeyHex,
    persistPeerDetectionKey,
    rememberPeerDetectionKey,
} from '../../lib/spool/detection-key';
import { PROTOCOL_KEYS } from '@/lib/config/protocol-keys';
import { OPRF_EVALUATE_AUDIENCE } from '@/lib/config/audiences';

type DiscoveryTokenMaterial = { token: string; encryptionKey: Uint8Array };

interface DiscoveryTokenCacheEntry {
    value: Promise<DiscoveryTokenMaterial | null>;
    readers: number;
    retired: boolean;
    wipeScheduled: boolean;
    expiryTimer: number | null;
}

const discoveryTokenCache = new Map<string, DiscoveryTokenCacheEntry>();
const DISCOVERY_TOKEN_CACHE_MAX_ENTRIES = 256;

function wipeRetiredDiscoveryTokenCacheEntry(entry: DiscoveryTokenCacheEntry): void {
    if (!entry.retired || entry.readers !== 0 || entry.wipeScheduled) return;
    entry.wipeScheduled = true;
    void entry.value
        .then((value) => value?.encryptionKey.fill(0))
        .catch(() => { });
}

function deleteDiscoveryTokenCacheEntry(key: string): void {
    const entry = discoveryTokenCache.get(key);
    discoveryTokenCache.delete(key);
    if (entry) {
        if (entry.expiryTimer !== null) clearTimeout(entry.expiryTimer);
        entry.expiryTimer = null;
        entry.retired = true;
        wipeRetiredDiscoveryTokenCacheEntry(entry);
    }
}

function setDiscoveryTokenCacheEntry(
    key: string,
    value: Promise<DiscoveryTokenMaterial | null>
): DiscoveryTokenCacheEntry {
    if (discoveryTokenCache.has(key)) deleteDiscoveryTokenCacheEntry(key);
    while (discoveryTokenCache.size >= DISCOVERY_TOKEN_CACHE_MAX_ENTRIES) {
        const oldest = discoveryTokenCache.keys().next().value;
        if (typeof oldest !== 'string') break;
        deleteDiscoveryTokenCacheEntry(oldest);
    }
    const entry: DiscoveryTokenCacheEntry = {
        value,
        readers: 0,
        retired: false,
        wipeScheduled: false,
        expiryTimer: null
    };
    discoveryTokenCache.set(key, entry);
    return entry;
}

function scheduleDiscoveryTokenCacheExpiry(
    key: string,
    entry: DiscoveryTokenCacheEntry
): void {
    entry.expiryTimer = window.setTimeout(() => {
        entry.expiryTimer = null;
        if (discoveryTokenCache.get(key) === entry) {
            deleteDiscoveryTokenCacheEntry(key);
        }
    }, DISCOVERY_TOKEN_CACHE_TTL_MS);
}

async function readDiscoveryTokenCacheEntry(key: string): Promise<DiscoveryTokenMaterial | null> {
    const entry = discoveryTokenCache.get(key);
    if (!entry || entry.retired) return null;
    entry.readers += 1;
    try {
        const value = await entry.value.catch(() => null);
        if (!value) return null;
        return {
            token: value.token,
            encryptionKey: value.encryptionKey.slice()
        };
    } finally {
        entry.readers -= 1;
        wipeRetiredDiscoveryTokenCacheEntry(entry);
    }
}

function clearDiscoveryTokenCache(): void {
    for (const key of Array.from(discoveryTokenCache.keys())) {
        deleteDiscoveryTokenCacheEntry(key);
    }
}

function clearDiscoveryLookupCaches(): void {
    clearDiscoveryTokenCache();
    discoveryResultCache.clear();
    discoveryNetworkFetchAt.clear();
    findUserCache.clear();
    forceRefreshFindUserCache.clear();
    findUserInFlightLock.clear();
}

function wipeOprfBlindResult(result: OPRFBlindResult | null | undefined): void {
    result?.blind.fill(0);
    result?.blinded.fill(0);
}

async function deriveOprfPowSeed(
    publicKey: string,
    epoch: number,
    blindedPoint: string
): Promise<string> {
    const input = new TextEncoder().encode(
        `${PROTOCOL_KEYS.DISCOVERY_OPRF_POW}\0${publicKey}\0${epoch}\0${blindedPoint}`
    );
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    const seed = digest.slice(0, 16);
    try {
        return CryptoUtils.Base64.arrayBufferToBase64(seed);
    } finally {
        input.fill(0);
        digest.fill(0);
        seed.fill(0);
    }
}

type DiscoveryPublication = {
    epochId: string;
    publishId: string;
    bucketIds: number[];
};

function coverPublicationHex(
    key: Uint8Array,
    serverScope: string,
    publicationWindow: number,
    purpose: 'id' | 'padding',
    counter = 0,
): string {
    const transcript = new TextEncoder().encode(
        `${PROTOCOL_KEYS.DISCOVERY_COVER_PUBLICATION}\0${serverScope}\0${publicationWindow}\0${purpose}\0${counter}`
    );
    const digest = blake3(transcript, { key, dkLen: 32 });
    try {
        return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
    } finally {
        transcript.fill(0);
        digest.fill(0);
    }
}

async function buildDiscoveryPublication(
    tokens: string[],
    publicationWindow: number,
    serverScope: string,
    coverKey?: Uint8Array,
): Promise<DiscoveryPublication | null> {
    if (
        !Number.isSafeInteger(publicationWindow) ||
        publicationWindow < 0 ||
        !/^[a-f0-9]{64}$/.test(serverScope)
    ) return null;

    const manifestResponse = await requestDiscoveryManifest().catch(() => null);
        const manifest = manifestResponse?.success ? manifestResponse.manifest : null;
        if (!manifest) {
            return null;
        }
        const bucketIds = new Set<number>();
        for (const token of tokens) {
            if (typeof token !== 'string' || !/^[a-f0-9]{64}$/i.test(token)) continue;
            bucketIds.add(await deriveDiscoveryBucketId(
                await deriveDiscoveryBucketKey(token),
                manifest.bucketCount
            ));
            if (bucketIds.size > DISCOVERY_PUBLICATION_BUCKET_COUNT) return null;
        }
        for (let counter = 0; bucketIds.size < DISCOVERY_PUBLICATION_BUCKET_COUNT; counter += 1) {
            if (counter >= 1024) return null;
            const fillerToken = coverKey
                ? coverPublicationHex(coverKey, serverScope, publicationWindow, 'padding', counter)
                : await account.discoveryPublication(serverScope, publicationWindow, 'padding', counter);
            bucketIds.add(await deriveDiscoveryBucketId(
                await deriveDiscoveryBucketKey(fillerToken),
                manifest.bucketCount
            ));
        }
    return {
            epochId: manifest.epochId,
            publishId: coverKey
                ? coverPublicationHex(coverKey, serverScope, publicationWindow, 'id')
                : await account.discoveryPublication(serverScope, publicationWindow, 'id'),
            bucketIds: Array.from(bucketIds)
    };
}

const findUserCache = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const forceRefreshFindUserCache = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const findUserInFlightLock = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const discoveryResultCache = new Map<string, { value: OPRFDiscoveryMaterial | null; expiresAt: number }>();
const DISCOVERY_RESULT_CACHE_MAX_ENTRIES = 1024;
const DISCOVERY_LOOKUP_MAX_IN_FLIGHT = 2;
const FIND_USER_HARD_TIMEOUT_MS = 4 * 60 * 1000;
const LIFECYCLE_PUBLISH_COALESCE_MS = 3000;
const FORCED_REFETCH_MIN_INTERVAL_MS = 60 * 1000;
const discoveryNetworkFetchAt = new Map<string, number>();

const setDiscoveryResultCache = createBoundedMapSetter(DISCOVERY_RESULT_CACHE_MAX_ENTRIES);

function noteDiscoveryNetworkFetch(key: string): void {
    setDiscoveryResultCache(discoveryNetworkFetchAt, key, Date.now());
}

const scopedDiscoveryCacheKey = (
    publicKey: string,
    ownerScope: string,
    normalizedHandle: string
): string => {
    if (
        !/^[a-f0-9]{64}$/i.test(publicKey) ||
        !/^[a-f0-9]{64}$/i.test(ownerScope) ||
        !/^[a-f0-9]{64}$/i.test(normalizedHandle)
    ) {
        throw new Error('invalid_discovery_cache_scope');
    }
    return `${publicKey.toLowerCase()}:${ownerScope.toLowerCase()}:${normalizedHandle.toLowerCase()}`;
};

const DISCOVERY_POSITIVE_CACHE_TTL_MS = 5 * 60 * 1000;
const DISCOVERY_NEGATIVE_CACHE_TTL_MS = 30 * 1000;
const DISCOVERY_TIMEOUT_CACHE_TTL_MS = 25 * 1000;
const DISCOVERY_TOKEN_CACHE_TTL_MS = 30 * 1000;
const OPRF_WAIT_TIMEOUT_MS = 10000;
const OPRF_EPOCH_OPERATION_SAFETY_MS = 15000;
const OPRF_EPOCH_REFRESH_DELAY_MS = 250;
const PUBLISH_ACK_TIMEOUT_MS = 15000;
const DISCOVERY_PUBLISH_POW_DIFFICULTY = 18;
const PREKEY_BUNDLE_CACHE_TTL_MS = 2 * 60 * 1000;
const DISCOVERY_FORWARD_PUBLISH_WINDOW_MS = 24 * 60 * 60 * 1000;
const DISCOVERY_FORWARD_PUBLISH_EPOCHS = Math.max(
    0,
    Math.ceil(DISCOVERY_FORWARD_PUBLISH_WINDOW_MS / DISCOVERY_EPOCH_DURATION_MS) - 1
);
function secureRandomUnit(): number {
    const sample = new Uint32Array(1);
    crypto.getRandomValues(sample);
    return (sample[0] + 0.5) / 0x100000000;
}

const PRE_READY_PUBLISH_FAILURES = new Set([
    'missing-handle',
    'auth-transport-not-ready',
    'missing-oprf-epoch',
    'missing-certified-identity-keys'
]);

type DiscoveryOprfState = {
    publicKey: string;
    epoch: number;
    epochRotatesAt: number;
    powDifficulty: number;
};

function parseDiscoveryOprfState(value: unknown): DiscoveryOprfState | null {
    if (
        !value ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype
    ) {
        return null;
    }
    const detail = value as Record<string, unknown>;
    if (Object.keys(detail).sort().join(',') !== 'epoch,epochRotatesAt,powDifficulty,publicKey,type') {
        return null;
    }
    const { publicKey, epoch, epochRotatesAt, powDifficulty } = detail;
    if (
        detail.type !== SignalType.OPRF_DISCOVERY_PUBLIC_KEY ||
        typeof publicKey !== 'string' ||
        !/^[a-f0-9]{64}$/.test(publicKey) ||
        !Number.isSafeInteger(epoch) ||
        (epoch as number) < 0 ||
        epoch !== Math.floor(Date.now() / DISCOVERY_EPOCH_DURATION_MS) ||
        !Number.isSafeInteger(epochRotatesAt) ||
        epochRotatesAt !== ((epoch as number) + 1) * DISCOVERY_EPOCH_DURATION_MS ||
        powDifficulty !== 18
    ) {
        return null;
    }
    return {
        publicKey,
        epoch: epoch as number,
        epochRotatesAt: epochRotatesAt as number,
        powDifficulty: powDifficulty as number
    };
}

function isPreReadyPublishFailure(reason: string): boolean {
    return PRE_READY_PUBLISH_FAILURES.has(reason);
}

const AVATAR_FETCH_RETRY_DELAYS_MS = [4000, 8000, 15000, 30000];
const avatarFetchInFlight = new Set<string>();
const avatarFetchRetryTimers = new Map<string, ReturnType<typeof setTimeout>>();
const AVATAR_FETCH_MAX_IN_FLIGHT = 32;

function clearAvatarFetchInFlight(): void {
    for (const timer of avatarFetchRetryTimers.values()) clearTimeout(timer);
    avatarFetchRetryTimers.clear();
    avatarFetchInFlight.clear();
}

function finishAvatarFetch(inFlightKey: string): void {
    const timer = avatarFetchRetryTimers.get(inFlightKey);
    if (timer !== undefined) clearTimeout(timer);
    avatarFetchRetryTimers.delete(inFlightKey);
    avatarFetchInFlight.delete(inFlightKey);
}

async function cachePeerAvatarFromRef(
    cacheUsername: string | null,
    avatarRef: AvatarRef | null | undefined,
    ownerScope: string,
    isCurrentOwner: () => boolean,
    attempt = 0
): Promise<void> {
    if (!cacheUsername) return;
    if (!avatarRef || typeof avatarRef.blobId !== 'string' || typeof avatarRef.keyB64 !== 'string') {
        return;
    }
    const inFlightKey = `${ownerScope}:${cacheUsername}:${avatarRef.hash}`;
    if (!isCurrentOwner()) {
        finishAvatarFetch(inFlightKey);
        return;
    }
    const currentHash = profilePictureSystem.getPeerAvatarHash(cacheUsername);
    if (currentHash === avatarRef.hash) {
        finishAvatarFetch(inFlightKey);
        return;
    }

    if (attempt === 0) {
        if (avatarFetchInFlight.has(inFlightKey)) return;
        if (avatarFetchInFlight.size >= AVATAR_FETCH_MAX_IN_FLIGHT) return;
        avatarFetchInFlight.add(inFlightKey);
    }

    const avatar = await fetchAvatarFromStore(avatarRef).catch(() => null);
    if (!isCurrentOwner()) {
        finishAvatarFetch(inFlightKey);
        return;
    }
    if (avatar && isValidAvatarData(avatar)) {
        finishAvatarFetch(inFlightKey);
        await profilePictureSystem.cachePeerAvatar(
            cacheUsername,
            avatar.data,
            avatar.mimeType,
            avatar.hash,
            avatar.isDefault === true
        );
        return;
    }
    if (attempt < AVATAR_FETCH_RETRY_DELAYS_MS.length) {
        const delay = AVATAR_FETCH_RETRY_DELAYS_MS[attempt];
        const timer = setTimeout(() => {
            if (avatarFetchRetryTimers.get(inFlightKey) === timer) {
                avatarFetchRetryTimers.delete(inFlightKey);
            }
            void cachePeerAvatarFromRef(cacheUsername, avatarRef, ownerScope, isCurrentOwner, attempt + 1);
        }, delay);
        avatarFetchRetryTimers.set(inFlightKey, timer);
    } else {
        finishAvatarFetch(inFlightKey);
    }
}

function publishForceAttemptDelayMs(lastFailure: string | null): number {
    if (!lastFailure) return 10_000;
    if (lastFailure === 'oprf-token-missing') return 60_000;
    if (lastFailure === 'publish-ack-failed') return 45_000;
    return isPreReadyPublishFailure(lastFailure) ? 5_000 : 15_000;
}

function publishRetryDelayMs(reason: string, preReadyReason: boolean): number {
    if (reason === 'oprf-token-missing') return 60_000 + Math.floor(secureRandomUnit() * 15_000);
    if (reason === 'publish-ack-failed') return 45_000 + Math.floor(secureRandomUnit() * 15_000);
    if (preReadyReason) return 5_000 + Math.floor(secureRandomUnit() * 10_000);
    return 15_000 + Math.floor(secureRandomUnit() * 15_000);
}
const DISCOVERY_COVER_PUBLISH_INTERVAL_MS = 5 * 60 * 1000;
const DISCOVERY_COVER_PUBLISH_INITIAL_MIN_MS = 20 * 1000;
const DISCOVERY_COVER_PUBLISH_INITIAL_JITTER_MS = 40 * 1000;

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

const hashDiscoveryMaterial = (material: unknown): string => {
    const bytes = new TextEncoder().encode(stableStringify(material));
    const digest = blake3(bytes, { dkLen: 32 });
    try {
        return bytesToHex(digest);
    } finally {
        bytes.fill(0);
        digest.fill(0);
    }
};

const randomBytesForDiscovery = (length: number): Uint8Array => {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
};

const randomHexForDiscovery = (bytes = 32): string => {
    const random = randomBytesForDiscovery(bytes);
    try {
        return bytesToHex(random);
    } finally {
        random.fill(0);
    }
};

const cloneDiscoveryHybridKeys = (keys: HybridKeys | null | undefined): HybridKeys | null => {
    if (
        keys?.native !== true ||
        !keys.x25519?.publicKeyBase64 ||
        !keys.kyber?.publicKeyBase64 ||
        !keys.dilithium?.publicKeyBase64 ||
        !keys.accountRoot?.publicKeyBase64
    ) {
        return null;
    }
    return {
        native: true,
        x25519: { publicKeyBase64: keys.x25519.publicKeyBase64 },
        kyber: { publicKeyBase64: keys.kyber.publicKeyBase64 },
        dilithium: { publicKeyBase64: keys.dilithium.publicKeyBase64 },
        accountRoot: { publicKeyBase64: keys.accountRoot.publicKeyBase64 }
    };
};

const hasSameDiscoveryPublicKeys = (
    current: HybridKeys | null | undefined,
    snapshot: HybridKeys
): boolean => (
    current?.x25519?.publicKeyBase64 === snapshot.x25519.publicKeyBase64 &&
    current?.kyber?.publicKeyBase64 === snapshot.kyber.publicKeyBase64 &&
    current?.dilithium?.publicKeyBase64 === snapshot.dilithium.publicKeyBase64 &&
    current?.accountRoot?.publicKeyBase64 === snapshot.accountRoot.publicKeyBase64
);

const wipeDiscoveryHybridKeys = (keys: HybridKeys | null): void => {
    void keys;
};

const randomDiscoveryCoverBlob = (): string => {
    const bytes = randomBytesForDiscovery((DISCOVERY_BLOB_BASE64_CHARS / 4) * 3);
    try {
        const encoded = Base64.arrayBufferToBase64(bytes);
        if (encoded.length !== DISCOVERY_BLOB_BASE64_CHARS || encoded.includes('=')) {
            throw new Error('Could not create fixed discovery cover blob');
        }
        return encoded;
    } finally {
        bytes.fill(0);
    }
};

export const invalidateDiscoveryCache = (handle: string) => {
    if (!handle) return;
    let normalized = handle;
    if (!/^[a-f0-9]{64}$/i.test(handle)) {
        normalized = computeBlindUserId(handle);
    }
    const suffix = `:${normalized.toLowerCase()}`;
    for (const key of discoveryResultCache.keys()) {
        if (key.endsWith(suffix)) discoveryResultCache.delete(key);
    }
    for (const key of discoveryNetworkFetchAt.keys()) {
        if (key.endsWith(suffix)) discoveryNetworkFetchAt.delete(key);
    }
};

export const useDiscovery = (
    accountUsername: string | undefined,
    hybridKeysRef?: RefObject<HybridKeys | null>
) => {
    const [discoveryTransportReadyVersion, setDiscoveryTransportReadyVersion] = useState(0);
    const oprfStateRef = useRef<Partial<DiscoveryOprfState>>({});
    const lastPublishedRef = useRef<number>(0);
    const avatarPublishTimeoutRef = useRef<number | null>(null);
    const pendingAvatarPublishRef = useRef<boolean>(false);
    const avatarStateVersionRef = useRef<number>(0);
    const lastPublishedAvatarStateVersionRef = useRef<number>(-1);
    const cachedBundleRef = useRef<{ cacheKey: string; bundle: any; expiresAt: number } | null>(null);
    const cachedPeerCertificateRef = useRef<{ cacheKey: string; certificate: PeerCertificateBundle } | null>(null);
    const lastOprfKeyRequestRef = useRef<number>(0);
    const oprfEpochRefreshTimeoutRef = useRef<number | null>(null);
    const lastDiscoveryTransportReadyRef = useRef<boolean | null>(null);
    const lastPublishFailureRef = useRef<string | null>(null);
    const publishingRef = useRef<boolean>(false);
    const publishPromiseRef = useRef<Promise<boolean> | null>(null);
    const lastPublishedFingerprintRef = useRef<string | null>(null);
    const lastPublishedContextFingerprintRef = useRef<string | null>(null);
    const lifecyclePublishTimerRef = useRef<number | null>(null);
    const coverPublicationStateRef = useRef<{
        publicationWindow: number;
        publishKey: Uint8Array;
    } | null>(null);
    const lastPublishAttemptRef = useRef<number>(0);
    const lastOprfPublicKeyRef = useRef<string | null>(null);
    const lastOprfPublicationWindowRef = useRef<number | null>(null);
    const oprfReadyPromiseRef = useRef<Promise<DiscoveryOprfState | null> | null>(null);
    const activeOwnerScopeRef = useRef<string | null>(null);
    const ownerAbortControllerRef = useRef(new AbortController());
    const effectiveHandle = useMemo(() => {
        const candidate = (accountUsername || '').trim();
        return candidate || undefined;
    }, [accountUsername]);
    const ownerScope = useMemo(
        () => effectiveHandle ? randomHexForDiscovery(32) : null,
        [effectiveHandle]
    );

    useLayoutEffect(() => {
        ownerAbortControllerRef.current.abort();
        ownerAbortControllerRef.current = new AbortController();
        activeOwnerScopeRef.current = ownerScope;
        clearDiscoveryLookupCaches();
        clearAvatarFetchInFlight();
        oprfStateRef.current = {};
        lastPublishedRef.current = 0;
        if (avatarPublishTimeoutRef.current) clearTimeout(avatarPublishTimeoutRef.current);
        avatarPublishTimeoutRef.current = null;
        pendingAvatarPublishRef.current = false;
        avatarStateVersionRef.current = 0;
        lastPublishedAvatarStateVersionRef.current = -1;
        cachedBundleRef.current = null;
        cachedPeerCertificateRef.current = null;
        lastOprfKeyRequestRef.current = 0;
        if (oprfEpochRefreshTimeoutRef.current !== null) {
            clearTimeout(oprfEpochRefreshTimeoutRef.current);
        }
        oprfEpochRefreshTimeoutRef.current = null;
        lastDiscoveryTransportReadyRef.current = null;
        lastPublishFailureRef.current = null;
        publishingRef.current = false;
        publishPromiseRef.current = null;
        lastPublishedFingerprintRef.current = null;
        lastPublishedContextFingerprintRef.current = null;
        if (lifecyclePublishTimerRef.current !== null) {
            clearTimeout(lifecyclePublishTimerRef.current);
            lifecyclePublishTimerRef.current = null;
        }
        coverPublicationStateRef.current?.publishKey.fill(0);
        coverPublicationStateRef.current = null;
        lastPublishAttemptRef.current = 0;
        lastOprfPublicKeyRef.current = null;
        lastOprfPublicationWindowRef.current = null;
        oprfReadyPromiseRef.current = null;

        return () => {
            if (oprfEpochRefreshTimeoutRef.current !== null) {
                clearTimeout(oprfEpochRefreshTimeoutRef.current);
                oprfEpochRefreshTimeoutRef.current = null;
            }
            if (activeOwnerScopeRef.current === ownerScope) {
                ownerAbortControllerRef.current.abort();
                activeOwnerScopeRef.current = null;
                coverPublicationStateRef.current?.publishKey.fill(0);
                coverPublicationStateRef.current = null;
            }
            clearDiscoveryLookupCaches();
            clearAvatarFetchInFlight();
        };
    }, [ownerScope]);

    const isDiscoveryTransportReady = useCallback((): boolean => {
        if (!effectiveHandle) {

            return false;
        }
        if (!websocketClient.isConnectedToServer()) {

            return false;
        }

        return websocketClient.isUnlinkedMode?.() === true &&
            websocketClient.isUnlinkedSessionReady?.() === true;
    }, [effectiveHandle]);

    const noteDiscoveryTransportReadinessChanged = useCallback((_reason?: unknown) => {
        const ready = isDiscoveryTransportReady();
        if (lastDiscoveryTransportReadyRef.current === ready) {
            return;
        }
        lastDiscoveryTransportReadyRef.current = ready;
        setDiscoveryTransportReadyVersion((version) => (version + 1) % Number.MAX_SAFE_INTEGER);
    }, [isDiscoveryTransportReady]);

    const requestOprfKey = useCallback((_reason: string | Event = 'auto', force = false) => {
        if (!ownerScope || activeOwnerScopeRef.current !== ownerScope) return;
        const now = Date.now();

        if (!force && now - lastOprfKeyRequestRef.current < 5000) {

            return;
        }
        if (!isDiscoveryTransportReady()) {

            return;
        }
        lastOprfKeyRequestRef.current = now;
        websocketClient.send({ type: SignalType.OPRF_DISCOVERY_PUBLIC_KEY });

    }, [isDiscoveryTransportReady, ownerScope]);

    const waitForOprfState = useCallback(async (
        reason: string,
        timeoutMs: number = OPRF_WAIT_TIMEOUT_MS
    ): Promise<DiscoveryOprfState | null> => {
        const operationOwnerScope = ownerScope;
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope
        );
        if (!isCurrentOwner()) return null;
        const current = oprfStateRef.current;
        if (
            current.publicKey &&
            current.epoch !== undefined &&
            Number.isSafeInteger(current.epochRotatesAt) &&
            (current.epochRotatesAt as number) > Date.now() + OPRF_EPOCH_OPERATION_SAFETY_MS
        ) {
            console.log('[DISCOVERY] oprf: using cached OPRF state', { reason, epoch: current.epoch });
            return current as DiscoveryOprfState;
        }

        if (
            current.publicKey &&
            Number.isSafeInteger(current.epochRotatesAt) &&
            (current.epochRotatesAt as number) > Date.now()
        ) {
            const boundaryDelay = (current.epochRotatesAt as number) - Date.now() +
                OPRF_EPOCH_REFRESH_DELAY_MS;
            const completed = await new Promise<boolean>((resolve) => {
                let settled = false;
                const finish = (value: boolean) => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timeoutId);
                    operationAbortSignal.removeEventListener('abort', onAbort);
                    resolve(value);
                };
                const onAbort = () => finish(false);
                const timeoutId = window.setTimeout(() => finish(true), boundaryDelay);
                operationAbortSignal.addEventListener('abort', onAbort, { once: true });
                if (operationAbortSignal.aborted) onAbort();
            });
            if (!completed) return null;
            if (!isCurrentOwner()) return null;
            const refreshed = oprfStateRef.current;
            if (
                refreshed.publicKey &&
                refreshed.epoch !== undefined &&
                Number.isSafeInteger(refreshed.epochRotatesAt) &&
                (refreshed.epochRotatesAt as number) > Date.now() + OPRF_EPOCH_OPERATION_SAFETY_MS
            ) {
                return refreshed as DiscoveryOprfState;
            }
        }
        oprfStateRef.current = {};

        if (oprfReadyPromiseRef.current) {

            return oprfReadyPromiseRef.current;
        }

        let readyPromise!: Promise<DiscoveryOprfState | null>;
        readyPromise = new Promise((resolve) => {
            let settled = false;
            const cleanup = () => {
                if (settled) return;
                settled = true;
                window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
                if (timeoutId) clearTimeout(timeoutId);
                operationAbortSignal.removeEventListener('abort', onAbort);
                if (oprfReadyPromiseRef.current === readyPromise) {
                    oprfReadyPromiseRef.current = null;
                }
            };

            const handler = (ev: Event) => {
                if (!isCurrentOwner()) {
                    cleanup();
                    resolve(null);
                    return;
                }
                const state = parseDiscoveryOprfState((ev as CustomEvent).detail);
                if (state) {
                    cleanup();
                    resolve(state);
                }
            };

            const onAbort = () => {
                cleanup();
                resolve(null);
            };

            const timeoutId = window.setTimeout(() => {
                console.warn('[DISCOVERY] oprf: WAIT TIMEOUT — server never sent OPRF public key/epoch', { reason, timeoutMs });
                cleanup();
                resolve(null);
            }, timeoutMs);

            window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            operationAbortSignal.addEventListener('abort', onAbort, { once: true });
            if (operationAbortSignal.aborted) onAbort();
        });
        if (!isCurrentOwner()) return null;
        oprfReadyPromiseRef.current = readyPromise;
        
        requestOprfKey(reason, true);

        return readyPromise;
    }, [requestOprfKey, ownerScope]);

    const pruneDiscoveryTokenCache = useCallback((epoch?: number) => {
        const allowed = new Set<number>();
        if (typeof epoch === 'number') {
            allowed.add(epoch);
            for (let i = 1; i <= DISCOVERY_FORWARD_PUBLISH_EPOCHS; i += 1) {
                allowed.add(epoch + i);
            }
        }
        for (const key of Array.from(discoveryTokenCache.keys())) {
            const parts = key.split(':');
            const keyEpoch = Number(parts[parts.length - 1]);
            if (!allowed.has(keyEpoch)) {
                deleteDiscoveryTokenCacheEntry(key);
            }
        }
    }, []);

    const waitForPqSession = useCallback(async (
        timeoutMs: number = 15000,
        abortSignal?: AbortSignal
    ): Promise<boolean> => {
        if (abortSignal?.aborted) return false;
        try {
            if (typeof (websocketClient as any)?.isPQSessionEstablished === 'function') {
                if ((websocketClient as any).isPQSessionEstablished()) {

                    return true;
                }
            }
        } catch { }


        return new Promise<boolean>((resolve) => {
            let settled = false;
            const cleanup = () => {
                if (settled) return;
                settled = true;
                window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, handler as EventListener);
                if (timeoutId) clearTimeout(timeoutId);
                abortSignal?.removeEventListener('abort', onAbort);
            };

            const handler = () => {
                cleanup();

                resolve(true);
            };

            const onAbort = () => {
                cleanup();
                resolve(false);
            };

            const timeoutId = window.setTimeout(() => {
                cleanup();
                try {
                    if (typeof (websocketClient as any)?.isPQSessionEstablished === 'function') {
                        const ready = (websocketClient as any).isPQSessionEstablished();

                        return resolve(ready);
                    }
                } catch { }

                resolve(false);
            }, timeoutMs);

            window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, handler as EventListener);
            abortSignal?.addEventListener('abort', onAbort, { once: true });
            if (abortSignal?.aborted) onAbort();
        });
    }, []);

    const sendSecureDiscoveryMessage = useCallback(async (
        payload: Record<string, unknown>,
        _reason: string,
        readyTimeoutMs: number = 15000
    ): Promise<boolean> => {
        const operationOwnerScope = ownerScope;
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
        const operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch)
        );

        if (!isCurrentOwner() || !isDiscoveryTransportReady()) {

            return false;
        }
        const ready = await waitForPqSession(readyTimeoutMs, operationAbortSignal);
        if (!isCurrentOwner() || !ready || !isDiscoveryTransportReady()) {

            return false;
        }
        try {

            await websocketClient.sendSecureControlMessage(payload, { failIfQueued: true });

            return isCurrentOwner() && isDiscoveryTransportReady();
        } catch {
            return false;
        }
    }, [isDiscoveryTransportReady, waitForPqSession, ownerScope]);

    const buildSelfPeerCertificate = async (
        username: string,
        keys: HybridKeys | null | undefined
    ): Promise<PeerCertificateBundle | null> => {
        if (keys?.native !== true || !keys.dilithium?.publicKeyBase64) return null;
        if (!keys.kyber?.publicKeyBase64 || !keys.x25519?.publicKeyBase64) return null;

        const proof = keys.dilithium.publicKeyBase64;
        const cacheKey = JSON.stringify({
            username,
            dilithiumPublicKey: keys.dilithium.publicKeyBase64,
            kyberPublicKey: keys.kyber.publicKeyBase64,
            x25519PublicKey: keys.x25519.publicKeyBase64,
            proof
        });
        const now = Date.now();
        const cached = cachedPeerCertificateRef.current;
        if (
            cached &&
            cached.cacheKey === cacheKey &&
            cached.certificate.expiresAt - now > P2P_PEER_CERT_PUBLISH_REFRESH_LEAD_MS
        ) {
            return cached.certificate;
        }
        const issuedAt = now;
        const expiresAt = issuedAt + P2P_PEER_CERT_TTL_MS;

        const unsignedCertificate: PeerCertificateBundle = {
            username,
            dilithiumPublicKey: keys.dilithium.publicKeyBase64,
            kyberPublicKey: keys.kyber.publicKeyBase64,
            x25519PublicKey: keys.x25519.publicKeyBase64,
            proof,
            issuedAt,
            expiresAt,
            signature: ''
        };
        const canonical = encodePeerCertificateSigningPayload(unsignedCertificate);
        let signature: string;
        try {
            signature = await account.sign(PROTOCOL_KEYS.DEVICE_CERTIFICATE_SIGNING, canonical);
        } finally {
            canonical.fill(0);
        }

        const certificate: PeerCertificateBundle = {
            ...unsignedCertificate,
            signature
        };
        cachedPeerCertificateRef.current = { cacheKey, certificate };
        return certificate;
    };

    const validatePeerCertificate = useCallback(async (
        targetHandle: string,
        publicKeys: {
            kyberPublicBase64: string;
            dilithiumPublicBase64: string;
            x25519PublicBase64: string;
        },
        cert: PeerCertificateBundle
    ): Promise<PeerCertificateBundle | null> => {
        try {
            const certificateUsername = typeof cert?.username === 'string' ? cert.username : '';
            if (!certificateUsername) return null;

            const requestedUsername = String(targetHandle || '').trim().toLowerCase();
            if (!AUTH_USERNAME_REGEX.test(requestedUsername) || certificateUsername.toLowerCase() !== requestedUsername) {
                return null;
            }
            if (cert.dilithiumPublicKey !== publicKeys.dilithiumPublicBase64) {
                return null;
            }
            if (cert.kyberPublicKey !== publicKeys.kyberPublicBase64) {
                return null;
            }
            if (cert.x25519PublicKey !== publicKeys.x25519PublicBase64) {
                return null;
            }
            return await validatePeerCertificateBundle(cert, certificateUsername);
        } catch {
            return null;
        }
    }, []);

    const validateDiscoveryMaterial = useCallback(async (
        targetHandle: string,
        material: OPRFDiscoveryBlob | null
    ): Promise<OPRFDiscoveryMaterial | null> => {
        const operationOwnerScope = ownerScope;
        const accountOwner = effectiveHandle?.toLowerCase() || null;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            accountOwner !== null &&
            activeOwnerScopeRef.current === operationOwnerScope
        );
        if (!isCurrentOwner()) return null;
        const reject = (reason: string): null => {
            console.warn('[DISCOVERY] validate: rejected decrypted material', { target: targetHandle, reason });
            return null;
        };
        if (
            !material ||
            typeof material !== 'object' ||
            Array.isArray(material) ||
            Object.getPrototypeOf(material) !== Object.prototype
        ) {
            return reject('material-shape');
        }

        const certifiedCandidate = material.certifiedPeerBundle as any;
        const deviceCandidate = certifiedCandidate?.deviceCert;
        if (
            !deviceCandidate ||
            typeof deviceCandidate !== 'object' ||
            Array.isArray(deviceCandidate)
        ) return reject('missing-device-cert');
        const sanitizedPublicKeys = sanitizeHybridKeys({
            kyberPublicBase64: deviceCandidate.deviceKyberPublicKey,
            dilithiumPublicBase64: deviceCandidate.deviceDilithiumPublicKey,
            x25519PublicBase64: deviceCandidate.deviceX25519PublicKey
        }) as OPRFDiscoveryMaterial['publicKeys'];
        if (
            !sanitizedPublicKeys?.kyberPublicBase64 ||
            !sanitizedPublicKeys?.dilithiumPublicBase64 ||
            !sanitizedPublicKeys?.x25519PublicBase64
        ) {
            return reject('device-public-keys');
        }

        const validated: OPRFDiscoveryMaterial = {
            publicKeys: {
                x25519PublicBase64: sanitizedPublicKeys.x25519PublicBase64,
                kyberPublicBase64: sanitizedPublicKeys.kyberPublicBase64,
                dilithiumPublicBase64: sanitizedPublicKeys.dilithiumPublicBase64
            },
            fullBundle: material.fullBundle
        };

        const reconstructedCertificate: PeerCertificateBundle = {
            username: deviceCandidate.username,
            dilithiumPublicKey: deviceCandidate.deviceDilithiumPublicKey,
            kyberPublicKey: deviceCandidate.deviceKyberPublicKey,
            x25519PublicKey: deviceCandidate.deviceX25519PublicKey,
            proof: deviceCandidate.deviceDilithiumPublicKey,
            issuedAt: deviceCandidate.issuedAt,
            expiresAt: deviceCandidate.expiresAt,
            signature: deviceCandidate.attestationSignature
        };
        const cert = await validatePeerCertificate(
            targetHandle,
            validated.publicKeys,
            reconstructedCertificate
        );
        if (!isCurrentOwner()) return null;
        if (!cert) {
            return reject('peer-certificate-invalid');
        }

        const peerCertificateFingerprint = computePeerCertificateFingerprint(cert);
        const certifiedIdentity = await validateCertifiedPeerBundleV3(material.certifiedPeerBundle, {
            targetHandle,
            publicKeys: validated.publicKeys,
            fullBundle: material.fullBundle,
            peerCertificate: cert,
            peerCertificateFingerprint
        });
        if (!isCurrentOwner()) return null;
        if (!certifiedIdentity.valid || !certifiedIdentity.identityRootFingerprint || !certifiedIdentity.bundleFingerprint) {
            return reject(`certified-bundle:${certifiedIdentity.reason || 'invalid'}`);
        }

        validated.peerCertificate = cert;
        validated.peerCertificateFingerprint = peerCertificateFingerprint;
        validated.certifiedPeerBundle = certifiedIdentity.bundle;
        validated.identityRootFingerprint = certifiedIdentity.identityRootFingerprint;
        validated.identityBundleFingerprint = certifiedIdentity.bundleFingerprint;

        const avatarRef = material.avatarRef;
        if (
            avatarRef &&
            typeof avatarRef === 'object' &&
            !Array.isArray(avatarRef) &&
            typeof avatarRef.hash === 'string' &&
            isValidAvatarRef(avatarRef, avatarRef.hash)
        ) {
            validated.avatarRef = {
                blobId: avatarRef.blobId,
                hash: avatarRef.hash,
                keyB64: avatarRef.keyB64,
                mimeType: avatarRef.mimeType
            };
        }

        return validated;
    }, [validatePeerCertificate, effectiveHandle, ownerScope]);

    const getDiscoveryHandle = useCallback((input: string): string => {
        const username = typeof input === 'string' ? input.trim().toLowerCase() : '';
        if (/^[a-f0-9]{64}$/.test(username)) return username;
        return AUTH_USERNAME_REGEX.test(username) ? computeBlindUserId(username) : '';
    }, []);

    const getAvatarForDiscovery = useCallback(async (): Promise<AvatarData | null> => {
        const ownAvatar = profilePictureSystem.getOwnAvatarData?.() ?? null;

        if (
            ownAvatar &&
            ownAvatar.isDefault === false &&
            isValidAvatarData(ownAvatar)
        ) {
            return ownAvatar;
        }
        return null;
    }, []);

    const finalizeDiscoverySnapshotResult = useCallback(async (
        cacheKey: string,
        targetHandle: string,
        encryptedBlobs: string[],
        encryptionKeys: Uint8Array[],
        cacheNegative = true,
        monitorContact = true
    ): Promise<OPRFDiscoveryMaterial | null> => {
        const operationOwnerScope = ownerScope;
        const accountOwner = effectiveHandle?.toLowerCase() || null;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            accountOwner !== null &&
            activeOwnerScopeRef.current === operationOwnerScope
        );
        if (!isCurrentOwner()) return null;
        let transparencyCheckFailed = false;
        
        let decryptedCount = 0;
        const decryptStats = { selectorMatches: 0 };
        let validationRejected = 0;
        let missingAccountRoot = 0;
        let transparencyError: string | null = null;
        for (const encryptedBlob of encryptedBlobs) {
            if (typeof encryptedBlob !== 'string' || encryptedBlob.length === 0) continue;
            for (const key of encryptionKeys) {
                if (!key) continue;
                let material: OPRFDiscoveryBlob | null = null;
                try {
                    material = oprfDiscoveryClient.decryptDiscoveryBlob(encryptedBlob, key, decryptStats);
                } catch { }
                if (!material) continue;
                decryptedCount += 1;

                const validated = await validateDiscoveryMaterial(targetHandle, material);
                if (!isCurrentOwner()) return null;
                if (!validated) {
                    validationRejected += 1;
                    continue;
                }

                if (accountOwner) {
                    void persistPeerDetectionKey(
                        accountOwner,
                        targetHandle,
                        material.spoolDetectionKey,
                    ).catch(() => { });
                } else {
                    rememberPeerDetectionKey(targetHandle, material.spoolDetectionKey);
                }

                if (material.keyTransparencyTransition && accountOwner) {
                    await keyTransparencyClient
                        .ingestPublishedTransition(accountOwner, material.keyTransparencyTransition)
                        .catch(() => { });
                    if (!isCurrentOwner()) return null;
                }

                const accountRootPublicKey =
                    validated.certifiedPeerBundle?.accountRoot?.accountRootPublicKey;
                if (typeof accountRootPublicKey !== 'string') {
                    missingAccountRoot += 1;
                    continue;
                }
                let transparencyContact: Awaited<ReturnType<
                    typeof keyTransparencyClient.verifyDiscoveredIdentity
                >>;
                try {
                    transparencyContact = await keyTransparencyClient.verifyDiscoveredIdentity({
                        ownerUsername: accountOwner!,
                        peerUsername: String(targetHandle).trim().toLowerCase(),
                        monitorContact,
                        discoveryEncryptionKey: key,
                        accountRootPublicKeyBase64: accountRootPublicKey,
                    });
                } catch (error) {
                    transparencyCheckFailed = true;
                    transparencyError = error instanceof Error ? error.message : String(error);
                    continue;
                }
                if (!isCurrentOwner()) return null;
                markKeyTransparencyVerifiedMaterial(
                    validated,
                    accountOwner!,
                    String(targetHandle).trim().toLowerCase(),
                    transparencyContact,
                );

                await savePersistedDiscoveryMaterial(
                    accountOwner!,
                    String(targetHandle).trim().toLowerCase(),
                    validated,
                    {
                        rootCommitment: transparencyContact.rootCommitment,
                        version: transparencyContact.version,
                    }
                ).catch(() => { });
                await keyTransparencyClient.persistAuthorizations(accountOwner!).catch(() => { });

                const cacheUsername = validated.peerCertificate?.username || String(targetHandle);
                void cachePeerAvatarFromRef(
                    cacheUsername,
                    validated.avatarRef,
                    operationOwnerScope!,
                    isCurrentOwner
                );
                setDiscoveryResultCache(discoveryResultCache, cacheKey, {
                    value: validated,
                    expiresAt: Date.now() + DISCOVERY_POSITIVE_CACHE_TTL_MS
                });
                return validated;
            }
        }

        console.warn('[DISCOVERY] finalize: no material accepted', {
            detail: JSON.stringify({
                target: targetHandle,
                key8: encryptionKeys
                    .filter(Boolean)
                    .map((key) => bytesToHex(key.slice(0, 8))),
                blobs: encryptedBlobs.length,
                selectorMatches: decryptStats.selectorMatches,
                decrypted: decryptedCount,
                validationRejected,
                missingAccountRoot,
                transparencyError,
            }),
        });

        if (cacheNegative && !transparencyCheckFailed) {
            setDiscoveryResultCache(discoveryResultCache, cacheKey, {
                value: null,
                expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
            });
        }
        return null;
    }, [validateDiscoveryMaterial, effectiveHandle, ownerScope]);

    const findDiscoveryBlobsInBuckets = useCallback(async (
        tokens: string[]
    ): Promise<DiscoveryBucketFetchResult | null> => {
        const normalizedTokens = Array.from(new Set(
            tokens
                .map((token) => typeof token === 'string' ? token.trim().toLowerCase() : '')
                .filter((token) => /^[a-f0-9]{64}$/i.test(token))
        ));
        if (normalizedTokens.length === 0) {

            return null;
        }

        if (!ownerScope) return null;
        const result = await fetchDiscoveryBlobsForTokens(normalizedTokens, ownerScope);
        const seen = new Set<string>();
        const results: string[] = [];
        for (const blob of result.blobs) {
            if (!seen.has(blob)) {
                seen.add(blob);
                results.push(blob);
            }
        }
        return { blobs: results, context: result.context };
    }, [ownerScope]);

    // Derives discovery tokens for one or more epochs using a single OPRF evaluation
    const getDiscoveryTokensForEpochs = useCallback(async (
        targetHandle: string,
        epochs: number[]
    ): Promise<Map<number, { token: string; encryptionKey: Uint8Array }> | null> => {
        const operationOwnerScope = ownerScope;
        const operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch)
        );
        if (!isCurrentOwner()) return null;
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) {

            return null;
        }

        const uniqueEpochs = Array.from(new Set(
            (Array.isArray(epochs) ? epochs : [])
                .filter((value) => Number.isFinite(value))
                .map((value) => Math.trunc(value))
        ));

        if (uniqueEpochs.length === 0) {

            return new Map();
        }
        const scopeState = await waitForOprfState('token-cache-scope');
        if (!isCurrentOwner()) return null;
        if (!scopeState?.publicKey || !/^[a-f0-9]{64}$/i.test(scopeState.publicKey)) {
            return null;
        }
        const scopeKey = scopedDiscoveryCacheKey(scopeState.publicKey, operationOwnerScope!, normalizedHandle);

        const results = new Map<number, { token: string; encryptionKey: Uint8Array }>();
        const missingEpochs: number[] = [];

        for (const epoch of uniqueEpochs) {
            const cacheKey = `${scopeKey}:${epoch}`;
            if (!discoveryTokenCache.has(cacheKey)) {
                missingEpochs.push(epoch);
                continue;
            }
            const cached = await readDiscoveryTokenCacheEntry(cacheKey);
            if (!isCurrentOwner()) {
                cached?.encryptionKey.fill(0);
                for (const result of results.values()) result.encryptionKey.fill(0);
                return null;
            }
            if (!cached) {
                missingEpochs.push(epoch);
                continue;
            }
            results.set(epoch, cached);
        }

        if (missingEpochs.length === 0) {

            return results;
        }


        const evaluation = await evaluateHandleWithOprf(normalizedHandle);
        if (!isCurrentOwner()) {
            wipeOprfBlindResult(evaluation?.blindResult);
            for (const result of results.values()) result.encryptionKey.fill(0);
            return null;
        }
        if (!evaluation) {
            for (const result of results.values()) result.encryptionKey.fill(0);
            return null;
        }

        try {
            const derived = oprfDiscoveryClient.finalizeTokenBatch(
                normalizedHandle,
                evaluation.blindResult,
                evaluation.response,
                missingEpochs
            );
            try {
                for (const derivedToken of derived.tokens) {
                    if (!isCurrentOwner()) {
                        for (const result of results.values()) result.encryptionKey.fill(0);
                        return null;
                    }
                    const value = {
                        token: derivedToken.token,
                        encryptionKey: derived.encryptionKey.slice()
                    };
                    results.set(derivedToken.epoch, value);

                    const cacheKey = `${scopeKey}:${derivedToken.epoch}`;
                    const cachedPromise = Promise.resolve({
                        token: value.token,
                        encryptionKey: value.encryptionKey.slice()
                    });
                    const cacheEntry = setDiscoveryTokenCacheEntry(cacheKey, cachedPromise);
                    scheduleDiscoveryTokenCacheExpiry(cacheKey, cacheEntry);
                }
            } finally {
                derived.encryptionKey.fill(0);
            }
        } catch (error) {
            for (const result of results.values()) result.encryptionKey.fill(0);
            throw error;
        }


        return results;
    }, [getDiscoveryHandle, waitForOprfState, ownerScope]);

    const evaluateHandleWithOprf = useCallback(async (
        normalizedHandle: string
    ): Promise<{ blindResult: OPRFBlindResult; response: OPRFServerResponse } | null> => {
        const operationOwnerScope = ownerScope;
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
        const operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch)
        );
        if (!isCurrentOwner()) return null;
        if (!normalizedHandle) {


            return null;
        }


        const [oprfState, sessionReady] = await Promise.all([
            waitForOprfState('oprf-token-batch'),
            waitForPqSession(15_000, operationAbortSignal)
        ]);
        if (!isCurrentOwner() || !isDiscoveryTransportReady()) return null;
        if (!oprfState?.publicKey) {


            return null;
        }
        if (!sessionReady) {


            return null;
        }

        const blindResult = oprfDiscoveryClient.blindHandle(normalizedHandle);
        const blindedHex = bytesToHex(blindResult.blinded);
        let retained = false;
        // Dedicated isolated Tor circuit
        try {
            const context = await captureCurrentServerContext();
            if (!isCurrentOwner()) return null;
            const powSeed = await deriveOprfPowSeed(
                oprfState.publicKey,
                oprfState.epoch,
                blindedHex
            );
            const powSolution = await solvePowChallenge({
                seed: powSeed,
                difficulty: oprfState.powDifficulty
            }, operationAbortSignal);
            await assertCurrentServerContext(context);
            if (!isCurrentOwner()) return null;
            const httpResp: any = await anonymousHttpFetch(
                OPRF_EVALUATE_AUDIENCE,
                {
                    blindedPoint: blindedHex,
                    powEpoch: oprfState.epoch,
                    powSolution
                },
                context.serverUrl
            );
            await assertCurrentServerContext(context);
            if (!isCurrentOwner()) return null;
            if (
                httpResp &&
                typeof httpResp === 'object' &&
                !Array.isArray(httpResp) &&
                Object.getPrototypeOf(httpResp) === Object.prototype &&
                Object.keys(httpResp).sort().join(',') === 'evaluated,ok,proof,publicKey' &&
                httpResp.ok === true &&
                typeof httpResp.evaluated === 'string' &&
                /^[a-f0-9]{64}$/.test(httpResp.evaluated) &&
                typeof httpResp.proof === 'string' &&
                /^[a-f0-9]{128}$/.test(httpResp.proof) &&
                httpResp.publicKey === oprfState.publicKey
            ) {

                retained = true;
                return { blindResult, response: { evaluated: httpResp.evaluated, proof: httpResp.proof, publicKey: httpResp.publicKey } };
            }

            return null;
        } catch {
            return null;
        } finally {
            if (!retained) wipeOprfBlindResult(blindResult);
        }
    }, [waitForOprfState, waitForPqSession, isDiscoveryTransportReady, ownerScope]);

    // Publishes current identity to billboard
    const runPublishSelf = useCallback(async (
        force = false,
        bypassAttemptDelay = false
    ): Promise<boolean> => {
        const operationOwnerScope = ownerScope;
        const operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        const accountHandle = effectiveHandle;
        const bundleUsername = accountUsername;
        let accountKeys: HybridKeys | null = null;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch) &&
            (accountKeys === null || hasSameDiscoveryPublicKeys(hybridKeysRef?.current, accountKeys))
        );

        const fail = (reason: string) => {
            if (isCurrentOwner()) lastPublishFailureRef.current = reason;
            return false;
        };

        if (!isCurrentOwner() || !accountHandle || !bundleUsername) {
            return false;
        }
        if (publishPromiseRef.current) {
            return publishPromiseRef.current;
        }
        if (!isDiscoveryTransportReady()) return fail('auth-transport-not-ready');

        const now = Date.now();
        const minAttemptDelay = force ? publishForceAttemptDelayMs(lastPublishFailureRef.current) : 30000;
        const lastAttemptSucceeded = lastPublishedRef.current > 0 && !lastPublishFailureRef.current;
        if (!bypassAttemptDelay && now - lastPublishAttemptRef.current < minAttemptDelay) {
            return lastAttemptSucceeded;
        }
        lastPublishAttemptRef.current = now;
        accountKeys = cloneDiscoveryHybridKeys(hybridKeysRef?.current);
        if (!accountKeys) return fail('missing-certified-identity-keys');

        let publishPromise!: Promise<boolean>;
        publishPromise = (async (): Promise<boolean> => {
            publishingRef.current = true;
            const epochTokenResults: Array<{ epoch: number; token: string; encryptionKey: Uint8Array }> = [];
            let publishedAvatarStateVersion = -1;
            try {
                let bundle: any = null;
                const cachedBundle = cachedBundleRef.current;
                const bundleCacheKey = JSON.stringify({
                    username: bundleUsername,
                    kyberPublicKey: accountKeys?.kyber?.publicKeyBase64,
                    dilithiumPublicKey: accountKeys?.dilithium?.publicKeyBase64,
                    x25519PublicKey: accountKeys?.x25519?.publicKeyBase64
                });
                if (
                    cachedBundle &&
                    cachedBundle.cacheKey === bundleCacheKey &&
                    cachedBundle.expiresAt > now
                ) {
                    bundle = cachedBundle.bundle;


                } else {

                    try {
                        const staticKyberPublic = accountKeys?.kyber?.publicKeyBase64;
                        if (!staticKyberPublic) {
                            throw new Error('Static account ML-KEM key unavailable');
                        }
                        if (!isCurrentOwner()) return false;
                        bundle = await signal.createPreKeyBundle(bundleUsername);
                        if (!isCurrentOwner()) return false;
                    } catch (error) {

                        throw error;
                    }

                    if (bundle) {
                        cachedBundleRef.current = {
                            cacheKey: bundleCacheKey,
                            bundle,
                            expiresAt: now + PREKEY_BUNDLE_CACHE_TTL_MS
                        };
                    }

                }
                if (!bundle) {

                    return fail('bundle-create-failed');
                }

                const kyberKey = accountKeys?.kyber?.publicKeyBase64;
                const dilithiumKey = accountKeys?.dilithium?.publicKeyBase64;
                const x25519Key = accountKeys?.x25519?.publicKeyBase64;
                const accountRootKey = accountKeys?.accountRoot?.publicKeyBase64;

                if (!kyberKey || !dilithiumKey || !x25519Key || !accountRootKey) {
                    return fail('missing-certified-identity-keys');
                }



                const peerCertificate = await buildSelfPeerCertificate(
                    String(bundleUsername),
                    accountKeys
                );
                if (!isCurrentOwner()) return false;

                if (!peerCertificate) return fail('peer-certificate-create-failed');

                const peerCertificateFingerprint = computePeerCertificateFingerprint(peerCertificate);

                const certifiedPeerBundle = await buildCertifiedPeerBundleV3({
                    username: String(bundleUsername),
                    publicKeys: {
                        kyberPublicBase64: kyberKey,
                        dilithiumPublicBase64: dilithiumKey,
                        x25519PublicBase64: x25519Key
                    },
                    fullBundle: bundle,
                    peerCertificate,
                    peerCertificateFingerprint,
                    accountRootPublicKey: accountRootKey,
                    signAccountRoot: (canonicalPayload) =>
                        account.sign(PROTOCOL_KEYS.ACCOUNT_ROOT_CERTIFICATE_SIGNING, canonicalPayload),
                    signDevice: (canonicalPayload) =>
                        account.sign(PROTOCOL_KEYS.DEVICE_CERTIFICATE_SIGNING, canonicalPayload),
                });
                if (!isCurrentOwner()) return false;


                publishedAvatarStateVersion = avatarStateVersionRef.current;
                const avatar = await getAvatarForDiscovery();
                if (!isCurrentOwner()) return false;
                void validateAvatarCoverBlobs();
                const avatarRef = avatar ? await publishAvatarToStore(avatar) : null;
                if (!isCurrentOwner()) return false;
                const publishOwner = String(accountHandle ?? '').trim().toLowerCase();
                
                const cachedKeyTransparencyTransition = publishOwner
                    ? await keyTransparencyClient.getPublishedTransition(publishOwner).catch(() => null)
                    : null;
                if (!isCurrentOwner()) return false;
                const spoolDetectionKey = await ownDetectionPublicKeyHex(publishOwner).catch(() => null);
                if (!isCurrentOwner()) return false;
                const preflightPublishInputFingerprint = cachedKeyTransparencyTransition
                    ? hashDiscoveryMaterial({
                        bundleUsername,
                        fullBundle: bundle,
                        kyberPublicKey: kyberKey,
                        dilithiumPublicKey: dilithiumKey,
                        x25519PublicKey: x25519Key,
                        accountRootPublicKey: accountRootKey,
                        peerCertificateFingerprint,
                        avatarRef: avatarRef ?? null,
                        keyTransparencyTransition: cachedKeyTransparencyTransition,
                        spoolDetectionKey: spoolDetectionKey ?? null,
                    })
                    : null;



                // Build publish token set
                const oprfState = await waitForOprfState('publish-missing-epoch');
                if (!isCurrentOwner()) return false;
                if (!oprfState || oprfState.epoch === undefined) {

                    return fail('missing-oprf-epoch');
                }
                const { epoch, publicKey } = oprfState;
                const publicationWindow = Math.floor(
                    epoch / (DISCOVERY_FORWARD_PUBLISH_EPOCHS + 1)
                );

                const preflightContextFingerprint = preflightPublishInputFingerprint
                    ? `${publicKey || 'no-key'}:${publicationWindow}:${preflightPublishInputFingerprint}`
                    : null;
                    
                if (
                    preflightContextFingerprint !== null &&
                    lastPublishedContextFingerprintRef.current === preflightContextFingerprint &&
                    lastPublishedRef.current > 0 &&
                    !lastPublishFailureRef.current
                ) {
                    lastPublishedAvatarStateVersionRef.current = publishedAvatarStateVersion;
                    return true;
                }
                const publishEpochs: number[] = [epoch];
                for (let i = 1; i <= DISCOVERY_FORWARD_PUBLISH_EPOCHS; i += 1) {
                    publishEpochs.push(epoch + i);
                }

                const uniqueEpochs = Array.from(new Set(publishEpochs));

                const normalizedPublishHandle = getDiscoveryHandle(accountHandle);
                if (!normalizedPublishHandle) {

                    return fail('oprf-token-missing');
                }
                const missingEpochs: number[] = [];
                const publishCacheScope = scopedDiscoveryCacheKey(
                    publicKey,
                    operationOwnerScope!,
                    normalizedPublishHandle
                );

                for (const publishEpoch of uniqueEpochs) {
                    const cacheKey = `${publishCacheScope}:${publishEpoch}`;
                    if (!discoveryTokenCache.has(cacheKey)) {
                        missingEpochs.push(publishEpoch);
                        continue;
                    }
                    const cached = await readDiscoveryTokenCacheEntry(cacheKey);
                    if (!isCurrentOwner()) {
                        cached?.encryptionKey.fill(0);
                        return false;
                    }
                    if (!cached) {
                        missingEpochs.push(publishEpoch);
                        continue;
                    }
                    epochTokenResults.push({
                        epoch: publishEpoch,
                        token: cached.token,
                        encryptionKey: cached.encryptionKey
                    });
                }


                if (missingEpochs.length > 0) {

                    const evaluation = await evaluateHandleWithOprf(normalizedPublishHandle);
                    if (!isCurrentOwner()) {
                        wipeOprfBlindResult(evaluation?.blindResult);
                        return false;
                    }
                    if (!evaluation) {

                        return fail('oprf-token-missing');
                    }

                    const derived = oprfDiscoveryClient.finalizeTokenBatch(
                        normalizedPublishHandle,
                        evaluation.blindResult,
                        evaluation.response,
                        missingEpochs
                    );
                    try {
                        for (const derivedToken of derived.tokens) {
                            if (!isCurrentOwner()) return false;
                            const resultKey = derived.encryptionKey.slice();
                            epochTokenResults.push({
                                epoch: derivedToken.epoch,
                                token: derivedToken.token,
                                encryptionKey: resultKey
                            });

                            const cacheKey = `${publishCacheScope}:${derivedToken.epoch}`;
                            const cachedPromise = Promise.resolve({
                                token: derivedToken.token,
                                encryptionKey: resultKey.slice()
                            });
                            const cacheEntry = setDiscoveryTokenCacheEntry(cacheKey, cachedPromise);
                            scheduleDiscoveryTokenCacheExpiry(cacheKey, cacheEntry);
                        }
                    } finally {
                        derived.encryptionKey.fill(0);
                    }

                }

                if (epochTokenResults.length === 0) {

                    return fail('oprf-token-missing');
                }
                const currentResult = epochTokenResults.find((entry) => entry.epoch === epoch);
                if (!currentResult) {

                    return fail('oprf-token-missing');
                }

                const transparencyStatus = await keyTransparencyClient.validateOwnIdentity({
                    ownerUsername: String(accountHandle).trim().toLowerCase(),
                    discoveryEncryptionKey: currentResult.encryptionKey,
                    accountRoot: {
                        publicKeyBase64: accountRootKey,
                        sign: (payload) => account.sign(PROTOCOL_KEYS.KEY_TRANSPARENCY_SIGNING, payload),
                    },
                    recovery: {
                        publicKeyBase64: (await account.publicKeys()).recoveryPublicBase64,
                        sign: (payload) => account.sign(PROTOCOL_KEYS.KEY_TRANSPARENCY_RECOVERY_SIGNING, payload),
                    },
                });
                if (!isCurrentOwner()) return false;
                if (transparencyStatus.status !== 'ready') {
                    return fail('key-transparency-recovery-pending');
                }

                const keyTransparencyTransition = await keyTransparencyClient
                    .getPublishedTransition(publishOwner)
                    .catch(() => null);
                if (!isCurrentOwner()) return false;
                if (!keyTransparencyTransition) {
                    return fail('missing-key-transparency-transition');
                }

                const material: OPRFDiscoveryBlob = {
                    fullBundle: bundle,
                    certifiedPeerBundle,
                    ...(spoolDetectionKey ? { spoolDetectionKey } : {}),
                    ...(avatarRef ? { avatarRef } : {}),
                    keyTransparencyTransition:
                        keyTransparencyTransition as OPRFDiscoveryBlob['keyTransparencyTransition'],
                };

                const publishInputFingerprint = hashDiscoveryMaterial({
                    bundleUsername,
                    fullBundle: bundle,
                    kyberPublicKey: kyberKey,
                    dilithiumPublicKey: dilithiumKey,
                    x25519PublicKey: x25519Key,
                    accountRootPublicKey: accountRootKey,
                    peerCertificateFingerprint,
                    avatarRef: avatarRef ?? null,
                    keyTransparencyTransition,
                    spoolDetectionKey: spoolDetectionKey ?? null,
                });
                const contextFingerprint = `${publicKey || 'no-key'}:${publicationWindow}:${publishInputFingerprint}`;

                if (
                    lastPublishedContextFingerprintRef.current === contextFingerprint &&
                    lastPublishedRef.current > 0 &&
                    !lastPublishFailureRef.current
                ) {
                    lastPublishedAvatarStateVersionRef.current = publishedAvatarStateVersion;
                    return true;
                }

                const tokenBatch = Array.from(new Set(epochTokenResults.map((entry) => entry.token)));
                const publication = await buildDiscoveryPublication(
                    tokenBatch,
                    publicationWindow,
                    publicKey
                );
                if (!isCurrentOwner()) return false;
                if (!publication) {

                    return fail('discovery-manifest-not-ready');
                }
                const publishFingerprint = `${publication.publishId}:${publishInputFingerprint}`;
                if (lastPublishedFingerprintRef.current === publishFingerprint) {
                    lastPublishedAvatarStateVersionRef.current = publishedAvatarStateVersion;
                    return true;
                }
                const encryptedBlob = oprfDiscoveryClient.encryptDiscoveryBlob(material, currentResult.encryptionKey);
                const publishWork = await createAnonymousHttpPow(
                    PROTOCOL_KEYS.DISCOVERY_PUBLISH_POW,
                    publication.epochId,
                    [
                        publication.publishId,
                        ...publication.bucketIds.map(String),
                        encryptedBlob
                    ],
                    DISCOVERY_PUBLISH_POW_DIFFICULTY
                );
                if (!isCurrentOwner()) return false;
                const publishRequestId = `pub-${crypto.randomUUID()}`;
                const ackSuccess = await new Promise<boolean>((resolve) => {
                    let settled = false;
                    const cleanup = () => {
                        if (settled) return;
                        settled = true;
                        window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, ackHandler as EventListener);
                        if (timeoutId) clearTimeout(timeoutId);
                    };

	                    const ackHandler = (ev: Event) => {
	                        if (!isCurrentOwner()) {
	                            cleanup();
	                            resolve(false);
	                            return;
	                        }
	                        const detail = (ev as CustomEvent).detail;
	                        const requestMatches = detail?.requestId === publishRequestId;
	                        const isExactSuccess =
	                            detail &&
	                            typeof detail === 'object' &&
	                            !Array.isArray(detail) &&
	                            Object.getPrototypeOf(detail) === Object.prototype &&
	                            Object.keys(detail).sort().join(',') === 'op,requestId,success,type' &&
	                            detail.type === SignalType.OK &&
	                            requestMatches &&
	                            detail.op === 'publish-discovery' &&
	                            detail.success === true;
	                        const isExactFailure =
	                            detail &&
	                            typeof detail === 'object' &&
	                            !Array.isArray(detail) &&
	                            Object.getPrototypeOf(detail) === Object.prototype &&
	                            Object.keys(detail).sort().join(',') === 'error,op,requestId,success,type' &&
	                            detail.type === SignalType.OK &&
	                            requestMatches &&
	                            detail.op === 'publish-discovery' &&
	                            detail.success === false &&
	                            typeof detail.error === 'string' &&
	                            /^[a-z0-9_]{1,64}$/.test(detail.error);
	                        if (isExactSuccess || isExactFailure) {
	                            cleanup();
	                            resolve(isExactSuccess);
	                            return;
	                        }
	                        if (
	                            requestMatches &&
	                            (detail?.type === SignalType.OK || detail?.type === SignalType.ERROR)
	                        ) {

	                        }
	                    };

                    const timeoutId = window.setTimeout(() => {
                        cleanup();
                        resolve(false);
                    }, PUBLISH_ACK_TIMEOUT_MS);

                    window.addEventListener(EventType.SECURE_SERVER_MESSAGE, ackHandler as EventListener);


                    if (!isCurrentOwner()) {
                        cleanup();
                        resolve(false);
                        return;
                    }

                    void sendSecureDiscoveryMessage(
                        {
                            type: SignalType.PUBLISH_DISCOVERY,
                            requestId: publishRequestId,
                            publication,
                            encryptedBlob,
                            ...publishWork
                        },
                        'publish-discovery',
                        PUBLISH_ACK_TIMEOUT_MS + 6000
                    ).then((sent) => {
                        if (!isCurrentOwner() || !sent) {
                            cleanup();
                            resolve(false);
                        }
                    }).catch(() => {
                        cleanup();
                        resolve(false);
                    });
                });
                if (!isCurrentOwner()) return false;

                if (!ackSuccess) {

                    return fail('publish-ack-failed');
                }

                lastPublishedRef.current = Date.now();
                lastPublishedContextFingerprintRef.current = contextFingerprint;
                lastPublishedFingerprintRef.current = publishFingerprint;
                lastPublishedAvatarStateVersionRef.current = publishedAvatarStateVersion;
                lastPublishFailureRef.current = null;
                return true;
            } catch (err) {
                const reason = err instanceof Error ? err.message : String(err);

                return fail(reason || 'publish-error');
            } finally {
                for (const result of epochTokenResults) result.encryptionKey.fill(0);
                if (
                    isCurrentOwner() &&
                    publishPromiseRef.current === publishPromise
                ) {
                    publishingRef.current = false;
                }

            }
        })();

        publishPromiseRef.current = publishPromise;

        try {
            const result = await publishPromise;

            return isCurrentOwner() && result;
        } finally {
            if (publishPromiseRef.current === publishPromise) {
                publishPromiseRef.current = null;
                publishingRef.current = false;

            }
            wipeDiscoveryHybridKeys(accountKeys);
            accountKeys = null;
        }
    }, [effectiveHandle, getDiscoveryHandle, evaluateHandleWithOprf, accountUsername, hybridKeysRef, getAvatarForDiscovery, sendSecureDiscoveryMessage, waitForOprfState, isDiscoveryTransportReady, ownerScope]);

    const publishSelf = useCallback(async (
        force = false,
        bypassAttemptDelay = false,
        trigger = 'unspecified'
    ): Promise<boolean> => {
        const triggerId = crypto.randomUUID();
        const startedAt = performance.now();
        let success = false;
        let error: string | undefined;
        console.log('[DISCOVERY] publish triggered', {
            triggerId,
            trigger,
            force,
            bypassAttemptDelay,
        });
        try {
            success = await runPublishSelf(force, bypassAttemptDelay);
            return success;
        } catch (caught) {
            error = caught instanceof Error ? caught.message : String(caught);
            return false;
        } finally {
            console.log('[DISCOVERY] publish result', {
                triggerId,
                trigger,
                success,
                durationMs: Math.round(performance.now() - startedAt),
                error: success ? undefined : error || lastPublishFailureRef.current || 'not-completed',
            });
        }
    }, [runPublishSelf]);

    const sendCoverPublication = useCallback(async (): Promise<boolean> => {
        const operationOwnerScope = ownerScope;
        const operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch)
        );

        if (!isCurrentOwner() || !effectiveHandle) {

            return false;
        }
        if (!isDiscoveryTransportReady()) {

            return false;
        }
        if (publishingRef.current) {

            return false;
        }
        if (Date.now() - lastPublishAttemptRef.current < 60_000) {

            return false;
        }

        const oprfEpoch = oprfStateRef.current.epoch;
        if (!Number.isSafeInteger(oprfEpoch) || (oprfEpoch as number) < 0) return false;
        const publicationWindow = Math.floor(
            (oprfEpoch as number) / (DISCOVERY_FORWARD_PUBLISH_EPOCHS + 1)
        );
        let coverState = coverPublicationStateRef.current;
        if (!coverState || coverState.publicationWindow !== publicationWindow) {
            coverState?.publishKey.fill(0);
            coverState = {
                publicationWindow,
                publishKey: randomBytesForDiscovery(32)
            };
            coverPublicationStateRef.current = coverState;
        }

        // Decoy publish
        const coverPublication = await buildDiscoveryPublication(
            [],
            coverState.publicationWindow,
            String(oprfStateRef.current.publicKey || ''),
            coverState.publishKey,
        );
        if (!isCurrentOwner() || !coverPublication) {

            return false;
        }

        const encryptedBlob = randomDiscoveryCoverBlob();
        const publishWork = await createAnonymousHttpPow(
            PROTOCOL_KEYS.DISCOVERY_PUBLISH_POW,
            coverPublication.epochId,
            [
                coverPublication.publishId,
                ...coverPublication.bucketIds.map(String),
                encryptedBlob
            ],
            DISCOVERY_PUBLISH_POW_DIFFICULTY
        );
        if (!isCurrentOwner()) return false;
        const sent = await sendSecureDiscoveryMessage(
            {
                type: SignalType.PUBLISH_DISCOVERY,
                requestId: `pub-${crypto.randomUUID()}`,
                publication: coverPublication,
                encryptedBlob,
                ...publishWork
            },
            'cover-publish-discovery',
            PUBLISH_ACK_TIMEOUT_MS + 6000
        );

        return isCurrentOwner() && sent;
    }, [effectiveHandle, sendSecureDiscoveryMessage, isDiscoveryTransportReady, ownerScope]);

    // Capture OPRF public key and epoch info from server
    useEffect(() => {

        const runWhenDiscoveryTransportReady = (onReady: () => void) => {
            const ready = isDiscoveryTransportReady();
            if (ready) onReady();
        };

        const lifecyclePublishReasons = new Set<string>();
        let lifecycleStopped = false;

        const requestLifecyclePublish = (reason: string, delayMs = LIFECYCLE_PUBLISH_COALESCE_MS) => {
            if (lifecycleStopped) return;
            lifecyclePublishReasons.add(reason);
            if (lifecyclePublishTimerRef.current !== null) return;
            lifecyclePublishTimerRef.current = window.setTimeout(async () => {
                lifecyclePublishTimerRef.current = null;
                if (lifecycleStopped || activeOwnerScopeRef.current !== ownerScope) return;
                const triggerReasons = Array.from(lifecyclePublishReasons).sort();
                lifecyclePublishReasons.clear();
                const success = await publishSelf(
                    true,
                    false,
                    `lifecycle:${triggerReasons.join('+') || 'unspecified'}`
                );
                if (
                    !success &&
                    !lifecycleStopped &&
                    activeOwnerScopeRef.current === ownerScope &&
                    isDiscoveryTransportReady()
                ) {
                    const failure = lastPublishFailureRef.current || 'unknown';
                    requestLifecyclePublish(
                        `retry:${failure}`,
                        publishRetryDelayMs(failure, isPreReadyPublishFailure(failure))
                    );
                }
            }, delayMs);
        };

        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === '__ws_connection_closed' || detail?.type === '__ws_connection_error' || detail?.type === '__ws_connection_opened') {

                oprfStateRef.current = {};
                if (oprfEpochRefreshTimeoutRef.current !== null) {
                    clearTimeout(oprfEpochRefreshTimeoutRef.current);
                    oprfEpochRefreshTimeoutRef.current = null;
                }
                noteDiscoveryTransportReadinessChanged(detail?.type || ev.type);
                return;
            }
            if (detail?.type === SignalType.OPRF_DISCOVERY_PUBLIC_KEY) {
                if (ev.type !== EventType.SECURE_SERVER_MESSAGE) return;
                const state = parseDiscoveryOprfState(detail);
                if (state) {
                    const { publicKey, epoch, epochRotatesAt, powDifficulty } = state;
                    const publicationWindow = Math.floor(
                        epoch / (DISCOVERY_FORWARD_PUBLISH_EPOCHS + 1)
                    );
                    const publicationContextChanged =
                        lastOprfPublicKeyRef.current !== publicKey ||
                        lastOprfPublicationWindowRef.current !== publicationWindow;
                    if (lastOprfPublicKeyRef.current && lastOprfPublicKeyRef.current !== publicKey) {
                        clearDiscoveryLookupCaches();

                    }
                    lastOprfPublicKeyRef.current = publicKey;
                    lastOprfPublicationWindowRef.current = publicationWindow;
                    oprfStateRef.current = { publicKey, epoch, epochRotatesAt, powDifficulty };
                    oprfDiscoveryClient.setServerPublicKey(publicKey);
                    pruneDiscoveryTokenCache(epoch);
                    if (oprfEpochRefreshTimeoutRef.current !== null) {
                        clearTimeout(oprfEpochRefreshTimeoutRef.current);
                    }
                    const refreshDelay = Math.max(
                        OPRF_EPOCH_REFRESH_DELAY_MS,
                        epochRotatesAt - Date.now() + OPRF_EPOCH_REFRESH_DELAY_MS
                    );
                    oprfEpochRefreshTimeoutRef.current = window.setTimeout(() => {
                        oprfEpochRefreshTimeoutRef.current = null;
                        if (activeOwnerScopeRef.current !== ownerScope) return;
                        oprfStateRef.current = {};
                        requestOprfKey('epoch-rotation', true);
                    }, refreshDelay);
                    if (publicationContextChanged && isDiscoveryTransportReady()) {
                        requestLifecyclePublish('oprf-context-changed');
                    }
                } else {

                }
            }
        };

        const onUnlinkedReady = () => {
            noteDiscoveryTransportReadinessChanged('unlinked-ready');
            runWhenDiscoveryTransportReady(() => {
                requestOprfKey('unlinked-ready');
                requestLifecyclePublish('unlinked-ready');
            });
        };
        const onHybridKeys = () => {
            cachedBundleRef.current = null;
            runWhenDiscoveryTransportReady(() => {
                requestLifecyclePublish('hybrid-keys');
            });
        };

        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.UNLINKED_SESSION_READY, onUnlinkedReady as EventListener);
        window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onHybridKeys as EventListener);

        const certificateRenewalInterval = window.setInterval(() => {
            const certificate = cachedPeerCertificateRef.current?.certificate;
            if (
                certificate &&
                certificate.expiresAt - Date.now() <= P2P_PEER_CERT_PUBLISH_REFRESH_LEAD_MS &&
                isDiscoveryTransportReady()
            ) {
                requestLifecyclePublish('peer-certificate-renewal');
            }
        }, P2P_PEER_TRUST_REFRESH_INTERVAL_MS);

        if (isDiscoveryTransportReady()) {
            requestOprfKey('initial-ready');
            requestLifecyclePublish('initial-ready');
        }

        return () => {
            lifecycleStopped = true;
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.UNLINKED_SESSION_READY, onUnlinkedReady as EventListener);
            window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onHybridKeys as EventListener);
            window.clearInterval(certificateRenewalInterval);
            if (lifecyclePublishTimerRef.current !== null) {
                clearTimeout(lifecyclePublishTimerRef.current);
                lifecyclePublishTimerRef.current = null;
            }
            lifecyclePublishReasons.clear();

        };
    }, [requestOprfKey, publishSelf, pruneDiscoveryTokenCache, isDiscoveryTransportReady, noteDiscoveryTransportReadinessChanged, ownerScope]);

    const scheduleAvatarPublish = useCallback((reason: string) => {

        if (!effectiveHandle) {

            return;
        }
        if (!isDiscoveryTransportReady()) {

            return;
        }
        if (lastPublishedAvatarStateVersionRef.current === avatarStateVersionRef.current) {
            return;
        }
        if (pendingAvatarPublishRef.current) {

            return;
        }
        pendingAvatarPublishRef.current = true;

        const jitterMs = 5000 + Math.floor(secureRandomUnit() * 25000);


        const runScheduledPublish = async (): Promise<void> => {
            pendingAvatarPublishRef.current = false;
            avatarPublishTimeoutRef.current = null;

            let success = false;
            for (let handoff = 0; handoff < 2; handoff += 1) {
                const targetVersion = avatarStateVersionRef.current;
                success = await publishSelf(true, true, `profile:${reason}`);
                if (activeOwnerScopeRef.current !== ownerScope) return;
                if (
                    success &&
                    targetVersion === avatarStateVersionRef.current &&
                    lastPublishedAvatarStateVersionRef.current === targetVersion
                ) return;
                if (!success) break;
            }

            if (
                activeOwnerScopeRef.current === ownerScope &&
                lastPublishedAvatarStateVersionRef.current !== avatarStateVersionRef.current &&
                !pendingAvatarPublishRef.current
            ) {
                const reason = lastPublishFailureRef.current || 'unknown';
                const retryDelay = publishRetryDelayMs(reason, isPreReadyPublishFailure(reason));
                pendingAvatarPublishRef.current = true;
                avatarPublishTimeoutRef.current = window.setTimeout(() => {
                    void runScheduledPublish();
                }, retryDelay);
            }
        };

        avatarPublishTimeoutRef.current = window.setTimeout(() => {
            void runScheduledPublish();
        }, jitterMs);
    }, [effectiveHandle, publishSelf, isDiscoveryTransportReady, ownerScope]);

    useEffect(() => {
        if (!effectiveHandle) {

            return;
        }
        if (!isDiscoveryTransportReady()) {

            return;
        }

        let stopped = false;
        let timeoutId: number | null = null;
        const scheduleNext = (delayMs: number) => {
            if (stopped) return;

            timeoutId = window.setTimeout(async () => {
                timeoutId = null;
                if (!stopped) {

                    await sendCoverPublication().catch(() => false);

                    scheduleNext(DISCOVERY_COVER_PUBLISH_INTERVAL_MS);
                }
            }, delayMs);
        };

        const initialDelay = DISCOVERY_COVER_PUBLISH_INITIAL_MIN_MS
            + Math.floor(secureRandomUnit() * DISCOVERY_COVER_PUBLISH_INITIAL_JITTER_MS);

        scheduleNext(initialDelay);

        return () => {
            stopped = true;
            if (timeoutId !== null) window.clearTimeout(timeoutId);

        };
    }, [effectiveHandle, sendCoverPublication, isDiscoveryTransportReady, discoveryTransportReadyVersion]);

    useEffect(() => {
        if (!effectiveHandle) {

            return;
        }


        const handler = (ev: Event) => {
            try {
                if (ev.type === EventType.PROFILE_PICTURE_UPDATED) {
                    const detail = (ev as CustomEvent).detail;

                    if (detail?.type === 'own') {
                        avatarStateVersionRef.current += 1;
                        scheduleAvatarPublish('profile-picture-updated');
                    }
                }
            } catch { }
        };

        window.addEventListener(EventType.PROFILE_PICTURE_UPDATED, handler as EventListener);

        return () => {
            window.removeEventListener(EventType.PROFILE_PICTURE_UPDATED, handler as EventListener);
            if (avatarPublishTimeoutRef.current) {
                clearTimeout(avatarPublishTimeoutRef.current);
            }
            avatarPublishTimeoutRef.current = null;
            pendingAvatarPublishRef.current = false;

        };
    }, [effectiveHandle, scheduleAvatarPublish]);


    // Find a user by handle using OPRF-derived tokens
    const findUser = useCallback(async (
        targetHandle: string,
        options?: { forceRefresh?: boolean; monitorContact?: boolean }
    ): Promise<OPRFDiscoveryMaterial | null> => {
        const operationOwnerScope = ownerScope;
        let operationConnectionEpoch: number | null = null;
        let networkEpochCaptured = false;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            (!networkEpochCaptured || (
                operationConnectionEpoch !== null &&
                websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch)
            ))
        );
        if (!isCurrentOwner()) return null;
        const forceRefresh = !!options?.forceRefresh;
        if (!shouldAttemptDiscovery(targetHandle)) {
            return null;
        }
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) {
            console.warn('[DISCOVERY] findUser: could not normalize handle', { target: targetHandle });
            return null;
        }
        if (!forceRefresh && effectiveHandle) {
            await keyTransparencyClient.restorePersistedAuthorizations(effectiveHandle).catch(() => 0);
            if (!isCurrentOwner()) return null;
            const persisted = await loadTrustedPersistedDiscoveryMaterial(
                effectiveHandle,
                targetHandle.trim().toLowerCase()
            );
            if (!isCurrentOwner()) return null;
            if (persisted) return persisted as OPRFDiscoveryMaterial;
        }
        operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        networkEpochCaptured = true;
        if (!isCurrentOwner()) return null;
        if (!isDiscoveryTransportReady()) {
            console.warn('[DISCOVERY] findUser: transport not ready', { target: targetHandle });
            return null;
        }
        const scopeState = await waitForOprfState('lookup-cache-scope');
        if (!isCurrentOwner()) return null;
        if (!scopeState?.publicKey || !/^[a-f0-9]{64}$/i.test(scopeState.publicKey)) {
            return null;
        }
        const lookupCacheKey = scopedDiscoveryCacheKey(
            scopeState.publicKey,
            operationOwnerScope!,
            normalizedHandle
        );

        if (!forceRefresh) {
            const cachedEntry = discoveryResultCache.get(lookupCacheKey);
            if (cachedEntry) {
                if (cachedEntry.expiresAt > Date.now()) {
                    return cachedEntry.value;
                }

                discoveryResultCache.delete(lookupCacheKey);
            }
            if (findUserCache.has(lookupCacheKey)) {

                return findUserCache.get(lookupCacheKey)!;
            }
        } else {
            const lastFetchAt = discoveryNetworkFetchAt.get(lookupCacheKey) || 0;
            const sinceFetch = Date.now() - lastFetchAt;
            const cachedEntry = discoveryResultCache.get(lookupCacheKey);
            if (
                lastFetchAt > 0 &&
                sinceFetch < FORCED_REFETCH_MIN_INTERVAL_MS &&
                cachedEntry &&
                cachedEntry.expiresAt > Date.now() &&
                cachedEntry.value
            ) {
                return cachedEntry.value;
            }
        }

        const activeLookup = findUserInFlightLock.get(lookupCacheKey);
        if (activeLookup) {
            return activeLookup;
        }

        if (forceRefresh) {
            const existingForce = forceRefreshFindUserCache.get(lookupCacheKey);
            if (existingForce) {

                return existingForce;
            }

            if (findUserCache.has(lookupCacheKey)) {

                return findUserCache.get(lookupCacheKey)!;
            }
        }

        if (findUserInFlightLock.size >= DISCOVERY_LOOKUP_MAX_IN_FLIGHT) {
            return null;
        }

        console.log('[DISCOVERY] findUser: network lookup started', {
            target: targetHandle,
            forceRefresh,
        });
        let promise!: Promise<OPRFDiscoveryMaterial | null>;
        const rawLookup = (async () => {
            let epochResults: Map<number, { token: string; encryptionKey: Uint8Array }> | null = null;
            try {
                const oprfState = await waitForOprfState('find-missing-epoch');
                if (!oprfState || oprfState.epoch === undefined) {
                    console.warn('[DISCOVERY] findUser: no oprf epoch available', { target: targetHandle });
                    return null;
                }
                const { epoch } = oprfState;


                const lookupEpochs = [epoch];
                epochResults = await getDiscoveryTokensForEpochs(normalizedHandle, lookupEpochs);
                if (!isCurrentOwner()) return null;
                if (!epochResults || !epochResults.get(epoch)) {
                    if (epochResults) {
                        for (const result of epochResults.values()) result.encryptionKey.fill(0);
                    }
                    await new Promise((resolve) => setTimeout(resolve, 500));
                    if (!isCurrentOwner()) return null;
                    epochResults = await getDiscoveryTokensForEpochs(normalizedHandle, lookupEpochs);
                    if (!isCurrentOwner()) return null;
                }
                const currentResult = epochResults?.get(epoch) || null;

                if (!currentResult) {
                    return null;
                }
                
                const lookupBucketDbg = await deriveDiscoveryBucketId(
                    await deriveDiscoveryBucketKey(currentResult.token),
                    DISCOVERY_FIXED_BUCKET_COUNT
                );

                const encryptionKeys = [currentResult.encryptionKey];

                const bucketTokens = [currentResult.token];
                let bucketLookupFailed = false;

                const runBucketLookup = async (): Promise<OPRFDiscoveryMaterial | null> => {
                    try {
                        const bucketResponse = await findDiscoveryBlobsInBuckets(bucketTokens);
                        if (!isCurrentOwner()) return null;
                        if (bucketResponse && bucketResponse.blobs.length > 0) {
                            const bucketResult = await finalizeDiscoverySnapshotResult(
                                lookupCacheKey,
                                targetHandle,
                                bucketResponse.blobs,
                                encryptionKeys,
                                false,
                                options?.monitorContact !== false
                            );
                            if (!isCurrentOwner()) return null;
                            if (bucketResult) {
                                noteDiscoveryNetworkFetch(lookupCacheKey);
                                console.log('[DISCOVERY] findUser: FOUND', { target: targetHandle });
                                return bucketResult;
                            }
                        }
                    } catch (e) {
                        console.warn('[DISCOVERY] findUser: bucket lookup threw', { target: targetHandle, error: e instanceof Error ? e.message : String(e) });
                        bucketLookupFailed = true;
                    }
                    return null;
                };

                const bucketResult = await runBucketLookup();
                if (bucketResult) {
                    return bucketResult;
                }
                if (bucketLookupFailed) {
                    return null;
                }
                if (!isCurrentOwner()) return null;
                
                const existingFound = discoveryResultCache.get(lookupCacheKey);
                if (!(existingFound && existingFound.value && existingFound.expiresAt > Date.now())) {
                    setDiscoveryResultCache(discoveryResultCache, lookupCacheKey, {
                        value: null,
                        expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                    });
                }
                return null;
            } catch {
                return null;
            } finally {
                if (epochResults) {
                    for (const result of epochResults.values()) result.encryptionKey.fill(0);
                }
                if (findUserInFlightLock.get(lookupCacheKey) === promise) {
                    findUserInFlightLock.delete(lookupCacheKey);
                }
                if (forceRefresh) {
                    if (forceRefreshFindUserCache.get(lookupCacheKey) === promise) {
                        forceRefreshFindUserCache.delete(lookupCacheKey);
                    }
                } else {
                    if (findUserCache.get(lookupCacheKey) === promise) {
                        findUserCache.delete(lookupCacheKey);
                    }
                }
            }
        })();

        promise = (async () => {
            let timer: ReturnType<typeof setTimeout> | undefined;
            try {
                return await Promise.race([
                    rawLookup,
                    new Promise<OPRFDiscoveryMaterial | null>((resolve) => {
                        timer = setTimeout(() => {
                            console.warn('[DISCOVERY] findUser: HARD TIMEOUT, abandoning lookup', {
                                target: targetHandle,
                                ms: FIND_USER_HARD_TIMEOUT_MS,
                            });
                            
                            if (findUserInFlightLock.get(lookupCacheKey) === promise) {
                                findUserInFlightLock.delete(lookupCacheKey);
                            }
                            resolve(null);
                        }, FIND_USER_HARD_TIMEOUT_MS);
                    }),
                ]);
            } finally {
                if (timer !== undefined) clearTimeout(timer);
            }
        })();

        findUserInFlightLock.set(lookupCacheKey, promise);
        if (forceRefresh) {
            forceRefreshFindUserCache.set(lookupCacheKey, promise);
        } else {
            findUserCache.set(lookupCacheKey, promise);
        }
        return promise;
    }, [getDiscoveryTokensForEpochs, getDiscoveryHandle, waitForOprfState, findDiscoveryBlobsInBuckets, finalizeDiscoverySnapshotResult, isDiscoveryTransportReady, ownerScope, effectiveHandle]);

    return {
        findUser
    };
};
