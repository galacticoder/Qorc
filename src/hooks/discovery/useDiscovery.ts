/**
 * OPRF peer discovery hook
 */

import { PostQuantumRandom } from '../../lib/cryptography/random';
import { sleep } from '../../lib/runtime/sleep';
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
    buildCertifiedPeerBundle,
    validateCertifiedPeerBundle
} from '@/lib/utils/certified-identity-utils';
import type { AvatarData } from '@/lib/types/avatar-types';
import { publishAvatarToStore, fetchAvatarFromStore, validateAvatarCoverBlobs as validateAvatarCoverBlobs } from '@/lib/avatar/avatar-store-client';
import { isValidAvatarRef } from '@/lib/avatar/avatar-ref';
import type { AvatarRef } from '@/lib/crypto/avatar-blob-crypto';
import type { HybridKeys } from '@/lib/types/auth-types';
import type { PeerCertificateBundle } from '@/lib/types/p2p-types';
import {
  AUTH_USERNAME_REGEX,
  AVATAR_FETCH_MAX_IN_FLIGHT,
  AVATAR_FETCH_RETRY_DELAYS_MS,
  DISCOVERY_COVER_PUBLISH_INITIAL_JITTER_MS,
  DISCOVERY_COVER_PUBLISH_INITIAL_MIN_MS,
  DISCOVERY_COVER_PUBLISH_INTERVAL_MS,
  DISCOVERY_EPOCH_DURATION_MS,
  DISCOVERY_FORCED_REFETCH_MIN_INTERVAL_MS,
  DISCOVERY_FORWARD_PUBLISH_EPOCHS,
  DISCOVERY_LIFECYCLE_PUBLISH_COALESCE_MS,
  DISCOVERY_LOOKUP_MAX_IN_FLIGHT,
  DISCOVERY_NEGATIVE_CACHE_TTL_MS,
  DISCOVERY_POSITIVE_CACHE_TTL_MS,
  DISCOVERY_PUBLISH_POW_DIFFICULTY,
  DISCOVERY_RESULT_CACHE_MAX_ENTRIES,
  DISCOVERY_TIMEOUT_CACHE_TTL_MS,
  DISCOVERY_TOKEN_CACHE_MAX_ENTRIES,
  OPRF_EPOCH_OPERATION_SAFETY_MS,
  OPRF_EPOCH_REFRESH_DELAY_MS,
  P2P_PEER_CERT_PUBLISH_CHECK_INTERVAL_MS,
  P2P_PEER_CERT_PUBLISH_REFRESH_LEAD_MS,
  P2P_PEER_CERT_TTL_MS,
  WS_CONTROL_RESPONSE_TIMEOUT_MS,
  WS_CONTROL_SEND_TIMEOUT_MS,
  OPRF_DISCOVERY_POW_DIFFICULTY,
  PRE_READY_PUBLISH_FAILURES,
  USE_DISCOVERY_COUNTER_LIMIT,
  USE_DISCOVERY_BYTES,
  USE_DISCOVERY_TIMEOUT_MS,
  USE_DISCOVERY_LAST_PUBLISH_ATTEMPT_REF_MINIMUM,
  USE_DISCOVERY_FIND_USER_DELAY_MS,
  OPRF_KEY_REQUEST_COOLDOWN_MS,
} from '@/lib/constants';
import { blake3 } from '@noble/hashes/blake3.js';
import { shouldAttemptDiscovery } from '@/lib/utils/discovery-utils';
import {
    DISCOVERY_PUBLICATION_BUCKET_COUNT,
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
import { isKeyTransparencyVerifiedMaterial } from '@/lib/key-transparency/verified-material';
import { createBoundedMapSetter } from '@/lib/utils/message-state-limits';
import { bytesToHex } from '../../../shared/bytes.js';
import { loadTrustedPersistedDiscoveryMaterial } from '@/lib/utils/signal-bundle-utils';
import {
    ownDetectionPublicKeyHex,
    persistPeerDetectionKey,
} from '../../lib/spool/detection-key';
import { PROTOCOL_KEYS } from '@/lib/config/protocol-keys';
import { OPRF_EVALUATE_AUDIENCE } from '@/lib/config/audiences';
import { DISCOVERY_PUBLICATION_RETRY_TTL_MS } from '../../../shared/discovery-constants.js';
import { DISCOVERY_LOOKUP_TIMEOUT_MS } from '../../../shared/anonymous-transfer-policy.js';
import {
    DiscoveryProgressStream,
    observeDiscoveryProgress,
    trackDiscoveryProgress,
    type DiscoveryLookupOptions,
    type DiscoveryProgressObserver,
} from '@/lib/discovery/progress';
import { parsePublicationAck, requestDiscoveryResponse } from '@/lib/discovery/request';
import {
    canReuseDiscoveryPublication,
    canRetryPreparedPublication,
    type PreparedDiscoveryPublication,
} from '@/lib/discovery/publication-retry';

type DiscoveryTokenMaterial = { token: string; encryptionKey: Uint8Array };

interface DiscoveryTokenCacheEntry {
    value: Promise<DiscoveryTokenMaterial | null>;
    readers: number;
    retired: boolean;
    wipeScheduled: boolean;
    expiryTimer: number | null;
}

const discoveryTokenCache = new Map<string, DiscoveryTokenCacheEntry>();

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
    }, DISCOVERY_PUBLICATION_RETRY_TTL_MS);
}

async function readDiscoveryTokenCacheEntry(key: string): Promise<DiscoveryTokenMaterial | null> {
    const entry = discoveryTokenCache.get(key);
    if (!entry || entry.retired) return null;
    entry.readers += 1;
    try {
        const value = await entry.value;
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

    const manifestResponse = await requestDiscoveryManifest();
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
            if (counter >= USE_DISCOVERY_COUNTER_LIMIT) return null;
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
        powDifficulty !== OPRF_DISCOVERY_POW_DIFFICULTY
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

const avatarFetchInFlight = new Set<string>();
const avatarFetchRetryTimers = new Map<string, ReturnType<typeof setTimeout>>();

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
    if (lastFailure && canRetryPreparedPublication(lastFailure)) return 15_000;
    return isPreReadyPublishFailure(lastFailure) ? 5_000 : 15_000;
}

function publishRetryDelayMs(reason: string, preReadyReason: boolean): number {
    if (reason === 'oprf-token-missing') return 60_000 + Math.floor(PostQuantumRandom.randomUnit(true) * 15_000);
    if (canRetryPreparedPublication(reason)) return 15_000 + Math.floor(PostQuantumRandom.randomUnit(true) * 15_000);
    if (preReadyReason) return 5_000 + Math.floor(PostQuantumRandom.randomUnit(true) * 10_000);
    return 15_000 + Math.floor(PostQuantumRandom.randomUnit(true) * 15_000);
}

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

const randomHexForDiscovery = (bytes = USE_DISCOVERY_BYTES): string => {
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
    const preparedPublicationRef = useRef<PreparedDiscoveryPublication | null>(null);
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
        preparedPublicationRef.current = null;
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
                preparedPublicationRef.current = null;
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

        return websocketClient.isUnlinkedMode() &&
            websocketClient.isUnlinkedSessionReady();
    }, [effectiveHandle]);

    const noteDiscoveryTransportReadinessChanged = useCallback((_reason?: unknown) => {
        const ready = isDiscoveryTransportReady();
        if (lastDiscoveryTransportReadyRef.current === ready) {
            return;
        }
        lastDiscoveryTransportReadyRef.current = ready;
        setDiscoveryTransportReadyVersion((version) => (version + 1) % Number.MAX_SAFE_INTEGER);
    }, [isDiscoveryTransportReady]);

    const waitForOprfState = useCallback(async (
        timeoutMs: number = WS_CONTROL_RESPONSE_TIMEOUT_MS
    ): Promise<DiscoveryOprfState | null> => {
        const operationOwnerScope = ownerScope;
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
        const operationIdentity = websocketClient.captureAnonymousHttpIdentity();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isAnonymousHttpIdentityCurrent(operationIdentity)
        );
        if (!isCurrentOwner()) return null;
        const current = oprfStateRef.current;
        if (
            current.publicKey &&
            current.epoch !== undefined &&
            Number.isSafeInteger(current.epochRotatesAt) &&
            (current.epochRotatesAt as number) > Date.now() + OPRF_EPOCH_OPERATION_SAFETY_MS
        ) {
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
        const operationConnectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
        readyPromise = requestDiscoveryResponse<DiscoveryOprfState>({
            operation: 'oprf',
            registerConnectionCancel: (cancel) => websocketClient.registerConnectionWaiterCancel(cancel),
            events: window,
            signal: operationAbortSignal,
            isCurrent: () => isCurrentOwner() &&
                websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch),
            responseTimeoutMs: timeoutMs,
            send: async (signal) => {
                await websocketClient.sendSecureControlMessage(
                    { type: SignalType.OPRF_DISCOVERY_PUBLIC_KEY },
                    { failIfQueued: true, signal }
                );
            },
            parse: (detail) => parseDiscoveryOprfState(detail) ?? undefined,
        }).catch(() => null).finally(() => {
            if (oprfReadyPromiseRef.current === readyPromise) oprfReadyPromiseRef.current = null;
        });
        if (!isCurrentOwner()) return null;
        oprfReadyPromiseRef.current = readyPromise;
        
        return readyPromise;
    }, [ownerScope]);

    const requestOprfKey = useCallback((force = false) => {
        if (!ownerScope || activeOwnerScopeRef.current !== ownerScope) return;
        const now = Date.now();
        if (!force && now - lastOprfKeyRequestRef.current < OPRF_KEY_REQUEST_COOLDOWN_MS) return;
        if (!isDiscoveryTransportReady()) return;
        lastOprfKeyRequestRef.current = now;
        if (force) oprfStateRef.current = {};
        void waitForOprfState();
    }, [isDiscoveryTransportReady, ownerScope, waitForOprfState]);

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
        timeoutMs: number = USE_DISCOVERY_TIMEOUT_MS,
        abortSignal?: AbortSignal
    ): Promise<boolean> => {
        if (abortSignal?.aborted) return false;
        if (websocketClient.isPQSessionEstablished()) return true;

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
                resolve(websocketClient.isPQSessionEstablished());
            }, timeoutMs);

            window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, handler as EventListener);
            abortSignal?.addEventListener('abort', onAbort, { once: true });
            if (abortSignal?.aborted) onAbort();
        });
    }, []);

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
        if (
            !material ||
            typeof material !== 'object' ||
            Array.isArray(material) ||
            Object.getPrototypeOf(material) !== Object.prototype
        ) {
            return null;
        }

        const certifiedCandidate = material.certifiedPeerBundle as any;
        const deviceCandidate = certifiedCandidate?.deviceCert;
        if (
            !deviceCandidate ||
            typeof deviceCandidate !== 'object' ||
            Array.isArray(deviceCandidate)
        ) return null;
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
            return null;
        }

        const validated: OPRFDiscoveryMaterial = {
            spoolDetectionKey: material.spoolDetectionKey,
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
            return null;
        }

        const peerCertificateFingerprint = computePeerCertificateFingerprint(cert);
        const certifiedIdentity = await validateCertifiedPeerBundle(material.certifiedPeerBundle, {
            targetHandle,
            publicKeys: validated.publicKeys,
            fullBundle: material.fullBundle,
            peerCertificate: cert
        });
        if (!isCurrentOwner()) return null;
        if (certifiedIdentity.valid === false) {
            return null;
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
        const ownAvatar = profilePictureSystem.getOwnAvatarData();

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
        monitorContact = true,
        isLookupCurrent: () => boolean,
        lookupSignal: AbortSignal,
        progress: DiscoveryProgressStream,
    ): Promise<OPRFDiscoveryMaterial | null> => {
        const operationOwnerScope = ownerScope;
        const accountOwner = effectiveHandle?.toLowerCase() || null;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            accountOwner !== null &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            isLookupCurrent()
        );
        if (!isCurrentOwner()) return null;
        let transparencyCheckFailed = false;
        
        for (const encryptedBlob of encryptedBlobs) {
            if (typeof encryptedBlob !== 'string' || encryptedBlob.length === 0) continue;
            for (const key of encryptionKeys) {
                if (!key) continue;
                const material = await oprfDiscoveryClient.decryptDiscoveryBlob(encryptedBlob, key);
                if (!isCurrentOwner() || lookupSignal.aborted) return null;
                if (!material) continue;

                const validated = await validateDiscoveryMaterial(targetHandle, material);
                if (!isCurrentOwner()) return null;
                if (!validated) continue;

                await keyTransparencyClient.ingestPublishedTransition(
                    accountOwner,
                    material.keyTransparencyTransition
                );
                if (!isCurrentOwner()) return null;

                const accountRootPublicKey =
                    validated.certifiedPeerBundle?.accountRoot?.accountRootPublicKey;
                if (typeof accountRootPublicKey !== 'string') continue;
                const peer = String(targetHandle).trim().toLowerCase();
                try {
                    progress.setPhase('checking-keys');
                    await keyTransparencyClient.verifyDiscoveredIdentity({
                        ownerUsername: accountOwner!,
                        peerUsername: peer,
                        monitorContact,
                        discoveryEncryptionKey: key,
                        accountRootPublicKeyBase64: accountRootPublicKey,
                        material: validated,
                        isCurrent: isCurrentOwner,
                        signal: lookupSignal,
                        onRetry: () => progress.setPhase('retrying-keys'),
                    });
                } catch {
                    transparencyCheckFailed = true;
                    continue;
                }
                const isAuthorized = () => isCurrentOwner() &&
                    isKeyTransparencyVerifiedMaterial(validated, accountOwner!, peer);
                if (!isAuthorized()) return null;

                await persistPeerDetectionKey(
                    accountOwner!,
                    targetHandle,
                    validated.spoolDetectionKey,
                );
                if (!isAuthorized()) return null;

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

        if (cacheNegative && !transparencyCheckFailed) {
            setDiscoveryResultCache(discoveryResultCache, cacheKey, {
                value: null,
                expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
            });
        }
        return null;
    }, [validateDiscoveryMaterial, effectiveHandle, ownerScope]);

    const findDiscoveryBlobsInBuckets = useCallback(async (
        tokens: string[],
        signal?: AbortSignal,
        onProgress?: DiscoveryProgressObserver,
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
        const result = await fetchDiscoveryBlobsForTokens(normalizedTokens, ownerScope, signal, onProgress);
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
        const operationIdentity = websocketClient.captureAnonymousHttpIdentity();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isAnonymousHttpIdentityCurrent(operationIdentity)
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
        const scopeState = await waitForOprfState();
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
        const operationIdentity = websocketClient.captureAnonymousHttpIdentity();
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isAnonymousHttpIdentityCurrent(operationIdentity)
        );
        if (!isCurrentOwner()) return null;
        if (!normalizedHandle) {


            return null;
        }

        const [oprfState, sessionReady] = await Promise.all([
            waitForOprfState(),
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
                context.serverUrl,
                { signal: operationAbortSignal }
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
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
        let accountKeys: HybridKeys | null = null;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            websocketClient.isConnectionPrivacyEpochCurrent(operationConnectionEpoch) &&
            (accountKeys === null || hasSameDiscoveryPublicKeys(hybridKeysRef?.current, accountKeys))
        );

        const fail = (reason: string) => {
            if (isCurrentOwner()) lastPublishFailureRef.current = reason;
            return false;
        };

        const sendPreparedPublication = async (
            prepared: PreparedDiscoveryPublication,
        ): Promise<boolean> => {
            const requestId = prepared.requestId;
            try {
                await requestDiscoveryResponse({
                    operation: 'publish',
                    registerConnectionCancel: (cancel) => websocketClient.registerConnectionWaiterCancel(cancel),
                    events: window,
                    signal: operationAbortSignal,
                    isCurrent: () => isCurrentOwner() && isDiscoveryTransportReady(),
                    send: async (signal) => {
                        await websocketClient.sendSecureControlMessage({
                            type: SignalType.PUBLISH_DISCOVERY,
                            requestId,
                            publication: prepared.publication,
                            encryptedBlob: prepared.encryptedBlob,
                            powNonce: prepared.powNonce,
                            powSolution: prepared.powSolution,
                        }, { failIfQueued: true, signal });
                    },
                    parse: (detail) => parsePublicationAck(detail, requestId),
                });
                if (!isCurrentOwner()) return false;
                lastPublishedRef.current = Date.now();
                lastPublishedContextFingerprintRef.current = prepared.contextFingerprint;
                lastPublishedFingerprintRef.current = prepared.fingerprint;
                lastPublishedAvatarStateVersionRef.current = prepared.avatarStateVersion;
                lastPublishFailureRef.current = null;
                if (preparedPublicationRef.current === prepared) preparedPublicationRef.current = null;
                return true;
            } catch (error) {
                const reason = error instanceof Error ? error.message : String(error);
                if (!canRetryPreparedPublication(reason) && preparedPublicationRef.current === prepared) {
                    preparedPublicationRef.current = null;
                }
                return fail(reason);
            }
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
                            expiresAt: now + DISCOVERY_PUBLICATION_RETRY_TTL_MS
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

                const certifiedPeerBundle = await buildCertifiedPeerBundle({
                    username: String(bundleUsername),
                    publicKeys: {
                        kyberPublicBase64: kyberKey,
                        dilithiumPublicBase64: dilithiumKey,
                        x25519PublicBase64: x25519Key
                    },
                    fullBundle: bundle,
                    peerCertificate,
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
                
                const cachedKeyTransparencyTransition = await keyTransparencyClient
                    .getPublishedTransition(publishOwner);
                if (!isCurrentOwner()) return false;
                const spoolDetectionKey = await ownDetectionPublicKeyHex(publishOwner);
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
                        spoolDetectionKey,
                    })
                    : null;



                // Build publish token set
                const oprfState = await waitForOprfState();
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

                const prepared = preparedPublicationRef.current;
                if (canReuseDiscoveryPublication(prepared, {
                    inputFingerprint: preflightPublishInputFingerprint,
                    epochId: String(epoch * DISCOVERY_EPOCH_DURATION_MS),
                    publicKey,
                    connectionEpoch: operationConnectionEpoch,
                    avatarStateVersion: publishedAvatarStateVersion,
                })) {
                    return await sendPreparedPublication(prepared);
                }
                preparedPublicationRef.current = null;
                    
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
                    .getPublishedTransition(publishOwner);
                if (!isCurrentOwner()) return false;
                if (!keyTransparencyTransition) {
                    return fail('missing-key-transparency-transition');
                }

                const material: OPRFDiscoveryBlob = {
                    fullBundle: bundle,
                    certifiedPeerBundle,
                    spoolDetectionKey,
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
                    spoolDetectionKey,
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
                const encryptedBlob = await oprfDiscoveryClient.encryptDiscoveryBlob(material, currentResult.encryptionKey);
                if (!isCurrentOwner()) return false;
                const publishWork = await createAnonymousHttpPow(
                    PROTOCOL_KEYS.DISCOVERY_PUBLISH_POW,
                    publication.epochId,
                    [
                        publication.publishId,
                        ...publication.bucketIds.map(String),
                        encryptedBlob
                    ],
                    DISCOVERY_PUBLISH_POW_DIFFICULTY,
                    operationAbortSignal
                );
                if (!isCurrentOwner()) return false;
                const preparedPublication: PreparedDiscoveryPublication = {
                    requestId: `pub-${crypto.randomUUID()}`,
                    publication,
                    encryptedBlob,
                    ...publishWork,
                    inputFingerprint: publishInputFingerprint,
                    contextFingerprint,
                    fingerprint: publishFingerprint,
                    publicKey,
                    connectionEpoch: operationConnectionEpoch!,
                    avatarStateVersion: publishedAvatarStateVersion,
                    expiresAt: Math.min(
                        Date.now() + DISCOVERY_PUBLICATION_RETRY_TTL_MS,
                        oprfState.epochRotatesAt,
                    ),
                };
                if (preparedPublication.expiresAt <= Date.now() + WS_CONTROL_SEND_TIMEOUT_MS) {
                    return fail('discovery_epoch_expired');
                }
                preparedPublicationRef.current = preparedPublication;
                return await sendPreparedPublication(preparedPublication);
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
    }, [effectiveHandle, getDiscoveryHandle, evaluateHandleWithOprf, accountUsername, hybridKeysRef, getAvatarForDiscovery, waitForOprfState, isDiscoveryTransportReady, ownerScope]);

    const publishSelf = useCallback(async (force = false, bypassAttemptDelay = false): Promise<boolean> => {
        try {
            return await runPublishSelf(force, bypassAttemptDelay);
        } catch {
            return false;
        }
    }, [runPublishSelf]);

    const sendCoverPublication = useCallback(async (): Promise<boolean> => {
        const operationOwnerScope = ownerScope;
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
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
        if (Date.now() - lastPublishAttemptRef.current < USE_DISCOVERY_LAST_PUBLISH_ATTEMPT_REF_MINIMUM) {

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
        const requestId = `pub-${crypto.randomUUID()}`;
        try {
            await requestDiscoveryResponse({
                operation: 'cover-publish',
                events: window,
                signal: operationAbortSignal,
                isCurrent: () => isCurrentOwner() && isDiscoveryTransportReady(),
                send: async (signal) => {
                    await websocketClient.sendSecureControlMessage({
                        type: SignalType.PUBLISH_DISCOVERY,
                        requestId,
                        publication: coverPublication,
                        encryptedBlob,
                        ...publishWork,
                    }, { failIfQueued: true, signal });
                },
                parse: (detail) => parsePublicationAck(detail, requestId),
            });
            return isCurrentOwner();
        } catch {
            return false;
        }
    }, [effectiveHandle, isDiscoveryTransportReady, ownerScope]);

    // Capture OPRF public key and epoch info from server
    useEffect(() => {

        const runWhenDiscoveryTransportReady = (onReady: () => void) => {
            const ready = isDiscoveryTransportReady();
            if (ready) onReady();
        };

        let lifecycleStopped = false;

        const requestLifecyclePublish = (delayMs = DISCOVERY_LIFECYCLE_PUBLISH_COALESCE_MS) => {
            if (lifecycleStopped) return;
            if (lifecyclePublishTimerRef.current !== null) return;
            lifecyclePublishTimerRef.current = window.setTimeout(async () => {
                lifecyclePublishTimerRef.current = null;
                if (lifecycleStopped || activeOwnerScopeRef.current !== ownerScope) return;
                const success = await publishSelf(true);
                if (
                    !success &&
                    !lifecycleStopped &&
                    activeOwnerScopeRef.current === ownerScope &&
                    isDiscoveryTransportReady()
                ) {
                    const failure = lastPublishFailureRef.current || 'unknown';
                    requestLifecyclePublish(
                        publishRetryDelayMs(failure, isPreReadyPublishFailure(failure))
                    );
                }
            }, delayMs);
        };

        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === '__ws_connection_closed' || detail?.type === '__ws_connection_error' || detail?.type === '__ws_connection_opened') {

                oprfStateRef.current = {};
                preparedPublicationRef.current = null;
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
                        requestOprfKey(true);
                    }, refreshDelay);
                    if (publicationContextChanged && isDiscoveryTransportReady()) {
                        requestLifecyclePublish();
                    }
                } else {

                }
            }
        };

        const onUnlinkedReady = () => {
            noteDiscoveryTransportReadinessChanged('unlinked-ready');
            runWhenDiscoveryTransportReady(() => {
                requestOprfKey();
                requestLifecyclePublish();
            });
        };
        const onHybridKeys = () => {
            cachedBundleRef.current = null;
            runWhenDiscoveryTransportReady(() => {
                requestLifecyclePublish();
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
                requestLifecyclePublish();
            }
        }, P2P_PEER_CERT_PUBLISH_CHECK_INTERVAL_MS);

        if (isDiscoveryTransportReady()) {
            requestOprfKey();
            requestLifecyclePublish();
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

        };
    }, [requestOprfKey, publishSelf, pruneDiscoveryTokenCache, isDiscoveryTransportReady, noteDiscoveryTransportReadinessChanged, ownerScope]);

    const scheduleAvatarPublish = useCallback(() => {

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

        const jitterMs = 5000 + Math.floor(PostQuantumRandom.randomUnit(true) * 25000);

        const runScheduledPublish = async (): Promise<void> => {
            pendingAvatarPublishRef.current = false;
            avatarPublishTimeoutRef.current = null;

            let success = false;
            for (let handoff = 0; handoff < 2; handoff += 1) {
                const targetVersion = avatarStateVersionRef.current;
                success = await publishSelf(true, true);
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
            + Math.floor(PostQuantumRandom.randomUnit(true) * DISCOVERY_COVER_PUBLISH_INITIAL_JITTER_MS);

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
                        scheduleAvatarPublish();
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
        options?: DiscoveryLookupOptions
    ): Promise<OPRFDiscoveryMaterial | null> => {
        const operationOwnerScope = ownerScope;
        const operationAbortSignal = ownerAbortControllerRef.current.signal;
        const lookupController = new AbortController();
        let operationIdentity: AbortSignal | null = null;
        let networkIdentityCaptured = false;
        const isCurrentOwner = () => (
            operationOwnerScope !== null &&
            !operationAbortSignal.aborted &&
            !lookupController.signal.aborted &&
            activeOwnerScopeRef.current === operationOwnerScope &&
            (!networkIdentityCaptured || websocketClient.isAnonymousHttpIdentityCurrent(operationIdentity))
        );
        if (!isCurrentOwner()) return null;
        const forceRefresh = !!options?.forceRefresh;
        if (!shouldAttemptDiscovery(targetHandle)) {
            return null;
        }
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) {
            return null;
        }
        if (!forceRefresh && effectiveHandle) {
            await keyTransparencyClient.restorePersistedAuthorizations(effectiveHandle);
            if (!isCurrentOwner()) return null;
            const persisted = await loadTrustedPersistedDiscoveryMaterial(
                effectiveHandle,
                targetHandle.trim().toLowerCase()
            );
            if (!isCurrentOwner()) return null;
            if (persisted) return persisted as OPRFDiscoveryMaterial;
        }
        operationIdentity = websocketClient.captureAnonymousHttpIdentity();
        networkIdentityCaptured = true;
        if (!isCurrentOwner()) return null;
        if (!isDiscoveryTransportReady()) {
            return null;
        }
        const scopeState = await waitForOprfState();
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

                return observeDiscoveryProgress(findUserCache.get(lookupCacheKey)!, options?.onProgress);
            }
        } else {
            const lastFetchAt = discoveryNetworkFetchAt.get(lookupCacheKey) || 0;
            const sinceFetch = Date.now() - lastFetchAt;
            const cachedEntry = discoveryResultCache.get(lookupCacheKey);
            if (
                lastFetchAt > 0 &&
                sinceFetch < DISCOVERY_FORCED_REFETCH_MIN_INTERVAL_MS &&
                cachedEntry &&
                cachedEntry.expiresAt > Date.now() &&
                cachedEntry.value
            ) {
                return cachedEntry.value;
            }
        }

        const activeLookup = findUserInFlightLock.get(lookupCacheKey);
        if (activeLookup) {
            return observeDiscoveryProgress(activeLookup, options?.onProgress);
        }

        if (forceRefresh) {
            const existingForce = forceRefreshFindUserCache.get(lookupCacheKey);
            if (existingForce) {

                return observeDiscoveryProgress(existingForce, options?.onProgress);
            }

            if (findUserCache.has(lookupCacheKey)) {

                return observeDiscoveryProgress(findUserCache.get(lookupCacheKey)!, options?.onProgress);
            }
        }

        if (findUserInFlightLock.size >= DISCOVERY_LOOKUP_MAX_IN_FLIGHT) {
            return null;
        }

        const abortLookup = () => lookupController.abort();
        operationAbortSignal.addEventListener('abort', abortLookup, { once: true });
        operationIdentity?.addEventListener('abort', abortLookup, { once: true });
        if (!isCurrentOwner()) abortLookup();
        const progress = new DiscoveryProgressStream();
        let promise!: Promise<OPRFDiscoveryMaterial | null>;
        const rawLookup = (async () => {
            let epochResults: Map<number, { token: string; encryptionKey: Uint8Array }> | null = null;
            try {
                const oprfState = await waitForOprfState();
                if (!oprfState || oprfState.epoch === undefined) {
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
                    await sleep(USE_DISCOVERY_FIND_USER_DELAY_MS);
                    if (!isCurrentOwner()) return null;
                    epochResults = await getDiscoveryTokensForEpochs(normalizedHandle, lookupEpochs);
                    if (!isCurrentOwner()) return null;
                }
                const currentResult = epochResults?.get(epoch) || null;

                if (!currentResult) {
                    return null;
                }
                
                const encryptionKeys = [currentResult.encryptionKey];

                const bucketTokens = [currentResult.token];
                let bucketLookupFailed = false;

                const runBucketLookup = async (): Promise<OPRFDiscoveryMaterial | null> => {
                    try {
                        const bucketResponse = await findDiscoveryBlobsInBuckets(bucketTokens, lookupController.signal, progress.report);
                        if (!isCurrentOwner()) return null;
                        if (bucketResponse && bucketResponse.blobs.length > 0) {
                            const bucketResult = await finalizeDiscoverySnapshotResult(
                                lookupCacheKey,
                                targetHandle,
                                bucketResponse.blobs,
                                encryptionKeys,
                                false,
                                options?.monitorContact !== false,
                                isCurrentOwner,
                                lookupController.signal,
                                progress,
                            );
                            if (!isCurrentOwner()) return null;
                            if (bucketResult) {
                                noteDiscoveryNetworkFetch(lookupCacheKey);
                                return bucketResult;
                            }
                        }
                    } catch {
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
                operationAbortSignal.removeEventListener('abort', abortLookup);
                operationIdentity?.removeEventListener('abort', abortLookup);
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
                            abortLookup();
                            
                            if (findUserInFlightLock.get(lookupCacheKey) === promise) {
                                findUserInFlightLock.delete(lookupCacheKey);
                            }
                            resolve(null);
                        }, DISCOVERY_LOOKUP_TIMEOUT_MS);
                    }),
                ]);
            } finally {
                if (timer !== undefined) clearTimeout(timer);
            }
        })();

        trackDiscoveryProgress(promise, progress);
        findUserInFlightLock.set(lookupCacheKey, promise);
        if (forceRefresh) {
            forceRefreshFindUserCache.set(lookupCacheKey, promise);
        } else {
            findUserCache.set(lookupCacheKey, promise);
        }
        return observeDiscoveryProgress(promise, options?.onProgress);
    }, [getDiscoveryTokensForEpochs, getDiscoveryHandle, waitForOprfState, findDiscoveryBlobsInBuckets, finalizeDiscoverySnapshotResult, isDiscoveryTransportReady, ownerScope, effectiveHandle]);

    return {
        findUser
    };
};
