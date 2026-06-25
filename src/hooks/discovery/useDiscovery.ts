/**
 * OPRF peer discovery hook
 */

import { useState, useCallback, useEffect, useMemo, useRef, RefObject } from 'react';
import * as pako from 'pako';
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
import { signal, p2p, isTauri, pir } from '@/lib/tauri-bindings';
import { getBlindRoutingClient } from '@/lib/transport/blind-routing-client';
import { computeBlindUserId } from '@/lib/utils/auth-utils';
import { CryptoUtils } from '@/lib/utils/crypto-utils';
import { generateDefaultAvatar, hashAvatarData, isValidAvatarData } from '@/lib/utils/avatar-utils';
import { normalizeP2PEndpointUrl } from '@/lib/utils/p2p-endpoint';
import { sanitizeHybridKeys } from '@/lib/utils/messaging-validators';
import {
    computePeerCertificateFingerprint,
    normalizePeerCertificateBundle,
    encodePeerCertificateSigningPayload,
    isSelfSignedPeerCertificate
} from '@/lib/utils/peer-certificate-utils';
import {
    buildCertifiedPeerBundleV2,
    validateCertifiedPeerBundleV2
} from '@/lib/utils/certified-identity-utils';
import type { AvatarData } from '@/lib/types/avatar-types';
import { publishAvatarToStore, fetchAvatarFromStore, ensureAvatarCoverBlobs } from '@/lib/avatar/avatar-store-client';
import type { AvatarRef } from '@/lib/crypto/avatar-blob-crypto';
import type { HybridKeys } from '@/lib/types/auth-types';
import type { PeerCertificateBundle } from '@/lib/types/p2p-types';
import { CERT_CLOCK_SKEW_MS, P2P_PEER_CERT_TTL_MS } from '@/lib/constants';
import { blake3 } from '@noble/hashes/blake3.js';
import { shouldAttemptDiscovery } from '@/lib/utils/discovery-utils';
import {
    deriveBlockListLookupId,
    deriveBundleLookupId,
    deriveMailboxMetadataId,
    deriveRendezvousRouteId,
    isRendezvousRouteId
} from '@/lib/transport/rendezvous-routing';
import { DISCOVERY_PIR_DATABASE_KIND, fetchPirEncryptedBlobsForTokens, isPirInteractive, markPirInteractiveActivity, requestPirManifest, runPirCoverQueries, sha256Base64Url, deriveDiscoveryPirSlotKey, deriveDiscoveryBucketId, manifestEpoch } from '@/lib/pir/pir-client';

const discoveryTokenCache = new Map<string, Promise<{ token: string; encryptionKey: Uint8Array } | null>>();

async function sha256HexOf(input: string): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)));
    return Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// K-anon publish convert per epoch OPRF tokens into { epochId, bucketId, publishId } using same derivation as lookup uses deriveDiscoveryPirSlotKey -> deriveDiscoveryBucketId over manifest epoch and bucketCount
async function buildDiscoveryBucketBatch(
    tokens: string[],
    publishKeyB64: string
): Promise<Array<{ epochId: string; bucketId: number; publishId: string }> | null> {
    const manifestResponse = await requestPirManifest({
        prepareWorker: false, kind: DISCOVERY_PIR_DATABASE_KIND, forceFresh: true, timeoutMs: 60_000
    }).catch(() => null);
    const manifest = (manifestResponse as any)?.success ? (manifestResponse as any).manifest : null;
    const bucketCount = manifest?.bucketCount;
    if (!manifest || !Number.isInteger(bucketCount) || (bucketCount as number) < 1) return null;
    const epochStart = manifestEpoch(manifest);
    const epochId = String(epochStart);
    const seen = new Set<number>();
    const out: Array<{ epochId: string; bucketId: number; publishId: string }> = [];
    for (const token of tokens) {
        if (typeof token !== 'string' || !/^[a-f0-9]{64}$/i.test(token)) continue;
        const slotKey = await deriveDiscoveryPirSlotKey(token);
        const bucketId = await deriveDiscoveryBucketId(slotKey, epochStart, bucketCount as number);
        if (seen.has(bucketId)) continue;
        seen.add(bucketId);
        const publishId = await sha256HexOf(`qor-discovery-publishid-v1\0${publishKeyB64}\0${epochId}\0${bucketId}`);
        out.push({ epochId, bucketId, publishId });
    }
    return out.length > 0 ? out : null;
}

const findUserCache = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const forceRefreshFindUserCache = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const findUserInFlightLock = new Map<string, Promise<OPRFDiscoveryMaterial | null>>();
const lastDiscoveryLookupAt = new Map<string, number>();
const discoveryResultCache = new Map<string, { value: OPRFDiscoveryMaterial | null; expiresAt: number }>();

const DISCOVERY_POSITIVE_CACHE_TTL_MS = 5 * 60 * 1000;
const DISCOVERY_STALE_SERVE_GRACE_MS = 60 * 1000;
const DISCOVERY_NEGATIVE_CACHE_TTL_MS = 30 * 1000;
const DISCOVERY_TIMEOUT_CACHE_TTL_MS = 25 * 1000;
const DISCOVERY_TOKEN_CACHE_TTL_MS = 30 * 1000;
const OPRF_EVAL_SEND_TIMEOUT_MS = 15000;
const OPRF_EVAL_RESPONSE_TIMEOUT_MS = 60000;
const OPRF_WAIT_TIMEOUT_MS = 10000;
const PUBLISH_ACK_TIMEOUT_MS = 15000;
const PREKEY_BUNDLE_CACHE_TTL_MS = 2 * 60 * 1000;
const DISCOVERY_EPOCH_DURATION_MS = 6 * 60 * 60 * 1000;
const DISCOVERY_FORWARD_PUBLISH_WINDOW_MS = 24 * 60 * 60 * 1000;
const DISCOVERY_FORWARD_PUBLISH_EPOCHS = Math.ceil(DISCOVERY_FORWARD_PUBLISH_WINDOW_MS / DISCOVERY_EPOCH_DURATION_MS);
const DISCOVERY_PIR_COVER_INTERVAL_MS = 180_000;
const DISCOVERY_PIR_COVER_MIN_MS = 45_000;
const DISCOVERY_PIR_COVER_MAX_MS = 480_000;

function nextDiscoveryCoverDelayMs() {
    const u = Math.max(1e-9, 1 - Math.random());
    const exp = -DISCOVERY_PIR_COVER_INTERVAL_MS * Math.log(u);
    return Math.min(DISCOVERY_PIR_COVER_MAX_MS, Math.max(DISCOVERY_PIR_COVER_MIN_MS, Math.round(exp)));
}
const DISCOVERY_PIR_COVER_RECORDS_PER_KIND = 1;
const DISCOVERY_PIR_LOOKUP_TIMEOUT_MS = 120_000;
const DISCOVERY_PIR_FOREGROUND_ACTIVITY_MS = 15 * 60_000;
const DISCOVERY_PIR_LOOKUP_CANDIDATES_PER_TOKEN = 4;
const DISCOVERY_PIR_LOOKUP_CONCURRENCY = 1;
const DISCOVERY_PIR_SETUP_PREWARM_DELAY_MS = 2_000;
const DISCOVERY_PIR_SETUP_PREWARM_MIN_INTERVAL_MS = 30 * 60_000;
const DISCOVERY_SNAPSHOT_WIRE_VERSION = 'qor-discovery-snapshot-gzip-v1';
const DISCOVERY_SNAPSHOT_BODY_VERSION = 'qor-discovery-snapshot-v1';
const PRE_READY_PUBLISH_FAILURES = new Set([
    'missing-handle',
    'not-discoverable',
    'auth-transport-not-ready',
    'blind-routing-client-missing',
    'missing-inbox-id',
    'missing-oprf-epoch',
    'missing-certified-identity-keys'
]);

function isPreReadyPublishFailure(reason: string): boolean {
    return PRE_READY_PUBLISH_FAILURES.has(reason);
}

const AVATAR_FETCH_RETRY_DELAYS_MS = [4000, 8000, 15000, 30000];
const avatarFetchInFlight = new Set<string>();

function requestDirectAvatarFallback(cacheUsername: string, attempt: number): void {
    if (attempt !== 0) return;
    console.log('[AVATAR] content-store miss -> requesting direct encrypted fallback', {
        peer: String(cacheUsername).slice(0, 24)
    });
    void profilePictureSystem.requestPeerAvatar(cacheUsername).catch(() => { });
}

async function cachePeerAvatarFromRef(cacheUsername: string | null, avatarRef: AvatarRef | null | undefined, attempt = 0): Promise<void> {
    if (!cacheUsername) return;
    if (!avatarRef || typeof avatarRef.blobId !== 'string' || typeof avatarRef.keyB64 !== 'string') {
        if (attempt === 0) console.log('[AVATAR] discovery bundle has NO avatarRef (peer not publishing an avatar)', { peer: String(cacheUsername).slice(0, 24) });
        return;
    }
    const currentHash = profilePictureSystem.getPeerAvatarHash(cacheUsername);
    if (currentHash === avatarRef.hash) {
        if (attempt === 0) console.log('[AVATAR] already have this avatar (hash match), skip fetch', { peer: String(cacheUsername).slice(0, 24) });
        avatarFetchInFlight.delete(`${cacheUsername}:${avatarRef.hash}`);
        return;
    }

    const inFlightKey = `${cacheUsername}:${avatarRef.hash}`;
    if (attempt === 0) {
        if (avatarFetchInFlight.has(inFlightKey)) return;
        avatarFetchInFlight.add(inFlightKey);
    }

    console.log('[AVATAR] fetching avatar from content store', { peer: String(cacheUsername).slice(0, 24), hadPrevious: !!currentHash, attempt });
    const avatar = await fetchAvatarFromStore(avatarRef);
    if (avatar && isValidAvatarData(avatar)) {
        console.log('[AVATAR] fetched OK -> caching', { peer: String(cacheUsername).slice(0, 24), isDefault: avatar.isDefault === true });
        avatarFetchInFlight.delete(inFlightKey);
        void profilePictureSystem.cachePeerAvatar(
            cacheUsername,
            avatar.data,
            avatar.mimeType,
            avatar.hash,
            avatar.isDefault === true
        );
        return;
    }
    requestDirectAvatarFallback(cacheUsername, attempt);
    if (attempt < AVATAR_FETCH_RETRY_DELAYS_MS.length) {
        const delay = AVATAR_FETCH_RETRY_DELAYS_MS[attempt];
        console.warn('[AVATAR] content-store fetch empty (blob not up yet?) -> retrying', { peer: String(cacheUsername).slice(0, 24), attempt, retryInMs: delay });
        setTimeout(() => { void cachePeerAvatarFromRef(cacheUsername, avatarRef, attempt + 1); }, delay);
    } else {
        console.warn('[AVATAR] content-store fetch gave up after retries', { peer: String(cacheUsername).slice(0, 24) });
        avatarFetchInFlight.delete(inFlightKey);
    }
}

function publishForceAttemptDelayMs(lastFailure: string | null): number {
    if (!lastFailure) return 10_000;
    if (lastFailure === 'oprf-token-missing') return 60_000;
    if (lastFailure === 'publish-ack-failed') return 45_000;
    return isPreReadyPublishFailure(lastFailure) ? 5_000 : 15_000;
}

function publishRetryDelayMs(reason: string, preReadyReason: boolean): number {
    if (reason === 'oprf-token-missing') return 60_000 + Math.floor(Math.random() * 15_000);
    if (reason === 'publish-ack-failed') return 45_000 + Math.floor(Math.random() * 15_000);
    if (preReadyReason) return 5_000 + Math.floor(Math.random() * 10_000);
    return 15_000 + Math.floor(Math.random() * 15_000);
}
const DISCOVERY_COVER_PUBLISH_INTERVAL_MS = 5 * 60 * 1000;
const DISCOVERY_COVER_PUBLISH_INITIAL_MIN_MS = 20 * 1000;
const DISCOVERY_COVER_PUBLISH_INITIAL_JITTER_MS = 40 * 1000;
const DISCOVERY_COVER_TOKEN_BATCH_SIZE = DISCOVERY_FORWARD_PUBLISH_EPOCHS + 2;
const DISCOVERY_COVER_BLOB_CHARS = 16 * 1024;
const DISCOVERY_PUBLISH_LOG_THROTTLE_MS = 5000;

const countClass = (count: number): string => {
    const n = Math.max(0, Math.trunc(Number(count) || 0));
    if (n === 0) return 'zero';
    if (n === 1) return 'one';
    if (n <= 4) return 'lte-4';
    if (n <= 16) return 'lte-16';
    if (n <= 128) return 'lte-128';
    return 'gt-128';
};

const byteClass = (bytes: number): string => {
    const n = Math.max(0, Math.trunc(Number(bytes) || 0));
    if (n <= 1024) return 'lte-1k';
    if (n <= 16 * 1024) return 'lte-16k';
    if (n <= 64 * 1024) return 'lte-64k';
    if (n <= 256 * 1024) return 'lte-256k';
    if (n <= 1024 * 1024) return 'lte-1m';
    return 'gt-1m';
};

const traceDiscoveryClient = (
    _event: string,
    _detail: Record<string, unknown> = {},
    _level: 'info' | 'warn' | 'error' = 'info'
) => {
};

const DISCOVERY_PUBLISH_CONSOLE_EVENTS = new Set([
    'publisher-check',
    'publisher-deferred',
    'publisher-start',
    'publish-skip',
    'publish-throttled',
    'publish-start',
    'publish-dispatch',
    'publish-ack',
    'publish-complete'
]);

const logDiscoveryLookup = (
    level: 'info' | 'warn' | 'error',
    event: string,
    detail: Record<string, unknown> = {}
) => {
    const payload: Record<string, unknown> = { event, ...detail };
    Object.keys(payload).forEach((key) => {
        if (payload[key] === undefined || payload[key] === null) {
            delete payload[key];
        }
    });
    const method = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
    method('[OPRF-DISCOVERY][lookup]', payload);
};

const logDiscoveryOprf = (
    level: 'info' | 'warn' | 'error',
    event: string,
    detail: Record<string, unknown> = {}
) => {
    const payload: Record<string, unknown> = { event, ...detail };
    Object.keys(payload).forEach((key) => {
        if (payload[key] === undefined || payload[key] === null) {
            delete payload[key];
        }
    });
    const method = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
    method('[OPRF-DISCOVERY][oprf]', payload);
};

type PendingDiscoveryRequest = {
    requestId: string;
    normalizedHandle: string;
    targetHandle: string;
    encryptionKeys: Uint8Array[];
    resolve: (value: OPRFDiscoveryMaterial | null) => void;
    timeoutId: number;
    settled: boolean;
    cacheNegative?: boolean;
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

const randomBytesForDiscovery = (length: number): Uint8Array => {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
};

const bytesToBase64Url = (bytes: Uint8Array): string => {
    let raw = '';
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
        raw += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const base64UrlToBytes = (value: string): Uint8Array => {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
    return bytes;
};

const randomHexForDiscovery = (bytes = 32): string => {
    return Array.from(randomBytesForDiscovery(bytes)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
};

const randomBase64UrlChars = (chars: number): string => {
    const needed = Math.ceil((chars * 3) / 4) + 4;
    return bytesToBase64Url(randomBytesForDiscovery(needed)).slice(0, chars);
};

const decodeCompressedDiscoverySnapshot = async (detail: any): Promise<string[]> => {
    const snapshot = detail?.snapshot;
    if (!snapshot || typeof snapshot !== 'object') {
        throw new Error('missing_compressed_discovery_snapshot');
    }
    if (snapshot.version !== DISCOVERY_SNAPSHOT_WIRE_VERSION) {
        throw new Error('unsupported_discovery_snapshot_wire_version');
    }
    if (snapshot.encoding !== 'base64url+gzip' || snapshot.compression !== 'gzip') {
        throw new Error('unsupported_discovery_snapshot_encoding');
    }
    if (typeof snapshot.compressed !== 'string' || typeof snapshot.digest !== 'string') {
        throw new Error('invalid_discovery_snapshot_payload');
    }

    const compressed = base64UrlToBytes(snapshot.compressed);
    const uncompressed = pako.inflate(compressed);
    const digest = await sha256Base64Url(uncompressed);
    if (digest !== snapshot.digest) {
        throw new Error('discovery_snapshot_digest_mismatch');
    }

    const decoded = JSON.parse(new TextDecoder().decode(uncompressed));
    if (decoded?.version !== DISCOVERY_SNAPSHOT_BODY_VERSION || !Array.isArray(decoded.entries)) {
        throw new Error('invalid_discovery_snapshot_body');
    }
    return decoded.entries.filter((entry: unknown): entry is string => typeof entry === 'string');
};

const INBOX_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/i;

const getDiscoveryCallerLabel = (): string => {
    try {
        const stack = new Error().stack;
        if (!stack) return 'unknown';
        const lines = stack.split('\n').slice(1).map(line => line.trim());
        for (const line of lines) {
            if (!line) continue;
            if (
                line.includes('useDiscovery') ||
                line.includes('findUser') ||
                line.includes('node_modules') ||
                line.includes('react-dom')
            ) {
                continue;
            }
            return line.replace(/^at\s+/, '').slice(0, 180);
        }
    } catch {
    }
    return 'unknown';
};

export const invalidateDiscoveryCache = (handle: string) => {
    if (!handle) return;
    let normalized = handle;
    if (!/^[a-f0-9]{64}$/i.test(handle)) {
        normalized = computeBlindUserId(handle);
    }
    discoveryResultCache.delete(normalized);
};

export const useDiscovery = (
    handle: string | undefined,
    signalUsername?: string,
    hybridKeysRef?: RefObject<HybridKeys | null>
) => {
    const [isDiscoverable, setIsDiscoverable] = useState(true);
    const [discoveryTransportReadyVersion, setDiscoveryTransportReadyVersion] = useState(0);
    const oprfStateRef = useRef<{ publicKey?: string; epoch?: number; previousEpoch?: number; epochRotatesAt?: number }>({});
    const lastPublishedRef = useRef<number>(0);
    const keysReadyPublishedRef = useRef<boolean>(false);
    const defaultAvatarCacheRef = useRef<Map<string, AvatarData>>(new Map());
    const avatarPublishTimeoutRef = useRef<number | null>(null);
    const pendingAvatarPublishRef = useRef<boolean>(false);
    const lastPublishedAvatarHashRef = useRef<string | null>(null);
    const cachedBundleRef = useRef<{ username: string; bundle: any; expiresAt: number } | null>(null);
    const cachedPeerCertificateRef = useRef<{ cacheKey: string; certificate: PeerCertificateBundle } | null>(null);
    const lastOprfKeyRequestRef = useRef<number>(0);
    const unlinkedReadyRef = useRef<boolean>(false);
    const lastDiscoveryTransportReadyRef = useRef<boolean | null>(null);
    const lastPublishFailureRef = useRef<string | null>(null);
    const publishingRef = useRef<boolean>(false);
    const publishPromiseRef = useRef<Promise<boolean> | null>(null);
    const lastPublishedFingerprintRef = useRef<string | null>(null);
    const lastPublishedContextFingerprintRef = useRef<string | null>(null);
    const lastDiscoveryPublishBlobLengthRef = useRef<number>(DISCOVERY_COVER_BLOB_CHARS);
    const lastPublishAttemptRef = useRef<number>(0);
    const publishAttemptSeqRef = useRef<number>(0);
    const lastPublishLogRef = useRef<{ key: string; at: number } | null>(null);
    const lastOprfPublicKeyRef = useRef<string | null>(null);
    const oprfReadyPromiseRef = useRef<Promise<{ publicKey: string; epoch: number; previousEpoch?: number; epochRotatesAt?: number } | null> | null>(null);
    const pirSetupPrewarmInFlightRef = useRef<Promise<void> | null>(null);
    const lastPirSetupPrewarmAtRef = useRef<number>(0);
    const pendingDiscoveryByRequestIdRef = useRef(new Map<string, PendingDiscoveryRequest>());
    const effectiveHandle = useMemo(() => {
        const candidate = (handle || signalUsername || '').trim();
        return candidate || undefined;
    }, [handle, signalUsername]);

    const isDiscoveryTransportReady = useCallback((emitTrace = true): boolean => {
        if (!effectiveHandle) {
            if (emitTrace) traceDiscoveryClient('transport.not-ready', { reason: 'not-logged-in' });
            return false;
        }
        if (!websocketClient.isConnectedToServer()) {
            if (emitTrace) traceDiscoveryClient('transport.not-ready', { reason: 'not-connected' });
            return false;
        }
        if (websocketClient.isUnlinkedMode?.()) {
            const ready = !!unlinkedReadyRef.current && !!websocketClient.isUnlinkedSessionReady?.();
            if (!ready && emitTrace) {
                traceDiscoveryClient('transport.not-ready', {
                    reason: 'unlinked-session-not-ready',
                    unlinkedReadyRef: unlinkedReadyRef.current,
                    unlinkedSessionReady: websocketClient.isUnlinkedSessionReady?.() === true
                });
            }
            return ready;
        }
        if (typeof websocketClient.isApplicationAuthReady === 'function' && !websocketClient.isApplicationAuthReady()) {
            if (emitTrace) traceDiscoveryClient('transport.not-ready', {
                reason: 'application-auth-not-ready',
                pqReady: websocketClient.isPQSessionEstablished?.() === true,
                serverEntryGranted: websocketClient.isServerAuthGranted?.() === true
            });
            return false;
        }
        try {
            if (typeof (websocketClient as any)?.isPQSessionEstablished === 'function') {
                const ready = !!(websocketClient as any).isPQSessionEstablished();
                if (!ready && emitTrace) {
                    traceDiscoveryClient('transport.not-ready', { reason: 'pq-session-not-ready' });
                }
                return ready;
            }
        } catch {
            if (emitTrace) traceDiscoveryClient('transport.not-ready', { reason: 'pq-readiness-check-threw' }, 'warn');
            return false;
        }
        return true;
    }, [effectiveHandle]);

    const discoveryPublishSnapshot = useCallback(() => {
        const keys = hybridKeysRef?.current;
        return {
            connected: websocketClient.isConnectedToServer?.() === true,
            pqReady: websocketClient.isPQSessionEstablished?.() === true,
            appAuthReady: websocketClient.isApplicationAuthReady?.() === true,
            serverEntryGranted: websocketClient.isServerAuthGranted?.() === true,
            unlinkedMode: websocketClient.isUnlinkedMode?.() === true,
            unlinkedReady: unlinkedReadyRef.current === true,
            hasOprfKey: !!oprfStateRef.current.publicKey,
            hasEpoch: oprfStateRef.current.epoch !== undefined,
            hasHybridKeys: !!(
                keys?.kyber?.publicKeyBase64 &&
                keys?.dilithium?.publicKeyBase64 &&
                keys?.x25519?.publicKeyBase64
            ),
            hasKyberPublic: !!keys?.kyber?.publicKeyBase64,
            hasKyberSecret: !!keys?.kyber?.secretKey,
            hasDilithiumPublic: !!keys?.dilithium?.publicKeyBase64,
            hasDilithiumSecret: !!keys?.dilithium?.secretKey,
            hasX25519Public: !!keys?.x25519?.publicKeyBase64,
            hasX25519Private: !!keys?.x25519?.private,
            hasAccountRootPublic: !!keys?.accountRoot?.publicKeyBase64,
            hasAccountRootSecret: !!keys?.accountRoot?.secretKey,
            hasEffectiveHandle: !!effectiveHandle,
            hasSignalUsername: !!signalUsername,
            publishInFlight: publishingRef.current,
            hasPublishPromise: !!publishPromiseRef.current,
            lastPublishedAgeMs: lastPublishedRef.current > 0 ? Date.now() - lastPublishedRef.current : null,
            lastAttemptAgeMs: lastPublishAttemptRef.current > 0 ? Date.now() - lastPublishAttemptRef.current : null,
            lastFailure: lastPublishFailureRef.current || null
        };
    }, [effectiveHandle, signalUsername, hybridKeysRef]);

    const noteDiscoveryTransportReadinessChanged = useCallback((reason: string) => {
        const ready = isDiscoveryTransportReady(false);
        if (lastDiscoveryTransportReadyRef.current === ready) {
            return;
        }
        lastDiscoveryTransportReadyRef.current = ready;
        setDiscoveryTransportReadyVersion((version) => (version + 1) % Number.MAX_SAFE_INTEGER);
        traceDiscoveryClient('transport.readiness-changed', {
            reason,
            ready,
            snapshot: discoveryPublishSnapshot()
        });
    }, [discoveryPublishSnapshot, isDiscoveryTransportReady]);

    const logDiscoveryPublish = useCallback((
        level: 'info' | 'warn',
        event: string,
        detail: Record<string, unknown> = {},
        throttleKey?: string
    ) => {
        if (!DISCOVERY_PUBLISH_CONSOLE_EVENTS.has(event)) return;
        const now = Date.now();
        const key = throttleKey || `${level}:${event}`;
        const last = lastPublishLogRef.current;
        if (last?.key === key && now - last.at < DISCOVERY_PUBLISH_LOG_THROTTLE_MS) {
            return;
        }
        lastPublishLogRef.current = { key, at: now };
        const payload: Record<string, unknown> = {
            event,
            attemptId: detail.attemptId,
            forced: detail.forced,
            reason: detail.reason,
            success: detail.success,
            stage: detail.stage,
            rttMs: detail.rttMs,
            elapsedMs: detail.elapsedMs,
            tokenBatchClass: detail.tokenBatchClass,
            encryptedBlobSizeClass: detail.encryptedBlobSizeClass,
            missingEpochClass: detail.missingEpochClass,
            lastFailure: detail.lastFailure
        };
        Object.keys(payload).forEach((key) => {
            if (payload[key] === undefined || payload[key] === null) {
                delete payload[key];
            }
        });
        console.log('[OPRF-DISCOVERY][publish]', payload);
    }, []);

    useEffect(() => {
        traceDiscoveryClient('hook.state', {
            isDiscoverable,
            snapshot: discoveryPublishSnapshot()
        });
    }, [isDiscoverable, discoveryPublishSnapshot]);

    const requestOprfKey = useCallback((reason: string | Event = 'auto') => {
        const label = typeof reason === 'string' ? reason : 'event';
        const now = Date.now();
        traceDiscoveryClient('oprf-public-key.requested', {
            reason: label,
            sinceLastMs: lastOprfKeyRequestRef.current > 0 ? now - lastOprfKeyRequestRef.current : null,
            snapshot: discoveryPublishSnapshot()
        });
        if (now - lastOprfKeyRequestRef.current < 5000) {
            traceDiscoveryClient('oprf-public-key.skipped', {
                reason: 'request-throttled',
                requestReason: label,
                sinceLastMs: now - lastOprfKeyRequestRef.current
            });
            return;
        }
        if (!isDiscoveryTransportReady()) {
            traceDiscoveryClient('oprf-public-key.skipped', {
                reason: 'transport-not-ready',
                requestReason: label,
                snapshot: discoveryPublishSnapshot()
            }, 'warn');
            return;
        }
        lastOprfKeyRequestRef.current = now;
        websocketClient.send({ type: SignalType.OPRF_DISCOVERY_PUBLIC_KEY, reason: label });
        traceDiscoveryClient('oprf-public-key.sent', {
            reason: label,
            snapshot: discoveryPublishSnapshot()
        });
    }, [isDiscoveryTransportReady, discoveryPublishSnapshot]);

    const waitForOprfState = useCallback(async (
        reason: string,
        timeoutMs: number = OPRF_WAIT_TIMEOUT_MS
    ): Promise<{ publicKey: string; epoch: number; previousEpoch?: number; epochRotatesAt?: number } | null> => {
        const current = oprfStateRef.current;
        if (current.publicKey && current.epoch !== undefined) {
            traceDiscoveryClient('oprf-state.ready-from-cache', {
                reason,
                hasPreviousEpoch: current.previousEpoch !== undefined,
                epoch: current.epoch
            });
            return current as { publicKey: string; epoch: number; previousEpoch?: number; epochRotatesAt?: number };
        }

        if (oprfReadyPromiseRef.current) {
            traceDiscoveryClient('oprf-state.wait-reused', { reason, timeoutMs });
            return oprfReadyPromiseRef.current;
        }

        traceDiscoveryClient('oprf-state.wait-start', {
            reason,
            timeoutMs,
            snapshot: discoveryPublishSnapshot()
        });
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
                    traceDiscoveryClient('oprf-state.received', {
                        reason,
                        epoch: detail.epoch,
                        hasPreviousEpoch: detail.previousEpoch !== undefined,
                        via: ev.type
                    });
                    resolve({
                        publicKey: detail.publicKey,
                        epoch: detail.epoch,
                        previousEpoch: detail.previousEpoch,
                        epochRotatesAt: detail.epochRotatesAt
                    });
                } else if ((detail?.type === SignalType.ERROR || detail?.type === SignalType.AUTH_ERROR) && typeof detail.message === 'string') {
                    cleanup();
                    traceDiscoveryClient('oprf-state.error', {
                        reason,
                        type: detail.type,
                        message: detail.message
                    }, 'warn');
                    resolve(null);
                }
            };

            const timeoutId = window.setTimeout(() => {
                cleanup();
                traceDiscoveryClient('oprf-state.timeout', {
                    reason,
                    timeoutMs,
                    snapshot: discoveryPublishSnapshot()
                }, 'warn');
                resolve(null);
            }, timeoutMs);

            window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        });

        return oprfReadyPromiseRef.current;
    }, [requestOprfKey, discoveryPublishSnapshot]);

    const pruneDiscoveryTokenCache = useCallback((epoch?: number, previousEpoch?: number) => {
        const allowed = new Set<number>();
        if (typeof epoch === 'number') {
            allowed.add(epoch);
            for (let i = 1; i <= DISCOVERY_FORWARD_PUBLISH_EPOCHS; i += 1) {
                allowed.add(epoch + i);
            }
        }
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
                if ((websocketClient as any).isPQSessionEstablished()) {
                    traceDiscoveryClient('pq-session.ready-immediate', { timeoutMs });
                    return true;
                }
            }
        } catch (error) {
            traceDiscoveryClient('pq-session.readiness-check-error', {
                error: error instanceof Error ? error.message : String(error)
            }, 'warn');
        }

        traceDiscoveryClient('pq-session.wait-start', { timeoutMs });
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
                traceDiscoveryClient('pq-session.established-event', { timeoutMs });
                resolve(true);
            };

            const timeoutId = window.setTimeout(() => {
                cleanup();
                try {
                    if (typeof (websocketClient as any)?.isPQSessionEstablished === 'function') {
                        const ready = (websocketClient as any).isPQSessionEstablished();
                        traceDiscoveryClient('pq-session.wait-timeout-check', { timeoutMs, ready }, ready ? 'info' : 'warn');
                        return resolve(ready);
                    }
                } catch (error) {
                    traceDiscoveryClient('pq-session.wait-timeout-check-error', {
                        timeoutMs,
                        error: error instanceof Error ? error.message : String(error)
                    }, 'warn');
                }
                traceDiscoveryClient('pq-session.wait-timeout', { timeoutMs }, 'warn');
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
        traceDiscoveryClient('secure-send.start', {
            reason,
            type: payload?.type,
            hasRequestId: typeof payload?.requestId === 'string',
            readyTimeoutMs,
            snapshot: discoveryPublishSnapshot()
        });
        if (!isDiscoveryTransportReady()) {
            traceDiscoveryClient('secure-send.blocked', {
                reason,
                blockReason: 'transport-not-ready',
                type: payload?.type,
                snapshot: discoveryPublishSnapshot()
            }, 'warn');
            return false;
        }
        const ready = await waitForPqSession(readyTimeoutMs);
        if (!ready) {
            traceDiscoveryClient('secure-send.blocked', {
                reason,
                blockReason: 'pq-session-not-ready',
                type: payload?.type,
                readyTimeoutMs,
                snapshot: discoveryPublishSnapshot()
            }, 'warn');
            return false;
        }
        try {
            traceDiscoveryClient('secure-send.dispatching', {
                reason,
                type: payload?.type,
                hasRequestId: typeof payload?.requestId === 'string'
            });
            await websocketClient.sendSecureControlMessage(payload, { failIfQueued: true });
            traceDiscoveryClient('secure-send.sent', {
                reason,
                type: payload?.type,
                hasRequestId: typeof payload?.requestId === 'string'
            });
            return true;
        } catch (err) {
            traceDiscoveryClient('secure-send.error', {
                reason,
                type: payload?.type,
                error: err instanceof Error ? err.message : String(err)
            }, 'warn');
            return false;
        }
    }, [isDiscoveryTransportReady, waitForPqSession, discoveryPublishSnapshot]);

    const buildSelfPeerCertificate = async (
        username: string,
        inboxId: string,
        keys: HybridKeys | null | undefined,
        p2pEndpointUrl?: string | null
    ): Promise<PeerCertificateBundle | null> => {
        if (!keys?.dilithium?.secretKey || !keys.dilithium.publicKeyBase64) return null;
        if (!keys.kyber?.publicKeyBase64 || !keys.x25519?.publicKeyBase64) return null;

        const normalizedEndpoint = normalizeP2PEndpointUrl(p2pEndpointUrl);
        const proof = keys.dilithium.publicKeyBase64;
        const cacheKey = JSON.stringify({
            username,
            inboxId,
            dilithiumPublicKey: keys.dilithium.publicKeyBase64,
            kyberPublicKey: keys.kyber.publicKeyBase64,
            x25519PublicKey: keys.x25519.publicKeyBase64,
            p2pEndpointUrl: normalizedEndpoint,
            proof
        });
        const now = Date.now();
        const cached = cachedPeerCertificateRef.current;
        if (
            cached &&
            cached.cacheKey === cacheKey &&
            cached.certificate.expiresAt - now > 5 * 60 * 1000
        ) {
            return cached.certificate;
        }
        const issuedAt = now;
        const expiresAt = issuedAt + P2P_PEER_CERT_TTL_MS;

        const unsignedCertificate: PeerCertificateBundle = {
            username,
            inboxId,
            dilithiumPublicKey: keys.dilithium.publicKeyBase64,
            kyberPublicKey: keys.kyber.publicKeyBase64,
            x25519PublicKey: keys.x25519.publicKeyBase64,
            p2pEndpointUrl: normalizedEndpoint,
            proof,
            issuedAt,
            expiresAt,
            signature: ''
        };
        const canonical = encodePeerCertificateSigningPayload(unsignedCertificate);
        const signatureBytes = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
        const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureBytes);

        const certificate: PeerCertificateBundle = {
            ...unsignedCertificate,
            signature
        };
        cachedPeerCertificateRef.current = { cacheKey, certificate };
        return certificate;
    };

    const validatePeerCertificate = useCallback(async (
        targetHandle: string,
        inboxId: string,
        publicKeys: {
            kyberPublicBase64: string;
            dilithiumPublicBase64: string;
            x25519PublicBase64: string;
        },
        cert: PeerCertificateBundle
    ): Promise<PeerCertificateBundle | null> => {
        try {
            const normalizedCert = normalizePeerCertificateBundle(cert);
            if (!normalizedCert.username) return null;

            const isHashedHandle = /^[a-f0-9]{64}$/i.test(String(targetHandle || ''));
            if (!isHashedHandle && normalizedCert.username !== String(targetHandle || '').trim()) {
                return null;
            }
            if (normalizedCert.inboxId && normalizedCert.inboxId !== inboxId) {
                return null;
            }
            if (normalizedCert.dilithiumPublicKey !== publicKeys.dilithiumPublicBase64) {
                return null;
            }
            if (normalizedCert.kyberPublicKey !== publicKeys.kyberPublicBase64) {
                return null;
            }
            if (normalizedCert.x25519PublicKey !== publicKeys.x25519PublicBase64) {
                return null;
            }

            const now = Date.now();
            if (normalizedCert.issuedAt > (now + CERT_CLOCK_SKEW_MS)) {
                return null;
            }
            if (normalizedCert.expiresAt <= (now - CERT_CLOCK_SKEW_MS)) {
                return null;
            }

            if (!isSelfSignedPeerCertificate(normalizedCert)) {
                return null;
            }

            const signature = CryptoUtils.Base64.base64ToUint8Array(normalizedCert.signature);
            const issuerKey = CryptoUtils.Base64.base64ToUint8Array(normalizedCert.proof);
            const canonical = encodePeerCertificateSigningPayload(normalizedCert);

            const valid = await CryptoUtils.Dilithium.verify(signature, canonical, issuerKey);
            if (!valid) {
                return null;
            }

            return normalizedCert;
        } catch {
            return null;
        }
    }, []);

    const validateDiscoveryMaterial = useCallback(async (
        targetHandle: string,
        material: OPRFDiscoveryMaterial | null
    ): Promise<OPRFDiscoveryMaterial | null> => {
        if (!material || typeof material !== 'object') {
            return null;
        }

        const inboxId = typeof material.inboxId === 'string' ? material.inboxId.trim() : '';
        if (!inboxId || !INBOX_ID_REGEX.test(inboxId)) {
            return null;
        }
        const routeId = isRendezvousRouteId(material.routeId)
            ? material.routeId
            : deriveRendezvousRouteId(inboxId);
        const mailboxLookupId = isRendezvousRouteId(material.mailboxLookupId)
            ? material.mailboxLookupId
            : deriveMailboxMetadataId(inboxId);
        const bundleLookupId = isRendezvousRouteId(material.bundleLookupId)
            ? material.bundleLookupId
            : deriveBundleLookupId(inboxId);
        const blockListLookupId = isRendezvousRouteId(material.blockListLookupId)
            ? material.blockListLookupId
            : deriveBlockListLookupId(inboxId);

        const sanitizedPublicKeys = sanitizeHybridKeys(material.publicKeys as any) as OPRFDiscoveryMaterial['publicKeys'];
        if (
            !sanitizedPublicKeys?.kyberPublicBase64 ||
            !sanitizedPublicKeys?.dilithiumPublicBase64 ||
            !sanitizedPublicKeys?.x25519PublicBase64
        ) {
            return null;
        }

        const validated: OPRFDiscoveryMaterial = {
            ...material,
            inboxId,
            routeId,
            mailboxLookupId,
            bundleLookupId,
            blockListLookupId,
            publicKeys: {
                ...sanitizedPublicKeys,
                x25519PublicBase64: sanitizedPublicKeys.x25519PublicBase64,
                kyberPublicBase64: sanitizedPublicKeys.kyberPublicBase64,
                dilithiumPublicBase64: sanitizedPublicKeys.dilithiumPublicBase64
            }
        };

        if (!material.peerCertificate || !material.certifiedPeerBundle) {
            return null;
        }

        const cert = await validatePeerCertificate(targetHandle, inboxId, validated.publicKeys, material.peerCertificate);
        if (!cert) {
            return null;
        }

        const peerCertificateFingerprint = computePeerCertificateFingerprint(cert);
        const certifiedIdentity = await validateCertifiedPeerBundleV2(material.certifiedPeerBundle, {
            targetHandle,
            inboxId,
            publicKeys: validated.publicKeys,
            fullBundle: material.fullBundle,
            peerCertificate: cert,
            peerCertificateFingerprint
        });
        if (!certifiedIdentity.valid || !certifiedIdentity.identityRootFingerprint || !certifiedIdentity.bundleFingerprint) {
            return null;
        }

        if (material.peerCertificateFingerprint && material.peerCertificateFingerprint.trim().toLowerCase() !== peerCertificateFingerprint) {
            return null;
        }
        if (material.identityRootFingerprint && material.identityRootFingerprint.trim().toLowerCase() !== certifiedIdentity.identityRootFingerprint) {
            return null;
        }
        if (material.identityBundleFingerprint && material.identityBundleFingerprint.trim().toLowerCase() !== certifiedIdentity.bundleFingerprint) {
            return null;
        }

        validated.peerCertificate = cert;
        validated.peerCertificateFingerprint = peerCertificateFingerprint;
        validated.certifiedPeerBundle = certifiedIdentity.bundle;
        validated.identityRootFingerprint = certifiedIdentity.identityRootFingerprint;
        validated.identityBundleFingerprint = certifiedIdentity.bundleFingerprint;

        if (validated.avatarRef && (typeof validated.avatarRef.blobId !== 'string' || typeof validated.avatarRef.keyB64 !== 'string')) {
            delete validated.avatarRef;
        }

        return validated;
    }, [validatePeerCertificate]);

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

    const normalizeRequestId = useCallback((value: unknown): string => {
        if (typeof value !== 'string') return '';
        const trimmed = value.trim();
        if (!trimmed) return '';
        return trimmed.slice(0, 128);
    }, []);

    const unregisterPendingDiscovery = useCallback((pending: PendingDiscoveryRequest) => {
        if (pending.timeoutId) {
            window.clearTimeout(pending.timeoutId);
            pending.timeoutId = 0;
        }
        pendingDiscoveryByRequestIdRef.current.delete(pending.requestId);
    }, []);

    const registerPendingDiscovery = useCallback((pending: PendingDiscoveryRequest) => {
        pending.timeoutId = window.setTimeout(() => {
            if (!pending.settled) {
                pending.settled = true;
                pending.resolve(null);
                unregisterPendingDiscovery(pending);
            }
        }, 60000);

        pendingDiscoveryByRequestIdRef.current.set(pending.requestId, pending);
    }, [unregisterPendingDiscovery]);


    const finalizeDiscoveryResult = useCallback(async (
        normalizedHandle: string,
        targetHandle: string,
        encryptedBlob: string | null,
        exists: boolean,
        encryptionKeys: Uint8Array[],
        cacheNegative = true
    ): Promise<OPRFDiscoveryMaterial | null> => {
        if (!exists || !encryptedBlob) {
            if (cacheNegative) {
                discoveryResultCache.set(normalizedHandle, {
                    value: null,
                    expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
                });
            }
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
            const validated = await validateDiscoveryMaterial(targetHandle, decrypted);
            if (!validated) {
                if (cacheNegative) {
                    discoveryResultCache.set(normalizedHandle, {
                        value: null,
                        expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
                    });
                }
                return null;
            }
            const isHashedHandle = /^[a-f0-9]{64}$/i.test(String(targetHandle || ''));
            const cacheUsername = validated.peerCertificate?.username || (!isHashedHandle ? String(targetHandle) : null);
            
            // Fetch avatar from the unlinkable content store in the background
            void cachePeerAvatarFromRef(cacheUsername, validated.avatarRef);
            discoveryResultCache.set(normalizedHandle, {
                value: validated,
                expiresAt: Date.now() + DISCOVERY_POSITIVE_CACHE_TTL_MS
            });
            return validated;
        }

        if (cacheNegative) {
            discoveryResultCache.set(normalizedHandle, {
                value: null,
                expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
            });
        }
        return null;
    }, [validateDiscoveryMaterial]);

    const finalizeDiscoverySnapshotResult = useCallback(async (
        normalizedHandle: string,
        targetHandle: string,
        encryptedBlobs: string[],
        encryptionKeys: Uint8Array[],
        cacheNegative = true
    ): Promise<OPRFDiscoveryMaterial | null> => {
        for (const encryptedBlob of encryptedBlobs) {
            if (typeof encryptedBlob !== 'string' || encryptedBlob.length === 0) continue;
            for (const key of encryptionKeys) {
                if (!key) continue;
                let material: OPRFDiscoveryMaterial | null = null;
                try {
                    material = oprfDiscoveryClient.decryptDiscoveryBlob(encryptedBlob, key);
                } catch { }
                if (!material) continue;

                const validated = await validateDiscoveryMaterial(targetHandle, material);
                if (!validated) continue;

                const isHashedHandle = /^[a-f0-9]{64}$/i.test(String(targetHandle || ''));
                const cacheUsername = validated.peerCertificate?.username || (!isHashedHandle ? String(targetHandle) : null);
                void cachePeerAvatarFromRef(cacheUsername, validated.avatarRef);

                discoveryResultCache.set(normalizedHandle, {
                    value: validated,
                    expiresAt: Date.now() + DISCOVERY_POSITIVE_CACHE_TTL_MS
                });
                return validated;
            }
        }

        if (cacheNegative) {
            discoveryResultCache.set(normalizedHandle, {
                value: null,
                expiresAt: Date.now() + DISCOVERY_NEGATIVE_CACHE_TTL_MS
            });
        }
        return null;
    }, [validateDiscoveryMaterial]);

    const resolvePendingDiscovery = useCallback(async (
        pending: PendingDiscoveryRequest,
        encryptedBlob: string | null,
        exists: boolean
    ) => {
        if (pending.settled) return;
        pending.settled = true;
        unregisterPendingDiscovery(pending);
        if (pending.timeoutId) clearTimeout(pending.timeoutId);

        const decrypted = await finalizeDiscoveryResult(
            pending.normalizedHandle,
            pending.targetHandle,
            encryptedBlob,
            exists,
            pending.encryptionKeys,
            pending.cacheNegative !== false
        );
        logDiscoveryLookup(decrypted ? 'info' : 'warn', 'direct-result', {
            requestId: pending.requestId,
            handle: pending.normalizedHandle,
            exists,
            encryptedBlobSizeClass: byteClass(typeof encryptedBlob === 'string' ? encryptedBlob.length : 0),
            result: decrypted ? 'found' : 'not-found-or-not-decryptable'
        });
        pending.resolve(decrypted);
    }, [finalizeDiscoveryResult, unregisterPendingDiscovery]);

    const resolvePendingDiscoverySnapshot = useCallback(async (
        pending: PendingDiscoveryRequest,
        encryptedBlobs: string[]
    ) => {
        if (pending.settled) return;
        pending.settled = true;
        unregisterPendingDiscovery(pending);
        if (pending.timeoutId) clearTimeout(pending.timeoutId);

        const decrypted = await finalizeDiscoverySnapshotResult(
            pending.normalizedHandle,
            pending.targetHandle,
            encryptedBlobs,
            pending.encryptionKeys,
            pending.cacheNegative !== false
        );
        logDiscoveryLookup(decrypted ? 'info' : 'warn', 'snapshot-result', {
            requestId: pending.requestId,
            handle: pending.normalizedHandle,
            encryptedBlobCountClass: countClass(encryptedBlobs.length),
            result: decrypted ? 'found' : 'not-found-or-not-decryptable'
        });
        pending.resolve(decrypted);
    }, [finalizeDiscoverySnapshotResult, unregisterPendingDiscovery]);

    const findDiscoveryBlobsViaPir = useCallback(async (
        tokens: string[]
    ): Promise<string[]> => {
        const normalizedTokens = Array.from(new Set(
            tokens
                .map((token) => typeof token === 'string' ? token.trim().toLowerCase() : '')
                .filter((token) => /^[a-f0-9]{64}$/i.test(token))
        ));
        if (normalizedTokens.length === 0) {
            logDiscoveryLookup('warn', 'pir-skip', { reason: 'no-valid-tokens' });
            return [];
        }

        try {
            const startedAt = Date.now();
            markPirInteractiveActivity(DISCOVERY_PIR_FOREGROUND_ACTIVITY_MS);
            logDiscoveryLookup('info', 'pir-start', {
                tokenCountClass: countClass(normalizedTokens.length),
                timeoutMs: DISCOVERY_PIR_LOOKUP_TIMEOUT_MS,
                maxCandidatesPerToken: DISCOVERY_PIR_LOOKUP_CANDIDATES_PER_TOKEN,
                concurrency: DISCOVERY_PIR_LOOKUP_CONCURRENCY
            });
            const blobs = await fetchPirEncryptedBlobsForTokens(normalizedTokens, {
                timeoutMs: DISCOVERY_PIR_LOOKUP_TIMEOUT_MS,
                maxCandidatesPerToken: DISCOVERY_PIR_LOOKUP_CANDIDATES_PER_TOKEN,
                concurrency: DISCOVERY_PIR_LOOKUP_CONCURRENCY
            });
            const seen = new Set<string>();
            const results: string[] = [];
            for (const blob of blobs) {
                if (!seen.has(blob)) {
                    seen.add(blob);
                    results.push(blob);
                }
            }
            logDiscoveryLookup(results.length > 0 ? 'info' : 'warn', 'pir-result', {
                tokenCountClass: countClass(normalizedTokens.length),
                encryptedBlobCountClass: countClass(results.length),
                elapsedMs: Date.now() - startedAt
            });
            return results;
        } catch (error) {
            logDiscoveryLookup('warn', 'pir-error', {
                tokenCountClass: countClass(normalizedTokens.length),
                error: error instanceof Error ? error.message : String(error)
            });
            throw error;
        }
    }, []);

    useEffect(() => {
        if (!isDiscoveryTransportReady(false)) {
            traceDiscoveryClient('pir-prewarm.effect-skip', {
                reason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }

        let cancelled = false;
        const timer = window.setTimeout(() => {
            if (cancelled || !isDiscoveryTransportReady(false)) return;
            const now = Date.now();
            if (pirSetupPrewarmInFlightRef.current) {
                traceDiscoveryClient('pir-prewarm.skip', { reason: 'in-flight' });
                return;
            }
            if (now - lastPirSetupPrewarmAtRef.current < DISCOVERY_PIR_SETUP_PREWARM_MIN_INTERVAL_MS) {
                traceDiscoveryClient('pir-prewarm.skip', { reason: 'recent' });
                return;
            }

            lastPirSetupPrewarmAtRef.current = now;
            logDiscoveryLookup('info', 'pir-prewarm-start', {
                timeoutMs: DISCOVERY_PIR_LOOKUP_TIMEOUT_MS,
                background: true
            });
            const prewarm = requestPirManifest({
                prepareWorker: true,
                timeoutMs: DISCOVERY_PIR_LOOKUP_TIMEOUT_MS,
                background: true,
                kind: DISCOVERY_PIR_DATABASE_KIND
            }).then((response) => {
                logDiscoveryLookup(response?.success ? 'info' : 'warn', 'pir-prewarm-complete', {
                    success: response?.success === true,
                    error: response?.success ? undefined : response?.error || 'pir_prewarm_failed',
                    elapsedMs: Date.now() - now
                });

                if (!response?.success) {
                    lastPirSetupPrewarmAtRef.current = 0;
                }
            }).catch((error) => {
                logDiscoveryLookup('warn', 'pir-prewarm-error', {
                    error: error instanceof Error ? error.message : String(error),
                    elapsedMs: Date.now() - now
                });
                lastPirSetupPrewarmAtRef.current = 0;
            }).finally(() => {
                if (pirSetupPrewarmInFlightRef.current === prewarm) {
                    pirSetupPrewarmInFlightRef.current = null;
                }
            });
            pirSetupPrewarmInFlightRef.current = prewarm;
        }, DISCOVERY_PIR_SETUP_PREWARM_DELAY_MS);

        return () => {
            cancelled = true;
            window.clearTimeout(timer);
        };
    }, [discoveryPublishSnapshot, discoveryTransportReadyVersion, isDiscoveryTransportReady]);

    useEffect(() => {
        if (!effectiveHandle) {
            traceDiscoveryClient('pir-cover.effect-skip', { reason: 'missing-effective-handle' });
            return;
        }
        if (!isDiscoveryTransportReady(false)) {
            traceDiscoveryClient('pir-cover.effect-skip', {
                reason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        let cancelled = false;
        let inFlight = false;

        const runCoverRound = async () => {
            if (cancelled || inFlight) {
                traceDiscoveryClient('pir-cover.round-skip', {
                    reason: cancelled ? 'cancelled' : 'in-flight'
                });
                return;
            }
            if (!isDiscoveryTransportReady()) {
                traceDiscoveryClient('pir-cover.round-skip', {
                    reason: 'transport-not-ready',
                    snapshot: discoveryPublishSnapshot()
                });
                return;
            }
            
            if (isPirInteractive()) {
                traceDiscoveryClient('pir-cover.round-skip', { reason: 'interactive-lookup' });
                return;
            }

            inFlight = true;
            try {
                traceDiscoveryClient('pir-cover.round-start');
                await runPirCoverQueries({
                    records: DISCOVERY_PIR_COVER_RECORDS_PER_KIND,
                    timeoutMs: 120_000,
                    background: true,
                    kind: DISCOVERY_PIR_DATABASE_KIND
                });
                traceDiscoveryClient('pir-cover.round-complete');
            } catch (error) {
                traceDiscoveryClient('pir-cover.round-error', {
                    error: error instanceof Error ? error.message : String(error)
                }, 'warn');
            } finally {
                inFlight = false;
            }
        };

        traceDiscoveryClient('pir-cover.effect-mounted', {
            meanIntervalMs: DISCOVERY_PIR_COVER_INTERVAL_MS
        });
        
        let coverTimer: number | null = null;
        const scheduleNextCover = () => {
            if (cancelled) return;
            coverTimer = window.setTimeout(async () => {
                traceDiscoveryClient('pir-cover.timer-fired');
                try { await runCoverRound(); } finally { scheduleNextCover(); }
            }, nextDiscoveryCoverDelayMs());
        };
        scheduleNextCover();

        return () => {
            cancelled = true;
            if (coverTimer != null) window.clearTimeout(coverTimer);
            traceDiscoveryClient('pir-cover.effect-unmounted');
        };
    }, [effectiveHandle, isDiscoveryTransportReady, discoveryPublishSnapshot, discoveryTransportReadyVersion]);

    /**
     * Derives discovery tokens for one or more epochs using a single OPRF evaluation
     */
    const getDiscoveryTokensForEpochs = useCallback(async (
        targetHandle: string,
        epochs: number[]
    ): Promise<Map<number, { token: string; encryptionKey: Uint8Array }> | null> => {
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) {
            traceDiscoveryClient('tokens.skip', { reason: 'normalized-handle-empty' }, 'warn');
            return null;
        }

        const uniqueEpochs = Array.from(new Set(
            (Array.isArray(epochs) ? epochs : [])
                .filter((value) => Number.isFinite(value))
                .map((value) => Math.trunc(value))
        ));
        traceDiscoveryClient('tokens.start', {
            epochCountClass: countClass(uniqueEpochs.length),
            cacheSizeClass: countClass(discoveryTokenCache.size)
        });
        if (uniqueEpochs.length === 0) {
            traceDiscoveryClient('tokens.complete', { result: 'empty-epoch-list' });
            return new Map();
        }

        const results = new Map<number, { token: string; encryptionKey: Uint8Array }>();
        const missingEpochs: number[] = [];

        for (const epoch of uniqueEpochs) {
            const cacheKey = `${normalizedHandle}:${epoch}`;
            const cachedPromise = discoveryTokenCache.get(cacheKey);
            if (!cachedPromise) {
                missingEpochs.push(epoch);
                continue;
            }
            const cached = await cachedPromise.catch(() => null);
            if (!cached) {
                missingEpochs.push(epoch);
                continue;
            }
            results.set(epoch, cached);
        }

        if (missingEpochs.length === 0) {
            traceDiscoveryClient('tokens.cache-hit-all', {
                epochCountClass: countClass(uniqueEpochs.length)
            });
            return results;
        }

        traceDiscoveryClient('tokens.cache-miss', {
            requestedEpochClass: countClass(uniqueEpochs.length),
            missingEpochClass: countClass(missingEpochs.length),
            cachedEpochClass: countClass(results.size)
        });
        const evaluation = await evaluateHandleWithOprf(normalizedHandle, 'lookup');
        if (!evaluation) {
            traceDiscoveryClient('tokens.oprf-evaluation-failed', {
                missingEpochClass: countClass(missingEpochs.length)
            }, 'warn');
            return null;
        }

        const derived = oprfDiscoveryClient.finalizeTokenBatch(
            normalizedHandle,
            evaluation.blindResult,
            evaluation.response,
            missingEpochs
        );
        for (const derivedToken of derived.tokens) {
            const value = {
                token: derivedToken.token,
                encryptionKey: derived.encryptionKey
            };
            results.set(derivedToken.epoch, value);

            const cacheKey = `${normalizedHandle}:${derivedToken.epoch}`;
            const cachedPromise = Promise.resolve(value);
            discoveryTokenCache.set(cacheKey, cachedPromise);
            window.setTimeout(() => {
                if (discoveryTokenCache.get(cacheKey) === cachedPromise) {
                    discoveryTokenCache.delete(cacheKey);
                }
            }, DISCOVERY_TOKEN_CACHE_TTL_MS);
        }

        traceDiscoveryClient('tokens.complete', {
            derivedEpochClass: countClass(derived.tokens.length),
            totalEpochClass: countClass(results.size)
        });
        return results;
    }, [getDiscoveryHandle]);

    const evaluateHandleWithOprf = useCallback(async (
        normalizedHandle: string,
        purpose: 'lookup' | 'publish' | 'cover' = 'lookup'
    ): Promise<{ blindResult: OPRFBlindResult; response: OPRFServerResponse } | null> => {
        if (!normalizedHandle) {
            traceDiscoveryClient('oprf-eval.skip', { reason: 'normalized-handle-empty' }, 'warn');
            logDiscoveryOprf('warn', 'eval-skip', { purpose, reason: 'normalized-handle-empty' });
            return null;
        }

        traceDiscoveryClient('oprf-eval.start', {
            snapshot: discoveryPublishSnapshot()
        });
        markPirInteractiveActivity(OPRF_EVAL_SEND_TIMEOUT_MS + OPRF_EVAL_RESPONSE_TIMEOUT_MS + 10_000);
        logDiscoveryOprf('info', 'eval-start', {
            purpose,
            handle: normalizedHandle,
            transportReady: isDiscoveryTransportReady(false)
        });
        const [oprfState, sessionReady] = await Promise.all([
            waitForOprfState('oprf-token-batch'),
            waitForPqSession()
        ]);
        if (!oprfState?.publicKey) {
            traceDiscoveryClient('oprf-eval.blocked', {
                reason: 'missing-oprf-state',
                sessionReady
            }, 'warn');
            logDiscoveryOprf('warn', 'eval-blocked', {
                purpose,
                handle: normalizedHandle,
                reason: 'missing-oprf-state',
                sessionReady
            });
            return null;
        }
        if (!sessionReady) {
            traceDiscoveryClient('oprf-eval.blocked', {
                reason: 'pq-session-not-ready',
                hasOprfState: !!oprfState?.publicKey
            }, 'warn');
            logDiscoveryOprf('warn', 'eval-blocked', {
                purpose,
                handle: normalizedHandle,
                reason: 'pq-session-not-ready',
                hasOprfState: !!oprfState?.publicKey
            });
            return null;
        }

        const blindResult = oprfDiscoveryClient.blindHandle(normalizedHandle);
        const blindedHex = Array.from(blindResult.blinded).map(b => b.toString(16).padStart(2, '0')).join('');
        const oprfRequestId = `oprf-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
        traceDiscoveryClient('oprf-eval.blinded', {
            blindedSizeClass: byteClass(blindedHex.length),
            epoch: oprfState.epoch,
            hasRequestId: true
        });
        logDiscoveryOprf('info', 'eval-request-ready', {
            purpose,
            handle: normalizedHandle,
            requestId: oprfRequestId,
            epoch: oprfState.epoch,
            sendTimeoutMs: OPRF_EVAL_SEND_TIMEOUT_MS,
            responseTimeoutMs: OPRF_EVAL_RESPONSE_TIMEOUT_MS
        });

        // Dedicated isolated Tor circuit (no WS fallback)
        try {
            const httpResp: any = await pir.discoveryApiFetch('oprf/evaluate', JSON.stringify({ blindedPoint: blindedHex }));
            if (httpResp?.ok === true
                && typeof httpResp.evaluated === 'string'
                && typeof httpResp.proof === 'string'
                && typeof httpResp.publicKey === 'string') {
                logDiscoveryOprf('info', 'eval-response', {
                    purpose, handle: normalizedHandle, requestId: oprfRequestId, epoch: oprfState.epoch, via: 'dedicated'
                });
                return { blindResult, response: { evaluated: httpResp.evaluated, proof: httpResp.proof, publicKey: httpResp.publicKey } };
            }
            logDiscoveryOprf('warn', 'eval-error-response', {
                purpose, handle: normalizedHandle, requestId: oprfRequestId, epoch: oprfState.epoch, via: 'dedicated', err: (httpResp as any)?.error
            });
            return null;
        } catch (e) {
            logDiscoveryOprf('warn', 'eval-error-response', {
                purpose, handle: normalizedHandle, requestId: oprfRequestId, epoch: oprfState.epoch, via: 'dedicated', err: e instanceof Error ? e.message : String(e)
            });
            return null;
        }
    }, [waitForOprfState, waitForPqSession, discoveryPublishSnapshot, isDiscoveryTransportReady]);

    /**
     * Publishes current identity to the billboard using OPRF-derived tokens
     */
    const publishSelf = useCallback(async (force = false): Promise<boolean> => {
        traceDiscoveryClient('publish.enter', {
            forced: force,
            snapshot: discoveryPublishSnapshot()
        });
        const fail = (reason: string) => {
            lastPublishFailureRef.current = reason;
            const preReadyReason = isPreReadyPublishFailure(reason);
            logDiscoveryPublish(preReadyReason ? 'info' : 'warn', 'publish-skip', {
                reason,
                forced: force,
                ...discoveryPublishSnapshot()
            }, `publish-skip:${reason}`);
            traceDiscoveryClient('publish.fail', {
                reason,
                forced: force,
                preReadyReason,
                snapshot: discoveryPublishSnapshot()
            }, preReadyReason ? 'info' : 'warn');
            return false;
        };


        if (!effectiveHandle) return fail('missing-handle');
        if (!isDiscoverable) return fail('not-discoverable');
        if (publishPromiseRef.current) {
            traceDiscoveryClient('publish.reuse-inflight', {
                forced: force,
                snapshot: discoveryPublishSnapshot()
            });
            return publishPromiseRef.current;
        }
        if (!isDiscoveryTransportReady()) return fail('auth-transport-not-ready');

        const now = Date.now();
        const minAttemptDelay = force ? publishForceAttemptDelayMs(lastPublishFailureRef.current) : 30000;
        const lastAttemptSucceeded = lastPublishedRef.current > 0 && !lastPublishFailureRef.current;
        if (now - lastPublishAttemptRef.current < minAttemptDelay) {
            logDiscoveryPublish('info', 'publish-throttled', {
                forced: force,
                lastAttemptSucceeded,
                lastFailure: lastPublishFailureRef.current || undefined,
                minAttemptDelay
            }, `publish-throttled:${lastAttemptSucceeded ? 'success' : 'failed'}`);
            traceDiscoveryClient('publish.throttled', {
                forced: force,
                minAttemptDelay,
                lastAttemptSucceeded,
                lastFailure: lastPublishFailureRef.current || undefined,
                sinceLastAttemptMs: now - lastPublishAttemptRef.current,
                snapshot: discoveryPublishSnapshot()
            });
            return lastAttemptSucceeded;
        }
        lastPublishAttemptRef.current = now;

        const publishPromise = (async (): Promise<boolean> => {
            publishingRef.current = true;
            const attemptId = ++publishAttemptSeqRef.current;
            logDiscoveryPublish('info', 'publish-start', {
                attemptId,
                forced: force,
                ...discoveryPublishSnapshot()
            }, `publish-start:${attemptId}`);
            traceDiscoveryClient('publish.attempt-start', {
                attemptId,
                forced: force,
                snapshot: discoveryPublishSnapshot()
            });
            try {
                let inboxId: string | null = null;
                let routeId: string | null = null;
                let mailboxLookupId: string | null = null;
                let bundleLookupId: string | null = null;
                let blockListLookupId: string | null = null;
                try {
                    traceDiscoveryClient('publish.blind-routing.lookup-start', {
                        attemptId,
                        hasSignalUsername: !!signalUsername,
                        hasEffectiveHandle: !!effectiveHandle
                    });
                    const blindClient = getBlindRoutingClient(signalUsername || effectiveHandle);
                    inboxId = blindClient.getMyInboxId();
                    routeId = blindClient.getMyRouteId();
                    mailboxLookupId = blindClient.getMyMailboxLookupId();
                    bundleLookupId = blindClient.getMyBundleLookupId();
                    blockListLookupId = blindClient.getMyBlockListLookupId();
                    traceDiscoveryClient('publish.blind-routing.lookup-result', {
                        attemptId,
                        hasInboxId: !!inboxId,
                        hasRouteId: !!routeId,
                        hasMailboxLookupId: !!mailboxLookupId,
                        hasBundleLookupId: !!bundleLookupId,
                        hasBlockListLookupId: !!blockListLookupId
                    });
                } catch (error) {
                    traceDiscoveryClient('publish.blind-routing.lookup-error', {
                        attemptId,
                        error: error instanceof Error ? error.message : String(error)
                    }, 'warn');
                    return fail('blind-routing-client-missing');
                }

                if (!inboxId) {

                    const waitStart = Date.now();
                    traceDiscoveryClient('publish.blind-routing.wait-inbox-start', {
                        attemptId,
                        timeoutMs: 3000
                    });
                    while (!inboxId && Date.now() - waitStart < 3000) {
                        await new Promise(resolve => setTimeout(resolve, 250));
                        try {
                            const blindClient = getBlindRoutingClient(signalUsername || effectiveHandle);
                            inboxId = blindClient.getMyInboxId();
                            routeId = blindClient.getMyRouteId();
                            mailboxLookupId = blindClient.getMyMailboxLookupId();
                            bundleLookupId = blindClient.getMyBundleLookupId();
                            blockListLookupId = blindClient.getMyBlockListLookupId();
                        } catch { break; }
                    }
                    traceDiscoveryClient('publish.blind-routing.wait-inbox-result', {
                        attemptId,
                        hasInboxId: !!inboxId,
                        waitedMs: Date.now() - waitStart
                    }, inboxId ? 'info' : 'warn');
                    if (!inboxId) return fail('missing-inbox-id');
                }

                const derivedRouteId = !routeId;
                const derivedMailboxLookupId = !mailboxLookupId;
                const derivedBundleLookupId = !bundleLookupId;
                const derivedBlockListLookupId = !blockListLookupId;
                routeId = routeId || deriveRendezvousRouteId(inboxId);
                mailboxLookupId = mailboxLookupId || deriveMailboxMetadataId(inboxId);
                bundleLookupId = bundleLookupId || deriveBundleLookupId(inboxId);
                blockListLookupId = blockListLookupId || deriveBlockListLookupId(inboxId);
                traceDiscoveryClient('publish.route-material-ready', {
                    attemptId,
                    derivedRouteId,
                    derivedMailboxLookupId,
                    derivedBundleLookupId,
                    derivedBlockListLookupId,
                    hasInboxId: !!inboxId,
                    hasRouteId: !!routeId,
                    hasMailboxLookupId: !!mailboxLookupId,
                    hasBundleLookupId: !!bundleLookupId,
                    hasBlockListLookupId: !!blockListLookupId
                });


                const bundleUsername = signalUsername || effectiveHandle;
                let bundle: any = null;
                const cachedBundle = cachedBundleRef.current;
                if (
                    cachedBundle &&
                    cachedBundle.username === bundleUsername &&
                    cachedBundle.expiresAt > now
                ) {
                    bundle = cachedBundle.bundle;
                    traceDiscoveryClient('publish.prekey-bundle.cache-hit', {
                        attemptId,
                        expiresInMs: cachedBundle.expiresAt - now
                    });

                } else {
                    traceDiscoveryClient('publish.prekey-bundle.create-start', {
                        attemptId,
                        hadCachedBundle: !!cachedBundle
                    });
                    try {
                        bundle = await signal.createPreKeyBundle(bundleUsername);
                    } catch (error) {
                        traceDiscoveryClient('publish.prekey-bundle.create-error', {
                            attemptId,
                            error: error instanceof Error ? error.message : String(error)
                        }, 'warn');
                        throw error;
                    }
                    traceDiscoveryClient('publish.prekey-bundle.create-result', {
                        attemptId,
                        hasBundle: !!bundle
                    }, bundle ? 'info' : 'warn');
                    if (bundle) {
                        cachedBundleRef.current = {
                            username: bundleUsername,
                            bundle,
                            expiresAt: now + PREKEY_BUNDLE_CACHE_TTL_MS
                        };
                        // The prekey bundle is embedded in the discovery blob below (fullBundle); there
                        // is no separate server-side bundle publish (the old table was never read).
                    }

                }
                if (!bundle) {
                    traceDiscoveryClient('publish.prekey-bundle.missing', { attemptId }, 'warn');
                    return fail('bundle-create-failed');
                }

                const kyberKey = hybridKeysRef?.current?.kyber?.publicKeyBase64;
                const dilithiumKey = hybridKeysRef?.current?.dilithium?.publicKeyBase64;
                const x25519Key = hybridKeysRef?.current?.x25519?.publicKeyBase64;
                let localP2PEndpoint: string | null = null;
                if (isTauri()) {
                    traceDiscoveryClient('publish.p2p-endpoint.lookup-start', { attemptId });
                    try {
                        localP2PEndpoint = await p2p.getLocalEndpoint();
                        traceDiscoveryClient('publish.p2p-endpoint.lookup-result', {
                            attemptId,
                            hasEndpoint: !!localP2PEndpoint
                        });
                    } catch (error) {
                        traceDiscoveryClient('publish.p2p-endpoint.lookup-error', {
                            attemptId,
                            error: error instanceof Error ? error.message : String(error)
                        }, 'warn');
                        localP2PEndpoint = null;
                    }
                } else {
                    traceDiscoveryClient('publish.p2p-endpoint.skip', {
                        attemptId,
                        reason: 'not-tauri'
                    });
                }

                const accountRootKey = hybridKeysRef?.current?.accountRoot?.publicKeyBase64;
                const accountRootSecretKey = hybridKeysRef?.current?.accountRoot?.secretKey;
                const deviceDilithiumSecretKey = hybridKeysRef?.current?.dilithium?.secretKey;
                traceDiscoveryClient('publish.identity-keys.check', {
                    attemptId,
                    hasKyberPublic: !!kyberKey,
                    hasDilithiumPublic: !!dilithiumKey,
                    hasDilithiumSecret: !!deviceDilithiumSecretKey,
                    hasX25519Public: !!x25519Key,
                    hasAccountRootPublic: !!accountRootKey,
                    hasAccountRootSecret: !!accountRootSecretKey
                });
                if (!kyberKey || !dilithiumKey || !x25519Key || !accountRootKey || !accountRootSecretKey || !deviceDilithiumSecretKey) {
                    return fail('missing-certified-identity-keys');
                }


                traceDiscoveryClient('publish.peer-certificate.build-start', { attemptId });
                const peerCertificate = await buildSelfPeerCertificate(
                    String(bundleUsername),
                    inboxId,
                    hybridKeysRef?.current,
                    localP2PEndpoint
                );
                traceDiscoveryClient('publish.peer-certificate.build-result', {
                    attemptId,
                    hasPeerCertificate: !!peerCertificate
                }, peerCertificate ? 'info' : 'warn');
                if (!peerCertificate) return fail('peer-certificate-create-failed');

                const peerCertificateFingerprint = computePeerCertificateFingerprint(peerCertificate);
                traceDiscoveryClient('publish.certified-bundle.build-start', {
                    attemptId,
                    hasPeerCertificateFingerprint: !!peerCertificateFingerprint
                });
                const certifiedPeerBundle = await buildCertifiedPeerBundleV2({
                    username: String(bundleUsername),
                    inboxId,
                    publicKeys: {
                        kyberPublicBase64: kyberKey,
                        dilithiumPublicBase64: dilithiumKey,
                        x25519PublicBase64: x25519Key
                    },
                    fullBundle: bundle,
                    peerCertificate,
                    peerCertificateFingerprint,
                    accountRootPublicKey: accountRootKey,
                    accountRootSecretKey,
                    deviceDilithiumSecretKey
                });
                traceDiscoveryClient('publish.certified-bundle.build-result', {
                    attemptId,
                    hasCertifiedPeerBundle: !!certifiedPeerBundle,
                    hasIdentityRootFingerprint: !!certifiedPeerBundle?.identityRootFingerprint,
                    hasBundleFingerprint: !!certifiedPeerBundle?.bundleFingerprint
                });

                const avatar = await getAvatarForDiscovery(String(bundleUsername));
                void ensureAvatarCoverBlobs();
                const avatarRef = avatar ? await publishAvatarToStore(avatar) : null;
                console.log('[AVATAR] self-publish to content store', {
                    hasAvatar: !!avatar, isDefault: (avatar as any)?.isDefault === true, uploadedRef: !!avatarRef
                });
                traceDiscoveryClient('publish.avatar.result', {
                    attemptId,
                    hasAvatar: !!avatar,
                    hasAvatarRef: !!avatarRef,
                    isDefaultAvatar: avatar?.isDefault === true,
                    avatarSizeClass: typeof avatar?.data === 'string' ? byteClass(avatar.data.length) : 'none'
                });

                const material: OPRFDiscoveryMaterial = {
                    inboxId,
                    routeId,
                    mailboxLookupId,
                    bundleLookupId,
                    blockListLookupId,
                    publicKeys: {
                        kyberPublicBase64: kyberKey,
                        dilithiumPublicBase64: dilithiumKey,
                        x25519PublicBase64: x25519Key
                    },
                    fullBundle: bundle,
                    peerCertificate,
                    peerCertificateFingerprint,
                    certifiedPeerBundle,
                    identityRootFingerprint: certifiedPeerBundle.identityRootFingerprint,
                    identityBundleFingerprint: certifiedPeerBundle.bundleFingerprint,
                    avatarRef: avatarRef || undefined
                };

                const materialFingerprint = hashDiscoveryMaterial(material);
                traceDiscoveryClient('publish.material.ready', {
                    attemptId,
                    hasFullBundle: !!material.fullBundle,
                    hasPeerCertificate: !!material.peerCertificate,
                    hasCertifiedPeerBundle: !!material.certifiedPeerBundle,
                    hasAvatarRef: !!material.avatarRef
                });


                // Build publish token set
                traceDiscoveryClient('publish.oprf-state.wait', { attemptId });
                const oprfState = await waitForOprfState('publish-missing-epoch');
                if (!oprfState || oprfState.epoch === undefined) {
                    traceDiscoveryClient('publish.oprf-state.missing', {
                        attemptId,
                        hasOprfState: !!oprfState,
                        hasEpoch: oprfState?.epoch !== undefined
                    }, 'warn');
                    return fail('missing-oprf-epoch');
                }
                const { epoch, previousEpoch, publicKey } = oprfState;
                traceDiscoveryClient('publish.oprf-state.ready', {
                    attemptId,
                    epoch,
                    hasPreviousEpoch: previousEpoch !== undefined
                });
                const contextFingerprint = `${publicKey || 'no-key'}:${epoch}:${materialFingerprint}`;
                if (lastPublishedContextFingerprintRef.current === contextFingerprint) {
                    traceDiscoveryClient('publish.skip', {
                        attemptId,
                        reason: 'context-already-published'
                    });
                    return true;
                }


                const publishEpochs: number[] = [epoch];
                if (previousEpoch !== undefined && previousEpoch !== epoch) {
                    publishEpochs.push(previousEpoch);
                }
                for (let i = 1; i <= DISCOVERY_FORWARD_PUBLISH_EPOCHS; i += 1) {
                    publishEpochs.push(epoch + i);
                }

                const uniqueEpochs = Array.from(new Set(publishEpochs));
                traceDiscoveryClient('publish.epochs.selected', {
                    attemptId,
                    epochCountClass: countClass(uniqueEpochs.length),
                    hasPreviousEpoch: previousEpoch !== undefined,
                    forwardEpochs: DISCOVERY_FORWARD_PUBLISH_EPOCHS
                });
                const normalizedPublishHandle = getDiscoveryHandle(effectiveHandle);
                if (!normalizedPublishHandle) {
                    traceDiscoveryClient('publish.handle-normalization.failed', { attemptId }, 'warn');
                    return fail('oprf-token-missing');
                }
                const epochTokenResults: Array<{ epoch: number; token: string; encryptionKey: Uint8Array }> = [];
                const missingEpochs: number[] = [];

                for (const publishEpoch of uniqueEpochs) {
                    const cacheKey = `${normalizedPublishHandle}:${publishEpoch}`;
                    const cachedPromise = discoveryTokenCache.get(cacheKey);
                    if (!cachedPromise) {
                        missingEpochs.push(publishEpoch);
                        continue;
                    }
                    const cached = await cachedPromise.catch(() => null);
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
                traceDiscoveryClient('publish.tokens.cache-scan-complete', {
                    attemptId,
                    cachedEpochClass: countClass(epochTokenResults.length),
                    missingEpochClass: countClass(missingEpochs.length)
                });

                if (missingEpochs.length > 0) {
                    traceDiscoveryClient('publish.tokens.oprf-needed', {
                        attemptId,
                        missingEpochClass: countClass(missingEpochs.length)
                    });
                    const evaluation = await evaluateHandleWithOprf(normalizedPublishHandle, 'publish');
                    if (!evaluation) {
                        traceDiscoveryClient('publish.tokens.oprf-failed', {
                            attemptId,
                            missingEpochClass: countClass(missingEpochs.length)
                        }, 'warn');
                        return fail('oprf-token-missing');
                    }

                    const derived = oprfDiscoveryClient.finalizeTokenBatch(
                        normalizedPublishHandle,
                        evaluation.blindResult,
                        evaluation.response,
                        missingEpochs
                    );
                    for (const derivedToken of derived.tokens) {
                        const value = { token: derivedToken.token, encryptionKey: derived.encryptionKey };
                        epochTokenResults.push({
                            epoch: derivedToken.epoch,
                            token: derivedToken.token,
                            encryptionKey: derived.encryptionKey
                        });

                        const cacheKey = `${normalizedPublishHandle}:${derivedToken.epoch}`;
                        const cachedPromise = Promise.resolve(value);
                        discoveryTokenCache.set(cacheKey, cachedPromise);
                        window.setTimeout(() => {
                            if (discoveryTokenCache.get(cacheKey) === cachedPromise) {
                                discoveryTokenCache.delete(cacheKey);
                            }
                        }, DISCOVERY_TOKEN_CACHE_TTL_MS);
                    }
                    traceDiscoveryClient('publish.tokens.derived', {
                        attemptId,
                        derivedEpochClass: countClass(derived.tokens.length),
                        cacheSizeClass: countClass(discoveryTokenCache.size)
                    });
                }

                if (epochTokenResults.length === 0) {
                    traceDiscoveryClient('publish.tokens.empty', { attemptId }, 'warn');
                    return fail('oprf-token-missing');
                }
                const currentResult = epochTokenResults.find((entry) => entry.epoch === epoch);
                if (!currentResult) {
                    traceDiscoveryClient('publish.tokens.current-missing', {
                        attemptId,
                        epoch,
                        tokenResultClass: countClass(epochTokenResults.length)
                    }, 'warn');
                    return fail('oprf-token-missing');
                }

                const tokenBatch = Array.from(new Set(epochTokenResults.map((entry) => entry.token)));
                const previousResult = previousEpoch !== undefined
                    ? epochTokenResults.find((entry) => entry.epoch === previousEpoch)
                    : undefined;
                traceDiscoveryClient('publish.tokens.ready', {
                    attemptId,
                    tokenBatchClass: countClass(tokenBatch.length),
                    hasCurrentToken: !!currentResult.token,
                    hasPreviousEpochToken: !!previousResult?.token
                });

                // derive the bucket entries server will store
                const publishKeyB64 = hybridKeysRef.current?.dilithium?.publicKeyBase64 || '';
                const bucketBatch = await buildDiscoveryBucketBatch(tokenBatch, publishKeyB64);
                if (!bucketBatch) {
                    traceDiscoveryClient('publish.bucket-batch-unavailable', { attemptId }, 'warn');
                    return fail('discovery-manifest-not-ready');
                }

                const publishFingerprint = `${currentResult.token}:${materialFingerprint}`;
                if (lastPublishedFingerprintRef.current === publishFingerprint) {

                    traceDiscoveryClient('publish.skip', {
                        attemptId,
                        reason: 'fingerprint-already-published'
                    });
                    return true;
                }

                const encryptedBlob = oprfDiscoveryClient.encryptDiscoveryBlob(material, currentResult.encryptionKey);
                lastDiscoveryPublishBlobLengthRef.current = Math.max(encryptedBlob.length, DISCOVERY_COVER_BLOB_CHARS);
                traceDiscoveryClient('publish.encrypted-blob.ready', {
                    attemptId,
                    encryptedBlobSizeClass: byteClass(encryptedBlob.length),
                    coverFloorSizeClass: byteClass(DISCOVERY_COVER_BLOB_CHARS)
                });
                logDiscoveryPublish('info', 'publish-dispatch', {
                    attemptId,
                    tokenBatchClass: countClass(tokenBatch.length),
                    missingEpochClass: countClass(missingEpochs.length),
                    encryptedBlobSizeClass: byteClass(encryptedBlob.length),
                    hasPreviousEpochToken: !!previousResult?.token
                }, `publish-dispatch:${attemptId}`);
                const publishRequestId = `pub-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
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
	                        const requestMatches = detail?.requestId === publishRequestId;
	                        const isPublishOk =
	                            detail?.type === SignalType.OK &&
	                            requestMatches &&
	                            (detail?.op === 'publish-discovery' || detail?.op === undefined);
	                        if (
	                            isPublishOk
	                        ) {
		                            cleanup();
		                            const accepted = detail?.success !== false;
                                    logDiscoveryPublish(accepted ? 'info' : 'warn', 'publish-ack', {
                                        attemptId,
                                        success: accepted,
                                        stage: typeof detail?.stage === 'string' ? detail.stage : 'unknown',
                                        rttMs: Date.now() - startedAt
                                    }, `publish-ack:${attemptId}`);
		                            traceDiscoveryClient('publish.ack.received', {
		                                attemptId,
                                success: accepted,
                                stage: typeof detail?.stage === 'string' ? detail.stage : 'unknown',
                                rttMs: Date.now() - startedAt,
	                                via: ev.type,
	                                hasOp: typeof detail?.op === 'string'
	                            }, accepted ? 'info' : 'warn');
	                            resolve(accepted);
	                            return;
	                        }
	                        if (
	                            detail?.type === SignalType.ERROR &&
	                            requestMatches &&
	                            typeof detail?.message === 'string'
	                        ) {
	                            cleanup();

                            traceDiscoveryClient('publish.ack.error-response', {
                                attemptId,
                                message: detail.message,
                                rttMs: Date.now() - startedAt,
                                via: ev.type
	                            }, 'warn');
	                            resolve(false);
	                            return;
	                        }
	                        if (
	                            requestMatches &&
	                            (detail?.type === SignalType.OK || detail?.type === SignalType.ERROR)
	                        ) {
	                            traceDiscoveryClient('publish.ack.unmatched-candidate', {
	                                attemptId,
	                                type: detail?.type,
	                                op: typeof detail?.op === 'string' ? detail.op : 'missing',
	                                hasSuccess: typeof detail?.success === 'boolean',
	                                via: ev.type
	                            }, 'warn');
	                        }
	                    };

                    const timeoutId = window.setTimeout(() => {
                        cleanup();

                        traceDiscoveryClient('publish.ack.timeout', {
                            attemptId,
                            timeoutMs: PUBLISH_ACK_TIMEOUT_MS,
                            elapsedMs: Date.now() - startedAt,
                            snapshot: discoveryPublishSnapshot()
                        }, 'warn');
                        resolve(false);
                    }, PUBLISH_ACK_TIMEOUT_MS);

                    window.addEventListener(EventType.SECURE_SERVER_MESSAGE, ackHandler as EventListener);
                    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, ackHandler as EventListener);
                    traceDiscoveryClient('publish.ack.listener-registered', {
                        attemptId,
                        timeoutMs: PUBLISH_ACK_TIMEOUT_MS,
                        tokenBatchClass: countClass(tokenBatch.length),
                        encryptedBlobSizeClass: byteClass(encryptedBlob.length)
                    });

                    void sendSecureDiscoveryMessage(
                        {
                            type: SignalType.PUBLISH_DISCOVERY,
                            requestId: publishRequestId,
                            bucketBatch,
                            encryptedBlob
                        },
                        'publish-discovery',
                        PUBLISH_ACK_TIMEOUT_MS + 6000
                    ).then((sent) => {
                        traceDiscoveryClient('publish.dispatch.send-result', {
                            attemptId,
                            sent,
                            elapsedMs: Date.now() - startedAt
                        }, sent ? 'info' : 'warn');
                        if (!sent) {
                            cleanup();
                            resolve(false);
                        }
                    }).catch((error) => {
                        traceDiscoveryClient('publish.dispatch.send-error', {
                            attemptId,
                            error: error instanceof Error ? error.message : String(error),
                            elapsedMs: Date.now() - startedAt
                        }, 'warn');
                        cleanup();
                        resolve(false);
                    });
                });

                if (!ackSuccess) {
                    traceDiscoveryClient('publish.result', {
                        attemptId,
                        success: false,
                        reason: 'publish-ack-failed',
                        elapsedMs: Date.now() - startedAt
                    }, 'warn');
                    return fail('publish-ack-failed');
                }

                lastPublishedRef.current = Date.now();
                lastPublishedContextFingerprintRef.current = contextFingerprint;
                lastPublishedFingerprintRef.current = publishFingerprint;
                lastPublishedAvatarHashRef.current = avatar?.hash ?? null;
                keysReadyPublishedRef.current = true;
                lastPublishFailureRef.current = null;
                logDiscoveryPublish('info', 'publish-complete', {
                    attemptId,
                    rttMs: Date.now() - startedAt
                }, `publish-complete:${attemptId}`);
                traceDiscoveryClient('publish.result', {
                    attemptId,
                    success: true,
                    elapsedMs: Date.now() - startedAt,
                    snapshot: discoveryPublishSnapshot()
                });

                if (avatarPublishTimeoutRef.current) {
                    clearTimeout(avatarPublishTimeoutRef.current);
                }
                avatarPublishTimeoutRef.current = null;
                pendingAvatarPublishRef.current = false;

                return true;
            } catch (err) {
                const reason = err instanceof Error ? err.message : String(err);
                traceDiscoveryClient('publish.exception', {
                    attemptId,
                    error: reason,
                    snapshot: discoveryPublishSnapshot()
                }, 'warn');
                return fail(reason || 'publish-error');
            } finally {
                publishingRef.current = false;
                traceDiscoveryClient('publish.attempt-finally', {
                    attemptId,
                    snapshot: discoveryPublishSnapshot()
                });
            }
        })();

        publishPromiseRef.current = publishPromise;
        traceDiscoveryClient('publish.promise-registered', {
            forced: force,
            snapshot: discoveryPublishSnapshot()
        });
        try {
            const result = await publishPromise;
            traceDiscoveryClient('publish.promise-resolved', {
                forced: force,
                result,
                snapshot: discoveryPublishSnapshot()
            }, result ? 'info' : 'warn');
            return result;
        } finally {
            if (publishPromiseRef.current === publishPromise) {
                publishPromiseRef.current = null;
                traceDiscoveryClient('publish.promise-cleared', {
                    forced: force,
                    snapshot: discoveryPublishSnapshot()
                });
            }
        }
    }, [effectiveHandle, isDiscoverable, getDiscoveryHandle, evaluateHandleWithOprf, signalUsername, hybridKeysRef, getAvatarForDiscovery, sendSecureDiscoveryMessage, waitForOprfState, isDiscoveryTransportReady, logDiscoveryPublish, discoveryPublishSnapshot]);

    const sendCoverPublication = useCallback(async (): Promise<boolean> => {
        traceDiscoveryClient('cover-publish.enter', {
            snapshot: discoveryPublishSnapshot()
        });
        if (!effectiveHandle || !isDiscoverable) {
            traceDiscoveryClient('cover-publish.skip', {
                reason: !effectiveHandle ? 'missing-handle' : 'not-discoverable',
                snapshot: discoveryPublishSnapshot()
            });
            return false;
        }
        if (!isDiscoveryTransportReady()) {
            traceDiscoveryClient('cover-publish.skip', {
                reason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            }, 'warn');
            return false;
        }
        if (publishingRef.current) {
            traceDiscoveryClient('cover-publish.skip', { reason: 'real-publish-in-flight' });
            return false;
        }
        if (Date.now() - lastPublishAttemptRef.current < 60_000) {
            traceDiscoveryClient('cover-publish.skip', {
                reason: 'recent-real-publish-attempt',
                sinceLastAttemptMs: Date.now() - lastPublishAttemptRef.current
            });
            return false;
        }

        const tokenBatch = Array.from(
            { length: DISCOVERY_COVER_TOKEN_BATCH_SIZE },
            () => randomHexForDiscovery(32)
        );
        const coverLength = Math.max(
            DISCOVERY_COVER_BLOB_CHARS,
            lastDiscoveryPublishBlobLengthRef.current || DISCOVERY_COVER_BLOB_CHARS
        );

        // Decoy publish
        const coverBucketBatch = await buildDiscoveryBucketBatch(tokenBatch, randomHexForDiscovery(32));
        if (!coverBucketBatch) {
            traceDiscoveryClient('cover-publish.skip', { reason: 'manifest-not-ready' }, 'warn');
            return false;
        }
        traceDiscoveryClient('cover-publish.dispatch', {
            tokenBatchClass: countClass(coverBucketBatch.length),
            coverSizeClass: byteClass(coverLength)
        });
        const sent = await sendSecureDiscoveryMessage(
            {
                type: SignalType.PUBLISH_DISCOVERY,
                bucketBatch: coverBucketBatch,
                encryptedBlob: randomBase64UrlChars(coverLength)
            },
            'cover-publish-discovery',
            PUBLISH_ACK_TIMEOUT_MS + 6000
        );
        traceDiscoveryClient('cover-publish.result', { sent }, sent ? 'info' : 'warn');
        return sent;
    }, [effectiveHandle, isDiscoverable, sendSecureDiscoveryMessage, isDiscoveryTransportReady, discoveryPublishSnapshot]);

    // Capture OPRF public key and epoch info from server
    useEffect(() => {
        traceDiscoveryClient('events.discovery-listeners-mounted', {
            snapshot: discoveryPublishSnapshot()
        });
        const runWhenDiscoveryTransportReady = (
            eventName: string,
            readyAction: string,
            onReady: () => void
        ) => {
            const ready = isDiscoveryTransportReady(false);
            traceDiscoveryClient(eventName, {
                action: ready ? readyAction : 'defer-until-transport-ready',
                snapshot: discoveryPublishSnapshot()
            });
            if (ready) onReady();
        };

        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === '__ws_connection_closed' || detail?.type === '__ws_connection_error' || detail?.type === '__ws_connection_opened') {
                traceDiscoveryClient('events.websocket-state', {
                    eventType: detail?.type,
                    via: ev.type,
                    previousUnlinkedReady: unlinkedReadyRef.current
                }, detail?.type === '__ws_connection_opened' ? 'info' : 'warn');
                unlinkedReadyRef.current = false;
                noteDiscoveryTransportReadinessChanged(detail?.type || ev.type);
                return;
            }
            if (detail?.type === SignalType.OPRF_DISCOVERY_PUBLIC_KEY) {
                const { publicKey, epoch, previousEpoch, epochRotatesAt } = detail;
                if (publicKey && epoch !== undefined) {
                    if (lastOprfPublicKeyRef.current && lastOprfPublicKeyRef.current !== publicKey) {
                        discoveryTokenCache.clear();
                        traceDiscoveryClient('events.oprf-public-key-rotated', {
                            via: ev.type,
                            epoch,
                            cacheCleared: true
                        });
                    }
                    lastOprfPublicKeyRef.current = publicKey;
                    oprfStateRef.current = { publicKey, epoch, previousEpoch, epochRotatesAt };
                    oprfDiscoveryClient.setServerPublicKey(publicKey);
                    pruneDiscoveryTokenCache(epoch, previousEpoch);
                    const ready = isDiscoveryTransportReady(false);
                    traceDiscoveryClient('events.oprf-public-key-received', {
                        via: ev.type,
                        epoch,
                        hasPreviousEpoch: previousEpoch !== undefined,
                        tokenCacheSizeClass: countClass(discoveryTokenCache.size),
                        action: ready ? 'publishSelf(true)' : 'defer-publish-until-transport-ready'
                    });
                    if (ready) {
                        void Promise.resolve().then(() => publishSelf(true));
                    }
                } else {
                    traceDiscoveryClient('events.oprf-public-key-ignored', {
                        via: ev.type,
                        hasPublicKey: !!publicKey,
                        hasEpoch: epoch !== undefined
                    }, 'warn');
                }
            }
        };

        const onUnlinkedReady = () => {
            unlinkedReadyRef.current = true;
            noteDiscoveryTransportReadinessChanged('unlinked-ready');
            runWhenDiscoveryTransportReady('events.unlinked-ready', 'requestOprfKey + publishSelf(true)', () => {
                requestOprfKey('unlinked-ready');
                void publishSelf(true);
            });
        };
        const onReconnected = () => {
            unlinkedReadyRef.current = false;
            noteDiscoveryTransportReadinessChanged('ws-reconnected');
            runWhenDiscoveryTransportReady('events.ws-reconnected', 'requestOprfKey', () => {
                requestOprfKey('ws-reconnected');
            });
        };
        const onHybridKeys = () => {
            cachedBundleRef.current = null;
            runWhenDiscoveryTransportReady('events.hybrid-keys-updated', 'publishSelf(true)', () => {
                void publishSelf(true);
            });
        };
        const onRouteCommitmentsRotated = () => {
            cachedBundleRef.current = null;
            runWhenDiscoveryTransportReady('events.route-commitments-rotated', 'publishSelf(true)', () => {
                void publishSelf(true);
            });
        };
        const onPqSessionEstablished = () => {
            noteDiscoveryTransportReadinessChanged('pq-session-established');
            runWhenDiscoveryTransportReady('events.pq-session-established', 'requestOprfKey + publishSelf(true)', () => {
                requestOprfKey('pq-session-ready');
                void publishSelf(true);
            });
        };
        const onAuthSuccess = () => {
            noteDiscoveryTransportReadinessChanged('auth-success');
            runWhenDiscoveryTransportReady('events.auth-success', 'requestOprfKey + publishSelf(true)', () => {
                requestOprfKey('auth-success');
                void publishSelf(true);
            });
        };
        const onServerEntryGranted = () => {
            noteDiscoveryTransportReadinessChanged('server-entry-granted');
            runWhenDiscoveryTransportReady('events.server-entry-granted', 'requestOprfKey + publishSelf(true)', () => {
                requestOprfKey('server-entry-granted');
                void publishSelf(true);
            });
        };

        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.UNLINKED_SESSION_READY, onUnlinkedReady as EventListener);
        window.addEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, onAuthSuccess as EventListener);
        window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onHybridKeys as EventListener);
        window.addEventListener(EventType.ROUTE_COMMITMENTS_ROTATED, onRouteCommitmentsRotated as EventListener);
        window.addEventListener(EventType.WS_RECONNECTED, onReconnected as EventListener);
        window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, onPqSessionEstablished as EventListener);
        window.addEventListener(EventType.SERVER_ENTRY_GRANTED, onServerEntryGranted as EventListener);

        return () => {
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.UNLINKED_SESSION_READY, onUnlinkedReady as EventListener);
            window.removeEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, onAuthSuccess as EventListener);
            window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onHybridKeys as EventListener);
            window.removeEventListener(EventType.ROUTE_COMMITMENTS_ROTATED, onRouteCommitmentsRotated as EventListener);
            window.removeEventListener(EventType.WS_RECONNECTED, onReconnected as EventListener);
            window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, onPqSessionEstablished as EventListener);
            window.removeEventListener(EventType.SERVER_ENTRY_GRANTED, onServerEntryGranted as EventListener);
            traceDiscoveryClient('events.discovery-listeners-unmounted');
        };
    }, [requestOprfKey, publishSelf, pruneDiscoveryTokenCache, discoveryPublishSnapshot, isDiscoveryTransportReady, noteDiscoveryTransportReadinessChanged]);

    useEffect(() => {
        traceDiscoveryClient('connection.pending-reset-listener.mounted');
        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            const type = detail?.type;
            if (type !== '__ws_connection_closed' && type !== '__ws_connection_error') return;

            traceDiscoveryClient('connection.pending-reset', {
                type,
                pendingDiscoveryClass: countClass(pendingDiscoveryByRequestIdRef.current.size)
            }, 'warn');
            for (const pending of Array.from(pendingDiscoveryByRequestIdRef.current.values())) {
                if (pending.settled) continue;
                pending.settled = true;
                if (pending.timeoutId) clearTimeout(pending.timeoutId);
                unregisterPendingDiscovery(pending);
                if (pending.cacheNegative !== false) {
                    discoveryResultCache.set(pending.normalizedHandle, {
                        value: null,
                        expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                    });
                }
                pending.resolve(null);
            }
        };

        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        return () => {
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
            traceDiscoveryClient('connection.pending-reset-listener.unmounted');
        };
    }, [unregisterPendingDiscovery]);

    const scheduleAvatarPublish = useCallback((reason: string) => {
        traceDiscoveryClient('avatar-publish.schedule-enter', {
            reason,
            snapshot: discoveryPublishSnapshot()
        });
        if (!effectiveHandle || !isDiscoverable) {
            traceDiscoveryClient('avatar-publish.schedule-skip', {
                reason,
                skipReason: !effectiveHandle ? 'missing-handle' : 'not-discoverable'
            });
            return;
        }
        if (!isDiscoveryTransportReady(false)) {
            traceDiscoveryClient('avatar-publish.schedule-skip', {
                reason,
                skipReason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        const ownAvatar = profilePictureSystem.getOwnAvatarData?.() ?? null;
        const ownHash = ownAvatar?.hash ?? null;
        if (ownHash && lastPublishedAvatarHashRef.current === ownHash) {
            traceDiscoveryClient('avatar-publish.schedule-skip', {
                reason,
                skipReason: 'avatar-unchanged'
            });
            return;
        }
        if (pendingAvatarPublishRef.current) {
            traceDiscoveryClient('avatar-publish.schedule-skip', {
                reason,
                skipReason: 'already-pending'
            });
            return;
        }
        pendingAvatarPublishRef.current = true;

        const jitterMs = 5000 + Math.floor(Math.random() * 25000);
        traceDiscoveryClient('avatar-publish.scheduled', {
            reason,
            jitterMs,
            hasOwnAvatar: !!ownAvatar,
            isDefaultAvatar: ownAvatar?.isDefault === true
        });

        avatarPublishTimeoutRef.current = window.setTimeout(() => {
            pendingAvatarPublishRef.current = false;
            avatarPublishTimeoutRef.current = null;
            traceDiscoveryClient('avatar-publish.timer-fired', {
                reason,
                action: 'publishSelf(true)'
            });
            void publishSelf(true);
        }, jitterMs);
    }, [effectiveHandle, isDiscoverable, publishSelf, discoveryPublishSnapshot, isDiscoveryTransportReady]);

    /**
     * Watch for hybrid keys becoming available and publish immediately
     */
    useEffect(() => {
        if (!effectiveHandle) {
            traceDiscoveryClient('keys-watch.skip', {
                reason: 'missing-effective-handle',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        if (!isDiscoveryTransportReady(false)) {
            traceDiscoveryClient('keys-watch.skip', {
                reason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        if (!oprfStateRef.current.publicKey) {
            traceDiscoveryClient('keys-watch.skip', {
                reason: 'missing-oprf-public-key',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }

        const hasKeys = !!(
            hybridKeysRef?.current?.kyber?.publicKeyBase64 &&
            hybridKeysRef?.current?.dilithium?.publicKeyBase64 &&
            hybridKeysRef?.current?.x25519?.publicKeyBase64
        );
        traceDiscoveryClient('keys-watch.state', {
            hasKeys,
            keysReadyPublished: keysReadyPublishedRef.current,
            snapshot: discoveryPublishSnapshot()
        });

        if (hasKeys && !keysReadyPublishedRef.current) {
            traceDiscoveryClient('keys-watch.publish-trigger', {
                action: 'publishSelf(true)'
            });
            void publishSelf(true);
        }
    }, [effectiveHandle, hybridKeysRef?.current, publishSelf, discoveryPublishSnapshot, isDiscoveryTransportReady, discoveryTransportReadyVersion]);

    useEffect(() => {
        if (!effectiveHandle || !isDiscoverable) {
            traceDiscoveryClient('cover-publish.effect-skip', {
                reason: !effectiveHandle ? 'missing-effective-handle' : 'not-discoverable',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        if (!isDiscoveryTransportReady(false)) {
            traceDiscoveryClient('cover-publish.effect-skip', {
                reason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }

        let stopped = false;
        let timeoutId: number | null = null;
        const scheduleNext = (delayMs: number) => {
            if (stopped) return;
            traceDiscoveryClient('cover-publish.timer-scheduled', { delayMs });
            timeoutId = window.setTimeout(async () => {
                timeoutId = null;
                if (!stopped) {
                    traceDiscoveryClient('cover-publish.timer-fired');
                    const result = await sendCoverPublication().catch((error) => {
                        traceDiscoveryClient('cover-publish.timer-error', {
                            error: error instanceof Error ? error.message : String(error)
                        }, 'warn');
                        return false;
                    });
                    traceDiscoveryClient('cover-publish.timer-result', { result }, result ? 'info' : 'warn');
                    scheduleNext(DISCOVERY_COVER_PUBLISH_INTERVAL_MS);
                }
            }, delayMs);
        };

        const initialDelay = DISCOVERY_COVER_PUBLISH_INITIAL_MIN_MS
            + Math.floor(Math.random() * DISCOVERY_COVER_PUBLISH_INITIAL_JITTER_MS);
        traceDiscoveryClient('cover-publish.effect-mounted', {
            initialDelay,
            intervalMs: DISCOVERY_COVER_PUBLISH_INTERVAL_MS
        });
        scheduleNext(initialDelay);

        return () => {
            stopped = true;
            if (timeoutId !== null) window.clearTimeout(timeoutId);
            traceDiscoveryClient('cover-publish.effect-unmounted');
        };
    }, [effectiveHandle, isDiscoverable, sendCoverPublication, discoveryPublishSnapshot, isDiscoveryTransportReady, discoveryTransportReadyVersion]);

    useEffect(() => {
        if (!effectiveHandle) {
            traceDiscoveryClient('profile-events.effect-skip', { reason: 'missing-effective-handle' });
            return;
        }
        traceDiscoveryClient('profile-events.effect-mounted');

        const handler = (ev: Event) => {
            try {
                if (ev.type === EventType.PROFILE_SETTINGS_UPDATED) {
                    traceDiscoveryClient('profile-events.received', {
                        eventType: ev.type,
                        action: 'scheduleAvatarPublish'
                    });
                    scheduleAvatarPublish('profile-settings-updated');
                    return;
                }

                if (ev.type === EventType.PROFILE_PICTURE_UPDATED) {
                    const detail = (ev as CustomEvent).detail;
                    traceDiscoveryClient('profile-events.received', {
                        eventType: ev.type,
                        detailType: detail?.type,
                        action: detail?.type === 'own' ? 'scheduleAvatarPublish' : 'ignore'
                    });
                    if (detail?.type === 'own') {
                        scheduleAvatarPublish('profile-picture-updated');
                    }
                }
            } catch (error) {
                traceDiscoveryClient('profile-events.handler-error', {
                    error: error instanceof Error ? error.message : String(error)
                }, 'warn');
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
            traceDiscoveryClient('profile-events.effect-unmounted');
        };
    }, [effectiveHandle, scheduleAvatarPublish]);

    /**
     * Periodic and state-based publisher
     */
    useEffect(() => {
        logDiscoveryPublish('info', 'publisher-check', {
            reason: 'effect-run'
        }, 'publisher-check');
        if (!effectiveHandle) {
            logDiscoveryPublish('info', 'publish-skip', {
                reason: 'missing-effective-handle'
            }, 'publish-skip:missing-effective-handle');
            traceDiscoveryClient('publisher.effect-skip', {
                reason: 'missing-effective-handle',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        if (!isDiscoverable) {
            logDiscoveryPublish('info', 'publish-skip', {
                reason: 'not-discoverable'
            }, 'publish-skip:not-discoverable');
            traceDiscoveryClient('publisher.effect-skip', {
                reason: 'not-discoverable',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }
        if (!isDiscoveryTransportReady(false)) {
            logDiscoveryPublish('info', 'publisher-deferred', {
                reason: 'transport-not-ready',
                lastFailure: lastPublishFailureRef.current || undefined
            }, 'publisher-deferred:transport-not-ready');
            traceDiscoveryClient('publisher.effect-skip', {
                reason: 'transport-not-ready',
                snapshot: discoveryPublishSnapshot()
            });
            return;
        }

        traceDiscoveryClient('publisher.effect-mounted', {
            snapshot: discoveryPublishSnapshot()
        });

        let intervalId: ReturnType<typeof setInterval> | null = null;
        let retryTimeoutId: ReturnType<typeof setTimeout> | null = null;
        let cancelled = false;

        const startPublishing = async () => {
            if (cancelled) {
                traceDiscoveryClient('publisher.start-skip', { reason: 'cancelled' });
                return;
            }
            if (!isDiscoveryTransportReady(false)) {
                logDiscoveryPublish('info', 'publisher-deferred', {
                    reason: 'transport-not-ready',
                    lastFailure: lastPublishFailureRef.current || undefined
                }, 'publisher-deferred:transport-not-ready');
                traceDiscoveryClient('publisher.start-deferred', {
                    reason: 'transport-not-ready',
                    snapshot: discoveryPublishSnapshot()
                });
                return;
            }


            logDiscoveryPublish('info', 'publisher-start', {
                forced: true,
                lastFailure: lastPublishFailureRef.current || undefined
            }, 'publisher-start');
            traceDiscoveryClient('publisher.start', {
                snapshot: discoveryPublishSnapshot()
            });
            const success = await publishSelf(true);
            traceDiscoveryClient('publisher.publish-result', {
                success,
                lastFailure: lastPublishFailureRef.current || null,
                snapshot: discoveryPublishSnapshot()
            }, success ? 'info' : 'warn');
            if (!success) {
                const reason = lastPublishFailureRef.current || 'unknown';
                const preReadyReason = isPreReadyPublishFailure(reason);
                if (reason === 'auth-transport-not-ready' || !isDiscoveryTransportReady(false)) {
                    traceDiscoveryClient('publisher.retry-deferred', {
                        reason,
                        waitFor: 'transport-ready',
                        snapshot: discoveryPublishSnapshot()
                    });
                    return;
                }
                if (!retryTimeoutId) {
                    const retryDelayMs = publishRetryDelayMs(reason, preReadyReason);

                    traceDiscoveryClient('publisher.retry-scheduled', {
                        reason,
                        preReadyReason,
                        retryDelayMs
                    }, preReadyReason ? 'info' : 'warn');
                    retryTimeoutId = setTimeout(() => {
                        retryTimeoutId = null;
                        traceDiscoveryClient('publisher.retry-fired', {
                            reason
                        });
                        void startPublishing();
                    }, retryDelayMs);
                } else {
                    traceDiscoveryClient('publisher.retry-already-scheduled', {
                        reason
                    });
                }
            }

            if (!intervalId) {
                traceDiscoveryClient('publisher.interval-started', {
                    intervalMs: 300000
                });
                intervalId = setInterval(() => {
                    traceDiscoveryClient('publisher.interval-fired', {
                        snapshot: discoveryPublishSnapshot()
                    });
                    if (isDiscoveryTransportReady(false)) {
                        void publishSelf();
                    } else {
                        traceDiscoveryClient('publisher.interval-skip', {
                            reason: 'transport-not-ready',
                            snapshot: discoveryPublishSnapshot()
                        });
                    }
                }, 300000);
            }
        };

        const oprfKeyHandler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === SignalType.OPRF_DISCOVERY_PUBLIC_KEY && detail.publicKey) {
                traceDiscoveryClient('publisher.oprf-key-event', {
                    via: ev.type,
                    action: isDiscoveryTransportReady(false) ? 'startPublishing' : 'defer-until-transport-ready'
                });
                if (isDiscoveryTransportReady(false)) {
                    void startPublishing();
                }
            }
        };

        traceDiscoveryClient('publisher.initial-start-queued');
        void startPublishing();
        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, oprfKeyHandler as EventListener);
        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, oprfKeyHandler as EventListener);

        return () => {
            cancelled = true;
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, oprfKeyHandler as EventListener);
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, oprfKeyHandler as EventListener);
            if (intervalId) clearInterval(intervalId);
            if (retryTimeoutId) clearTimeout(retryTimeoutId);
            traceDiscoveryClient('publisher.effect-unmounted');
        };
    }, [effectiveHandle, isDiscoverable, publishSelf, discoveryPublishSnapshot, isDiscoveryTransportReady, discoveryTransportReadyVersion, logDiscoveryPublish]);

    useEffect(() => {
        if (websocketClient.isUnlinkedMode()) {
            if (isDiscoveryTransportReady(false)) {
                void publishSelf();
            } else {
                traceDiscoveryClient('unlinked-publish.skip', {
                    reason: 'transport-not-ready',
                    snapshot: discoveryPublishSnapshot()
                });
            }
        }
    }, [publishSelf, isDiscoveryTransportReady, discoveryPublishSnapshot, discoveryTransportReadyVersion]);

    useEffect(() => {
        const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === SignalType.ERROR) {
                const requestId = normalizeRequestId(detail.requestId);
                if (requestId) {
                    const pending = pendingDiscoveryByRequestIdRef.current.get(requestId);
                    if (pending) {
                        void resolvePendingDiscovery(pending, null, false);
                        return;
                    }
                }
                return;
            }

            if (detail?.type === SignalType.DISCOVERY_SNAPSHOT) {
                const requestId = normalizeRequestId(detail.requestId);
                if (!requestId) return;
                const pending = pendingDiscoveryByRequestIdRef.current.get(requestId);
                if (!pending) return;
                if (detail?.success === false) {
                    logDiscoveryLookup('warn', 'snapshot-response-error', {
                        requestId,
                        handle: pending.normalizedHandle,
                        error: typeof detail?.error === 'string' ? detail.error : 'snapshot_failed'
                    });
                    void resolvePendingDiscoverySnapshot(pending, []);
                    return;
                }
                void (async () => {
                    try {
                        const entries = await decodeCompressedDiscoverySnapshot(detail);
                        logDiscoveryLookup('info', 'snapshot-response', {
                            requestId,
                            handle: pending.normalizedHandle,
                            entryCountClass: countClass(entries.length),
                            paddedEntryCountClass: countClass(Number(detail?.snapshot?.paddedEntryCount) || 0)
                        });
                        await resolvePendingDiscoverySnapshot(pending, entries);
                    } catch (error) {
                        logDiscoveryLookup('warn', 'snapshot-decode-error', {
                            requestId,
                            handle: pending.normalizedHandle,
                            error: error instanceof Error ? error.message : String(error)
                        });
                        await resolvePendingDiscoverySnapshot(pending, []);
                    }
                })();
                return;
            }
            return;
        };

        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        return () => {
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as EventListener);
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as EventListener);
        };
    }, [normalizeRequestId, resolvePendingDiscovery, resolvePendingDiscoverySnapshot, unregisterPendingDiscovery]);

    useEffect(() => {
        return () => {
            for (const pending of Array.from(pendingDiscoveryByRequestIdRef.current.values())) {
                pending.settled = true;
                if (pending.timeoutId) clearTimeout(pending.timeoutId);
            }
            pendingDiscoveryByRequestIdRef.current.clear();
        };
    }, []);

    /**
     * Find a user by handle using OPRF-derived tokens
     */
    const findUser = useCallback(async (
        targetHandle: string,
        options?: { forceRefresh?: boolean }
    ): Promise<OPRFDiscoveryMaterial | null> => {
        if (websocketClient.isUnlinkedMode?.() && !unlinkedReadyRef.current) {
            logDiscoveryLookup('warn', 'lookup-skip', {
                reason: 'unlinked-not-ready',
                handle: String(targetHandle || '').slice(0, 128)
            });
            return null;
        }
        const forceRefresh = !!options?.forceRefresh;
        const caller = getDiscoveryCallerLabel();
        if (!shouldAttemptDiscovery(targetHandle)) {
            logDiscoveryLookup('warn', 'lookup-skip', {
                reason: 'invalid-or-ineligible-handle',
                handle: String(targetHandle || '').slice(0, 128),
                forceRefresh
            });
            return null;
        }
        const normalizedHandle = getDiscoveryHandle(targetHandle);
        if (!normalizedHandle) {
            logDiscoveryLookup('warn', 'lookup-skip', {
                reason: 'normalized-handle-empty',
                handle: String(targetHandle || '').slice(0, 128),
                forceRefresh
            });
            return null;
        }

        if (!forceRefresh) {
            const cachedEntry = discoveryResultCache.get(normalizedHandle);
            if (cachedEntry) {
                if (cachedEntry.expiresAt > Date.now()) {
                    logDiscoveryLookup(cachedEntry.value ? 'info' : 'warn', 'lookup-cache-hit', {
                        handle: normalizedHandle,
                        result: cachedEntry.value ? 'found' : 'not-found',
                        ttlMs: cachedEntry.expiresAt - Date.now(),
                        caller
                    });
                    return cachedEntry.value;
                }
                
                if (cachedEntry.value) {
                    logDiscoveryLookup('info', 'lookup-cache-stale-serve', {
                        handle: normalizedHandle,
                        caller
                    });


                    discoveryResultCache.set(normalizedHandle, {
                        value: cachedEntry.value,
                        expiresAt: Date.now() + DISCOVERY_STALE_SERVE_GRACE_MS
                    });
                    void findUser(normalizedHandle, { forceRefresh: true }).catch(() => { });
                    return cachedEntry.value;
                }
                logDiscoveryLookup('info', 'lookup-cache-expired', {
                    handle: normalizedHandle,
                    caller
                });
                discoveryResultCache.delete(normalizedHandle);
            }
            if (findUserCache.has(normalizedHandle)) {
                logDiscoveryLookup('info', 'lookup-reuse-cache', {
                    handle: normalizedHandle,
                    forceRefresh,
                    caller
                });
                return findUserCache.get(normalizedHandle)!;
            }
        }

        const activeLookup = findUserInFlightLock.get(normalizedHandle);
        if (activeLookup) {
            logDiscoveryLookup('info', 'lookup-reuse-inflight', {
                handle: normalizedHandle,
                forceRefresh,
                caller
            });
            return activeLookup;
        }

        if (forceRefresh) {
            const existingForce = forceRefreshFindUserCache.get(normalizedHandle);
            if (existingForce) {
                logDiscoveryLookup('info', 'lookup-reuse-force-cache', {
                    handle: normalizedHandle,
                    caller
                });
                return existingForce;
            }

            if (findUserCache.has(normalizedHandle)) {
                logDiscoveryLookup('info', 'lookup-reuse-cache', {
                    handle: normalizedHandle,
                    forceRefresh,
                    caller
                });
                return findUserCache.get(normalizedHandle)!;
            }
        }

        const promise = (async () => {
            const lookupStartedAt = Date.now();
            try {
                lastDiscoveryLookupAt.set(normalizedHandle, Date.now());
                markPirInteractiveActivity(DISCOVERY_PIR_FOREGROUND_ACTIVITY_MS);
                logDiscoveryLookup('info', 'lookup-start', {
                    handle: normalizedHandle,
                    forceRefresh,
                    caller,
                    transportReady: isDiscoveryTransportReady(false),
                    unlinkedReady: unlinkedReadyRef.current
                });

                // Get current epoch token first then previous epoch from cache
                const oprfState = await waitForOprfState('find-missing-epoch');
                if (!oprfState || oprfState.epoch === undefined) {
                    logDiscoveryLookup('warn', 'lookup-stop', {
                        handle: normalizedHandle,
                        reason: 'missing-oprf-state',
                        elapsedMs: Date.now() - lookupStartedAt
                    });
                    return null;
                }
                const { epoch, previousEpoch } = oprfState;
                logDiscoveryLookup('info', 'oprf-state-ready', {
                    handle: normalizedHandle,
                    epoch,
                    hasPreviousEpoch: previousEpoch !== undefined && previousEpoch !== epoch
                });

                const lookupEpochs = [epoch];
                if (previousEpoch !== undefined && previousEpoch !== epoch) {
                    lookupEpochs.push(previousEpoch);
                }
                let epochResults = await getDiscoveryTokensForEpochs(normalizedHandle, lookupEpochs);
                if (!epochResults || !epochResults.get(epoch)) {
                    logDiscoveryLookup('warn', 'token-derive-retry', {
                        handle: normalizedHandle,
                        epochCountClass: countClass(lookupEpochs.length)
                    });
                    await new Promise((resolve) => setTimeout(resolve, 500));
                    epochResults = await getDiscoveryTokensForEpochs(normalizedHandle, lookupEpochs);
                }
                const currentResult = epochResults?.get(epoch) || null;
                const previousResult = previousEpoch !== undefined && previousEpoch !== epoch
                    ? (epochResults?.get(previousEpoch) || null)
                    : null;

                if (!currentResult) {
                    logDiscoveryLookup('warn', 'lookup-stop', {
                        handle: normalizedHandle,
                        reason: 'missing-current-token',
                        epoch,
                        elapsedMs: Date.now() - lookupStartedAt
                    });
                    return null;
                }
                logDiscoveryLookup('info', 'token-derive-result', {
                    handle: normalizedHandle,
                    epoch,
                    hasCurrentToken: !!currentResult?.token,
                    hasPreviousToken: !!previousResult?.token,
                    epochResultCountClass: countClass(epochResults?.size || 0)
                });

                const encryptionKeys = [currentResult.encryptionKey];
                if (previousResult?.encryptionKey) encryptionKeys.push(previousResult.encryptionKey);

                const pirTokens = [currentResult.token];
                if (previousResult?.token) pirTokens.push(previousResult.token);
                let pirLookupFailed = false;

                const runPirLookup = async (): Promise<OPRFDiscoveryMaterial | null> => {
                    try {
                        const pirEncryptedBlobs = await findDiscoveryBlobsViaPir(pirTokens);
                        if (pirEncryptedBlobs.length > 0) {
                            const pirResult = await finalizeDiscoverySnapshotResult(
                                normalizedHandle,
                                targetHandle,
                                pirEncryptedBlobs,
                                encryptionKeys,
                                false
                            );
                            if (pirResult) return pirResult;
                            logDiscoveryLookup('warn', 'pir-decrypt-result', {
                                handle: normalizedHandle,
                                result: 'not-decryptable-or-invalid',
                                encryptedBlobCountClass: countClass(pirEncryptedBlobs.length)
                            });
                        }
                    } catch (error) {
                        pirLookupFailed = true;
                        logDiscoveryLookup('warn', 'pir-path-error', {
                            handle: normalizedHandle,
                            error: error instanceof Error ? error.message : String(error)
                        });
                    }
                    return null;
                };

                const startSnapshotCover = (reason: string) => {
                    if (!isDiscoveryTransportReady(false)) return;
                    logDiscoveryLookup('info', 'snapshot-cover-disabled', {
                        handle: normalizedHandle,
                        reason,
                        cover: 'pir-cover-query-only'
                    });
                };

                logDiscoveryLookup('info', 'lookup-pir-main-start', {
                    handle: normalizedHandle,
                    pirTokenCountClass: countClass(pirTokens.length),
                    timeoutMs: DISCOVERY_PIR_LOOKUP_TIMEOUT_MS,
                    snapshotCover: 'post-pir'
                });

                const pirResult = await runPirLookup();
                if (pirResult) {
                    startSnapshotCover('pir-found');
                    logDiscoveryLookup('info', 'lookup-complete', {
                        handle: normalizedHandle,
                        source: 'pir',
                        result: 'found',
                        elapsedMs: Date.now() - lookupStartedAt
                    });
                    return pirResult;
                }
                if (pirLookupFailed) {
                    startSnapshotCover('pir-error');
                    logDiscoveryLookup('warn', 'lookup-stop', {
                        handle: normalizedHandle,
                        reason: 'pir-lookup-failed',
                        elapsedMs: Date.now() - lookupStartedAt
                    });
                    return null;
                }

                // Dont let a not-found erase an existing still-valid found entry
                const existingFound = discoveryResultCache.get(normalizedHandle);
                if (!(existingFound && existingFound.value && existingFound.expiresAt > Date.now())) {
                    discoveryResultCache.set(normalizedHandle, {
                        value: null,
                        expiresAt: Date.now() + DISCOVERY_TIMEOUT_CACHE_TTL_MS
                    });
                }
                logDiscoveryLookup('warn', 'lookup-complete', {
                    handle: normalizedHandle,
                    source: 'pir',
                    result: 'not-found',
                    elapsedMs: Date.now() - lookupStartedAt
                });
                startSnapshotCover('pir-not-found');
                return null;
            } catch (error) {
                logDiscoveryLookup('error', 'lookup-error', {
                    handle: normalizedHandle,
                    error: error instanceof Error ? error.message : String(error),
                    elapsedMs: Date.now() - lookupStartedAt
                });
                return null;
            } finally {
                findUserInFlightLock.delete(normalizedHandle);
                if (forceRefresh) {
                    forceRefreshFindUserCache.delete(normalizedHandle);
                } else {
                    findUserCache.delete(normalizedHandle);
                }
            }
        })();

        findUserInFlightLock.set(normalizedHandle, promise);
        if (forceRefresh) {
            forceRefreshFindUserCache.set(normalizedHandle, promise);
        } else {
            findUserCache.set(normalizedHandle, promise);
        }
        return promise;
    }, [getDiscoveryTokensForEpochs, getDiscoveryHandle, waitForOprfState, registerPendingDiscovery, sendSecureDiscoveryMessage, unregisterPendingDiscovery, findDiscoveryBlobsViaPir, finalizeDiscoverySnapshotResult, isDiscoveryTransportReady]);

    const ensurePublished = useCallback(async (force = true): Promise<boolean> => {
        traceDiscoveryClient('ensurePublished.enter', {
            forced: force,
            snapshot: discoveryPublishSnapshot()
        });
        const result = await publishSelf(force);
        traceDiscoveryClient('ensurePublished.result', {
            forced: force,
            result,
            lastFailure: lastPublishFailureRef.current || null,
            snapshot: discoveryPublishSnapshot()
        }, result ? 'info' : 'warn');
        return result;
    }, [publishSelf, discoveryPublishSnapshot]);

    return {
        findUser,
        ensurePublished,
        isDiscoverable,
        setIsDiscoverable
    };
};
