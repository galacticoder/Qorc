/**
 * Client the unlinkable avatar content store
 */

import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import {
    encryptAvatarToPurb,
    decryptAvatarPurb,
    AVATAR_PURB_WIRE_BYTES,
    type AvatarRef
} from '../crypto/avatar-blob-crypto';
import { PostQuantumUtils } from '../utils/pq-utils';
import { hashAvatarData, isValidAvatarData } from '../utils/avatar-utils';
import type { AvatarData } from '../types/avatar-types';
import { PrivacyPassClient, PrivacyPassHelpers, type AnonymousToken } from '../cryptography/privacy-pass-client';
import { tokenVault } from '../database/token-vault';
import websocketClient from '../websocket/websocket';
import { encryptedStorage } from '../database/encrypted-storage';
import {
    assertCurrentServerContext,
    captureCurrentServerContext,
    type CurrentServerContext,
} from '../security/local-account-scope';
import { createAnonymousHttpPow } from '../cryptography/anonymous-http-pow';
import { wipeAnonymousToken } from '../cryptography/wipe';
import { DISCOVERY_EPOCH_DURATION_MS } from '../constants';
import { PostQuantumRandom } from '../cryptography/random';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEYS } from '../database/storage-keys';
import {
    ACCOUNT_AUTH_PURPOSE,
    AVATAR_BLOB_GET_AUDIENCE,
    AVATAR_BLOB_PUT_AUDIENCE,
    AVATAR_POOL_AUDIENCE,
} from '../config/audiences';

const AVATAR_COVER_TOTAL_IDS = 10;
const AVATAR_BLOB_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const POOL_CACHE_TTL_MS = 5 * 60 * 1000;
const POOL_SAMPLE_LIMIT = 256;
const COVER_BLOBS_PER_CLIENT = 12;
const COVER_REFRESH_MS = 6 * 60 * 60 * 1000;
const DECOY_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const DECOY_CACHE_MAX = 1024;

const AVATAR_UPLOAD_JITTER_MIN_MS = 1_000;
const AVATAR_UPLOAD_JITTER_MAX_MS = 10_000;
const AVATAR_REFRESH_MARGIN_MS = 24 * 60 * 60 * 1000;
const AVATAR_UPLOAD_MAX_ATTEMPTS = 3;
const AVATAR_PUT_TRANSPORT_WARN_INTERVAL_MS = 30_000;
const AVATAR_GET_POW_DIFFICULTY = 16;
const AVATAR_PUT_POW_DIFFICULTY = 18;

interface AvatarPoolState {
    ids: string[];
    powEpoch: number;
    fetchedAt: number;
    serverScope: string;
}

let poolCache: AvatarPoolState | null = null;
let lastCoverUploadAt = 0;
let coverUploadBatchPending = false;
let lastAvatarPutTransportWarnAt = 0;
const decoyCache = new Map<string, { ids: string[]; expiresAt: number }>();
const scheduledUploads = new Set<ReturnType<typeof setTimeout>>();
let accountGeneration = 0;

async function fetchPool(context: CurrentServerContext): Promise<AvatarPoolState | null> {
    const now = Date.now();
    const currentEpoch = Math.floor(now / DISCOVERY_EPOCH_DURATION_MS);
    if (
        poolCache?.serverScope === context.serverScope &&
        poolCache.powEpoch === currentEpoch &&
        now - poolCache.fetchedAt < POOL_CACHE_TTL_MS
    ) return poolCache;
    try {
        const resp: any = await anonymousHttpFetch(
            AVATAR_POOL_AUDIENCE,
            { limit: POOL_SAMPLE_LIMIT },
            context.serverUrl
        );
        await assertCurrentServerContext(context);
        if (
            !resp ||
            typeof resp !== 'object' ||
            Array.isArray(resp) ||
            Object.keys(resp).sort().join(',') !== 'ids,ok,powEpoch' ||
            resp.ok !== true ||
            !Array.isArray(resp.ids) ||
            resp.ids.length !== POOL_SAMPLE_LIMIT ||
            resp.ids.some((x: unknown) => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x)) ||
            new Set(resp.ids).size !== resp.ids.length ||
            !Number.isSafeInteger(resp.powEpoch) ||
            resp.powEpoch !== Math.floor(Date.now() / DISCOVERY_EPOCH_DURATION_MS)
        ) throw new Error('Invalid avatar pool response');
        const ids: string[] = resp.ids.slice().sort();
        poolCache = {
            ids,
            powEpoch: resp.powEpoch,
            fetchedAt: Date.now(),
            serverScope: context.serverScope
        };
        return poolCache;
    } catch {
        return null;
    }
}

// Random bytes of exactly one PURB's wire size
function randomCoverPurbBase64(): string {
    const buf = new Uint8Array(AVATAR_PURB_WIRE_BYTES);
    try {
        for (let off = 0; off < buf.length; off += 65536) {
            crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, buf.length)));
        }
        return PostQuantumUtils.uint8ArrayToBase64(buf);
    } finally {
        buf.fill(0);
    }
}

function randomHexId(): string {
    const bytes = new Uint8Array(32);
    try {
        crypto.getRandomValues(bytes);
        let value = '';
        for (const byte of bytes) value += byte.toString(16).padStart(2, '0');
        return value;
    } finally {
        bytes.fill(0);
    }
}

// One shot PUT of a blob
async function putAvatarBlob(
    blobId: string,
    data: string,
    generation: number
): Promise<boolean> {
    let token: AnonymousToken | null = null;
    let redemption: Awaited<ReturnType<PrivacyPassClient['prepareRedemption']>> | null = null;
    try {
        if (generation !== accountGeneration) return false;
        const context = await captureCurrentServerContext();
        const assertOwner = async () => {
            if (generation !== accountGeneration) throw new Error('Avatar account changed');
            await assertCurrentServerContext(context);
        };
        await assertOwner();
        const powEpoch = Math.floor(Date.now() / DISCOVERY_EPOCH_DURATION_MS);
        const work = await createAnonymousHttpPow(
            PROTOCOL_KEYS.AVATAR_PUT_HTTP_POW,
            powEpoch,
            [blobId, data],
            AVATAR_PUT_POW_DIFFICULTY
        );
        await assertOwner();
        if (powEpoch !== Math.floor(Date.now() / DISCOVERY_EPOCH_DURATION_MS)) return false;
        const serverEntryAuthorization = await websocketClient.reserveServerEntryAuthorization();
        await assertOwner();
        if (!serverEntryAuthorization) return false;
        [token] = await tokenVault.reserveResumeTokens(1);
        await assertOwner();
        if (!token) return false;
        redemption = await new PrivacyPassClient(ACCOUNT_AUTH_PURPOSE).prepareRedemption(token);
        await assertOwner();
        const authorization = PrivacyPassHelpers.formatResponse(redemption);
        const resp: any = await anonymousHttpFetch(
            AVATAR_BLOB_PUT_AUDIENCE,
            {
                authorization,
                serverEntryAuthorization,
                blobId,
                data,
                powEpoch,
                ...work
            },
            context.serverUrl
        );
        await assertOwner();
        const ok = !!resp &&
            typeof resp === 'object' &&
            !Array.isArray(resp) &&
            Object.keys(resp).join(',') === 'ok' &&
            resp.ok === true;
        if (!ok) console.warn('[AVATAR] blob PUT rejected by server', { error: resp?.error || 'unknown' });
        return ok;
    } catch (e: any) {
        const now = Date.now();
        const details = { error: e?.message || String(e) };
        if (now - lastAvatarPutTransportWarnAt > AVATAR_PUT_TRANSPORT_WARN_INTERVAL_MS) {
            lastAvatarPutTransportWarnAt = now;
            console.warn('[AVATAR] blob PUT threw (transport)', details);
        } else {
            console.log('[AVATAR] blob PUT still failing (transport)', details);
        }
        return false;
    } finally {
        redemption?.nullifier.fill(0);
        redemption?.mac.fill(0);
        if (token) wipeAnonymousToken(token);
    }
}

// Schedule a PUT at a random delay
function scheduleJitteredUpload(
    blobId: string,
    data: string,
    attempt = 0,
    onSuccess?: () => void | Promise<void>,
    generation = accountGeneration,
    onComplete?: (success: boolean) => void
): void {
    const delay = AVATAR_UPLOAD_JITTER_MIN_MS + PostQuantumRandom.randomInt(AVATAR_UPLOAD_JITTER_MAX_MS - AVATAR_UPLOAD_JITTER_MIN_MS);
    const timer = setTimeout(async () => {
        scheduledUploads.delete(timer);
        if (generation !== accountGeneration) { onComplete?.(false); return; }
        const ok = await putAvatarBlob(blobId, data, generation);
        if (generation !== accountGeneration) { onComplete?.(false); return; }
        if (ok) {
            try {
                await onSuccess?.();
            } catch {
                onComplete?.(false);
                return;
            }
            onComplete?.(true);
            return;
        }
        if (attempt + 1 < AVATAR_UPLOAD_MAX_ATTEMPTS) {
            scheduleJitteredUpload(blobId, data, attempt + 1, onSuccess, generation, onComplete);
        } else {
            onComplete?.(false);
        }
    }, delay);
    scheduledUploads.add(timer);
}

/**
 * Keep the public avatar pool populated with this client's share of cover PURBs
 */
export async function ensureAvatarCoverBlobs(): Promise<void> {
    const now = Date.now();
    if (coverUploadBatchPending || now - lastCoverUploadAt < COVER_REFRESH_MS) return;
    coverUploadBatchPending = true;
    const generation = accountGeneration;
    let anySucceeded = false;

    const uploadNext = (index: number) => {
        if (generation !== accountGeneration) return;
        if (index >= COVER_BLOBS_PER_CLIENT) {
            coverUploadBatchPending = false;
            if (anySucceeded) lastCoverUploadAt = Date.now();
            return;
        }
        scheduleJitteredUpload(
            randomHexId(),
            randomCoverPurbBase64(),
            0,
            undefined,
            generation,
            (success) => {
                anySucceeded ||= success;
                uploadNext(index + 1);
            }
        );
    };
    uploadNext(0);
}

// Saved record of the avatar blob currently advertising
interface AvatarUploadState { hash: string; ref: AvatarRef; expiresAt: number; }
interface PendingAvatarUpload { hash: string; ref: AvatarRef; expiresAt: number; generation: number; }
let avatarUploadState: AvatarUploadState | null = null;
let pendingAvatarUpload: PendingAvatarUpload | null = null;
let avatarUploadStateLoadedGeneration = -1;

export function isValidAvatarRef(value: unknown, expectedHash: string): value is AvatarRef {
    if (
        !value ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).sort().join(',') !== 'blobId,hash,keyB64,mimeType'
    ) return false;
    const ref = value as Record<string, unknown>;
    if (
        typeof ref.blobId !== 'string' ||
        !/^[a-f0-9]{64}$/.test(ref.blobId) ||
        ref.hash !== expectedHash ||
        typeof ref.keyB64 !== 'string' ||
        ref.mimeType !== 'image/webp'
    ) return false;
    try {
        const key = PostQuantumUtils.base64ToUint8Array(ref.keyB64);
        try {
            return key.length === 32 && PostQuantumUtils.uint8ArrayToBase64(key) === ref.keyB64;
        } finally {
            key.fill(0);
        }
    } catch {
        return false;
    }
}

function parseAvatarUploadState(value: unknown, now = Date.now()): AvatarUploadState | null {
    if (
        !value ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).sort().join(',') !== 'expiresAt,hash,ref'
    ) return null;
    const state = value as Record<string, unknown>;
    if (
        typeof state.hash !== 'string' ||
        !/^[a-f0-9]{64}$/.test(state.hash) ||
        !Number.isSafeInteger(state.expiresAt) ||
        (state.expiresAt as number) <= now ||
        (state.expiresAt as number) > now + AVATAR_BLOB_TTL_MS ||
        !isValidAvatarRef(state.ref, state.hash)
    ) return null;
    return {
        hash: state.hash,
        ref: { ...(state.ref as AvatarRef) },
        expiresAt: state.expiresAt as number
    };
}

async function loadAvatarUploadState(generation: number): Promise<AvatarUploadState | null> {
    if (generation !== accountGeneration) return null;
    if (avatarUploadStateLoadedGeneration === generation) return avatarUploadState;
    if (!encryptedStorage.isInitialized()) return null;
    try {
        const stored = await encryptedStorage.getItem(STORAGE_KEYS.AVATAR_PUBLICATION_STATE);
        if (generation !== accountGeneration) return null;
        if (avatarUploadStateLoadedGeneration !== generation) {
            avatarUploadState = parseAvatarUploadState(stored);
            avatarUploadStateLoadedGeneration = generation;
            if (stored !== null && avatarUploadState === null) {
                await encryptedStorage.removeItem(STORAGE_KEYS.AVATAR_PUBLICATION_STATE).catch(() => { });
                if (generation !== accountGeneration) return null;
            }
        }
    } catch {
        return null;
    }
    return generation === accountGeneration ? avatarUploadState : null;
}

async function saveAvatarUploadState(state: AvatarUploadState, generation: number): Promise<boolean> {
    if (generation !== accountGeneration) return false;
    const ownedState = {
        hash: state.hash,
        ref: { ...state.ref },
        expiresAt: state.expiresAt
    };
    avatarUploadState = ownedState;
    avatarUploadStateLoadedGeneration = generation;
    const rollback = () => {
        if (generation === accountGeneration && avatarUploadState === ownedState) {
            avatarUploadState = null;
            avatarUploadStateLoadedGeneration = -1;
        }
    };
    if (!encryptedStorage.isInitialized()) {
        rollback();
        return false;
    }
    try {
        await encryptedStorage.setItem(STORAGE_KEYS.AVATAR_PUBLICATION_STATE, ownedState);
    } catch {
        rollback();
        return false;
    }
    return generation === accountGeneration && avatarUploadState === ownedState;
}

export function resetAvatarStoreClient(): void {
    accountGeneration += 1;
    for (const timer of scheduledUploads) clearTimeout(timer);
    scheduledUploads.clear();
    poolCache = null;
    decoyCache.clear();
    avatarUploadState = null;
    avatarUploadStateLoadedGeneration = -1;
    pendingAvatarUpload = null;
    lastCoverUploadAt = 0;
    coverUploadBatchPending = false;
    lastAvatarPutTransportWarnAt = 0;
}

/**
 * Make sure clients avatar is in the store and return AvatarRef to embed in keys blob
 */
export async function publishAvatarToStore(avatar: AvatarData): Promise<AvatarRef | null> {
    if (
        !isValidAvatarData(avatar) ||
        avatar.isDefault !== false ||
        avatar.mimeType !== 'image/webp' ||
        await hashAvatarData(avatar.data) !== avatar.hash
    ) return null;
    const generation = accountGeneration;
    const now = Date.now();
    const state = await loadAvatarUploadState(generation);
    if (generation !== accountGeneration) return null;

    if (state && state.hash === avatar.hash && state.expiresAt - now > AVATAR_REFRESH_MARGIN_MS) {
        return state.ref;
    }
    if (
        pendingAvatarUpload?.generation === generation &&
        pendingAvatarUpload.hash === avatar.hash
    ) {
        return state && state.hash === avatar.hash && state.expiresAt > now ? state.ref : null;
    }

    const reuseRef = state && state.hash === avatar.hash ? state.ref : undefined;
    let ref: AvatarRef;
    let purbBase64: string;
    try {
        const enc = encryptAvatarToPurb(avatar, reuseRef);
        ref = enc.ref;
        purbBase64 = enc.purbBase64;
    } catch {
        return null;
    }

    const expiresAt = now + AVATAR_BLOB_TTL_MS;
    if (generation !== accountGeneration) return null;
    pendingAvatarUpload = { hash: avatar.hash, ref, expiresAt, generation };
    scheduleJitteredUpload(ref.blobId, purbBase64, 0, async () => {
        if (generation !== accountGeneration) return;
        const saved = await saveAvatarUploadState({ hash: avatar.hash, ref, expiresAt }, generation);
        if (generation !== accountGeneration) return;
        if (!saved) throw new Error('Avatar publication state was not persisted');
        if (
            pendingAvatarUpload?.generation === generation &&
            pendingAvatarUpload.ref.blobId === ref.blobId
        ) {
            pendingAvatarUpload = null;
        }
        console.log('[AVATAR] blob upload confirmed');
    }, generation, (success) => {
        if (
            !success &&
            pendingAvatarUpload?.generation === generation &&
            pendingAvatarUpload.ref.blobId === ref.blobId
        ) {
            pendingAvatarUpload = null;
        }
    });
    return state && state.hash === avatar.hash && state.expiresAt > now ? state.ref : null;
}

// Pick a stable decoy set for a target
function stableDecoysFor(targetBlobId: string, pool: string[], serverScope: string): string[] {
    const now = Date.now();
    const cacheKey = `${serverScope}:${targetBlobId}`;
    const cached = decoyCache.get(cacheKey);
    if (cached && cached.expiresAt > now) return cached.ids;

    if (decoyCache.size > DECOY_CACHE_MAX) {
        for (const [k, v] of decoyCache) if (v.expiresAt <= now) decoyCache.delete(k);
        if (decoyCache.size > DECOY_CACHE_MAX) decoyCache.clear();
    }
    const decoys = PostQuantumRandom.shuffleInPlace(pool.filter((id) => id !== targetBlobId)).slice(0, Math.max(0, AVATAR_COVER_TOTAL_IDS - 1));
    decoyCache.set(cacheKey, { ids: decoys, expiresAt: now + DECOY_CACHE_TTL_MS });
    return decoys;
}

/**
 * Fetch and decrypt peer's avatar by its ref
 */
export async function fetchAvatarFromStore(ref: AvatarRef): Promise<AvatarData | null> {
    const expectedHash = typeof ref?.hash === 'string' ? ref.hash : '';
    if (!isValidAvatarRef(ref, expectedHash)) return null;
    try {
        const generation = accountGeneration;
        const context = await captureCurrentServerContext();
        const assertOwner = async () => {
            if (generation !== accountGeneration) throw new Error('Avatar account changed');
            await assertCurrentServerContext(context);
        };
        const poolState = await fetchPool(context);
        await assertOwner();
        if (!poolState) return null;
        if (poolState.powEpoch !== Math.floor(Date.now() / DISCOVERY_EPOCH_DURATION_MS)) {
            poolCache = null;
            return null;
        }
        const decoys = stableDecoysFor(ref.blobId, poolState.ids, context.serverScope);
        if (decoys.length !== AVATAR_COVER_TOTAL_IDS - 1) return null;
        const ids = PostQuantumRandom.shuffleInPlace(Array.from(new Set([ref.blobId, ...decoys])));
        if (ids.length !== AVATAR_COVER_TOTAL_IDS) return null;

        const work = await createAnonymousHttpPow(
            PROTOCOL_KEYS.AVATAR_GET_HTTP_POW,
            poolState.powEpoch,
            ids,
            AVATAR_GET_POW_DIFFICULTY
        );
        await assertOwner();
        const resp: any = await anonymousHttpFetch(
            AVATAR_BLOB_GET_AUDIENCE,
            { ids, powEpoch: poolState.powEpoch, ...work },
            context.serverUrl
        );
        await assertOwner();
        if (
            !resp ||
            typeof resp !== 'object' ||
            Array.isArray(resp) ||
            Object.keys(resp).sort().join(',') !== 'blobs,ok' ||
            resp.ok !== true ||
            !Array.isArray(resp.blobs) ||
            resp.blobs.length !== AVATAR_COVER_TOTAL_IDS
        ) return null;
        const blobs: Array<{ id: string; data: string }> = resp.blobs;
        const responseIds = new Set<string>();
        for (const blob of blobs) {
            if (
                !blob ||
                typeof blob !== 'object' ||
                Array.isArray(blob) ||
                Object.keys(blob).sort().join(',') !== 'data,id' ||
                typeof blob.id !== 'string' ||
                !ids.includes(blob.id) ||
                responseIds.has(blob.id) ||
                typeof blob.data !== 'string'
            ) return null;
            responseIds.add(blob.id);
        }
        if (responseIds.size !== ids.length) return null;
        const target = blobs.find((b) => b?.id === ref.blobId);
        if (!target || typeof target.data !== 'string') return null;

        const avatar = decryptAvatarPurb(target.data, ref);
        if (!avatar) return null;

        // Re verify the content hash so a tampered/substituted blob is rejected
        const computed = await hashAvatarData(avatar.data);
        await assertOwner();
        if (ref.hash && computed !== ref.hash) return null;
        const validated = { ...avatar, hash: computed };
        return isValidAvatarData(validated) ? validated : null;
    } catch {
        return null;
    }
}
