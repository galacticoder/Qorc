/**
 * Client the unlinkable avatar content store
 */

import { pir } from '../tauri-bindings';
import { encryptAvatarToPurb, decryptAvatarPurb, AVATAR_PURB_WIRE_BYTES, type AvatarRef } from '../crypto/avatar-blob-crypto';
import { PostQuantumUtils } from '../utils/pq-utils';
import { hashAvatarData } from '../utils/avatar-utils';
import type { AvatarData } from '../types/avatar-types';

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
const AVATAR_UPLOAD_STATE_KEY = 'qor.avatar.upload.v1';
const AVATAR_UPLOAD_MAX_ATTEMPTS = 3;
const AVATAR_PUT_TRANSPORT_WARN_INTERVAL_MS = 30_000;

let poolCache: { ids: string[]; fetchedAt: number } | null = null;
let lastCoverUploadAt = 0;
let lastAvatarPutTransportWarnAt = 0;
const decoyCache = new Map<string, { ids: string[]; expiresAt: number }>();

async function fetchPool(): Promise<string[]> {
    const now = Date.now();
    if (poolCache && now - poolCache.fetchedAt < POOL_CACHE_TTL_MS) return poolCache.ids;
    try {
        const resp: any = await pir.discoveryApiFetch('avatar/pool', JSON.stringify({ limit: POOL_SAMPLE_LIMIT }));
        const ids: string[] = Array.isArray(resp?.ids) ? resp.ids.filter((x: unknown) => typeof x === 'string') : [];
        poolCache = { ids, fetchedAt: now };
        return ids;
    } catch {
        return poolCache?.ids ?? [];
    }
}

// Unbiased in place Fisher Yates shuffle
function shuffle<T>(arr: T[]): T[] {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function randomHexId(): string {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
}

// Random bytes of exactly one PURB's wire size
function randomCoverPurbBase64(): string {
    const buf = new Uint8Array(AVATAR_PURB_WIRE_BYTES);
    for (let off = 0; off < buf.length; off += 65536) {
        crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, buf.length)));
    }
    return PostQuantumUtils.uint8ArrayToBase64(buf);
}

// One shot PUT of a blob
async function putAvatarBlob(blobId: string, data: string, expiresAt: number): Promise<boolean> {
    try {
        const resp: any = await pir.discoveryApiFetch('avatar/blob/put', JSON.stringify({ blobId, data, expiresAt }));
        const ok = resp?.ok === true;
        if (!ok) console.warn('[AVATAR] blob PUT rejected by server', { blobId: blobId.slice(0, 12), error: resp?.error || 'unknown', dataLen: data.length });
        return ok;
    } catch (e: any) {
        const now = Date.now();
        const details = { blobId: blobId.slice(0, 12), error: e?.message || String(e) };
        if (now - lastAvatarPutTransportWarnAt > AVATAR_PUT_TRANSPORT_WARN_INTERVAL_MS) {
            lastAvatarPutTransportWarnAt = now;
            console.warn('[AVATAR] blob PUT threw (transport)', details);
        } else {
            console.log('[AVATAR] blob PUT still failing (transport)', details);
        }
        return false;
    }
}

// Schedule a PUT at a random delay
function scheduleJitteredUpload(blobId: string, data: string, expiresAt: number, attempt = 0, onSuccess?: () => void): void {
    const delay = AVATAR_UPLOAD_JITTER_MIN_MS + Math.floor(Math.random() * (AVATAR_UPLOAD_JITTER_MAX_MS - AVATAR_UPLOAD_JITTER_MIN_MS));
    setTimeout(async () => {
        const ok = await putAvatarBlob(blobId, data, expiresAt);
        if (ok) { onSuccess?.(); return; }
        if (attempt + 1 < AVATAR_UPLOAD_MAX_ATTEMPTS) scheduleJitteredUpload(blobId, data, expiresAt, attempt + 1, onSuccess);
    }, delay);
}

/**
 * Keep the public avatar pool populated with this client's share of cover PURBs
 */
export async function ensureAvatarCoverBlobs(): Promise<void> {
    const now = Date.now();
    if (now - lastCoverUploadAt < COVER_REFRESH_MS) return;
    lastCoverUploadAt = now;
    const expiresAt = now + AVATAR_BLOB_TTL_MS;
    for (let i = 0; i < COVER_BLOBS_PER_CLIENT; i++) {
        scheduleJitteredUpload(randomHexId(), randomCoverPurbBase64(), expiresAt);
    }
}

// Saved record of the avatar blob we're currently advertising
interface AvatarUploadState { hash: string; ref: AvatarRef; expiresAt: number; uploaded: boolean; }
let avatarUploadState: AvatarUploadState | null = null;
let avatarUploadStateLoaded = false;
let avatarUploadedThisSession = false;

function loadAvatarUploadState(): AvatarUploadState | null {
    if (avatarUploadStateLoaded) return avatarUploadState;
    avatarUploadStateLoaded = true;
    try {
        const raw = localStorage.getItem(AVATAR_UPLOAD_STATE_KEY);
        if (raw) {
            const p = JSON.parse(raw);
            if (p && typeof p.hash === 'string' && p.ref && typeof p.ref.blobId === 'string'
                && typeof p.ref.keyB64 === 'string' && typeof p.expiresAt === 'number') {
                avatarUploadState = { hash: p.hash, ref: p.ref, expiresAt: p.expiresAt, uploaded: p.uploaded === true };
            }
        }
    } catch {}
    return avatarUploadState;
}

function saveAvatarUploadState(s: AvatarUploadState): void {
    avatarUploadState = s;
    avatarUploadStateLoaded = true;
    try { localStorage.setItem(AVATAR_UPLOAD_STATE_KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

/**
 * Make sure this client's avatar is in the store and return the AvatarRef to embed in the keys blob
 */
export async function publishAvatarToStore(avatar: AvatarData): Promise<AvatarRef | null> {
    if (typeof avatar?.data !== 'string' || avatar.data.length === 0) return null;
    const now = Date.now();
    const state = loadAvatarUploadState();

    if (state && state.uploaded && avatarUploadedThisSession && state.hash === avatar.hash && state.expiresAt - now > AVATAR_REFRESH_MARGIN_MS) {
        return state.ref;
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
    saveAvatarUploadState({ hash: avatar.hash, ref, expiresAt, uploaded: false });
    scheduleJitteredUpload(ref.blobId, purbBase64, expiresAt, 0, () => {
        avatarUploadedThisSession = true;
        saveAvatarUploadState({ hash: avatar.hash, ref, expiresAt, uploaded: true });
        console.log('[AVATAR] blob upload CONFIRMED in store', { blobId: ref.blobId.slice(0, 12) });
    });
    return ref;
}

// Pick a stable decoy set for a target
function stableDecoysFor(targetBlobId: string, pool: string[]): string[] {
    const now = Date.now();
    const cached = decoyCache.get(targetBlobId);
    if (cached && cached.expiresAt > now) return cached.ids;

    if (decoyCache.size > DECOY_CACHE_MAX) {
        for (const [k, v] of decoyCache) if (v.expiresAt <= now) decoyCache.delete(k);
        if (decoyCache.size > DECOY_CACHE_MAX) decoyCache.clear();
    }
    const decoys = shuffle(pool.filter((id) => id !== targetBlobId)).slice(0, Math.max(0, AVATAR_COVER_TOTAL_IDS - 1));
    decoyCache.set(targetBlobId, { ids: decoys, expiresAt: now + DECOY_CACHE_TTL_MS });
    return decoys;
}

/**
 * Fetch and decrypt peer's avatar by its ref
 */
export async function fetchAvatarFromStore(ref: AvatarRef): Promise<AvatarData | null> {
    if (!ref || typeof ref.blobId !== 'string' || typeof ref.keyB64 !== 'string') return null;
    try {
        const pool = await fetchPool();
        const decoys = stableDecoysFor(ref.blobId, pool);
        const ids = shuffle(Array.from(new Set([ref.blobId, ...decoys])));

        const resp: any = await pir.discoveryApiFetch('avatar/blob/get', JSON.stringify({ ids }));
        const blobs: Array<{ id?: string; data?: string }> = Array.isArray(resp?.blobs) ? resp.blobs : [];
        const target = blobs.find((b) => b?.id === ref.blobId);
        if (!target || typeof target.data !== 'string') return null;

        const avatar = decryptAvatarPurb(target.data, ref);
        if (!avatar) return null;

        // Re verify the content hash so a tampered/substituted blob is rejected
        const computed = await hashAvatarData(avatar.data);
        if (ref.hash && computed !== ref.hash) return null;
        return { ...avatar, hash: computed };
    } catch {
        return null;
    }
}
