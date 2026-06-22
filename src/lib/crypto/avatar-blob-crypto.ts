/**
 * Avatar PURB cryptography
 */

import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumRandom } from '../cryptography/random';
import { PQ_AEAD_NONCE_SIZE, PQ_AEAD_MAC_SIZE, MAX_AVATAR_SIZE_BYTES } from '../constants';
import type { AvatarData } from '../types/avatar-types';

export const AVATAR_PURB_CAPACITY = 256 * 1024;
export const AVATAR_PURB_WIRE_BYTES = PQ_AEAD_NONCE_SIZE + PQ_AEAD_MAC_SIZE + (AVATAR_PURB_CAPACITY + 32);

const AVATAR_BLOB_AAD = 'qor-avatar-purb-v1';
const LEN_PREFIX = 4;
const MAX_AVATAR_DATA_CHARS = Math.floor(MAX_AVATAR_SIZE_BYTES * 1.4);

export interface AvatarRef {
    blobId: string;
    keyB64: string;
    hash: string;
    mimeType: string;
}

export interface EncryptedAvatarBlob {
    ref: AvatarRef;
    purbBase64: string;
}

function bytesToHex(bytes: Uint8Array): string {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
}

/**
 * Encrypt avatar into uniform size PURB and return ref to embed in keys blob
 */
export function encryptAvatarToPurb(avatar: AvatarData, existingRef?: AvatarRef): EncryptedAvatarBlob {
    if (typeof avatar?.data !== 'string' || avatar.data.length === 0) {
        throw new Error('avatar has no data');
    }
    if (avatar.data.length > MAX_AVATAR_DATA_CHARS) {
        throw new Error('avatar exceeds maximum size');
    }
    const content = new TextEncoder().encode(JSON.stringify({
        data: avatar.data,
        mimeType: avatar.mimeType,
        hash: avatar.hash,
        isDefault: avatar.isDefault === true
    }));
    if (content.length + LEN_PREFIX > AVATAR_PURB_CAPACITY) {
        throw new Error('avatar too large for PURB capacity');
    }

    const plaintext = new Uint8Array(AVATAR_PURB_CAPACITY);
    new DataView(plaintext.buffer).setUint32(0, content.length, true);
    plaintext.set(content, LEN_PREFIX);
    const padLen = AVATAR_PURB_CAPACITY - LEN_PREFIX - content.length;
    if (padLen > 0) plaintext.set(PostQuantumRandom.randomBytes(padLen), LEN_PREFIX + content.length);

    const reuse = existingRef
        && typeof existingRef.blobId === 'string' && /^[a-f0-9]{64}$/.test(existingRef.blobId)
        && typeof existingRef.keyB64 === 'string';
    let key: Uint8Array;
    if (reuse) {
        const decoded = PostQuantumUtils.base64ToUint8Array(existingRef!.keyB64);
        key = decoded.length === 32 ? decoded : PostQuantumRandom.randomBytes(32);
    } else {
        key = PostQuantumRandom.randomBytes(32);
    }
    const aad = new TextEncoder().encode(AVATAR_BLOB_AAD);
    const { ciphertext, nonce, tag } = PostQuantumAEAD.encrypt(plaintext, key, aad);

    const combined = new Uint8Array(nonce.length + tag.length + ciphertext.length);
    combined.set(nonce, 0);
    combined.set(tag, nonce.length);
    combined.set(ciphertext, nonce.length + tag.length);

    return {
        ref: {
            blobId: reuse ? existingRef!.blobId : bytesToHex(PostQuantumRandom.randomBytes(32)),
            keyB64: reuse ? existingRef!.keyB64 : PostQuantumUtils.uint8ArrayToBase64(key),
            hash: avatar.hash,
            mimeType: avatar.mimeType
        },
        purbBase64: PostQuantumUtils.uint8ArrayToBase64(combined)
    };
}

// Decrypt fetched PURB using its ref
export function decryptAvatarPurb(purbBase64: string, ref: AvatarRef): AvatarData | null {
    try {
        const data = PostQuantumUtils.base64ToUint8Array(purbBase64);
        if (data.length < PQ_AEAD_NONCE_SIZE + PQ_AEAD_MAC_SIZE + LEN_PREFIX) return null;
        const nonce = data.slice(0, PQ_AEAD_NONCE_SIZE);
        const tag = data.slice(PQ_AEAD_NONCE_SIZE, PQ_AEAD_NONCE_SIZE + PQ_AEAD_MAC_SIZE);
        const ciphertext = data.slice(PQ_AEAD_NONCE_SIZE + PQ_AEAD_MAC_SIZE);
        const key = PostQuantumUtils.base64ToUint8Array(ref.keyB64);
        const aad = new TextEncoder().encode(AVATAR_BLOB_AAD);

        const plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, key, aad);
        if (plaintext.length < LEN_PREFIX) return null;
        const contentLen = new DataView(plaintext.buffer, plaintext.byteOffset, LEN_PREFIX).getUint32(0, true);
        if (contentLen <= 0 || contentLen + LEN_PREFIX > plaintext.length) return null;

        const content = plaintext.slice(LEN_PREFIX, LEN_PREFIX + contentLen);
        const obj = JSON.parse(new TextDecoder().decode(content));
        if (typeof obj?.data !== 'string' || obj.data.length === 0) return null;
        return {
            data: obj.data,
            mimeType: typeof obj.mimeType === 'string' ? obj.mimeType : 'image/png',
            hash: typeof obj.hash === 'string' ? obj.hash : ref.hash,
            updatedAt: Date.now(),
            isDefault: obj.isDefault === true
        };
    } catch {
        return null;
    }
}
