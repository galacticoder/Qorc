/**
 * Avatar PURB cryptography
 */

import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumRandom } from '../cryptography/random';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { MAX_AVATAR_DATA_URL_CHARS } from '../constants';
import type { AvatarData } from '../types/avatar-types';
import { HASH_OUTPUT_BYTES, POST_QUANTUM_AEAD_NONCE_BYTES } from '../../../shared/crypto-sizes.js';
import { Base64 } from '../cryptography/base64';
import { bytesToHex } from '../../../shared/bytes.js';

export const AVATAR_PURB_CAPACITY = 256 * 1024;
export const AVATAR_PURB_WIRE_BYTES = POST_QUANTUM_AEAD_NONCE_BYTES + HASH_OUTPUT_BYTES + (AVATAR_PURB_CAPACITY + 32);

const LEN_PREFIX = 4;

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

/**
 * Encrypt avatar into uniform size PURB and return ref to embed in keys blob
 */
export function encryptAvatarToPurb(avatar: AvatarData, existingRef?: AvatarRef): EncryptedAvatarBlob {
    if (typeof avatar?.data !== 'string' || avatar.data.length === 0) {
        throw new Error('avatar has no data');
    }
    if (avatar.data.length > MAX_AVATAR_DATA_URL_CHARS) {
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
    let padding: Uint8Array | null = null;
    let key: Uint8Array | null = null;
    let aad: Uint8Array | null = null;
    let ciphertext: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let tag: Uint8Array | null = null;
    let combined: Uint8Array | null = null;
    let blobIdBytes: Uint8Array | null = null;
    try {
        new DataView(plaintext.buffer).setUint32(0, content.length, true);
        plaintext.set(content, LEN_PREFIX);
        const padLen = AVATAR_PURB_CAPACITY - LEN_PREFIX - content.length;
        if (padLen > 0) {
            padding = PostQuantumRandom.randomBytes(padLen);
            plaintext.set(padding, LEN_PREFIX + content.length);
        }

        if (
            existingRef &&
            typeof existingRef.blobId === 'string' &&
            /^[a-f0-9]{64}$/.test(existingRef.blobId) &&
            typeof existingRef.keyB64 === 'string'
        ) {
            const decoded = PostQuantumUtils.base64ToUint8Array(existingRef.keyB64);
            if (
                decoded.length === 32 &&
                Base64.arrayBufferToBase64(decoded) === existingRef.keyB64
            ) {
                key = decoded;
            } else {
                decoded.fill(0);
            }
        }
        if (!key) key = PostQuantumRandom.randomBytes(32);

        aad = new TextEncoder().encode(PROTOCOL_KEYS.AVATAR_BLOB_AAD);
        ({ ciphertext, nonce, tag } = PostQuantumAEAD.encrypt(plaintext, key, aad));
        combined = new Uint8Array(nonce.length + tag.length + ciphertext.length);
        combined.set(nonce, 0);
        combined.set(tag, nonce.length);
        combined.set(ciphertext, nonce.length + tag.length);
        blobIdBytes = PostQuantumRandom.randomBytes(32);

        return {
            ref: {
                blobId: bytesToHex(blobIdBytes),
                keyB64: Base64.arrayBufferToBase64(key),
                hash: avatar.hash,
                mimeType: avatar.mimeType
            },
            purbBase64: Base64.arrayBufferToBase64(combined)
        };
    } finally {
        content.fill(0);
        plaintext.fill(0);
        padding?.fill(0);
        key?.fill(0);
        aad?.fill(0);
        ciphertext?.fill(0);
        nonce?.fill(0);
        tag?.fill(0);
        combined?.fill(0);
        blobIdBytes?.fill(0);
    }
}

// Decrypt fetched PURB using its ref
export function decryptAvatarPurb(purbBase64: string, ref: AvatarRef): AvatarData | null {
    let data: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let tag: Uint8Array | null = null;
    let ciphertext: Uint8Array | null = null;
    let key: Uint8Array | null = null;
    let aad: Uint8Array | null = null;
    let plaintext: Uint8Array | null = null;
    let content: Uint8Array | null = null;
    try {
        if (typeof purbBase64 !== 'string' || typeof ref?.keyB64 !== 'string') return null;
        data = PostQuantumUtils.base64ToUint8Array(purbBase64);
        if (
            data.length !== AVATAR_PURB_WIRE_BYTES ||
            Base64.arrayBufferToBase64(data) !== purbBase64
        ) return null;
        nonce = data.slice(0, POST_QUANTUM_AEAD_NONCE_BYTES);
        tag = data.slice(POST_QUANTUM_AEAD_NONCE_BYTES, POST_QUANTUM_AEAD_NONCE_BYTES + HASH_OUTPUT_BYTES);
        ciphertext = data.slice(POST_QUANTUM_AEAD_NONCE_BYTES + HASH_OUTPUT_BYTES);
        key = PostQuantumUtils.base64ToUint8Array(ref.keyB64);
        if (key.length !== 32 || Base64.arrayBufferToBase64(key) !== ref.keyB64) return null;
        aad = new TextEncoder().encode(PROTOCOL_KEYS.AVATAR_BLOB_AAD);

        plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, key, aad);
        if (plaintext.length < LEN_PREFIX) return null;
        const contentLen = new DataView(plaintext.buffer, plaintext.byteOffset, LEN_PREFIX).getUint32(0, true);
        if (contentLen <= 0 || contentLen + LEN_PREFIX > plaintext.length) return null;

        content = plaintext.slice(LEN_PREFIX, LEN_PREFIX + contentLen);
        const obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(content));
        if (
            !obj ||
            typeof obj !== 'object' ||
            Array.isArray(obj) ||
            Object.keys(obj).sort().join(',') !== 'data,hash,isDefault,mimeType' ||
            typeof obj.data !== 'string' ||
            obj.data.length === 0 ||
            obj.data.length > MAX_AVATAR_DATA_URL_CHARS ||
            typeof obj.hash !== 'string' ||
            obj.hash !== ref.hash ||
            typeof obj.mimeType !== 'string' ||
            obj.mimeType !== ref.mimeType ||
            typeof obj.isDefault !== 'boolean'
        ) return null;
        return {
            data: obj.data,
            mimeType: obj.mimeType,
            hash: obj.hash,
            isDefault: obj.isDefault === true
        };
    } catch {
        return null;
    } finally {
        data?.fill(0);
        nonce?.fill(0);
        tag?.fill(0);
        ciphertext?.fill(0);
        key?.fill(0);
        aad?.fill(0);
        plaintext?.fill(0);
        content?.fill(0);
    }
}
