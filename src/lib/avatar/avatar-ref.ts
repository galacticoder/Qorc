import type { AvatarRef } from '../crypto/avatar-blob-crypto';
import { AVATAR_STORE_CLIENT_KEY_LENGTH_EXPECTED } from '../constants/avatars';
import { canonicalBase64Shape } from '../../../shared/canonical-base64.js';
import { isHex } from '../../../shared/bytes.js';
import { HASH_OUTPUT_BYTES } from '../../../shared/crypto-sizes.js';

export function isValidAvatarRef(value: unknown, expectedHash: string): value is AvatarRef {
    if (
        !value ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).sort().join(',') !== 'blobId,hash,keyB64,mimeType'
    ) return false;
    const ref = value as Record<string, unknown>;
    return isHex(ref.blobId, { exactBytes: HASH_OUTPUT_BYTES }) &&
        isHex(ref.hash, { exactBytes: HASH_OUTPUT_BYTES }) &&
        ref.hash === expectedHash &&
        canonicalBase64Shape(ref.keyB64, { exactBytes: AVATAR_STORE_CLIENT_KEY_LENGTH_EXPECTED }) &&
        ref.mimeType === 'image/webp';
}
