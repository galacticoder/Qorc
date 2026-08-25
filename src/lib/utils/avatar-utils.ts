import {
    MAX_AVATAR_SIZE_BYTES,
    MAX_AVATAR_DIMENSION,
    MAX_AVATAR_DATA_URL_CHARS,
    ALLOWED_AVATAR_MIME_TYPES,
    AVATAR_CACHE_TTL_MS
} from '../constants';
import type { AvatarData, CachedAvatar } from '../types/avatar-types';
import {
    validateJpegContainer,
    validatePngContainer,
    validateWebpContainer
} from './image-container-validation';
import { bytesToHex } from './byte-utils';
import { Base64 } from '../cryptography/base64';
import { canonicalBase64Shape } from '../../../shared/canonical-base64.js';

const DEFAULT_AVATAR_COLORS = [
  '#5865F2', '#57F287', '#FEE75C', '#EB459E', '#ED4245',
  '#3BA55C', '#FAA61A', '#9B59B6', '#1ABC9C', '#E91E63'
] as const;

export function getDefaultAvatarColor(username: string): string {
  const normalized = (username || '').toLowerCase().trim();
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    hash = normalized.charCodeAt(i) + ((hash << 5) - hash);
  }
  return DEFAULT_AVATAR_COLORS[Math.abs(hash) % DEFAULT_AVATAR_COLORS.length];
}

// Truncates long hexadecimal usernames to first 8 characters
export function truncateUsername(username: string): string {
  if (typeof username !== 'string' || username.length === 0) return '';
  return username.length > 32 ? `${username.slice(0, 8)}...` : username;
}

// Generates a deterministic default avatar SVG for a username
export function generateDefaultAvatar(username: string): string {
  const color = getDefaultAvatarColor(username);

  let initials = '?';
  const isHash = /^[a-f0-9]{32,}$/i.test(username);
  if (isHash) {
    initials = username.slice(0, 2).toUpperCase();
  } else {
    const clean = username.replace(/[^a-zA-Z0-9]/g, '');
    initials = (clean || '?').slice(0, 2).toUpperCase();
  }

  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
      <rect width="512" height="512" fill="${color}"/>
      <text x="50%" y="50%" font-family="Arial, sans-serif" font-weight="bold" font-size="256" fill="#FFFFFF" text-anchor="middle" dy=".35em">${initials}</text>
    </svg>`;

  return `data:image/svg+xml;base64,${Base64.arrayBufferToBase64(new TextEncoder().encode(svg))}`;
}

interface ImageValidationOptions {
    allowGeneratedDefaultSvg?: boolean;
    maxDimension?: number;
    maxDataUrlChars?: number;
}

const SAFE_DEFAULT_SVG = /^\s*<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="512" height="512" viewBox="0 0 512 512">\s*<rect width="512" height="512" fill="#(?:5865F2|57F287|FEE75C|EB459E|ED4245|3BA55C|FAA61A|9B59B6|1ABC9C|E91E63)"\/>\s*<text x="50%" y="50%" font-family="Arial, sans-serif" font-weight="bold" font-size="256" fill="#FFFFFF" text-anchor="middle" dy="\.35em">[A-Z0-9._?\-]{1,2}<\/text>\s*<\/svg>\s*$/;

function rasterDimensions(
    bytes: Uint8Array,
    mimeType: string,
    maxDimension: number
): { width: number; height: number } | null {
    const limits = {
        maxWidth: maxDimension,
        maxHeight: maxDimension,
        maxPixels: maxDimension * maxDimension
    };
    try {
        if (mimeType === 'image/png') return validatePngContainer(bytes, limits);
        if (mimeType === 'image/jpeg') return validateJpegContainer(bytes, limits);
        if (mimeType === 'image/webp') return validateWebpContainer(bytes, limits);
    } catch {
        return null;
    }
    return null;
}

export function validateImageData(
    dataUrl: string,
    options: ImageValidationOptions = {}
): { valid: boolean; mimeType: string; error?: string } {
    if (!dataUrl || typeof dataUrl !== 'string') {
        return { valid: false, mimeType: '', error: 'Invalid data URL' };
    }
    if (options.maxDataUrlChars && dataUrl.length > options.maxDataUrlChars) {
        return { valid: false, mimeType: '', error: 'Image data exceeds storage capacity' };
    }

    const match = dataUrl.match(/^data:(image\/[a-z0-9+.-]+);base64,([A-Za-z0-9+/]*={0,2})$/);
    if (!match) {
        return { valid: false, mimeType: '', error: 'Invalid data URL format' };
    }

    const mimeType = match[1];
    if (!ALLOWED_AVATAR_MIME_TYPES.includes(mimeType as typeof ALLOWED_AVATAR_MIME_TYPES[number])) {
        return { valid: false, mimeType, error: `Unsupported image type: ${mimeType}` };
    }

    const base64Data = match[2];
    if (base64Data.length > Math.ceil(MAX_AVATAR_SIZE_BYTES / 3) * 4) {
        return { valid: false, mimeType, error: 'Image too large' };
    }
    let bytes: Uint8Array | null = null;

    try {
        if (!canonicalBase64Shape(base64Data, { maxBytes: MAX_AVATAR_SIZE_BYTES })) {
            return { valid: false, mimeType, error: 'Non-canonical base64 encoding' };
        }
        bytes = Base64.base64ToUint8Array(base64Data);
        const byteLength = bytes.length;

        if (byteLength > MAX_AVATAR_SIZE_BYTES) {
            return { valid: false, mimeType, error: `Image too large: ${Math.round(byteLength / 1024)}KB (max ${MAX_AVATAR_SIZE_BYTES / 1024}KB)` };
        }

        if (byteLength < 100) {
            return { valid: false, mimeType, error: 'Image too small or corrupted' };
        }

        const isJpeg = bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
        const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47 &&
            bytes[4] === 0x0D && bytes[5] === 0x0A && bytes[6] === 0x1A && bytes[7] === 0x0A;
        const isWebp = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
            bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50;

        if (mimeType === 'image/svg+xml') {
            const binaryString = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
            if (!options.allowGeneratedDefaultSvg || !SAFE_DEFAULT_SVG.test(binaryString)) {
                return { valid: false, mimeType, error: 'Only generated default SVG avatars are allowed' };
            }
            return { valid: true, mimeType };
        }

        if (!isJpeg && !isPng && !isWebp) {
            return { valid: false, mimeType, error: 'Invalid image magic bytes' };
        }

        if ((mimeType === 'image/jpeg' && !isJpeg) ||
            (mimeType === 'image/png' && !isPng) ||
            (mimeType === 'image/webp' && !isWebp)) {
            return { valid: false, mimeType, error: 'MIME type mismatch with file content' };
        }

        const dimensions = rasterDimensions(bytes, mimeType, options.maxDimension ?? MAX_AVATAR_DIMENSION);
        if (!dimensions || dimensions.width < 1 || dimensions.height < 1) {
            return { valid: false, mimeType, error: 'Invalid image dimensions' };
        }
        if (
            options.maxDimension &&
            (dimensions.width > options.maxDimension || dimensions.height > options.maxDimension)
        ) {
            return { valid: false, mimeType, error: 'Image dimensions exceed the allowed maximum' };
        }
    } catch {
        return { valid: false, mimeType, error: 'Invalid base64 encoding' };
    } finally {
        bytes?.fill(0);
    }

    return { valid: true, mimeType };
}

export async function compressImage(dataUrl: string, maxSize: number = MAX_AVATAR_DIMENSION): Promise<string> {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            try {
                let width = img.width;
                let height = img.height;

                if (width > maxSize || height > maxSize) {
                    if (width > height) {
                        height = Math.round((height * maxSize) / width);
                        width = maxSize;
                    } else {
                        width = Math.round((width * maxSize) / height);
                        height = maxSize;
                    }
                }

                const canvas = document.createElement('canvas');
                canvas.width = width;
                canvas.height = height;
                const ctx = canvas.getContext('2d');
                if (!ctx) {
                    reject(new Error('Canvas context unavailable'));
                    return;
                }

                ctx.drawImage(img, 0, 0, width, height);

                let quality = 0.9;
                let result = canvas.toDataURL('image/webp', quality);

                while (result.length > MAX_AVATAR_DATA_URL_CHARS && quality > 0.3) {
                    quality -= 0.1;
                    result = canvas.toDataURL('image/webp', quality);
                }

                if (result.length > MAX_AVATAR_DATA_URL_CHARS) {
                    reject(new Error('Unable to compress image to acceptable size'));
                    return;
                }

                resolve(result);
            } catch (e) {
                reject(e);
            }
        };
        img.onerror = () => reject(new Error('Failed to load image'));
        img.src = dataUrl;
    });
}

export async function hashAvatarData(data: string): Promise<string> {
    const { blake3 } = await import('@noble/hashes/blake3.js');
    const bytes = new TextEncoder().encode(data);
    const hash = blake3(bytes, { dkLen: 32 });
    try {
        return bytesToHex(hash);
    } finally {
        bytes.fill(0);
        hash.fill(0);
    }
}

export function isValidAvatarData(data: unknown): data is AvatarData {
    if (
        !data || typeof data !== 'object' || Array.isArray(data) ||
        Object.getPrototypeOf(data) !== Object.prototype ||
        Object.keys(data).sort().join(',') !== 'data,hash,isDefault,mimeType'
    ) return false;
    const d = data as any;
    if (
        typeof d.data === 'string' &&
        typeof d.mimeType === 'string' &&
        typeof d.hash === 'string' && /^[a-f0-9]{64}$/.test(d.hash) &&
        typeof d.isDefault === 'boolean' &&
        ALLOWED_AVATAR_MIME_TYPES.includes(d.mimeType) &&
        (d.isDefault === true || d.mimeType === 'image/webp') &&
        d.data.length <= MAX_AVATAR_DATA_URL_CHARS
    ) {
        const validation = validateImageData(d.data, {
            allowGeneratedDefaultSvg: d.isDefault,
            maxDimension: MAX_AVATAR_DIMENSION,
            maxDataUrlChars: MAX_AVATAR_DATA_URL_CHARS
        });
        return validation.valid && validation.mimeType === d.mimeType;
    }
    return false;
}

export function isValidCachedAvatar(data: unknown): data is CachedAvatar {
    if (
        !data || typeof data !== 'object' || Array.isArray(data) ||
        Object.getPrototypeOf(data) !== Object.prototype ||
        Object.keys(data).sort().join(',') !== 'cachedAt,data,expiresAt,hash,isDefault'
    ) return false;
    const d = data as any;
    const now = Date.now();
    if (
        typeof d.data !== 'string' || d.data.length > MAX_AVATAR_DATA_URL_CHARS ||
        typeof d.hash !== 'string' || !/^[a-f0-9]{64}$/.test(d.hash) ||
        typeof d.isDefault !== 'boolean' ||
        !Number.isSafeInteger(d.cachedAt) || d.cachedAt < 0 || d.cachedAt > now + 60_000 ||
        !Number.isSafeInteger(d.expiresAt) || d.expiresAt <= now ||
        d.expiresAt <= d.cachedAt || d.expiresAt - d.cachedAt > AVATAR_CACHE_TTL_MS + 60_000
    ) return false;
    return validateImageData(d.data, {
        allowGeneratedDefaultSvg: d.isDefault,
        maxDimension: MAX_AVATAR_DIMENSION,
        maxDataUrlChars: MAX_AVATAR_DATA_URL_CHARS
    }).valid;
}
