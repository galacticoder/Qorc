import {
    MAX_AVATAR_SIZE_BYTES,
    MAX_AVATAR_DIMENSION,
    ALLOWED_AVATAR_MIME_TYPES
} from '../constants';
import type { AvatarData, CachedAvatar } from '../types/avatar-types';

// Generates a deterministic color based on the username
export const getAvatarColor = (username: string): string => {
    const normalized = (username || '').toLowerCase().trim();
    const colors = [
        '#5865F2',
        '#57F287',
        '#FEE75C',
        '#EB459E',
        '#ED4245',
        '#3BA55C',
        '#FAA61A',
        '#9B59B6',
        '#1ABC9C',
        '#E91E63'
    ];

    let hash = 0;
    for (let i = 0; i < normalized.length; i++) {
        hash = normalized.charCodeAt(i) + ((hash << 5) - hash);
    }

    return colors[Math.abs(hash) % colors.length];
};

// Generates initials from the username
export const getAvatarInitials = (username: string): string => {
    if (!username) return '?';

    const isHash = /^[a-f0-9]{32,}$/i.test(username);

    if (isHash) {
        return username.slice(0, 2).toUpperCase();
    }

    const clean = username.replace(/[^a-zA-Z0-9]/g, '');
    if (!clean) return username.charAt(0).toUpperCase();

    return clean.slice(0, 2).toUpperCase();
};

// Truncates long hexadecimal usernames (32+ characters) to first 8 characters
export function truncateUsername(username: string): string {
  if (typeof username !== 'string' || username.length === 0) return '';
  return username.length > 32 ? `${username.slice(0, 8)}...` : username;
}

// Generates a deterministic default avatar SVG for a username
export function generateDefaultAvatar(username: string): string {
  const normalized = (username || '').toLowerCase().trim();
  const colors = [
    '#5865F2', '#57F287', '#FEE75C', '#EB459E', '#ED4245',
    '#3BA55C', '#FAA61A', '#9B59B6', '#1ABC9C', '#E91E63'
  ];
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    hash = normalized.charCodeAt(i) + ((hash << 5) - hash);
  }
  const color = colors[Math.abs(hash) % colors.length];

  let initials = '?';
  const isHash = /^[a-f0-9]{32,}$/i.test(username);
  if (isHash) {
    initials = username.slice(0, 2).toUpperCase();
  } else {
    const clean = username.replace(/[^a-zA-Z0-9]/g, '');
    initials = (clean || username).slice(0, 2).toUpperCase();
  }

  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
      <rect width="512" height="512" fill="${color}"/>
      <text x="50%" y="50%" font-family="Arial, sans-serif" font-weight="bold" font-size="256" fill="#FFFFFF" text-anchor="middle" dy=".35em">${initials}</text>
    </svg>`;

  return `data:image/svg+xml;base64,${btoa(svg)}`;
}

export function validateImageData(dataUrl: string): { valid: boolean; mimeType: string; error?: string } {
    if (!dataUrl || typeof dataUrl !== 'string') {
        return { valid: false, mimeType: '', error: 'Invalid data URL' };
    }

    const match = dataUrl.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,/i);
    if (!match) {
        return { valid: false, mimeType: '', error: 'Invalid data URL format' };
    }

    const mimeType = match[1].toLowerCase();
    if (!ALLOWED_AVATAR_MIME_TYPES.includes(mimeType as typeof ALLOWED_AVATAR_MIME_TYPES[number])) {
        return { valid: false, mimeType, error: `Unsupported image type: ${mimeType}` };
    }

    const base64Data = dataUrl.slice(dataUrl.indexOf(',') + 1);

    try {
        const binaryString = atob(base64Data);
        const bytes = binaryString.length;

        if (bytes > MAX_AVATAR_SIZE_BYTES) {
            return { valid: false, mimeType, error: `Image too large: ${Math.round(bytes / 1024)}KB (max ${MAX_AVATAR_SIZE_BYTES / 1024}KB)` };
        }

        if (bytes < 100) {
            return { valid: false, mimeType, error: 'Image too small or corrupted' };
        }

        const header = new Uint8Array(12);
        for (let i = 0; i < Math.min(12, binaryString.length); i++) {
            header[i] = binaryString.charCodeAt(i);
        }

        const isJpeg = header[0] === 0xFF && header[1] === 0xD8 && header[2] === 0xFF;
        const isPng = header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47;
        const isWebp = header[0] === 0x52 && header[1] === 0x49 && header[2] === 0x46 && header[3] === 0x46 &&
            header[8] === 0x57 && header[9] === 0x45 && header[10] === 0x42 && header[11] === 0x50;
        const isSvg = mimeType === 'image/svg+xml' && (binaryString.includes('<svg') || binaryString.includes('<?xml'));

        if (!isJpeg && !isPng && !isWebp && !isSvg) {
            return { valid: false, mimeType, error: 'Invalid image magic bytes' };
        }

        if ((mimeType === 'image/jpeg' && !isJpeg) ||
            (mimeType === 'image/png' && !isPng) ||
            (mimeType === 'image/webp' && !isWebp) ||
            (mimeType === 'image/svg+xml' && !isSvg)) {
            return { valid: false, mimeType, error: 'MIME type mismatch with file content' };
        }
    } catch {
        return { valid: false, mimeType, error: 'Invalid base64 encoding' };
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

                while (result.length > MAX_AVATAR_SIZE_BYTES * 1.4 && quality > 0.3) {
                    quality -= 0.1;
                    result = canvas.toDataURL('image/webp', quality);
                }

                if (result.length > MAX_AVATAR_SIZE_BYTES * 1.4) {
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
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function isValidAvatarData(data: unknown): data is AvatarData {
    if (!data || typeof data !== 'object') return false;
    const d = data as any;
    return (
        typeof d.data === 'string' &&
        typeof d.mimeType === 'string' &&
        typeof d.hash === 'string' &&
        typeof d.updatedAt === 'number' &&
        ALLOWED_AVATAR_MIME_TYPES.includes(d.mimeType) &&
        d.data.length <= MAX_AVATAR_SIZE_BYTES * 1.4 &&
        d.hash.length === 64
    );
}

export function isValidCachedAvatar(data: unknown): data is CachedAvatar {
    if (!data || typeof data !== 'object') return false;
    const d = data as any;
    const isDataValid = d.data === null || (typeof d.data === 'string' && d.data.length <= MAX_AVATAR_SIZE_BYTES * 1.4);
    const isHashValid = d.hash === null || (typeof d.hash === 'string' && d.hash.length === 64);

    return (
        isDataValid &&
        isHashValid &&
        typeof d.cachedAt === 'number' &&
        typeof d.expiresAt === 'number'
    );
}