import { POST_QUANTUM_AEAD_NONCE_BYTES, HASH_OUTPUT_BYTES } from '../../../shared/crypto-sizes.js';

export const MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024;
export const MAX_AVATAR_SIZE_BYTES = 512 * 1024;
export const MAX_AVATAR_DIMENSION = 512;
export const MAX_AVATAR_SOURCE_DIMENSION = 8192;
export const MAX_AVATAR_DATA_URL_CHARS = 240 * 1024;
export const ALLOWED_AVATAR_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'] as const;
export const AVATAR_PURB_CAPACITY = 256 * 1024;

export const MAX_PEER_AVATAR_CACHE_ENTRIES = 128;
export const AVATAR_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_IMAGE_READINESS_ENTRIES = 256;
export const AVATAR_IMAGE_READY_TIMEOUT_MS = 8_000;
export const AVATAR_BLOB_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const AVATAR_REFRESH_MARGIN_MS = 24 * 60 * 60 * 1000;

export const AVATAR_COVER_TOTAL_IDS = 10;
export const AVATAR_POOL_CACHE_TTL_MS = 5 * 60 * 1000;
export const AVATAR_POOL_SAMPLE_LIMIT = 256;
export const AVATAR_COVER_BLOBS_PER_CLIENT = 12;
export const AVATAR_COVER_REFRESH_MS = 6 * 60 * 60 * 1000;
export const AVATAR_DECOY_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
export const MAX_AVATAR_DECOY_CACHE_ENTRIES = 1024;

export const AVATAR_FETCH_MAX_IN_FLIGHT = 32;
export const AVATAR_FETCH_RETRY_DELAYS_MS = [4000, 8000, 15000, 30000];
export const AVATAR_GET_POW_DIFFICULTY = 16;
export const AVATAR_PUT_POW_DIFFICULTY = 18;
export const AVATAR_UPLOAD_JITTER_MIN_MS = 1_000;
export const AVATAR_UPLOAD_JITTER_MAX_MS = 10_000;
export const AVATAR_UPLOAD_MAX_ATTEMPTS = 3;
export const AVATAR_PUT_TRANSPORT_WARN_INTERVAL_MS = 30_000;

export const AVATAR_PURB_WIRE_BYTES = POST_QUANTUM_AEAD_NONCE_BYTES + HASH_OUTPUT_BYTES + (AVATAR_PURB_CAPACITY + 32);
export const AVATAR_PURB_LENGTH_PREFIX_BYTES = 4;
export const DEFAULT_AVATAR_COLORS = [
  '#5865F2', '#57F287', '#FEE75C', '#EB459E', '#ED4245',
  '#3BA55C', '#FAA61A', '#9B59B6', '#1ABC9C', '#E91E63'
] as const;
export const SAFE_DEFAULT_SVG = /^\s*<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="512" height="512" viewBox="0 0 512 512">\s*<rect width="512" height="512" fill="#(?:5865F2|57F287|FEE75C|EB459E|ED4245|3BA55C|FAA61A|9B59B6|1ABC9C|E91E63)"\/>\s*<text x="50%" y="50%" font-family="Arial, sans-serif" font-weight="bold" font-size="256" fill="#FFFFFF" text-anchor="middle" dy="\.35em">[A-Z0-9._?\-]{1,2}<\/text>\s*<\/svg>\s*$/;
export const USER_AVATAR_SIZES = {
    xs: 24,
    sm: 32,
    md: 40,
    lg: 48,
    xl: 80
} as const;
export const AVATAR_BLOB_CRYPTO_DECODED_LENGTH_EXPECTED = 32;
export const AVATAR_BLOB_CRYPTO_KEY_LENGTH_EXPECTED = 32;
export const AVATAR_UTILS_USERNAME_LENGTH_LIMIT = 32;
export const AVATAR_UTILS_BYTE_LENGTH_MINIMUM = 100;
export const AVATAR_STORE_CLIENT_KEY_LENGTH_EXPECTED = 32;
