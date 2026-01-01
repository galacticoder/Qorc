// Username rules
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 32;

// Regex patterns
export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;
export const VALID_EMOJI_PICKER_ID = /^[A-Za-z0-9_-]+$/;
export const HEX_PATTERN = /^[a-f0-9]{32,}$/i;
export const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
export const IPV6_REGEX = /^\[?[A-F0-9:]+\]?$/i;

// Event metadata + rate limits
export const MAX_EVENT_TYPE_LENGTH = 32;
export const MAX_EVENT_USERNAME_LENGTH = 256;

export const RESET_FEEDBACK_DURATION_MS = 1000;
export const DEFAULT_MAX_TYPING_USERS = 200;
export const DEFAULT_TYPING_TIMEOUT_MS = 5500;
export const DEFAULT_TYPING_EVENT_RATE_WINDOW_MS = 60_000;
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 240;
export const DEFAULT_EVENT_RATE_WINDOW_MS = 10_000;
export const DEFAULT_EVENT_RATE_MAX = 200;
export const DEFAULT_UI_EVENT_RATE_MAX = 500;

// UI call status throttling
export const UI_CALL_STATUS_RATE_WINDOW_MS = 10_000;
export const UI_CALL_STATUS_RATE_MAX = 500;
export const MAX_UI_CALL_STATUS_PEER_LENGTH = 256;
export const MAX_UI_CALL_STATUS_VALUE_LENGTH = 64;

// Password constraints
export const PASSWORD_MAX_LENGTH = 1000;
export const SERVER_PASSWORD_MAX_LENGTH = 1000;

// Filename helpers
export const MAX_FILENAME_LENGTH = 255;
export const FILENAME_SANITIZE_REGEX = /[^\w.-]/g;

// File-size units
export const FILE_SIZE_UNITS = ["Bytes", "KB", "MB", "GB"] as const;
export const FILE_SIZE_BASE = 1024;

// ChatInterface.tsx
export const SCROLL_THRESHOLD = 200;
export const NEAR_BOTTOM_THRESHOLD = 100;
export const MAX_BACKGROUND_MESSAGES = 1000;
export const BACKGROUND_BATCH_SIZE = 100;

export const QUALITY_OPTIONS = ['low', 'medium', 'high'] as const;
export const DEFAULT_QUALITY: QualityOption = 'medium';
export type QualityOption = (typeof QUALITY_OPTIONS)[number];
export const QUALITY_LABELS: Record<QualityOption, string> = {
    low: 'Low',
    medium: 'Medium',
    high: 'High'
};

export const QUALITY_DESCRIPTIONS: Record<QualityOption, string> = {
    low: 'Lower bandwidth usage',
    medium: 'Balanced quality and bandwidth',
    high: 'Best quality, higher bandwidth'
};

export const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tiff'] as const;
export const VIDEO_EXTENSIONS = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'wmv', 'flv', 'mkv'] as const;
export const AUDIO_EXTENSIONS = ['mp3', 'wav', 'ogg', 'webm', 'm4a', 'aac', 'flac'] as const;

// useFileSender.ts
export const DEFAULT_CHUNK_SIZE_SMALL = 192 * 1024;
export const DEFAULT_CHUNK_SIZE_LARGE = 384 * 1024;
export const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024;
export const MAX_CHUNKS_PER_SECOND = 50;
export const INACTIVITY_TIMEOUT_MS = 120000;
export const P2P_CONNECT_TIMEOUT_MS = 3500;
export const RATE_LIMITER_SLEEP_MS = 10;
export const PAUSE_POLL_MS = 100;
export const P2P_POLL_MS = 100;
export const YIELD_INTERVAL = 8;
export const MAC_SALT = new TextEncoder().encode('ft-mac-salt-v1');

export const SESSION_WAIT_MS = 12_000;
export const SESSION_POLL_BASE_MS = 200;
export const SESSION_POLL_MAX_MS = 1_500;
export const BUNDLE_REQUEST_COOLDOWN_MS = 5000;
export const SESSION_FRESH_COOLDOWN_MS = 10_000;

// PassphrasePrompt.tsx
export const PASSPHRASE_MIN_LENGTH = 12;
export const PASSPHRASE_MAX_LENGTH = 1000;

// Urls and network checks
export const MAX_CACHE_SIZE = 100;
export const MAX_URL_LENGTH = 2048;
export const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

// General size caps
export const MAX_FILE_SIZE = 50 * 1024 * 1024;
export const MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024;

export const MAX_P2P_INCOMING_QUEUE = 256;
export const MAX_P2P_PEER_CACHE = 256;
export const P2P_PEER_CACHE_TTL_MS = 5 * 60 * 1000;
export const P2P_ROUTE_PROOF_TTL_MS = 60 * 1000;
export const MAX_P2P_CERT_CACHE_SIZE = 128;
export const MAX_P2P_ROUTE_PROOF_CACHE_SIZE = 512;
export const MAX_MESSAGE_CONTENT_LENGTH = 64 * 1024;
export const MAX_P2P_USERNAME_LENGTH = 96;
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const RATE_LIMIT_MAX_MESSAGES = 200;
export const CERT_CLOCK_SKEW_MS = 2 * 60 * 1000;
export const RECEIPT_RETENTION_MS = 24 * 60 * 60 * 1000;