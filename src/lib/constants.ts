// Username rules
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 32;

// Regex patterns
export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;
export const VALID_EMOJI_PICKER_ID = /^[A-Za-z0-9_-]+$/;
export const HEX_PATTERN = /^[a-f0-9]{32,}$/i;
export const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
export const IPV6_REGEX = /^\[?[A-F0-9:]+\]?$/i;
export const BASE64_SAFE_REGEX = /^[A-Za-z0-9+/=_-]+$/;
export const FILENAME_SANITIZE_REGEX = /[^\w.-]/g;
export const BASE64_STANDARD_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
export const BASE64_URLSAFE_REGEX = /^[A-Za-z0-9_-]*={0,2}$/;
export const CONVERSATION_USERNAME_PATTERN = /^[a-zA-Z0-9._-]{2,64}$/;
export const CLIPBOARD_CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
export const URL_REGEX = /(https?:\/\/(?:[-\w.]|%[0-9A-Fa-f]{2})+(?::[0-9]+)?(?:\/(?:[\w\/_~!$&'()*+,;=:@.-]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%._~!$'()*+,;:@/?-]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?)/gi;
export const SIMPLE_URL_REGEX = /(?:^|\s)((?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\/(?:[\w\/_~!$&'()*+,;=:@.-]|%[0-9A-Fa-f]{2})*)*(?:\?(?:[\w&=%._~!$'()*+,;:@/?-]|%[0-9A-Fa-f]{2})*)?(?:#(?:[\w._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?/gi;

export const READ_RECEIPT_PREFIX = 'read-receipt-';
export const DELIVERY_RECEIPT_PREFIX = 'delivery-receipt-';

// Cache and key lengths
export const ID_CACHE_TTL_MS = 5 * 60 * 1000;
export const MAX_ID_CACHE_SIZE = 4_096;
export const KYBER_PUBLIC_KEY_LENGTH = 1_568;
export const DILITHIUM_PUBLIC_KEY_LENGTH = 2_592;
export const X25519_PUBLIC_KEY_LENGTH = 32;
export const MAX_PAYLOAD_CACHE_SIZE = 2000;

// Event metadata + rate limits
export const MAX_EVENT_TYPE_LENGTH = 32;
export const MAX_EVENT_USERNAME_LENGTH = 256;
export const MAX_CONTENT_LENGTH = 16 * 1024;
export const RATE_LIMIT_MAX_RECEIPTS = 100;

export const RESET_FEEDBACK_DURATION_MS = 1000;
export const DEFAULT_MAX_TYPING_USERS = 200;
export const DEFAULT_TYPING_TIMEOUT_MS = 5500;
export const DEFAULT_TYPING_EVENT_RATE_WINDOW_MS = 60_000;
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 240;
export const DEFAULT_EVENT_RATE_WINDOW_MS = 10_000;
export const DEFAULT_EVENT_RATE_MAX = 200;
export const DEFAULT_UI_EVENT_RATE_MAX = 500;

// Typing
export const TYPING_STOP_DELAY = 1500;
export const MIN_TYPING_INTERVAL = 4000;
export const CONVERSATION_CHANGE_DEBOUNCE = 100;
export const TYPING_DOMAIN = 'typing-indicator-v1';

// UI call status throttling
export const UI_CALL_STATUS_RATE_WINDOW_MS = 10_000;
export const UI_CALL_STATUS_RATE_MAX = 500;
export const MAX_UI_CALL_STATUS_PEER_LENGTH = 256;
export const MAX_UI_CALL_STATUS_VALUE_LENGTH = 64;

// Password constraints
export const PASSWORD_MAX_LENGTH = 1000;
export const SERVER_PASSWORD_MAX_LENGTH = 1000;

// File helpers
export const MAX_FILENAME_LENGTH = 255;
export const MAX_FILEDATA_LENGTH = 10 * 1024 * 1024;
export const MAX_INLINE_BYTES = 10 * 1024 * 1024;

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
export const MAX_USERNAME_LENGTH = 96;
export const CERT_CLOCK_SKEW_MS = 2 * 60 * 1000;
export const RECEIPT_RETENTION_MS = 24 * 60 * 60 * 1000;
export const P2P_MESSAGE_RATE_LIMIT = 100;
export const P2P_MESSAGE_RATE_WINDOW_MS = 60_000;
export const P2P_MAX_MESSAGE_SIZE = 5 * 1024 * 1024;
export const P2P_MAX_PEERS = 100;

// General rate limit
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const RATE_LIMIT_MAX_MESSAGES = 200;

// Conversation constants
export const MAX_PREVIEW_LENGTH = 80;
export const CONVERSATION_MIN_USERNAME_LENGTH = 2;
export const CONVERSATION_MAX_USERNAME_LENGTH = 64;
export const MAX_CONVERSATIONS = 1000;
export const CONVERSATION_RATE_LIMIT_WINDOW_MS = 10_000;
export const CONVERSATION_RATE_LIMIT_MAX = 8;
export const VALIDATION_TIMEOUT_MS = 15_000;

// Local message constants
export const MAX_LOCAL_MESSAGE_ID_LENGTH = 160;
export const MAX_LOCAL_MESSAGE_LENGTH = 10_000;
export const MAX_LOCAL_USERNAME_LENGTH = 256;
export const MAX_LOCAL_MIMETYPE_LENGTH = 128;
export const MAX_LOCAL_EMOJI_LENGTH = 32;
export const MAX_LOCAL_FILE_SIZE_BYTES = 50 * 1024 * 1024;
export const MAX_INLINE_BASE64_BYTES = 10 * 1024 * 1024;
export const LOCAL_EVENT_RATE_LIMIT_WINDOW_MS = 10_000;
export const LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS = 120;

// Replies
export const REPLY_MAX_TRACKED_ORIGINS = 5000;
export const REPLY_MAX_REPLIES_PER_ORIGIN = 250;
export const REPLY_RATE_LIMIT_WINDOW_MS = 10_000;
export const REPLY_RATE_LIMIT_MAX_EVENTS = 100;

// Websocket constants
export const WEBSOCKET_RATE_LIMIT_WINDOW_MS = 1_000;
export const WEBSOCKET_RATE_LIMIT_MAX_MESSAGES = 500;

export const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
export const MAX_TOTAL_CHUNKS = 10_000;
export const MAX_CHUNK_SIZE_BYTES = 384 * 1024;
export const MAX_CONCURRENT_TRANSFERS = 16;
export const MAX_BASE64_CHARS = MAX_CHUNK_SIZE_BYTES * 2;
export const RATE_LIMIT_MAX_EVENTS = 6_000;

// Database constants
export const DB_MAX_PENDING_MESSAGES = 500;
export const DB_MAX_PENDING_MAPPINGS = 1000;
export const DB_MAX_MESSAGES = 5000;
export const DB_RATE_LIMIT_WINDOW_MS = 10_000;
export const DB_RATE_LIMIT_MAX_EVENTS = 200;
export const DB_SAVE_DEBOUNCE_MS = 100;

// Username display constants
export const USERNAME_DISPLAY_MAX_LENGTH = 256;
export const USERNAME_DISPLAY_RATE_LIMIT_WINDOW_MS = 5_000;
export const USERNAME_DISPLAY_RATE_LIMIT_MAX_EVENTS = 50;
export const USERNAME_DISPLAY_CACHE_TTL_MS = 5 * 60 * 1000;
export const USERNAME_DISPLAY_MAX_CACHE_SIZE = 512;
export const USERNAME_DISPLAY_RESOLVE_TIMEOUT_MS = 10_000;
export const USERNAME_ANON_PREFIX = 'anon:';
export const USERNAME_HEX_PATTERN = /^[a-f0-9]{32}$/i;
export const USERNAME_OBFUSCATED_LENGTH = 12;

// Calling constants
export const CALLING_MAX_USERNAME_LENGTH = 120;
export const CALLING_MAX_CALL_ID_LENGTH = 256;
export const CALLING_EVENT_ALLOWED_PAYLOAD_KEYS = new Set([
  'type',
  'peer',
  'at',
  'callId',
  'status',
  'startTime',
  'endTime',
  'durationMs',
  'direction',
  'isVideo',
  'isOutgoing'
]);
export const CALL_TIMEOUT = 60_000;
export const CALL_RING_TIMEOUT = 60_000;
export const CALL_AUDIO_PADDING_BLOCK = 128;
export const CALL_KEY_ROTATION_INTERVAL = 10_000;

// Blocking constants
export const NOTIFICATION_TITLE = 'Message Blocked';
export const NOTIFICATION_BODY = 'A message was blocked. See app for details.';
export const QUEUE_STORAGE_VERSION = 1;
export const QUEUE_SESSION_KEY_ID = 'queue_session_key';
export const BLOCK_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_BLOCK_LIST_SIZE = 10000;
export const BLOCK_QUEUE_OVERFLOW_LIMIT = 1000;
export const BLOCK_MAX_QUEUE_AGE_MS = 5 * 60 * 1000;
export const BLOCK_STATUS_CACHE_TTL_MS = 30000;
export const BLOCK_RATE_LIMIT_WINDOW_MS = 60_000;
export const BLOCK_RATE_LIMIT_MAX_EVENTS = 10;
export const BLOCK_SYNC_RATE_LIMIT_WINDOW_MS = 30_000;
export const BLOCK_SYNC_RATE_LIMIT_MAX_EVENTS = 3;
export const CIRCUIT_BREAKER_THRESHOLD = 5;
export const CIRCUIT_BREAKER_TIMEOUT_MS = 30000;

// Clipboard
export const MAX_CLIPBOARD_SIZE = 100 * 1024;
export const MAX_INPUT_SIZE = 1024 * 1024;
export const RATE_LIMIT_ATTEMPTS = 10;

// Links
export const MAX_LINKS_PER_TEXT = 50;
export const SUSPICIOUS_QUERY_PARAMS = new Set([
  'redirect',
  'url',
  'target',
  'goto',
  'dest',
  'destination',
  'location',
]);
export const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'biz', 'info', 'name',
  'pro', 'aero', 'asia', 'cat', 'coop', 'jobs', 'mobi', 'museum', 'travel',
  'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br', 'ru', 'it',
  'es', 'nl', 'se', 'no', 'fi', 'dk', 'ch', 'be', 'at', 'pl', 'cz', 'gr',
  'pt', 'ie', 'hu', 'ro', 'bg', 'sk', 'hr', 'si', 'lt', 'lv', 'ee', 'kr',
  'hk', 'sg', 'nz', 'mx', 'ar', 'cl', 'co', 'za', 'ae', 'sa', 'tr', 'il',
  'id', 'my', 'ph', 'th', 'vn', 'pk', 'bd', 'ng', 'ke', 'gh', 'tz', 'ug',
  'zw', 'io', 'ai', 'app', 'dev', 'tech', 'cloud', 'digital', 'software',
  'systems', 'solutions', 'online', 'store', 'shop', 'blog', 'news',
  'press', 'today', 'life', 'live', 'world', 'social', 'media', 'xyz',
  'top', 'club', 'site', 'space', 'fun', 'link', 'click', 'help',
  'design', 'art', 'eco', 'one', 'plus', 'guru', 'global', 'agency',
  'company', 'center', 'tv', 'fm', 'cc', 'ly', 'me', 'gg', 'gl', 'gs',
  'la', 'md', 'nu', 'sh', 'su', 'to', 'ws',
]);
export const COMMON_COMPOUND_TLDS = new Set([
  'co.uk',
  'com.au',
  'com.br',
  'com.cn',
  'com.sg',
  'com.tr',
  'com.mx',
  'com.sa',
  'com.ar',
  'com.pl',
  'com.hk',
  'com.tw',
]);

// Message Handling
export const MAX_MESSAGE_JSON_BYTES = 64 * 1024;
export const MAX_FILE_JSON_BYTES = 256 * 1024;
export const MAX_CALL_SIGNAL_BYTES = 256 * 1024;
export const MAX_INLINE_FILE_BYTES = 5 * 1024 * 1024;
export const MAX_BLOB_URLS = 32;
export const BLOB_URL_TTL_MS = 15 * 60 * 1000;
export const MESSAGE_RATE_LIMIT_WINDOW_MS = 5_000;
export const MESSAGE_RATE_LIMIT_MAX = 300;

export const MAX_RETRY_ATTEMPTS = 3;
export const PENDING_QUEUE_TTL_MS = 120_000;
export const PENDING_QUEUE_MAX_PER_PEER = 50;
export const MAX_GLOBAL_PENDING_MESSAGES = 1000;
export const KEY_REQUEST_CACHE_DURATION = 5000;
export const PQ_KEY_REPLENISH_COOLDOWN_MS = 60_000;
export const MAX_RESETS_PER_PEER = 5;
export const RESET_WINDOW_MS = 60_000;

// Post-Quantum Cryptography
export const PQ_RANDOM_MAX_BYTES_LIMIT = 100 * 1024 * 1024;
export const PQ_RANDOM_DEFAULT_MAX_BYTES = 1_048_576;
export const PQ_UTILS_MAX_DATA_SIZE = 10 * 1024 * 1024;
export const PQ_SESSION_DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;
export const PQ_PROTOCOL_MAX_MESSAGE_AGE_MS = 5 * 60 * 1000;
export const PQ_PROTOCOL_MAX_SEEN_ENTRIES = 10_000;
export const PQ_PROTOCOL_SEEN_BUFFER_RATIO = 0.9;
export const PQ_AEAD_KEY_SIZE = 64;
export const PQ_AEAD_NONCE_SIZE = 36;
export const PQ_AEAD_GCM_IV_SIZE = 12;
export const PQ_AEAD_XCHACHA_NONCE_SIZE = 24;
export const PQ_AEAD_MAC_SIZE = 32;
export const PQ_KEM_PUBLIC_KEY_SIZE = 1568;
export const PQ_KEM_SECRET_KEY_SIZE = 3168;
export const PQ_KEM_CIPHERTEXT_SIZE = 1568;
export const PQ_KEM_SHARED_SECRET_SIZE = 32;
export const PQ_SIG_PUBLIC_KEY_SIZE = 2592;
export const PQ_SIG_SECRET_KEY_SIZE = 4896;
export const PQ_SIG_SIGNATURE_SIZE = 4627;
export const PQ_WORKER_MAX_RESTART_ATTEMPTS = 5;
export const SECURE_MEMORY_MAX_BUFFER_SIZE = 1_048_576;
export const CRYPTO_CACHE_TTL_MS = 5 * 60 * 1000;
export const LONG_TERM_ENVELOPE_VERSION = 'lt-v1';
export const REPLAY_WINDOW_MS = 5 * 60 * 1000;
export const MAX_PROCESSED_IDS = 2048;
export const KEY_LIFETIME_MS = 60 * 60 * 1000;

// Crypto Config
export const CRYPTO_AES_KEY_SIZE = 256;
export const CRYPTO_IV_LENGTH = 12;
export const CRYPTO_AUTH_TAG_LENGTH = 16;
export const CRYPTO_HKDF_HASH = 'SHA-256';
export const CRYPTO_X25519_DERIVE_BITS = 256;

// Envelope versions
export const HYBRID_ENVELOPE_VERSION = 'hybrid-envelope-v1';
export const INNER_ENVELOPE_VERSION = 'inner-envelope-v1';

// Argon2 defaults
export const ARGON2_DEFAULT_TIME = 5;
export const ARGON2_DEFAULT_MEM = 2 ** 17;
export const ARGON2_DEFAULT_PARALLELISM = 4;
export const ARGON2_VERSION = 0x13;
export const ARGON2_HASH_LEN = 32;
export const ARGON2_MAX_ENCODED_LENGTH = 512;
export const HASH_DATA_MAX_SIZE = 1_000_000;
export const HASH_TIMEOUT_MIN_MS = 1000;
export const HASH_TIMEOUT_MAX_MS = 300000;
export const HASH_DEFAULT_TIMEOUT_MS = 30000;

// Worker constants
export const WORKER_MAX_KEYS = 256;
export const WORKER_AUTH_TOKEN_LIFETIME_MS = 60 * 60 * 1000;
export const WORKER_RATE_LIMIT_DEFAULT_WINDOW_MS = 60_000;
export const WORKER_RATE_LIMIT_DEFAULT_MAX = 100;
export const WORKER_RATE_LIMIT_KEM_GENERATE_MAX = 10;
export const WORKER_RATE_LIMIT_KEM_DESTROY_MAX = 50;
export const WORKER_RATE_LIMIT_ARGON2_HASH_MAX = 20;
export const WORKER_RATE_LIMIT_ARGON2_VERIFY_MAX = 50;

// Crypto HKDF Info
export const CRYPTO_HKDF_INFO = 'Qor-chat hybrid key v2';
export const LONG_TERM_ENVELOPE_KDF_INFO = 'long-term-aead-key-v1';

// Noise Protocol
export const NOISE_PROTOCOL_VERSION = 'hybrid-session-v1';
export const NOISE_SESSION_SALT = 'qorchat-hybrid-session-v1';
export const NOISE_KEY_ROTATION_INTERVAL_MS = 10 * 60 * 1000;
export const NOISE_MAX_MESSAGES_PER_SESSION = 1_000_000;
export const NOISE_MAX_SESSION_AGE_MS = 24 * 60 * 60 * 1000;
export const NOISE_REPLAY_WINDOW_SIZE = BigInt(32768);

// QUIC Transport
export const QUIC_CONNECTION_TIMEOUT_MS = 30_000;
export const QUIC_KEEPALIVE_INTERVAL_MS = 10_000;
export const QUIC_MAX_STREAMS_PER_CONNECTION = 100;
export const QUIC_RECONNECT_BACKOFF_BASE_MS = 1000;
export const QUIC_MAX_RECONNECT_ATTEMPTS = 5;
export const QUIC_BUFFER_LOW_THRESHOLD = 256 * 1024;