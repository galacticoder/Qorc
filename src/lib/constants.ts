export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 32;

export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;
export const VALID_EMOJI_PICKER_ID = /^[A-Za-z0-9_-]+$/;
export const HEX_PATTERN = /^[a-f0-9]{32,}$/i;
export const FILENAME_SANITIZE_REGEX = /[^\w.-]/g;
export const BASE64_STANDARD_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
export const CONVERSATION_USERNAME_PATTERN = /^[a-zA-Z0-9._-]{2,64}$/;
export const AUTH_USERNAME_REGEX = /^[a-z0-9._-]{3,100}$/;
export const CLIPBOARD_CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
export const UNSAFE_FILENAME_CHARS_REGEX = /[\u0000-\u001F\u007F/\\:*?"<>|]+/g;
export const WHITESPACE_COLLAPSE_REGEX = /\s+/g;
export const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F]/g;
export const NEWLINE_REGEX = /[\r\n]+/g;

export const ID_CACHE_TTL_MS = 5 * 60 * 1000;
export const MAX_ID_CACHE_SIZE = 4_096;
export const KYBER_PUBLIC_KEY_LENGTH = 1_568;
export const DILITHIUM_PUBLIC_KEY_LENGTH = 2_592;
export const X25519_PUBLIC_KEY_LENGTH = 32;

export const MAX_EVENT_TYPE_LENGTH = 32;
export const MAX_EVENT_USERNAME_LENGTH = 256;
export const MAX_CONTENT_LENGTH = 16 * 1024;
export const RATE_LIMIT_MAX_RECEIPTS = 100;
export const RECEIPT_BATCH_WINDOW_MS = 300;
export const MAX_RECEIPT_BATCH_IDS = 256;

export const DEFAULT_MAX_TYPING_USERS = 200;
export const DEFAULT_TYPING_TIMEOUT_MS = 8000;
export const DEFAULT_TYPING_EVENT_RATE_WINDOW_MS = 60_000;
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 240;
export const DEFAULT_EVENT_RATE_WINDOW_MS = 10_000;
export const DEFAULT_EVENT_RATE_MAX = 200;
export const DEFAULT_UI_EVENT_RATE_MAX = 500;

export const TYPING_STOP_DELAY = 1500;
export const MIN_TYPING_INTERVAL = 6000;

export const UI_CALL_STATUS_RATE_WINDOW_MS = 10_000;
export const UI_CALL_STATUS_RATE_MAX = 500;
export const MAX_UI_CALL_STATUS_PEER_LENGTH = 256;
export const MAX_UI_CALL_STATUS_VALUE_LENGTH = 64;

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 1000;
export const PASSPHRASE_MIN_LENGTH = 16;
export const PASSPHRASE_MAX_LENGTH = 1000;
export const SERVER_PASSWORD_MAX_LENGTH = 1000;

export const MAX_FILENAME_LENGTH = 255;

export const FILE_SIZE_UNITS = ["Bytes", "KB", "MB", "GB"] as const;
export const FILE_SIZE_BASE = 1024;

export const SCROLL_THRESHOLD = 200;
export const NEAR_BOTTOM_THRESHOLD = 100;
export const CONVERSATION_SEGMENT_SIZE = 50;
export const CONVERSATION_WARM_MESSAGE_COUNT = 20;
export const CALL_LOG_SEGMENT_SIZE = 50;
export const MAX_BACKGROUND_MESSAGES = CONVERSATION_SEGMENT_SIZE;
export const SEGMENT_UNLOAD_IDLE_MS = 3 * 60 * 1000;
export const INITIAL_LOAD_DELAY_MS = 500;
export const MAX_UI_MESSAGES_PER_CONVERSATION = MAX_BACKGROUND_MESSAGES;
export const MAX_UI_MESSAGES_TOTAL = 2_048;
export const MAX_CONVERSATION_STORED_MESSAGES = 10_000;
export const MAX_KNOWN_PEERS = 2_048;
export const MAX_PEER_AVATAR_CACHE_ENTRIES = 128;
export const TARGET_FPS = 60;
export const VISUAL_FRAME_SEND_DEADLINE_MS = 400;
export const VISUAL_FRAME_SEND_DEADLINE_MAX_MS = 1_500;
export const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tiff'] as const;
export const VIDEO_EXTENSIONS = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'wmv', 'flv', 'mkv'] as const;
export const AUDIO_EXTENSIONS = ['mp3', 'wav', 'ogg', 'webm', 'm4a', 'aac', 'flac'] as const;

export const DEFAULT_CHUNK_SIZE_SMALL = 29 * 1024;
export const DEFAULT_CHUNK_SIZE_LARGE = DEFAULT_CHUNK_SIZE_SMALL;
export const LARGE_FILE_THRESHOLD = 50 * 1024 * 1024;
export const MAX_CHUNKS_PER_SECOND = 5;
export const INACTIVITY_TIMEOUT_MS = 120000;
export const RATE_LIMITER_SLEEP_MS = 10;

export const FILE_RETRANSMIT_RETENTION_MS = 3 * 60 * 1000;
export const MAX_CONCURRENT_P2P_CONNECTS = 16;
export const MAX_RETAINED_TRANSFERS = 8;
export const FILE_NACK_STALL_MS = 6000;
export const MAX_NACK_ATTEMPTS = 4;
export const MAX_RETRANSMIT_CHUNKS_PER_REQUEST = 512;
export const RETRANSMIT_MIN_INTERVAL_MS = 2000;
export const YIELD_INTERVAL = 8;
export const MAC_SALT = new TextEncoder().encode(PROTOCOL_KEYS.FILE_TRANSFER_MAC_SALT);

export const SESSION_WAIT_MS = 12_000;
export const SESSION_POLL_BASE_MS = 200;
export const SESSION_POLL_MAX_MS = 1_500;
export const SESSION_FRESH_COOLDOWN_MS = 10_000;
export const WS_FIXED_MESSAGE_SIZE_BYTES = 64 * 1024;
export const WS_COVER_TRAFFIC_MIN_INTERVAL_MS = 10_000;
export const WS_COVER_TRAFFIC_MAX_INTERVAL_MS = 45_000;

export const MAX_FILE_SIZE = 70 * 1024 * 1024;
export const MAX_PROFILE_IMAGE_SIZE = 5 * 1024 * 1024;
export const MAX_VOICE_NOTE_BYTES = 16 * 1024 * 1024;
export const MAX_VOICE_NOTE_DURATION_SECONDS = 10 * 60;

export {
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_EPOCH_DURATION_MS,
} from '../../shared/discovery-constants.js';

export const P2P_PEER_CACHE_TTL_MS = 5 * 60 * 1000;
export const P2P_PEER_CERT_PUBLISH_REFRESH_LEAD_MS = 8 * 60 * 60 * 1000;
export const P2P_PEER_TRUST_REFRESH_LEAD_MS = 6 * 60 * 60 * 1000;
export const P2P_PEER_TRUST_REFRESH_MAX_AGE_MS = 18 * 60 * 60 * 1000;
export const P2P_PEER_TRUST_REFRESH_INTERVAL_MS = 15 * 60 * 1000;
export const P2P_PEER_TRUST_REFRESH_INITIAL_MIN_MS = 30 * 1000;
export const P2P_PEER_TRUST_REFRESH_INITIAL_JITTER_MS = 60 * 1000;
export const P2P_ROUTE_PROOF_TTL_MS = 60 * 1000;
export const MAX_P2P_CERT_CACHE_SIZE = 128;
export const MAX_USERNAME_LENGTH = 96;
export const CERT_CLOCK_SKEW_MS = 2 * 60 * 1000;
export const RECEIPT_RETENTION_MS = 24 * 60 * 60 * 1000;
export const P2P_MESSAGE_RATE_LIMIT = 100;
export const P2P_MESSAGE_RATE_WINDOW_MS = 60_000;
export const P2P_GLOBAL_MESSAGE_RATE_LIMIT = P2P_MESSAGE_RATE_LIMIT * 10;
export const P2P_RATE_LIMITER_MAX_ENTRIES = 1024;
export const MAX_INBOUND_PROCESSING_QUEUE = 256;
export const P2P_MAX_PEERS = 64;
export const P2P_PEER_CERT_TTL_MS = 24 * 60 * 60 * 1000;
export const RATE_LIMIT_WINDOW_MS = 60_000;

export const MAX_PREVIEW_LENGTH = 80;
export const CONVERSATION_MIN_USERNAME_LENGTH = 2;
export const CONVERSATION_MAX_USERNAME_LENGTH = 64;
export const MAX_CONVERSATIONS = 1000;
export const CONVERSATION_RATE_LIMIT_WINDOW_MS = 10_000;
export const CONVERSATION_RATE_LIMIT_MAX = 8;

export const MAX_LOCAL_MESSAGE_ID_LENGTH = 160;
export const MAX_LOCAL_USERNAME_LENGTH = 256;
export const MAX_LOCAL_MIMETYPE_LENGTH = 128;
export const MAX_LOCAL_EMOJI_LENGTH = 32;
export const MAX_LOCAL_FILE_SIZE_BYTES = 1024 * 1024 * 1024;
export const LOCAL_EVENT_RATE_LIMIT_WINDOW_MS = 10_000;
export const LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS = 120;

export const REPLY_MAX_TRACKED_ORIGINS = 5000;
export const REPLY_MAX_REPLIES_PER_ORIGIN = 250;
export const REPLY_RATE_LIMIT_WINDOW_MS = 10_000;
export const REPLY_RATE_LIMIT_MAX_EVENTS = 100;

export const WEBSOCKET_RATE_LIMIT_WINDOW_MS = 1_000;
export const WEBSOCKET_RATE_LIMIT_MAX_MESSAGES = 500;

export const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE;
export const MAX_TOTAL_CHUNKS = 10_000;
export const MAX_CHUNK_SIZE_BYTES = DEFAULT_CHUNK_SIZE_SMALL;
export const MAX_CONCURRENT_TRANSFERS = 16;
export const MAX_CONCURRENT_TRANSFERS_PER_PEER = 4;
export const GLOBAL_INBOUND_FILE_MEMORY_BUDGET = 192 * 1024 * 1024;
export const MAX_BASE64_CHARS = 4 * Math.ceil((MAX_CHUNK_SIZE_BYTES + 35) / 3);
export const RATE_LIMIT_MAX_EVENTS = 6_000;

export const DB_MAX_PENDING_MESSAGES = 500;
export const DB_SAVE_DEBOUNCE_MS = 100;

export const USERNAME_DISPLAY_MAX_LENGTH = 256;
export const CALLING_MAX_USERNAME_LENGTH = 120;
export const CALLING_MAX_CALL_ID_LENGTH = 32;
export const MAX_CALL_SIGNAL_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const CALLING_EVENT_ALLOWED_PAYLOAD_KEYS = new Set([
  'account',
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
export const CALL_DEVICE_SETTLE_MS = 800;
export const MAX_BLOCK_LIST_SIZE = 10000;
export const BLOCK_STATUS_CACHE_TTL_MS = 30000;
export const BLOCK_RATE_LIMIT_WINDOW_MS = 60_000;
export const BLOCK_RATE_LIMIT_MAX_EVENTS = 10;

export const MAX_CLIPBOARD_SIZE = 100 * 1024;
export const MAX_INPUT_SIZE = 1024 * 1024;
export const RATE_LIMIT_ATTEMPTS = 10;

export const MAX_MESSAGE_JSON_BYTES = 64 * 1024;
export const MAX_SIGNAL_PAYLOAD_JSON_BYTES = 64 * 1024;
export const MAX_CALL_SIGNAL_BYTES = 16 * 1024;
export const MESSAGE_RATE_LIMIT_WINDOW_MS = 5_000;
export const MESSAGE_RATE_LIMIT_MAX = 2000;

export const MAX_PENDING_RETRY_PER_PEER = 50;
export const MAX_PENDING_RETRY_PEERS = 200;
export const OUTBOUND_RETRY_MAX_AGE_MS = 60 * 60 * 1000;
export const KEY_REQUEST_CACHE_DURATION = 5000;
export const MAX_RESETS_PER_PEER = 5;
export const RESET_WINDOW_MS = 60_000;

export const PQ_RANDOM_MAX_BYTES_LIMIT = 100 * 1024 * 1024;
export const PQ_RANDOM_DEFAULT_MAX_BYTES = 1_048_576;
export const PQ_UTILS_MAX_DATA_SIZE = 10 * 1024 * 1024;
export const PQ_AEAD_NONCE_SIZE = 36;
export const PQ_AEAD_GCM_IV_SIZE = 12;
export const PQ_AEAD_MAC_SIZE = 32;
export const PQ_AEAD_CIPHERTEXT_OVERHEAD = 32;
export const PQ_KEM_PUBLIC_KEY_SIZE = 1568;
export const PQ_KEM_SECRET_KEY_SIZE = 3168;
export const PQ_KEM_CIPHERTEXT_SIZE = 1568;
export const PQ_KEM_SHARED_SECRET_SIZE = 32;
export const PQ_SIG_PUBLIC_KEY_SIZE = 2592;
export const PQ_SIG_SECRET_KEY_SIZE = 4896;
export const PQ_SIG_SIGNATURE_SIZE = 4627;
export const PQ_WORKER_MAX_RESTART_ATTEMPTS = 5;

export const CRYPTO_AES_KEY_SIZE = 256;
export const CRYPTO_IV_LENGTH = 12;
export const CRYPTO_AUTH_TAG_LENGTH = 16;
export const CRYPTO_HKDF_HASH = 'SHA-256';
export const CRYPTO_X25519_DERIVE_BITS = 256;

export const HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES = 1024 * 1024;
export const HYBRID_ENVELOPE_MAX_OUTER_CIPHERTEXT_BYTES = 2 * 1024 * 1024;
export const HYBRID_ENVELOPE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

export const NOISE_MAX_SESSION_AGE_MS = 24 * 60 * 60 * 1000;
export const NOISE_REPLAY_WINDOW_SIZE = BigInt(32768);

export const P2P_CONNECTION_TIMEOUT_MS = 90_000;
export const P2P_KEEPALIVE_INTERVAL_MS = 10_000;
export const P2P_MAX_STREAMS_PER_CONNECTION = 8;
export const P2P_STUCK_STATE_TIMEOUT_MS = 180_000;

export const STORAGE_RATE_LIMIT_WINDOW_MS = 1_000;
export const STORAGE_RATE_LIMIT_MAX_OPS = 100;

export const SECURE_DB_MAX_VALUE_SIZE = 100 * 1024 * 1024;
export const SECURE_DB_MIN_CLEANUP_INTERVAL = 60_000;
export const SECURE_DB_MAX_EPHEMERAL_BATCH = 1000;
export const SECURE_DB_MAX_FILE_SIZE = MAX_FILE_SIZE;
export const SECURE_DB_BLOCKED_MIME_TYPES = [
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-sh',
    'application/x-bat',
    'application/x-executable',
    'application/vnd.microsoft.portable-executable',
  ];
export const TOR_DEFAULT_MONITOR_INTERVAL_MS = 30_000;
export const TOR_MAX_BACKOFF_MS = 30_000;

export const MAX_PENDING_QUEUE = 500;
export const MAX_PENDING_QUEUE_BYTES = 32 * 1024 * 1024;
export const MAX_REPLAY_WINDOW_MS = 5 * 60 * 1000;
export const INITIAL_RECONNECT_DELAY_MS = 1_000;
export const MAX_RECONNECT_DELAY_MS = 60_000;
export const RATE_LIMIT_BACKOFF_MS = 5_000;
export const MAX_MESSAGE_AAD_LENGTH = 256;
export const SESSION_REKEY_INTERVAL_MS = 60 * 60 * 1000;
export const QUEUE_FLUSH_INTERVAL_MS = 1_000;

export const MAX_MESSAGES_PER_MINUTE = 120;
export const MAX_BURST_MESSAGES = 20;

export const HEARTBEAT_INTERVAL_MS = 35_000;
export const HEARTBEAT_TIMEOUT_MS = 90_000;
export const MAX_MISSED_HEARTBEATS = 4;



export const MAX_PQ_ENVELOPE_CIPHERTEXT_BYTES = 12 * 1024 * 1024;
export const MAX_PQ_ENVELOPE_AAD_BYTES = 1024;

export const MAX_AVATAR_SIZE_BYTES = 512 * 1024;
export const MAX_AVATAR_DIMENSION = 512;
export const MAX_AVATAR_DATA_URL_CHARS = 240 * 1024;
export const ALLOWED_AVATAR_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'] as const;
export const AVATAR_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
import { PROTOCOL_KEYS } from './config/protocol-keys';
