export const CONVERSATION_SEGMENT_SIZE = 50;
export const CONVERSATION_WARM_MESSAGE_COUNT = 20;
export const CALL_LOG_SEGMENT_SIZE = 50;
export const MAX_CONVERSATION_STORED_MESSAGES = 10_000;
export const MAX_CONVERSATION_INPUT_MESSAGES = MAX_CONVERSATION_STORED_MESSAGES + 500;
export const MAX_KNOWN_PEERS = 2_048;
export const DB_MAX_PENDING_MESSAGES = 500;
export const DB_SAVE_DEBOUNCE_MS = 100;
export const MAX_CONVERSATION_BATCH_WRITES = 511;
export const MAX_SEGMENT_INDEX = 2 ** 40;

export const STORAGE_RATE_LIMIT_WINDOW_MS = 1_000;
export const STORAGE_RATE_LIMIT_MAX_OPS = 100;
export const SECURE_DB_MAX_VALUE_SIZE = 100 * 1024 * 1024;
export const SECURE_DB_MIN_CLEANUP_INTERVAL = 60_000;
export const SECURE_DB_MAX_EPHEMERAL_BATCH = 1000;
export const SECURE_DB_BLOCKED_MIME_TYPES = [
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-sh',
    'application/x-bat',
    'application/x-executable',
    'application/vnd.microsoft.portable-executable',
  ];
export const MAX_SCOPED_STORAGE_CONTEXTS = 32_768;
export const SQLITE_KV_MAX_MUTATION_DELETIONS = 2_048;
export const MAX_CONVERSATION_MUTATION_DELETIONS = SQLITE_KV_MAX_MUTATION_DELETIONS;
export const MAX_EPHEMERAL_LIST_ITEMS = 500;

export const MAX_BLOCK_LIST_SIZE = 10000;
export const BLOCK_STATUS_CACHE_TTL_MS = 30000;
export const MAX_HELD_PER_PEER = 100;
export const MAX_PENDING_PEERS = 128;
export const MAX_HELD_GLOBAL = 256;
export const MAX_HELD_BYTES = 16 * 1024 * 1024;
export const MAX_HELD_MESSAGE_BYTES = 2 * 1024 * 1024;

export const LINK_PREVIEW_CACHE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
export const MAX_LINK_PREVIEW_CACHE_ENTRIES = 48;
export const MAX_LINK_PREVIEW_CACHE_BYTES = 24 * 1024 * 1024;
export const MAX_LINK_PREVIEW_RECORD_BYTES = 3 * 1024 * 1024;
export const MAX_LINK_PREVIEW_IMAGE_DATA_URL_LENGTH = 2_100_000;

export const USER_RECORD_KEYS = new Set([
  'hybridPublicKeys',
  'id',
  'identityBundleFingerprint',
  'identityRootFingerprint',
  'peerCertificateFingerprint',
  'peerCertificateVerifiedAt',
  'username',
]);
export const KNOWN_USER_UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const KNOWN_USER_FINGERPRINT_REGEX = /^[a-f0-9]{64}$/;
export const MAX_DATE_TIMESTAMP = 8_640_000_000_000_000;
export const MAX_TIMER_DELAY_MS = 2_147_483_647;
export const CONVERSATION_METADATA_KEYS = new Set([
  'firstSegment',
  'isPinned',
  'lastMessage',
  'lastReadTimestamp',
  'lastSegment',
  'peerUsername',
  'pinnedAt',
]);
export const SEGMENT_INDEX_DIGITS = 13;
export const SQLITE_KV_ACCOUNT_NAMESPACE_VALUE_LENGTH_LIMIT = 120;
export const TOKEN_VAULT_EXISTING_0_BLINDED_ELEMENT_LENGTH_EXPECTED = 32;
export const ENCRYPTED_STORAGE_KEY_LENGTH_LIMIT = 256;
export const SECURE_DB_STORE_BYTES_LENGTH_LIMIT = 256;
export const SECURE_DB_KEY_BYTES_LENGTH_LIMIT = 256;
export const SECURE_DB_ADDITIONAL_DELETES_LENGTH_LIMIT = 512;
export const SECURE_DB_LIMIT = 50;
export const SECURE_DB_MAX_COUNT = 500;
export const SECURE_DB_ENTRY_LENGTH_MINIMUM = 256;
export const SECURE_DB_APPEND_EPHEMERAL_LIST_VALUE_LENGTH_MINIMUM = 256;
export const MESSAGE_PERSISTENCE_LIMIT = 50;
export const USE_SECURE_DB_LIMIT = 50;

export const DB_OPERATION_RETRY_BASE_MS = 1_000;
export const DB_OPERATION_RETRY_MAX_EXPONENT = 5;
export const DB_OPERATION_RETRY_CAP_MS = 30_000;
