import { PROTOCOL_KEYS } from '../config/protocol-keys';

export const MAX_FILENAME_LENGTH = 255;
export const MAX_FILE_SIZE = 70 * 1024 * 1024;
export const FILE_SIZE_UNITS = ['Bytes', 'KB', 'MB', 'GB'] as const;
export const FILE_SIZE_BASE = 1024;
export const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tiff'] as const;
export const VIDEO_EXTENSIONS = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'wmv', 'flv', 'mkv'] as const;
export const AUDIO_EXTENSIONS = ['mp3', 'wav', 'ogg', 'webm', 'm4a', 'aac', 'flac'] as const;

export const MAX_JPEG_SEGMENTS = 512;
export const MAX_JPEG_SCANS = 16;
export const MAX_WEBP_CHUNKS = 4;
export const MAX_IMAGE_PREVIEW_BYTES = 32 * 1024 * 1024;
export const MAX_IMAGE_PREVIEW_DIMENSION = 8192;
export const MAX_IMAGE_PREVIEW_PIXELS = 16 * 1024 * 1024;
export const MAX_CANVAS_DIMENSION = MAX_IMAGE_PREVIEW_DIMENSION;
export const MAX_CANVAS_PIXELS = MAX_IMAGE_PREVIEW_PIXELS;
export const MEDIA_HEADER_BYTES = 64;

export const DEFAULT_CHUNK_SIZE_SMALL = 29 * 1024;
export const MAX_TOTAL_CHUNKS = 10_000;
export const MAX_BASE64_CHARS = 4 * Math.ceil((DEFAULT_CHUNK_SIZE_SMALL + 35) / 3);
export const MAX_CHUNKS_PER_SECOND = 80;
export const RATE_LIMITER_SLEEP_MS = 10;
export const INACTIVITY_TIMEOUT_MS = 120000;
export const MAX_CONCURRENT_TRANSFERS = 16;
export const MAX_CONCURRENT_TRANSFERS_PER_PEER = 4;
export const GLOBAL_INBOUND_FILE_MEMORY_BUDGET = 192 * 1024 * 1024;
export const MAX_RETAINED_FILE_BYTES = 128 * 1024 * 1024;
export const MAX_RETAINED_TRANSFERS = 8;
export const MAX_FILE_SESSION_PEERS = 512;
export const YIELD_INTERVAL = 8;
export const MAC_SALT = new TextEncoder().encode(PROTOCOL_KEYS.FILE_TRANSFER_MAC_SALT);

export const FILE_RETRANSMIT_RETENTION_MS = 3 * 60 * 1000;
export const FILE_TRANSPORT_ACK_CHUNK_INTERVAL = 32;
export const FILE_TRANSPORT_ACK_MAX_INTERVAL_MS = 5000;
export const FILE_NACK_STALL_MS = 6000;
export const MAX_NACK_ATTEMPTS = 4;
export const MAX_RETRANSMIT_CHUNKS_PER_REQUEST = 512;
export const RETRANSMIT_MIN_INTERVAL_MS = 2000;
export const FILE_RECOVERY_PROBE_INITIAL_MS = 15_000;
export const FILE_RECOVERY_PROBE_MAX_MS = 120_000;
export const MAX_FILE_SEND_RESTARTS = 2;
export const FILE_PERSIST_RETRY_BASE_MS = 1_500;
export const FILE_PERSIST_RETRY_MAX_MS = 15_000;
export const MAX_CANCELED_FILE_TRANSFERS = 512;

export const JPEG_SOF_MARKERS = new Set([
    0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
    0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf
]);
export const SUPPORTED_JPEG_SOF_MARKERS = new Set([0xc0, 0xc2]);
export const VOICE_NOTE_MIME_BY_EXTENSION = Object.freeze({
  webm: 'audio/webm',
  ogg: 'audio/ogg',
  m4a: 'audio/mp4',
  mp3: 'audio/mpeg',
} as const);
export const FILE_CHUNK_KEYS = [
  'chunkData',
  'chunkIndex',
  'chunkMac',
  'chunkSize',
  'envelope',
  'fileId',
  'fileSize',
  'fileTransferId',
  'filename',
  'from',
  'isLastChunk',
  'messageId',
  'recoveryProbe',
  'timestamp',
  'to',
  'totalChunks',
  'type',
] as const;
export const IMAGE_CONTAINER_VALIDATION_BYTES_LENGTH_MINIMUM = 4;
export const IMAGE_CONTAINER_VALIDATION_SEGMENT_LENGTH_MINIMUM = 11;
export const IMAGE_CONTAINER_VALIDATION_COMPONENT_COUNT_EXPECTED = 3;
export const IMAGE_CONTAINER_VALIDATION_CHUNK_DATA_LENGTH_MINIMUM = 10;
export const IMAGE_CONTAINER_VALIDATION_WEBP_LOSSLESS_DIMENSIONS_CHUNK_DATA_LENGTH_MINIMUM = 5;
export const IMAGE_CONTAINER_VALIDATION_VALIDATE_WEBP_CONTAINER_BYTES_LENGTH_MINIMUM = 30;
export const IMAGE_CONTAINER_VALIDATION_EXTENDED_DATA_LENGTH_EXPECTED = 10;
export const FILE_UTILS_BYTES_LENGTH_LIMIT = 4;
export const FILE_UTILS_SNIFF_AUDIO_MIME_BYTES_LENGTH_LIMIT = 12;
export const FILE_UTILS_BOX_SIZE_LIMIT = 8;
export const FILE_UTILS_STRIP_IMAGE_METADATA_TIMEOUT_MS = 30_000;
export const USE_FILE_SENDER_SEND_CHUNKS_DELAY_MS = 1000;
export const CHUNK_VALIDATION_PAYLOAD_FILENAME_LENGTH_MINIMUM = 128;
export const CHUNK_VALIDATION_PAYLOAD_CHUNK_MAC_LENGTH_EXPECTED = 44;
export const CHUNK_DECRYPTION_IV_LENGTH_EXPECTED = 12;
export const CHUNK_DECRYPTION_AUTH_TAG_LENGTH_EXPECTED = 16;
export const CHUNK_DECRYPTION_AES_KEY_BYTES_LENGTH_EXPECTED = 32;
export const CHUNK_DECRYPTION_MAC_KEY_LENGTH_EXPECTED = 32;
export const CHUNK_DECRYPTION_EXPECTED_MAC_LENGTH_EXPECTED = 32;
export const USE_FILE_HANDLER_SCHEDULE_RETRY_TIMEOUT_MS = 1500;

export const FILE_SEND_PROGRESS_REPORT_INTERVAL_MS = 10_000;
