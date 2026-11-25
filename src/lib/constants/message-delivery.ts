import { SignalType } from '../types/signal-types';

export const RATE_LIMIT_MAX_RECEIPTS = 100;
export const RECEIPT_BATCH_WINDOW_MS = 300;
export const MAX_RECEIPT_BATCH_IDS = 256;
export const RECEIPT_RETENTION_MS = 24 * 60 * 60 * 1000;
export const RECEIPT_BATCH_MAX_FLUSH_ATTEMPTS = 5;
export const MAX_RECEIPT_BATCH_PEERS = 256;
export const MAX_DELIVERY_RECEIPT_OUTBOX_ENTRIES = 500;
export const MAX_DELIVERY_RECEIPT_OUTBOX_ENTRIES_PER_PEER = 64;
export const DURABLE_RECEIPT_OUTBOX_TTL_MS = 12 * 60 * 60 * 1000;
export const SENT_RECEIPT_RETENTION_MS = 30 * 60 * 1000;
export const DELIVERY_RECEIPT_OUTBOX_RETRY_INTERVAL_MS = 30 * 1000;
export const DELIVERY_RECEIPT_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const MAX_PENDING_RECEIPTS = 512;
export const IN_MEMORY_PENDING_RECEIPT_TTL_MS = 10 * 60 * 1000;
export const MAX_SENT_RECEIPT_HISTORY = 4096;
export const MAX_DB_RECEIPT_ATTEMPTS = 8;
export const READ_RECEIPT_QUEUE_RECHECK_MS = 1000;
export const READ_RECEIPT_BACKOFF_BASE_MS = 1000;
export const READ_RECEIPT_BACKOFF_MAX_MS = 60_000;

export const DELIVERY_ACK_TIMEOUT_MS = 25_000;
export const BLIND_ROUTE_ACK_LIVENESS_POLL_MS = 1_000;
export const MAX_AWAITING_ACK = 500;
export const MAX_EARLY_ACKS_PER_PEER = 32;
export const MAX_ACKED_CHUNK_TRANSFERS = 64;
export const MAX_CONCURRENT_ACK_SPOOLS = 4;
export const MAX_BLIND_ACK_WAITERS = 512;
export const MAX_DURABLE_ACK_BYTES = 16 * 1024 * 1024;
export const DURABLE_ACK_RETRY_MS = 30_000;
export const DURABLE_ACK_RESTORE_RETRY_BASE_MS = 1000;

export const MAX_PENDING_RETRY_PER_PEER = 50;
export const MAX_PENDING_RETRY_PEERS = 200;
export const OUTBOUND_RETRY_MAX_AGE_MS = 60 * 60 * 1000;
export const CALL_SIGNAL_QUEUE_MAX_WAIT_MS = 5_000;
export const REDELIVER_FLUSH_INTERVAL_MS = 3000;
export const REDELIVER_MAX_PENDING = 400;
export const SPOOL_MAX_ATTEMPTS = 3;
export const SPOOL_RETRY_BASE_MS = 1500;
export const MAX_QUEUED_SENDS_PER_PEER = 100;
export const MAX_QUEUED_PRIORITY_SENDS = 256;
export const MAX_TOTAL_SEND_TASKS = 512;
export const MAX_CONCURRENT_SEND_TASKS = 8;
export const MAX_PRIORITY_BURST = 4;
export const MAX_RETRY_QUEUE_BYTES = 16 * 1024 * 1024;
export const MAX_GLOBAL_PENDING_RETRIES = 500;
export const MAX_DURABLE_SEND_RETRY_ATTEMPTS = 2;
export const MAX_DELIVERED_OPERATION_TOMBSTONES = 1000;
export const RETRY_REHYDRATE_DELAY_MS = 5000;

export const RETRY_SIGNAL_TYPES = new Set<string>([
  SignalType.MESSAGE,
  SignalType.EDIT_MESSAGE,
  SignalType.DELETE_MESSAGE,
  SignalType.REACTION_ADD,
  SignalType.REACTION_REMOVE,
]);
export const RETRY_ENTRY_KEYS = new Set([
  'content', 'editMessageId', 'messageSignalType', 'originalMessageId',
  'queuedAt', 'replyTo', 'retryCount', 'retryId', 'user'
]);
export const UNACKNOWLEDGED_ENTRY_KEYS = new Set([
  ...RETRY_ENTRY_KEYS,
  'timestamp'
]);
export const RETRY_USER_KEYS = new Set(['username']);
export const RETRY_REPLY_KEYS = new Set(['content', 'id', 'sender']);
export const UNIFIED_SIGNAL_TRANSPORT_QUEUE_RECOVERY_CLEAR_TIMEOUT_MS = 50;
export const UNIFIED_SIGNAL_TRANSPORT_MSG_ERROR_LENGTH_LIMIT = 200;
export const RECEIPTS_UPDATE_MESSAGE_RECEIPT_TIMEOUT_MS = 500;

export const ACK_TRACKED_SIGNAL_TYPES: ReadonlySet<SignalType> = new Set([
    SignalType.MESSAGE,
    SignalType.EDIT_MESSAGE, SignalType.DELETE_MESSAGE,
    SignalType.REACTION_ADD, SignalType.REACTION_REMOVE,
    SignalType.FILE_MESSAGE_CHUNK
]);
export const LIVE_ONLY_SIGNAL_TYPES: ReadonlySet<SignalType> = new Set([
    SignalType.CALL_SIGNAL,
    SignalType.TYPING_START, SignalType.TYPING_STOP,
    SignalType.FILE_MESSAGE_CHUNK, SignalType.FILE_TRANSFER_CANCEL
]);

export const DB_RECEIPT_RETRY_BASE_MS = 1_000;
export const DB_RECEIPT_RETRY_MAX_EXPONENT = 5;
export const DB_RECEIPT_RETRY_CAP_MS = 30_000;
export const DURABLE_ACK_RECONCILE_BASE_MS = 1_000;
export const DURABLE_ACK_RECONCILE_MAX_EXPONENT = 6;
export const DURABLE_ACK_RECONCILE_CAP_MS = 60_000;
