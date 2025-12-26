/**
 * Type definitions and constants for WebSocket client
 */

export type WebSocketLifecycleState =
  | 'idle'
  | 'tor-check'
  | 'connecting'
  | 'handshaking'
  | 'connected'
  | 'disconnected'
  | 'paused'
  | 'error';

export interface PendingSend {
  id: string;
  payload: unknown;
  createdAt: number;
  attempt: number;
  flushAfter: number;
  highPriority?: boolean;
}

export interface ServerKeyMaterial {
  kyberPublicKey: Uint8Array;
  dilithiumPublicKey?: Uint8Array;
  x25519PublicKey?: Uint8Array;
  fingerprint: string;
  serverId?: string;
}

export interface ConnectionMetrics {
  lastConnectedAt: number | null;
  totalReconnects: number;
  consecutiveFailures: number;
  lastFailureAt: number | null;
  lastRateLimitAt: number | null;
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
  averageLatencyMs: number;
  lastLatencyMs: number | null;
  securityEvents: {
    replayAttempts: number;
    signatureFailures: number;
    rateLimitHits: number;
    fingerprintMismatches: number;
  };
}

export interface RateLimitState {
  messageTimestamps: number[];
  lastResetTime: number;
  violationCount: number;
}

export interface ConnectionHealth {
  state: WebSocketLifecycleState;
  isHealthy: boolean;
  metrics: ConnectionMetrics;
  queueDepth: number;
  sessionAge: number | null;
  torStatus: {
    ready: boolean;
    circuitHealth: 'unknown' | 'good' | 'degraded' | 'poor';
  };
  lastHeartbeat: number | null;
  quality: 'excellent' | 'good' | 'fair' | 'poor' | 'unknown';
}

export interface MessageHandler {
  (message: unknown): void;
}

// WebSocket constants
export const MAX_PENDING_QUEUE = 500;
export const MAX_REPLAY_WINDOW_MS = 5 * 60 * 1000;
export const REPLAY_CACHE_LIMIT = 10_000;
export const INITIAL_RECONNECT_DELAY_MS = 1_000;
export const MAX_RECONNECT_DELAY_MS = 60_000;
export const RATE_LIMIT_BACKOFF_MS = 5_000;
export const MAX_HANDSHAKE_ATTEMPTS = 3;
export const MAX_MESSAGE_AAD_LENGTH = 256;
export const SESSION_REKEY_INTERVAL_MS = 60 * 60 * 1000;
export const KEY_ROTATION_WARNING_MS = 45 * 60 * 1000;
export const QUEUE_FLUSH_INTERVAL_MS = 1_000;

export const MAX_MESSAGES_PER_MINUTE = 120;
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const MAX_BURST_MESSAGES = 20;
export const RATE_LIMIT_VIOLATION_THRESHOLD = 3;

export const HEARTBEAT_INTERVAL_MS = 35_000;
export const HEARTBEAT_TIMEOUT_MS = 90_000;
export const MAX_MISSED_HEARTBEATS = 4;
export const LATENCY_SAMPLE_WEIGHT = 0.2;
export const CIRCUIT_BREAKER_THRESHOLD = 5;
export const CIRCUIT_BREAKER_TIMEOUT_MS = 60_000;

export const MAX_NONCE_SEQUENCE_GAP = 1000;
export const TIMESTAMP_SKEW_TOLERANCE_MS = 5_000;

export const SESSION_FAILOVER_GRACE_PERIOD_MS = 10_000;

export const MAX_INCOMING_WS_STRING_CHARS = 10_000_000;
export const MAX_PQ_ENVELOPE_CIPHERTEXT_BYTES = 12 * 1024 * 1024;
export const MAX_PQ_ENVELOPE_NONCE_BYTES = 1024;
export const MAX_PQ_ENVELOPE_TAG_BYTES = 1024;
export const MAX_PQ_ENVELOPE_AAD_BYTES = 1024;

// Helper functions
export const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

export const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

export const estimateBase64DecodedBytes = (value: string): number => {
  const trimmed = value.trim();
  if (!trimmed) return 0;
  const pad = trimmed.endsWith('==') ? 2 : trimmed.endsWith('=') ? 1 : 0;
  return Math.floor((trimmed.length * 3) / 4) - pad;
};

// Default metrics factory
export const createDefaultMetrics = (): ConnectionMetrics => ({
  lastConnectedAt: null,
  totalReconnects: 0,
  consecutiveFailures: 0,
  lastFailureAt: null,
  lastRateLimitAt: null,
  messagesSent: 0,
  messagesReceived: 0,
  bytesSent: 0,
  bytesReceived: 0,
  averageLatencyMs: 0,
  lastLatencyMs: null,
  securityEvents: {
    replayAttempts: 0,
    signatureFailures: 0,
    rateLimitHits: 0,
    fingerprintMismatches: 0
  }
});

// Default rate limit state factory
export const createDefaultRateLimitState = (): RateLimitState => ({
  messageTimestamps: [],
  lastResetTime: Date.now(),
  violationCount: 0
});
