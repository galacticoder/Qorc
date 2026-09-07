import { envInt } from '../utils/env.js';

export const SERVER_CONSTANTS = {
  BANDWIDTH_QUOTA: envInt('WS_BANDWIDTH_QUOTA_BYTES', 64 * 1024 * 1024, 8 * 1024 * 1024, 512 * 1024 * 1024),
  BANDWIDTH_WINDOW: envInt('WS_BANDWIDTH_WINDOW_MS', 60 * 1000, 5 * 1000, 10 * 60 * 1000),
  MESSAGE_HARD_LIMIT_PER_MINUTE: envInt('WS_FRAME_MAX_PER_WINDOW', 500, 50, 100_000),
  MESSAGE_RATE_RESET_INTERVAL: envInt('WS_FRAME_WINDOW_MS', 60_000, 5_000, 10 * 60_000),
  HEARTBEAT_INTERVAL: 30000,
  WS_FIXED_MESSAGE_SIZE_BYTES: 64 * 1024,
  AVATAR_BLOB_MAX_COUNT: envInt('AVATAR_BLOB_MAX_COUNT', 20_000, 100, 100_000),
};

// Security headers
export const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'microphone=(self), camera=(self)',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; worker-src 'self' blob:;",
};

const FIRST_PARTY_ORIGINS = [
  'tauri://localhost',
  'http://tauri.localhost',
  'https://tauri.localhost',
];

export const CORS_CONFIG = {
  ALLOWED_ORIGINS: (() => {
    const rawOrigins = process.env.ALLOWED_CORS_ORIGINS || '';
    const configured = rawOrigins
      .split(',')
      .map(origin => origin.trim())
      .filter(origin => origin.length > 0);
    return Array.from(new Set([...FIRST_PARTY_ORIGINS, ...configured]));
  })(),
  ALLOWED_METHODS: 'GET, POST, PUT, DELETE, OPTIONS',
  ALLOWED_HEADERS: 'Content-Type, Authorization',
  MAX_AGE_SECONDS: 86400,
};
