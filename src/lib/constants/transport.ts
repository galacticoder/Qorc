import {
  HASH_OUTPUT_BYTES,
  POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES,
} from '../../../shared/crypto-sizes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export const SESSION_WAIT_MS = 12_000;
export const SESSION_POLL_BASE_MS = 200;
export const SESSION_POLL_MAX_MS = 1_500;
export const SESSION_FRESH_COOLDOWN_MS = 10_000;
export const MAX_MESSAGE_FRAME_SIZE = 4 * 1024 * 1024;
export const MAX_CALL_FRAME_SIZE = 2 * 1024 * 1024;
export const MAX_PENDING_ENCRYPT_OPERATIONS = 128;
export const MAX_PENDING_ENCRYPT_BYTES = 4 * MAX_MESSAGE_FRAME_SIZE;
export const MAX_PENDING_REALTIME_ENCRYPT_OPERATIONS = 5;
export const MAX_PENDING_VISUAL_ENCRYPT_OPERATIONS = 2;
export const MAX_PENDING_DECRYPT_OPERATIONS = 128;
export const MAX_PENDING_DECRYPT_BYTES = 4 * MAX_MESSAGE_FRAME_SIZE;

export const TOR_DEFAULT_MONITOR_INTERVAL_MS = 30_000;
export const TOR_MAX_BACKOFF_MS = 30_000;
export const TOR_DEEP_HEALTH_CHECK_INTERVAL_MS = 5 * 60 * 1000;
export const TOR_BOOTSTRAP_TIMEOUT_MS = 150_000;
export const TOR_BOOTSTRAP_POLL_MS = 1_000;
export const STARTUP_CONNECT_ATTEMPTS = 2;
export const STARTUP_CONNECT_RETRY_DELAY_MS = 2500;

export const TRANSPORT_FRAME_HEADER_SIZE = 12;
export const FRAME_OVERHEAD = TRANSPORT_FRAME_HEADER_SIZE + HASH_OUTPUT_BYTES;
export const NOISE_FRAME_OVERHEAD = FRAME_OVERHEAD + POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES;
export const SEALED_KDF_CONTEXT = new TextEncoder().encode(PROTOCOL_KEYS.SEALED_SENDER_KDF);
export const SEALED_AAD_CONTEXT = new TextEncoder().encode(PROTOCOL_KEYS.SEALED_SENDER_AAD);
export const DEFAULT_BRIDGE_TRANSPORT_PATH = './pluggable_transports/lyrebird';
export const DEFAULT_SNOWFLAKE_BRIDGE = 'snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn';
export const READ_ONLY_TRANSFER_ATTEMPT_MINIMUM = 3;
export const TOR_AUTO_SETUP_MAX_ATTEMPTS = 90;
export const TOR_AUTO_SETUP_LOCAL_VERIFY_ATTEMPTS_LIMIT = 5;
export const STARTUP_CONNECTION_START_WATCHDOG_INTERVAL_MS = 1500;

export const TOR_DEGRADED_LATENCY_MS = 5_000;

export const TOR_MONITOR_BACKOFF_BASE_MS = 1_000;

export const FrameSize = {
  STANDARD: 131072,
  XLARGE: 262144
} as const;

export enum FrameType {
  MESSAGE = 0x01,
}
