//! Native client limits, timing, and defaults.

pub(crate) mod validation {
    pub(crate) const HARD_MAX_JSON_DEPTH: usize = 64;
    pub(crate) const AUTH_USERNAME_MIN_BYTES: usize = 3;
    pub(crate) const AUTH_USERNAME_MAX_BYTES: usize = 100;
}

pub(crate) mod audio {
    use std::time::Duration;

    pub(crate) const SAMPLE_RATE_HZ: u32 = 48_000;
    pub(crate) const FRAME_SAMPLES: usize = 960;
    pub(crate) const SILENCE_FADE_SAMPLES: usize = SAMPLE_RATE_HZ as usize / 200;
    pub(crate) const MAX_OPUS_PACKET_BYTES: usize = 1276;
    pub(crate) const MAX_CODEC_SESSIONS: usize = 4;
    pub(crate) const MAX_QUEUE_SAMPLES: usize = FRAME_SAMPLES * 10;
    pub(crate) const EDGE_FADE_SAMPLES: usize = 240;
    pub(crate) const MAX_PLAYBACK_SESSIONS: usize = 2;
    pub(crate) const CAPTURE_FRAME_WAIT: Duration = Duration::from_secs(1);
    pub(crate) const CAPTURE_START_WAIT: Duration = Duration::from_secs(10);
    pub(crate) const MAX_CAPTURE_SESSIONS: usize = 2;
    pub(crate) const MICROPHONE_FRAME_HEADER_BYTES: usize = 24;
    pub(crate) const FRAME_BYTES: usize = FRAME_SAMPLES * std::mem::size_of::<f32>();
    pub(crate) const OPUS_BITRATE_BPS: i32 = 48_000;
    pub(crate) const OPUS_COMPLEXITY: i32 = 10;
    pub(crate) const OPUS_EXPECTED_PACKET_LOSS_PERCENT: i32 = 10;
}

pub(crate) mod camera {
    use std::time::Duration;

    pub(crate) const MAX_SESSIONS: usize = 2;
    pub(crate) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
    pub(crate) const FRAME_WAIT: Duration = Duration::from_secs(1);
    pub(crate) const START_WAIT: Duration = Duration::from_secs(10);
}

pub(crate) mod screen {
    use std::time::Duration;

    pub(crate) const MAX_SESSIONS: usize = 1;
    pub(crate) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    pub(crate) const MAX_CAPTURE_BUFFER_BYTES: usize = MAX_FRAME_BYTES * 2;
    pub(crate) const FRAME_WAIT: Duration = Duration::from_secs(1);
    pub(crate) const START_WAIT: Duration = Duration::from_secs(120);
    #[cfg(target_os = "linux")]
    pub(crate) const CAPTURE_WIDTH: u16 = 1280;
    #[cfg(target_os = "linux")]
    pub(crate) const CAPTURE_HEIGHT: u16 = 720;
    #[cfg(target_os = "linux")]
    pub(crate) const CAPTURE_FRAME_RATE: u16 = 60;
    #[cfg(target_os = "linux")]
    pub(crate) const GSTREAMER_FIRST_FRAME_WAIT: Duration = Duration::from_secs(8);
    #[cfg(target_os = "linux")]
    pub(crate) const GSTREAMER_PIPE_WAIT_MS: libc::c_int = 25;
}

pub(crate) mod account {
    pub(crate) const MAX_VAULT_JSON_CHARS: usize = 24 * 1024;
    pub(crate) const MAX_CREDENTIAL_BYTES: usize = 4096;
    pub(crate) const TOKEN_VAULT_MAX_PLAINTEXT_BYTES: usize = 7 * 1024 * 1024;
    pub(crate) const ARGON_MEMORY_KIB: u32 = 512 * 1024;
    pub(crate) const ARGON_ITERATIONS: u32 = 6;
    pub(crate) const ARGON_LANES: u32 = 4;
    pub(crate) const SIGN_INPUT_MAX_BYTES: usize = 1024 * 1024;
}

pub(crate) mod database {
    pub(crate) const NATIVE_MESSAGE_CONTENT_MAX_BYTES: usize = 66 * 1024;
    pub(crate) const NATIVE_MESSAGE_ID_MAX_BYTES: usize = 256;
    pub(crate) const DB_NAME_MAX_LEN: usize = 256;
    pub(crate) const DB_VALUE_MAX_BYTES: usize = 128 * 1024 * 1024;
    pub(crate) const DB_FILE_STORE_QUOTA_BYTES: u64 = 10 * 1024 * 1024 * 1024;
    pub(crate) const DB_RENDERER_STORE_QUOTA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    pub(crate) const DB_ACCOUNT_QUOTA_MAX_BYTES: u64 = 12 * 1024 * 1024 * 1024;
    pub(crate) const DB_ENUMERATION_MAX_ENTRIES: usize = 10_000;
    pub(crate) const DB_MUTATION_MAX_WRITES: usize = 512;
    pub(crate) const DB_MUTATION_MAX_DELETIONS: usize = 2_048;
    pub(crate) const DB_MAX_CONVERSATION_DELETIONS: usize = 10_201;
    pub(crate) const DB_MUTATION_MAX_TOTAL_VALUE_BYTES: usize = 128 * 1024 * 1024;
    pub(crate) const DB_MUTATION_MAX_JSON_BYTES: usize = 180 * 1024 * 1024;
    pub(crate) const DB_MUTATION_MAX_STRUCTURAL_TOKENS: usize = 55_000;
    pub(crate) const MAX_KEYS: usize = 32_768;
}

pub(crate) mod storage {
    pub(crate) const SECURE_VALUE_MAX_BYTES: usize = 8 * 1024 * 1024;
    pub(crate) const SECURE_STORE_MAX_ITEMS: u64 = 4096;
    pub(crate) const SECURE_STORE_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    pub(crate) const SECURE_KEY_MAX_LEN: usize = 512;
    #[cfg(target_os = "linux")]
    pub(crate) const MAX_MACHINE_ID_BYTES: u64 = 256;
}

pub(crate) mod message_content {
    pub(crate) const MAX_PRIVATE_MESSAGE_CHARS: usize = 16 * 1024;
    pub(crate) const MAX_RENDER_WIDTH: u32 = 800;
    pub(crate) const MAX_RENDER_HEIGHT: u32 = 4096;
    pub(crate) const MAX_LINK_URL_BYTES: usize = 2048;
    pub(crate) const MAX_MESSAGE_LINK_PREVIEWS: usize = 3;
}

pub(crate) mod link_preview {
    pub(crate) const MAX_HTML_BYTES: usize = 512 * 1024;
    pub(crate) const MAX_IMAGE_BYTES: usize = 1536 * 1024;
    pub(crate) const MAX_REDIRECTS: usize = 4;
    pub(crate) const MAX_PARALLEL_LINK_PREVIEW_FETCHES: usize = 8;
}

pub(crate) mod signal {
    pub(crate) const PREKEY_ROTATION_MS: u64 = 24 * 60 * 60 * 1000;
    pub(crate) const PREKEY_RETENTION_MS: u64 = 7 * PREKEY_ROTATION_MS;
    pub(crate) const SIGNAL_DEVICE_ID_MAX: u32 = 127;
    pub(crate) const MAX_SIGNAL_STORE_BLOB_BYTES: usize = 64 * 1024 * 1024;
    pub(crate) const MAX_SIGNAL_PLAINTEXT_BYTES: usize = 64 * 1024;
    pub(crate) const MAX_PENDING_DECRYPTS: usize = 512;
    pub(crate) const MAX_PENDING_DECRYPT_TOTAL_BYTES: usize = 8 * 1024 * 1024;
    pub(crate) const MAX_PENDING_TRANSPORT_MESSAGE_ID_BYTES: usize = 256;
    pub(crate) const MAX_PENDING_APPLICATION_TYPE_BYTES: usize = 64;
    pub(crate) const MAX_SIGNAL_CIPHERTEXT_BYTES: usize = 512 * 1024;
    pub(crate) const MAX_PEER_ML_KEM_KEYS: usize = 10_000;
    pub(crate) const MAX_STORED_SIGNAL_RECORDS: usize = 10_000;
    pub(crate) const MAX_STORED_ROTATING_PREKEY_RECORDS: usize = 16;
    pub(crate) const MAX_BASE_KEYS_PER_KYBER_PAIR: usize = 16_384;
    pub(crate) const MAX_KYBER_REPLAY_PAIRS: usize = 4_096;
    pub(crate) const MAX_KYBER_REPLAY_KEYS: usize = 100_000;
    pub(crate) const MAX_SIGNAL_PREKEY_BUNDLE_JSON_BYTES: usize = 16 * 1024;
    pub(crate) const MAX_SIGNAL_PREKEY_BUNDLE_STRING_BYTES: usize = 4 * 1024;
    pub(crate) const MAX_SIGNAL_ENCRYPTED_JSON_BYTES: usize = 768 * 1024;
    pub(crate) const MAX_SIGNAL_ENCRYPTED_STRING_BYTES: usize = 700 * 1024;
    pub(crate) const MAX_SIGNAL_ACK_JSON_BYTES: usize = 1024;
}

pub(crate) mod hybrid {
    pub(crate) const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
    pub(crate) const MAX_OUTER_BYTES: usize = 2 * 1024 * 1024;
    pub(crate) const MAX_ENVELOPE_JSON_BYTES: usize = 4 * 1024 * 1024;
}

pub(crate) mod anonymous_http {
    use std::time::Duration;

    pub(crate) const WARM_POOL_TARGET: usize = 4;
    pub(crate) const WARM_ENTRY_MAX_AGE: Duration = Duration::from_secs(240);
    pub(crate) const REQUEST_SMALL_BYTES: usize = 8 * 1024;
    pub(crate) const REQUEST_LARGE_BYTES: usize = 272 * 1024;
    pub(crate) const REQUEST_PIR_BYTES: usize = 1600 * 1024;
    pub(crate) const RESPONSE_SMALL_BYTES: usize = 24 * 1024;
    pub(crate) const RESPONSE_TAG_UPDATE_BYTES: usize = 32 * 1024;
    pub(crate) const RESPONSE_TAG_INDEX_BYTES: usize = 256 * 1024;
    pub(crate) const RESPONSE_KEY_TRANSPARENCY_SYNC_BYTES: usize = 1408 * 1024;
    pub(crate) const RESPONSE_PIR_BYTES: usize = 768 * 1024;
    pub(crate) const RESPONSE_AVATAR_BYTES: usize = 2576 * 1024;
    pub(crate) const RESPONSE_DISCOVERY_BYTES: usize = 2832 * 1024;
    pub(crate) const HEADER_TIMEOUT: Duration = Duration::from_secs(180);
    pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(150);
    pub(crate) const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
    pub(crate) const MIN_BODY_TIMEOUT: Duration = Duration::from_secs(300);
    pub(crate) const MIN_TRANSFER_BYTES_PER_SECOND: usize = 16 * 1024;
    pub(crate) const AVATAR_BODY_TIMEOUT: Duration = Duration::from_secs(356);
    pub(crate) const DISCOVERY_BODY_TIMEOUT: Duration = Duration::from_secs(580);
}

pub(crate) mod p2p {
    pub(crate) const MAX_STREAM_ID_BYTES: usize = 96;
    pub(crate) const STREAM_ID_SUFFIX_MIN_BYTES: usize = 16;
    pub(crate) const STREAM_ID_SUFFIX_MAX_BYTES: usize = 64;
    pub(crate) const HANDSHAKE_SESSION_ID_BYTES: usize = 32;
    pub(crate) const ONION_VIRTUAL_PORT: u16 = 9_735;
    pub(crate) const ONION_AUDIO_VIRTUAL_PORT: u16 = 9_736;
    pub(crate) const ONION_DIAL_TIMEOUT_SECS: u64 = 45;
    pub(crate) const ONION_PUBLISH_RETRY_SECS: u64 = 5;
    pub(crate) const ONION_PUBLISH_RETRY_MAX_SECS: u64 = 120;
    pub(crate) const AUDIO_LANE_TARGET_COUNT: usize = 4;
    pub(crate) const AUDIO_LANE_ACTIVE_COUNT: usize = 1;
    pub(crate) const AUDIO_LANE_SWITCH_MIN_GAIN_MS: u64 = 75;
    pub(crate) const AUDIO_LANE_SWITCH_MIN_GAIN_PERCENT: u64 = 10;
    pub(crate) const AUDIO_LANE_SWITCH_CONFIRMATIONS: u8 = 3;
    pub(crate) const AUDIO_LANE_PROBE_INTERVAL_SECS: u64 = 2;
    pub(crate) const AUDIO_LANE_PROBE_TIMEOUT_SECS: u64 = 6;
    pub(crate) const AUDIO_LANE_BIND_TIMEOUT_SECS: u64 = 10;
    pub(crate) const AUDIO_LANE_RETRY_BASE_SECS: u64 = 5;
    pub(crate) const AUDIO_LANE_RETRY_MAX_SECS: u64 = 60;
    pub(crate) const MAX_PENDING_AUDIO_LANES: usize = 64;
    pub(crate) const REQUEST_TIMEOUT_SECS: u64 = ONION_DIAL_TIMEOUT_SECS + 15;
    pub(crate) const SEND_TIMEOUT_SECS: u64 = 10;
    pub(crate) const FRAME_BODY_BASE_TIMEOUT_SECS: u64 = 15;
    pub(crate) const FRAME_BODY_MIN_BYTES_PER_SECOND: usize = 4 * 1024;
    pub(crate) const FRAME_BODY_MAX_TIMEOUT_SECS: u64 = 120;
    pub(crate) const ENDPOINT_CLOSE_TIMEOUT_SECS: u64 = 5;
    pub(crate) const AUTHENTICATION_TIMEOUT_SECS: u64 = 120;
    pub(crate) const COMMAND_RESPONSE_GRACE_SECS: u64 = 2;
    pub(crate) const ROTATE_RESPONSE_TIMEOUT_SECS: u64 = 30;
    pub(crate) const MAX_PROTOCOL_ERRORS: u8 = 3;
    pub(crate) const MAX_CONCURRENT_DIALS: usize = 16;
    pub(crate) const MAX_PENDING_INCOMING_HANDSHAKES: usize = 32;
    pub(crate) const MAX_UNAUTHENTICATED_CONNECTIONS: usize = 16;
    pub(crate) const PER_CONNECTION_SEND_QUEUE: usize = 64;
    pub(crate) const PER_CONNECTION_REALTIME_SEND_QUEUE: usize = 5;
    pub(crate) const MAX_PREAUTH_FRAMES_PER_CONNECTION: usize = 12;
    pub(crate) const MAX_PREAUTH_BYTES_PER_CONNECTION: usize = 256 * 1024;
    pub(crate) const MAX_PREAUTH_FRAME_BYTES: usize = 24 * 1024;
    pub(crate) const MAX_INBOUND_BUFFERED_BYTES: usize = 16 * 1024 * 1024;
    pub(crate) const MAX_INBOUND_BUFFERED_FRAMES: usize = 1024;
    pub(crate) const P2P_EVENT_CHANNEL_CAPACITY: usize =
        MAX_INBOUND_BUFFERED_FRAMES + (MAX_P2P_ALIASES * 2);
    pub(crate) const INBOUND_PRESSURE_RETRY_MS: u64 = 25;
    pub(crate) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
    pub(crate) const MAX_AUTHENTICATED_PAYLOAD_BYTES: usize = 3 * ((MAX_FRAME_BYTES - 2) / 4);
    pub(crate) const MAX_OUTBOUND_QUEUED_BYTES: usize = 16 * 1024 * 1024;
    pub(crate) const MAX_OUTBOUND_QUEUED_FRAMES: usize = 1024;
    pub(crate) const MAX_PENDING_CONTROL_COMMANDS: usize = 1024;
    pub(crate) const MAX_P2P_CONNECTIONS: usize = 64;
    pub(crate) const MAX_P2P_ALIASES: usize = MAX_P2P_CONNECTIONS * 4;
}

pub(crate) mod websocket {
    pub(crate) const WEBSOCKET_UPGRADE_TIMEOUT_SECS: u64 = 30;
    pub(crate) const SOCKS_CONNECT_TIMEOUT_SECS: u64 = 150;
    pub(crate) const SERVER_CONNECTION_TIMEOUT_SECS: u64 =
        SOCKS_CONNECT_TIMEOUT_SECS + WEBSOCKET_UPGRADE_TIMEOUT_SECS + 10;
    pub(crate) const WEBSOCKET_WRITE_TIMEOUT_SECS: u64 = 30;
    pub(crate) const STALE_CONNECTING_SECS: u64 = SERVER_CONNECTION_TIMEOUT_SECS + 10;
    pub(crate) const MAX_WS_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
    pub(crate) const MAX_WS_JSON_DEPTH: usize = 32;
    pub(crate) const MAX_WS_JSON_STRUCTURAL_TOKENS: usize = 16 * 1024;
    pub(crate) const MAX_WS_WRITE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
    pub(crate) const MAX_WS_PENDING_WRITES: usize = 1024;
    pub(crate) const MAX_WS_PENDING_WRITE_BYTES: usize = 64 * 1024 * 1024;
    pub(crate) const PQ_WS_FIXED_CELL_BYTES: usize = 64 * 1024;
    pub(crate) const MAX_WS_INBOUND_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
    pub(crate) const MAX_WS_INBOUND_BUFFERED_FRAMES: usize = 4096;
    pub(crate) const WS_EVENT_CHANNEL_CAPACITY: usize = MAX_WS_INBOUND_BUFFERED_FRAMES + 16;
}

pub(crate) mod tor {
    pub(crate) const DEFAULT_SOCKS_PORT: u16 = 9050;
    pub(crate) const DEFAULT_CONTROL_PORT: u16 = 9051;
    pub(crate) const PORT_SCAN_RANGE: u16 = 100;
    pub(crate) const MAX_CONFIG_SIZE: usize = 50000;
    pub(crate) const MAX_TOR_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
    pub(crate) const MAX_TOR_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
    pub(crate) const MAX_TOR_ARCHIVE_ENTRIES: usize = 4096;
    pub(crate) const MAX_TOR_ARCHIVE_PATH_BYTES: usize = 1024;
    pub(crate) const MAX_TOR_ARCHIVE_DEPTH: usize = 16;
    pub(crate) const MAX_CONTROL_LINE_BYTES: usize = 8 * 1024;
    pub(crate) const MAX_CONTROL_RESPONSE_LINES: usize = 64;
    pub(crate) const CONTROL_READ_FAILURE_THRESHOLD: u32 = 3;
    pub(crate) const TOR_KEEPALIVE_PERIOD_SECS: u32 = 60;
}

pub(crate) mod pir {
    pub(crate) const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
    pub(crate) const MAX_RECORDS: u32 = 1 << 20;
    pub(crate) const MAX_ENTRY_BYTES: u32 = 1 << 20;
    pub(crate) const MAX_BATCH_QUERIES: usize = 16;
}

pub(crate) mod auth_pow {
    pub(crate) const AUTH_POW_MAX_DIFFICULTY: u8 = 28;
    pub(crate) const AUTH_POW_MAX_BATCH_ITERATIONS: u32 = 1_000_000;
    pub(crate) const AUTH_POW_MAX_PENDING: usize = 64;
}

pub(crate) mod system {
    #[cfg(target_os = "linux")]
    use std::time::Duration;

    pub(crate) const MAX_INSTANCE_ID_BYTES: usize = 64;
    pub(crate) const MAX_EXTERNAL_URL_BYTES: usize = 8 * 1024;
    pub(crate) const MAX_FRONTEND_LOG_BATCH: usize = 32;
    pub(crate) const MAX_FRONTEND_LOG_LINE_BYTES: usize = 128 * 1024;
    pub(crate) const MAX_FRONTEND_LOG_BATCH_BYTES: usize = 4 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    pub(crate) const MEDIA_PERMISSION_LEASE_TTL: Duration = Duration::from_secs(10);
    pub(crate) const CALLBACK_CHUNK_BYTES: usize = 5 * 1024;
    pub(crate) const ANONYMOUS_CALLBACK_CHUNK_BYTES: usize = 64 * 1024;
    #[cfg(not(target_os = "android"))]
    pub(crate) const RATE_LIMIT_WINDOW_MS: u128 = 60_000;
    #[cfg(not(target_os = "android"))]
    pub(crate) const MAX_NOTIFICATIONS_PER_WINDOW: usize = 5;
}

pub(crate) mod media {
    pub(crate) const SESSION_ID_MIN_BYTES: usize = 16;
    pub(crate) const SESSION_ID_MAX_BYTES: usize = 64;
    pub(crate) const PCM_SESSION_ID_BYTES: usize = 32;
    pub(crate) const CAMERA_DEVICE_ID_MAX_BYTES: usize = 512;
    pub(crate) const AUDIO_DEVICE_ID_MAX_BYTES: usize = 1024;
}
