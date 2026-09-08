pub const BACKGROUND_SESSION_ACTIVE: &str = "bg_session_active";
pub const DISCOVERY_MATERIAL_PREFIX: &str = "discmat:";
pub const EXPLICIT_LOGOUT: &str = "qorc_explicit_logout";
pub const KEY_TRANSPARENCY_AUTHORIZATION_PREFIX: &str = "kt-authorizations:";
pub const KEY_TRANSPARENCY_CONTACT_PREFIX: &str = "kt-contact:";
pub const KEY_TRANSPARENCY_HEAD_PREFIX: &str = "kt-head:";
pub const KEY_TRANSPARENCY_INCIDENT_PREFIX: &str = "kt-incident:";
pub const KEY_TRANSPARENCY_MONITOR_PREFIX: &str = "kt-monitors:";
pub const KEY_TRANSPARENCY_RECORD_PREFIX: &str = "kt-records:";
pub const KEY_TRANSPARENCY_WARNING_PREFIX: &str = "kt-warnings:";
pub const LAST_AUTH_DISPLAY_PREFIX: &str = "last-auth-display:";
pub const LAST_AUTH_USER_PREFIX: &str = "last-auth-user:";
pub const NATIVE_ACCOUNT_VAULT_PREFIX: &str = "native-account-vault:";
pub const NATIVE_DATABASE_SALT_DISK: &[u8] = b"native_db_salt_disk";
pub const NATIVE_DATABASE_SALT_SYMMETRIC: &[u8] = b"native_db_salt_sym";
pub const NATIVE_DATABASE_SALT_QUANTUM: &[u8] = b"native_db_salt_quant";
pub const NATIVE_MESSAGE_CONTENT_STORE_SUFFIX: &str = "native-message-content";
pub const NATIVE_TOKEN_VAULT_PREFIX: &str = "native-token-vault:";
pub const PEER_CERTIFICATE_PREFIX: &str = "peercert:";
pub const PRIVACY_PASS_TOKEN_PREFIX: &str = "pp_tokens_";
pub const PRIVATE_AUTH_SLOT_PREFIX: &str = "private_auth_slot_";
pub const REGISTRATION_ATTEMPT_PREFIX: &str = "registration_attempt_";
pub const SERVER_PQ_PIN: &str = "server_pq_pin";
pub const SIGNAL_SESSION_STORE: &str = "signal_session_store";
pub const SIGNAL_IDENTITY_STORE: &str = "signal_identity_store";
pub const SIGNAL_PEER_MLKEM_STORE: &str = "signal_peer_mlkem_store";
pub const SIGNAL_PENDING_DECRYPT_STORE: &str = "signal_pending_decrypt_store";
pub const SIGNAL_SIGNED_PREKEY_STORE: &str = "signal_signed_prekey_store";
pub const SIGNAL_MLKEM_PREKEY_STORE: &str = "signal_mlkem_prekey_store";
pub const SIGNAL_MLKEM_REPLAY_STORE: &str = "signal_mlkem_replay_store";
pub const SIGNAL_STATIC_MLKEM_STORE: &str = "signal_static_mlkem_store";
pub const SPOOL_CONSUMED_PROBES_PREFIX: &str = "spoolconsumed:";
pub const SPOOL_DETECTION_PREFIX: &str = "spooldet:";
pub const SPOOL_PEER_DETECTION_PREFIX: &str = "spoolpeerdet:";
pub const TOR_BRIDGES_ENABLED: &str = "qorc_tor_bridges_enabled";
pub const TOR_BRIDGE_LINES: &str = "qorc_tor_bridge_lines";
pub const TOR_BRIDGE_TRANSPORT: &str = "qorc_tor_bridge_transport";

pub const RENDERER_EXACT_KEYS: &[&str] = &[
    SERVER_PQ_PIN,
    EXPLICIT_LOGOUT,
    BACKGROUND_SESSION_ACTIVE,
    TOR_BRIDGES_ENABLED,
    TOR_BRIDGE_TRANSPORT,
    TOR_BRIDGE_LINES,
];

pub const RENDERER_SCOPED_PREFIXES: &[&str] = &[
    PRIVACY_PASS_TOKEN_PREFIX,
    LAST_AUTH_USER_PREFIX,
    LAST_AUTH_DISPLAY_PREFIX,
    PRIVATE_AUTH_SLOT_PREFIX,
    REGISTRATION_ATTEMPT_PREFIX,
    PEER_CERTIFICATE_PREFIX,
    KEY_TRANSPARENCY_HEAD_PREFIX,
    KEY_TRANSPARENCY_INCIDENT_PREFIX,
    KEY_TRANSPARENCY_CONTACT_PREFIX,
    KEY_TRANSPARENCY_WARNING_PREFIX,
    KEY_TRANSPARENCY_MONITOR_PREFIX,
    KEY_TRANSPARENCY_AUTHORIZATION_PREFIX,
    KEY_TRANSPARENCY_RECORD_PREFIX,
    SPOOL_CONSUMED_PROBES_PREFIX,
    SPOOL_DETECTION_PREFIX,
    SPOOL_PEER_DETECTION_PREFIX,
    DISCOVERY_MATERIAL_PREFIX,
];
