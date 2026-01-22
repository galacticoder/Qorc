/**
 * Tauri API Bindings
 * Pure Tauri TypeScript bindings for all commands
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, emit } from '@tauri-apps/api/event';

// ============================================
// Type Definitions
// ============================================

export interface ScreenSource {
    id: string;
    name: string;
    thumbnail: string | null;
    source_type: string;
    app_icon: string | null;
    display_size: [number, number] | null;
}

export interface TorInstallStatus {
    is_installed: boolean;
    version: string | null;
    path: string | null;
}

export interface TorStatus {
    is_running: boolean;
    process_id: number | null;
    socks_port: number;
    control_port: number;
    bootstrapped: boolean;
    bootstrap_progress: number;
}

export interface TorInfo {
    version: string;
    socks_port: number;
    control_port: number;
    bootstrapped: boolean;
    bootstrap_progress: number;
}

export interface IdentityBundle {
    registration_id: number;
    identity_key_public: string;
    identity_key_fingerprint: string;
}

export interface PreKeyInfo {
    keyId: number;
    publicKeyBase64: string;
}

export interface SignedPreKeyInfo {
    keyId: number;
    publicKeyBase64: string;
    signatureBase64: string;
}

export interface KyberPreKeyInfo {
    keyId: number;
    publicKeyBase64: string;
    signatureBase64: string;
}

export interface PQKyberPreKey {
    keyId: number;
    publicKeyBase64: string;
}

export interface PreKeyBundle {
    registrationId: number;
    deviceId: number;
    identityKeyBase64: string;
    preKey: PreKeyInfo | null;
    signedPreKey: SignedPreKeyInfo;
    kyberPreKey: KyberPreKeyInfo | null;
    pqKyber: PQKyberPreKey | null;
}

export interface EncryptedMessage {
    signal_message: string;
    message_type: number;
    kem_ciphertext: string;
    salt: string;
    nonce: string;
    ciphertext: string;
    tag: string;
    aad: string;
    sender: string;
    recipient: string;
    their_kem_fingerprint: string;
}

export interface DecryptResult {
    success: boolean;
    plaintext: string | null;
    error: string | null;
    requires_key_refresh: boolean | null;
}

export interface DeviceCredentials {
    device_id: string;
    public_key_pem: string;
    fingerprint: string;
}

export interface LinkPreview {
    url: string;
    title: string | null;
    description: string | null;
    image: string | null;
    site_name: string | null;
    favicon: string | null;
}

export interface PlatformInfo {
    platform: string;
    arch: string;
    version: string;
    hostname: string;
}

// ============================================
// Secure Storage
// ============================================

export const storage = {
    init: () => invoke<boolean>('secure_init'),
    get: (key: string) => invoke<string | null>('secure_get', { key }),
    set: (key: string, value: string) => invoke<boolean>('secure_set', { key, value }),
    remove: (key: string) => invoke<boolean>('secure_remove', { key }),
    has: (key: string) => invoke<boolean>('secure_has', { key }),
    keys: () => invoke<string[]>('secure_keys'),
    clear: () => invoke<boolean>('secure_clear'),
};

// ============================================
// Tor Management
// ============================================

export const tor = {
    checkInstallation: () => invoke<TorInstallStatus>('tor_check_installation'),
    download: () => invoke<{ success: boolean; already_exists?: boolean; error?: string }>('tor_download'),
    install: () => invoke<{ success: boolean; already_exists?: boolean; error?: string }>('tor_install'),
    configure: (config: string) => invoke<boolean>('tor_configure', { config: { config } }),
    start: () => invoke<{ success: boolean; starting?: boolean; error?: string }>('tor_start'),
    stop: () => invoke<boolean>('tor_stop'),
    status: () => invoke<TorStatus>('tor_status'),
    info: () => invoke<TorInfo>('tor_info'),
    initialize: () => invoke<boolean>('tor_initialize'),
    verifyConnection: () => invoke<{ success: boolean; ip_address?: string; error?: string }>('tor_verify_connection'),
    testConnection: () => invoke<{ success: boolean; ip_address?: string; error?: string }>('tor_test_connection'),
    rotateCircuit: () => invoke<{ success: boolean; ip_changed?: boolean; before_ip?: string; after_ip?: string }>('tor_rotate_circuit'),
    uninstall: () => invoke<boolean>('tor_uninstall'),
};

// ============================================
// Signal Protocol
// ============================================

export const signal = {
    // Identity
    generateIdentity: (username: string) => invoke<IdentityBundle>('signal_generate_identity', { username }),
    generatePreKeys: (username: string, startId: number, count: number) =>
        invoke<PreKeyInfo[]>('signal_generate_prekeys', { username, startId, count }),
    generateSignedPreKey: (username: string, keyId: number) =>
        invoke<SignedPreKeyInfo>('signal_generate_signed_prekey', { username, keyId }),
    generateKyberPreKey: (username: string, keyId: number) =>
        invoke<KyberPreKeyInfo>('signal_generate_kyber_prekey', { username, keyId }),
    generatePQKyberPreKey: (username: string, keyId: number) =>
        invoke<PQKyberPreKey>('signal_generate_pq_kyber_prekey', { username, keyId }),

    // Sessions
    createPreKeyBundle: (username: string) => invoke<PreKeyBundle>('signal_create_prekey_bundle', { username }),
    processPreKeyBundle: (selfUsername: string, peerUsername: string, bundle: PreKeyBundle) =>
        invoke<boolean>('signal_process_prekey_bundle', { selfUsername, peerUsername, bundle }),
    hasSession: (selfUsername: string, peerUsername: string, deviceId?: number) =>
        invoke<boolean>('signal_has_session', { selfUsername, peerUsername, deviceId }),
    deleteSession: (selfUsername: string, peerUsername: string, deviceId?: number) =>
        invoke<boolean>('signal_delete_session', { selfUsername, peerUsername, deviceId }),
    deleteAllSessions: (selfUsername: string, peerUsername: string) =>
        invoke<boolean>('signal_delete_all_sessions', { selfUsername, peerUsername }),

    // Encryption
    encrypt: (fromUsername: string, toUsername: string, plaintext: string) =>
        invoke<EncryptedMessage>('signal_encrypt', { fromUsername, toUsername, plaintext }),
    decrypt: (fromUsername: string, toUsername: string, encrypted: EncryptedMessage) =>
        invoke<DecryptResult>('signal_decrypt', { fromUsername, toUsername, encrypted }),

    // Keys
    setPeerKyberKey: (peerUsername: string, publicKey: string) =>
        invoke<boolean>('signal_set_peer_kyber_key', { peerUsername, publicKey }),
    hasPeerKyberKey: (peerUsername: string) => invoke<boolean>('signal_has_peer_kyber_key', { peerUsername }),
    trustPeerIdentity: (selfUsername: string, peerUsername: string, deviceId?: number) =>
        invoke<boolean>('signal_trust_peer_identity', { selfUsername, peerUsername, deviceId }),
    setStaticMlkemKeys: (username: string, publicKey: string, secretKey: string) =>
        invoke<boolean>('signal_set_static_mlkem_keys', { username, publicKey, secretKey }),
    initStorage: (username: string) => invoke<boolean>('signal_init_storage', { username }),
    setStorageKey: (key: string) => invoke<boolean>('signal_set_storage_key', { key }),
};

// ============================================
// WebSocket
// ============================================

export const websocket = {
    connect: () => invoke<{ success: boolean; already_connected?: boolean; new_connection?: boolean; error?: string }>('ws_connect'),
    disconnect: () => invoke<boolean>('ws_disconnect'),
    send: (payload: unknown) => invoke<{ success: boolean; queued?: boolean; error?: string }>('ws_send', { payload }),
    probeConnect: (url: string, timeoutMs?: number) => invoke<{ success: boolean; error?: string }>('ws_probe_connect', { url, timeoutMs }),
    setServerUrl: (url: string) => invoke<boolean>('ws_set_server_url', { url }),
    getServerUrl: () => invoke<string | null>('ws_get_server_url'),
    getState: () => invoke<{ connected: boolean; connecting: boolean; reconnect_attempts: number; queue_size: number; connection_duration_ms: number }>('ws_get_state'),
    setBackgroundMode: (enabled: boolean) => invoke<boolean>('ws_set_background_mode', { enabled }),
    setTorReady: (ready: boolean, socksPort?: number) => invoke<boolean>('ws_set_tor_ready', { ready, socksPort }),
};

// ============================================
// P2P Signaling
// ============================================

export const p2p = {
    connect: (connectionId: string, serverUrl: string, options?: { username?: string; registrationPayload?: unknown }) =>
        invoke<{ success: boolean; already_connected?: boolean; error?: string }>('p2p_signaling_connect', { connectionId, serverUrl, options }),
    disconnect: (connectionId: string) => invoke<boolean>('p2p_signaling_disconnect', { connectionId }),
    send: (connectionId: string, message: unknown) => invoke<{ success: boolean; error?: string }>('p2p_signaling_send', { connectionId, message }),
    getStatus: () => invoke<{ activeConnections: number; connectionIds: string[]; torReady: boolean; backgroundMode: boolean }>('p2p_signaling_status'),
    setBackgroundMode: (enabled: boolean) => invoke<boolean>('p2p_set_background_mode', { enabled }),
    setTorReady: (ready: boolean, socksPort?: number) => invoke<boolean>('p2p_set_tor_ready', { ready, socksPort }),
};

// ============================================
// Notifications
// ============================================

export const notifications = {
    show: (title: string, body?: string, icon?: string) => invoke<boolean>('notification_show', { title, body, icon }),
    setEnabled: (enabled: boolean) => invoke<boolean>('notification_set_enabled', { enabled }),
    isEnabled: () => invoke<boolean>('notification_is_enabled'),
    setBadge: (count: number) => invoke<boolean>('notification_set_badge', { count }),
    clearBadge: () => invoke<boolean>('notification_clear_badge'),
    getBadge: () => invoke<number>('notification_get_badge'),
};

// ============================================
// File Operations
// ============================================

export const file = {
    save: (filename: string, data: string, mimeType?: string) =>
        invoke<{ success: boolean; path?: string; error?: string }>('file_save', { filename, data, mimeType }),
    getDownloadSettings: () => invoke<{ download_path: string | null; ask_where_to_save: boolean }>('file_get_download_settings'),
    setDownloadPath: (path: string) => invoke<boolean>('file_set_download_path', { path }),
    chooseDownloadPath: () => invoke<string | null>('file_choose_download_path'),
    readBase64: (path: string) => invoke<string>('file_read_base64', { path }),
    getInfo: (path: string) => invoke<{ exists: boolean; is_file: boolean; is_directory: boolean; size: number; name: string }>('file_get_info', { path }),
};

// ============================================
// System
// ============================================

export const system = {
    getPlatformInfo: () => invoke<PlatformInfo>('get_platform_info'),
    getPlatform: () => invoke<string>('get_platform'),
    getArch: () => invoke<string>('get_arch'),
    openExternal: (url: string) => invoke<boolean>('open_external', { url }),
    getScreenSources: (options?: { types?: string[]; thumbnailSize?: { width: number; height: number } }) =>
        invoke<ScreenSource[]>('get_screen_sources', { options }),
    getUserDataPath: () => invoke<string>('get_user_data_path'),
    getAppVersion: () => invoke<string>('get_app_version'),
    getAppName: () => invoke<string>('get_app_name'),
    getServerUrl: () => invoke<string | null>('get_server_url'),
};

// ============================================
// Power Save Blocker
// ============================================

export const power = {
    start: (blockerType?: string) => invoke<number>('power_save_blocker_start', { blockerType }),
    stop: (id: number) => invoke<boolean>('power_save_blocker_stop', { id }),
    isStarted: (id: number) => invoke<boolean>('power_save_blocker_is_started', { id }),
};

// ============================================
// Session Management
// ============================================

export const session = {
    getBackgroundState: () => invoke<{ active: boolean; last_activity: number | null; pending_messages: number }>('session_get_background_state'),
    setBackgroundState: (active: boolean) => invoke<boolean>('session_set_background_state', { active }),
    storePQKeys: (keys: { session_id: string; aes_key: string; mac_key: string; created_at: number }) =>
        invoke<boolean>('session_store_pq_keys', { keys }),
    getPQKeys: (sessionId: string) =>
        invoke<{ session_id: string; aes_key: string; mac_key: string; created_at: number } | null>('session_get_pq_keys', { sessionId }),
    deletePQKeys: (sessionId: string) => invoke<boolean>('session_delete_pq_keys', { sessionId }),
    updatePendingCount: (count: number) => invoke<boolean>('session_update_pending_count', { count }),
};

// ============================================
// Auth & Device Credentials
// ============================================

export const auth = {
    refreshTokens: (refreshToken: string) =>
        invoke<{ success: boolean; access_token?: string; refresh_token?: string; expires_in?: number; error?: string }>('auth_refresh_tokens', { refreshToken }),
    getDeviceCredentials: () => invoke<DeviceCredentials>('device_get_credentials'),
    signChallenge: (challenge: string) => invoke<{ signature: string; device_id: string }>('device_sign_challenge', { challenge }),
};

// ============================================
// Link Preview
// ============================================

export const link = {
    fetchPreview: (url: string) => invoke<LinkPreview>('link_fetch_preview', { url }),
};

// ============================================
// Database
// ============================================

export const database = {
    init: (username: string, masterKeyB64: string) => invoke<boolean>('db_init', { username, masterKeyB64 }),
    setSecure: (store: string, key: string, value: Uint8Array) => invoke<boolean>('db_set_secure', { store, key, value: Array.from(value) }),
    getSecure: (store: string, key: string) => invoke<number[] | null>('db_get_secure', { store, key }).then(v => v ? new Uint8Array(v) : null),
    listSecure: (store: string) => invoke<[string, number[]][]>('db_list_secure', { store }).then(v => v.map(([k, bytes]) => [k, new Uint8Array(bytes)] as [string, Uint8Array])),
    scanSecure: (prefix: string) => invoke<[string, string, number[]][]>('db_scan_secure', { prefix }).then(v => v.map(([s, k, bytes]) => [s, k, new Uint8Array(bytes)] as [string, string, Uint8Array])),
    delete: (store: string, key: string) => invoke<boolean>('db_delete', { store, key }),
    clearStore: (store: string) => invoke<boolean>('db_clear_store', { store }),
};

// ============================================
// System Tray
// ============================================

export const tray = {
    /** Get close-to-tray setting (default: true) */
    getCloseToTray: () => invoke<boolean>('get_close_to_tray'),
    /** Set close-to-tray setting */
    setCloseToTray: (enabled: boolean) => invoke<boolean>('set_close_to_tray', { enabled }),
    /** Set tray badge unread count */
    setUnreadCount: (count: number) => invoke<void>('tray_set_unread_count', { count }),
    /** Increment tray badge unread count */
    incrementUnread: () => invoke<void>('tray_increment_unread'),
    /** Clear tray badge unread count */
    clearUnread: () => invoke<void>('tray_clear_unread'),
};

// ============================================
// Events
// ============================================

export const events = {
    listen,
    emit,
    onTorStatus: (callback: (data: unknown) => void) => listen('tor-status', (e) => callback(e.payload)),
    onWsMessage: (callback: (data: unknown) => void) => listen('ws-message', (e) => callback(e.payload)),
    onP2PMessage: (callback: (data: unknown) => void) => listen('p2p-message', (e) => callback(e.payload)),
};

// ============================================
// Utility
// ============================================

export function isTauri(): boolean {
    return (
        '__TAURI__' in window ||
        '__TAURI_INTERNALS__' in window ||
        '__TAURI_IPC__' in window
    );
}
