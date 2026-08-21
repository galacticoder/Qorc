/**
 * Tauri API Bindings
 * Tauri TypeScript bindings for all commands
 */

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Base64 } from './cryptography/base64';
import { PROTOCOL_KEYS } from './config/protocol-keys';
import type { AudioLaneTelemetry } from './transport/secure-transport';

function serializeJsonForNative(value: unknown): string {
    const encoded = JSON.stringify(value);
    if (typeof encoded !== 'string') throw new Error('Value is not JSON serializable');
    return encoded;
}

export interface NativeScreenSource {
    id: string;
    name: string;
    source_type: string;
}

export interface NativeCameraDevice {
    device_id: string;
    label: string;
}

export interface NativeCameraFrame {
    sequence: number;
    capturedAt: number;
    width: number;
    height: number;
    enabled: boolean;
    jpeg: Uint8Array;
}

const parseNativeCameraFrame = (value: ArrayBuffer): NativeCameraFrame | null => {
    const bytes = new Uint8Array(value);
    if (bytes.byteLength === 32 && bytes.every(byte => byte === 0)) return null;
    if (bytes.byteLength <= 32 || bytes.byteLength > 4 * 1024 * 1024 + 32) {
        throw new Error('Invalid native camera frame length');
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const sequence = Number(view.getBigUint64(4, false));
    const capturedAt = Number(view.getBigUint64(12, false));
    const width = view.getUint16(20, false);
    const height = view.getUint16(22, false);
    const payloadLength = view.getUint32(24, false);
    const jpeg = bytes.subarray(32);
    if (
        view.getUint8(0) !== 1 || view.getUint8(1) !== 1 || view.getUint8(2) > 1 ||
        view.getUint8(3) !== 0 || view.getUint32(28, false) !== 0 ||
        !Number.isSafeInteger(sequence) || sequence <= 0 ||
        !Number.isSafeInteger(capturedAt) || capturedAt <= 0 ||
        width < 2 || height < 2 || width > 1280 || height > 720 ||
        width * height > 1280 * 720 || payloadLength !== jpeg.byteLength ||
        jpeg.byteLength < 4 || jpeg[0] !== 0xff || jpeg[1] !== 0xd8 ||
        jpeg[jpeg.byteLength - 2] !== 0xff || jpeg[jpeg.byteLength - 1] !== 0xd9
    ) {
        throw new Error('Invalid native camera frame');
    }
    return {
        sequence,
        capturedAt,
        width,
        height,
        enabled: view.getUint8(2) === 1,
        jpeg,
    };
};

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

export interface SignedPreKeyInfo {
    keyId: number;
    publicKeyBase64: string;
    signatureBase64: string;
}

export interface MlKemPreKeyInfo {
    keyId: number;
    publicKeyBase64: string;
    signatureBase64: string;
}

export interface StaticMlKemKey {
    publicKeyBase64: string;
    signatureBase64: string;
}

export interface PreKeyBundle {
    registrationId: number;
    deviceId: number;
    identityKeyBase64: string;
    signedPreKey: SignedPreKeyInfo;
    mlKemPreKey: MlKemPreKeyInfo;
    staticMlKem: StaticMlKemKey;
}

export interface PQEnvelopeAlgorithms {
    kem: string;
    kdf: string;
    aead: string;
}

export interface PQEnvelope {
    version: string;
    algorithms: PQEnvelopeAlgorithms;
    kemCiphertext: string;
    nonce: string;
    ciphertext: string;
    salt: string;
}

export interface EncryptedMessage {
    messageType: number;
    pqEnvelope: PQEnvelope;
}

export interface DecryptResult {
    success: boolean;
    plaintext: string | null;
    content_ref: string | null;
    error: string | null;
    requires_key_refresh: boolean | null;
    pending_id: string | null;
}

export interface PendingDecryptedMessage {
    pendingId: string;
    fromUsername: string;
    senderIdentityKey: string;
    identityRootFingerprint: string;
    identityBundleFingerprint: string;
    transportMessageId: string;
    applicationType: string;
    plaintext: string;
    contentRef: string | null;
}

export interface NativeMessageContentCommitResult {
    stored: boolean;
    duplicate: boolean;
}

export interface NativeRenderedMessageContent {
    pngBase64: string;
    width: number;
    height: number;
}

export interface AuthPowBatchResult {
    solution: string | null;
    nextNonce: string;
    iterations: number;
}

export interface NativeAccountPublicKeys {
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
    x25519PublicBase64: string;
    accountRootPublicBase64: string;
    recoveryPublicBase64: string;
}

export interface NativeAccountOpenResult {
    created: boolean;
    publicKeys: NativeAccountPublicKeys;
}

export interface NativeHybridPlaintext {
    routing: {
        to: string;
        from: string;
        type: string;
        timestamp: number;
        size: number;
    };
    payloadType: 'text' | 'json' | 'binary';
    payloadBase64: string;
}

export const account = {
    open: (
        accountOwner: string,
        username: string,
        password: string,
        passphrase: string,
    ) => invoke<NativeAccountOpenResult>('account_open', {
        accountOwner,
        username,
        password,
        passphrase,
    }),
    publicKeys: () => invoke<NativeAccountPublicKeys>('account_public_keys'),
    isUnlocked: (accountOwner: string) =>
        invoke<boolean>('account_is_unlocked', { accountOwner }),
    sign: (purpose: string, message: Uint8Array) =>
        invoke<string>('account_sign', {
            purpose,
            messageBase64: Base64.arrayBufferToBase64(message),
        }),
    p2pHandshakeSecrets: (
        kemCiphertext: Uint8Array,
        peerX25519Public: Uint8Array,
    ) => invoke<{ pqSecretBase64: string; x25519SecretBase64: string }>(
        'account_p2p_handshake_secrets',
        {
            kemCiphertextBase64: Base64.arrayBufferToBase64(kemCiphertext),
            peerX25519PublicBase64: Base64.arrayBufferToBase64(peerX25519Public),
        },
    ),
    discoveryPublication: (
        serverScope: string,
        publicationWindow: number,
        purpose: 'id' | 'padding',
        counter = 0,
    ) => invoke<string>('account_discovery_publication', {
        serverScope,
        publicationWindow,
        purpose,
        counter,
    }),
    decryptHybrid: (envelope: unknown, expectedSenderPublic: string) =>
        invoke<NativeHybridPlaintext>('account_decrypt_hybrid', {
            envelopeJson: serializeJsonForNative(envelope),
            expectedSenderPublic,
        }),
    openSealedEnvelope: (envelope: unknown) =>
        invoke<{ from: string; payload: unknown } | null>('account_open_sealed_envelope', {
            envelopeJson: serializeJsonForNative(envelope),
        }),
    tokenVaultLoad: (serverScope: string, vaultKind: 'working' | 'resume') =>
        invoke<string | null>('account_token_vault_load', { serverScope, vaultKind }),
    tokenVaultStore: (
        serverScope: string,
        vaultKind: 'working' | 'resume',
        plaintextJson: string,
    ) => invoke<boolean>('account_token_vault_store', { serverScope, vaultKind, plaintextJson }),
    tokenVaultRemove: (serverScope: string, vaultKind: 'working' | 'resume') =>
        invoke<boolean>('account_token_vault_remove', { serverScope, vaultKind }),
    lock: (accountOwner: string) =>
        invoke<boolean>('account_lock', { accountOwner }),
};

export const storage = {
    get: (key: string) => invoke<string | null>('secure_get', { key }),
    set: (key: string, value: string) => invoke<boolean>('secure_set', { key, value }),
    remove: (key: string) => invoke<boolean>('secure_remove', { key }),
    has: (key: string) => invoke<boolean>('secure_has', { key }),
};

export const authPow = {
    solveBatch: (
        seedBase64: string,
        difficulty: number,
        startNonceBase64: string,
        maxIterations: number
    ) => invoke<AuthPowBatchResult>('auth_pow_solve_batch', {
        seedBase64,
        difficulty,
        startNonceBase64,
        maxIterations
    })
};

export const tor = {
    configure: (config: string) => invoke<boolean>('tor_configure', { config: { config } }),
    start: () => invoke<{ success: boolean; starting?: boolean; error?: string }>('tor_start'),
    stop: () => invoke<boolean>('tor_stop'),
    status: () => invoke<TorStatus>('tor_status'),
    info: () => invoke<TorInfo>('tor_info'),
    verifyConnection: () => invoke<{ success: boolean; ip_address?: string; error?: string }>('tor_verify_connection'),
    rotateCircuit: () => invoke<{ success: boolean; ip_changed?: boolean; before_ip?: string; after_ip?: string }>('tor_rotate_circuit'),
};

export const signal = {
    // Sessions
    createPreKeyBundle: (username: string) => invoke<PreKeyBundle>('signal_create_prekey_bundle', { username }),
    processVerifiedPreKeyBundle: async (selfUsername: string, peerUsername: string, bundle: PreKeyBundle) => {
        await invoke<boolean>('signal_install_transparency_verified_peer_identity', {
            selfUsername,
            peerUsername,
            newIdentityKey: bundle.identityKeyBase64,
        });
        return invoke<boolean>('signal_process_prekey_bundle', {
            selfUsername,
            peerUsername,
            bundleJson: serializeJsonForNative(bundle),
        });
    },
    hasSession: (selfUsername: string, peerUsername: string) =>
        invoke<boolean>('signal_has_session', { selfUsername, peerUsername }),
    hasPeerStaticMlkemKey: (selfUsername: string, peerUsername: string) =>
        invoke<boolean>('signal_has_peer_static_mlkem_key', { selfUsername, peerUsername }),
    deleteAllSessions: (selfUsername: string, peerUsername: string) =>
        invoke<boolean>('signal_delete_all_sessions', { selfUsername, peerUsername }),

    // Encryption
    encrypt: (fromUsername: string, toUsername: string, plaintext: string) =>
        invoke<EncryptedMessage>('signal_encrypt', { fromUsername, toUsername, plaintext }),
    encryptContentRef: (
        fromUsername: string,
        toUsername: string,
        plaintextTemplate: string,
        contentRef: string,
    ) => invoke<EncryptedMessage>('signal_encrypt_content_ref', {
        fromUsername,
        toUsername,
        plaintextTemplate,
        contentRef,
    }),
    decrypt: (
        fromUsername: string,
        toUsername: string,
        encrypted: EncryptedMessage,
        transportMessageId: string,
        applicationType: string,
        identityRootFingerprint: string,
        identityBundleFingerprint: string,
    ) =>
        invoke<DecryptResult>('signal_decrypt', {
            fromUsername,
            toUsername,
            encryptedJson: serializeJsonForNative(encrypted),
            transportMessageId,
            applicationType,
            identityRootFingerprint,
            identityBundleFingerprint,
        }),
    listPendingDecrypts: (username: string) =>
        invoke<PendingDecryptedMessage[]>('signal_list_pending_decrypts', { username }),
    ackPendingDecrypts: (username: string, pendingIds: string[]) =>
        invoke<boolean>('signal_ack_pending_decrypts', {
            username,
            pendingIdsJson: serializeJsonForNative(pendingIds),
        }),

    // Keys
    installTransparencyVerifiedPeerIdentity: (selfUsername: string, peerUsername: string, newIdentityKey: string) =>
        invoke<boolean>('signal_install_transparency_verified_peer_identity', { selfUsername, peerUsername, newIdentityKey }),
    revokeTransparencyPeerIdentity: (selfUsername: string, peerUsername: string) =>
        invoke<boolean>('signal_revoke_transparency_peer_identity', { selfUsername, peerUsername }),
    peekPreKeyIdentity: (fromUsername: string, toUsername: string, encrypted: EncryptedMessage) =>
        invoke<string | null>('signal_peek_prekey_identity', {
            fromUsername,
            toUsername,
            encryptedJson: serializeJsonForNative(encrypted),
        }),
    initStorage: (username: string) => invoke<boolean>('signal_init_storage', { username }),
};

export const nativeMessageContent = {
    storeOutgoing: (
        storageId: string,
        content: string,
        recipient: string,
        applicationType: 'message' | 'edit-message',
        wireMessageId: string,
        overwrite = false,
    ) =>
        invoke<NativeMessageContentCommitResult>('message_content_store_outgoing', {
            storageId,
            content,
            recipient,
            applicationType,
            wireMessageId,
            overwrite,
        }),
    commitPending: (
        username: string,
        pendingId: string,
        expectedWireMessageId: string,
        storageId: string,
        overwrite = false,
    ) => invoke<NativeMessageContentCommitResult>('message_content_commit_pending', {
        username,
        pendingId,
        expectedWireMessageId,
        storageId,
        overwrite,
    }),
    has: (storageId: string) => invoke<boolean>('message_content_has', { storageId }),
    render: (storageId: string, maxWidth: number, fontSize: number, color: string) =>
        invoke<NativeRenderedMessageContent>('message_content_render', {
            storageId,
            maxWidth,
            fontSize,
            color,
        }),
    cloneForDisplay: (sourceId: string, targetId: string, overwrite = false) =>
        invoke<NativeMessageContentCommitResult>('message_content_clone_for_display', {
            sourceId,
            targetId,
            overwrite,
        }),
    copy: (storageId: string) => invoke<boolean>('message_content_copy', { storageId }),
    revokeSend: (storageId: string) => invoke<boolean>('message_content_revoke_send', { storageId }),
    delete: (storageId: string) => invoke<boolean>('message_content_delete', { storageId }),
};

export const websocket = {
    connect: () => invoke<{ success: boolean; already_connected?: boolean; new_connection?: boolean; connectionToken?: number; error?: string }>('ws_connect'),
    disconnect: (connectionToken?: number) => invoke<boolean>('ws_disconnect', { connectionToken }),
    rotateSocksIdentity: () => invoke<void>('ws_rotate_socks_identity'),
    send: (payloadJson: string, connectionToken: number) =>
        invoke<{ success: boolean; queued?: boolean; error?: string }>('ws_send', { payloadJson, connectionToken }),
    setServerUrl: (url: string) => invoke<void>('ws_set_server_url', { url }),
    getServerUrl: () => invoke<string | null>('ws_get_server_url'),
    getState: () => invoke<{ connected: boolean; connecting: boolean; queue_size: number; connectionToken?: number }>('ws_get_state'),
    syncTorState: () => invoke<boolean>('ws_sync_tor_state'),
};

export interface NativePirQuery {
    sessionId: number;
    query: string;
    pubParams: string;
}

export const pir = {
    generateQuery: (count: number, entryBytes: number, targetRow: number) =>
        invoke<NativePirQuery>('pir_generate_query', { count, entryBytes, targetRow }),
    decodeResponse: (response: string, sessionId: number) =>
        invoke<string>('pir_decode_response', { response, sessionId }),
    generateBatchQuery: (count: number, entryBytes: number, targetRows: number[]) =>
        invoke<NativePirQuery>('pir_generate_batch_query', { count, entryBytes, targetRows }),
    decodeBatchResponse: (response: string, sessionId: number) =>
        invoke<string>('pir_decode_batch_response', { response, sessionId }),
    discardQuery: (sessionId: number) =>
        invoke<void>('pir_discard_query', { sessionId }),
};

export const audioCodec = {
    start: (sessionId: string) => invoke<boolean>('audio_opus_start', { sessionId }),
    stop: (sessionId: string) => invoke<boolean>('audio_opus_stop', { sessionId }),
    encode: (sessionId: string, pcm: Uint8Array) =>
        invoke<ArrayBuffer>('audio_opus_encode', pcm, {
            headers: { 'x-qor-audio-session': sessionId },
        }).then(value => new Uint8Array(value)),
    decode: (sessionId: string, packet: Uint8Array, fec = false) =>
        invoke<ArrayBuffer>('audio_opus_decode', packet, {
            headers: {
                'x-qor-audio-session': sessionId,
                'x-qor-opus-fec': fec ? '1' : '0',
            },
        }).then(value => new Uint8Array(value)),
};

export const nativeCamera = {
    devices: () => invoke<NativeCameraDevice[]>('camera_devices'),
    start: (
        sessionId: string,
        deviceId: string | null,
        width: number,
        height: number,
        frameRate: number,
    ) => invoke<boolean>('camera_capture_start', { sessionId, deviceId, width, height, frameRate }),
    setEnabled: (sessionId: string, enabled: boolean) =>
        invoke<boolean>('camera_capture_set_enabled', { sessionId, enabled }),
    pull: (sessionId: string, afterSequence: number) =>
        invoke<ArrayBuffer>('camera_capture_pull', { sessionId, afterSequence })
            .then(parseNativeCameraFrame),
    stop: (sessionId: string) => invoke<boolean>('camera_capture_stop', { sessionId }),
};

export const p2p = {
    connect: (connectionId: string, endpointUrl: string) =>
        invoke<{ success: boolean; already_connected?: boolean; connectionToken?: number; error?: string }>('p2p_connect', { connectionId, endpointUrl }),
    disconnect: (connectionId: string, connectionToken?: number) =>
        invoke<boolean>('p2p_disconnect', { connectionId, connectionToken }),
    rotateIdentity: () => invoke<string>('p2p_rotate_identity'),
    send: (
        connectionId: string,
        connectionToken: number,
        message: unknown,
        options?: {
            deadline?: number;
            priority?: 'normal' | 'realtime' | 'visual';
            audioEndpoint?: string;
            audioLaneRttCeiling?: number;
        }
    ) => {
        const body = message instanceof Uint8Array
            ? message
            : new TextEncoder().encode(serializeJsonForNative(message));
        return invoke<{ success: boolean; error?: string; audioLanes?: AudioLaneTelemetry }>('p2p_send', body, {
            headers: {
                'x-qor-p2p-connection': connectionId,
                'x-qor-p2p-token': String(connectionToken),
                'x-qor-p2p-deadline': String(options?.deadline ?? 0),
                'x-qor-p2p-audio-endpoint': options?.audioEndpoint ?? '',
                'x-qor-p2p-audio-rtt-ceiling': String(options?.audioLaneRttCeiling ?? 0),
            },
        });
    },
    authenticateConnection: (connectionId: string, connectionToken: number) =>
        invoke<boolean>('p2p_authenticate_connection', { connectionId, connectionToken }),
    getLocalEndpoint: () => invoke<string | null>('p2p_local_endpoint'),
};

export const anonymousHttp = {
    fetch: (body: Uint8Array, expectedServerUrl: string, lane: 'primary' | 'pir' = 'primary') =>
        invoke<ArrayBuffer>('anonymous_api_fetch', body, {
            headers: {
                [PROTOCOL_KEYS.EXPECTED_SERVER_HEADER]: expectedServerUrl,
                'x-qor-anonymous-transport-lane': lane,
            },
        }),
    prewarm: () => invoke<boolean>('prewarm_anonymous_transport'),
};

export const notifications = {
    show: () => invoke<boolean>('notification_show'),
    setEnabled: (enabled: boolean) => invoke<boolean>('notification_set_enabled', { enabled }),
};

export const system = {
    getInstanceId: () => invoke<string>('get_instance_id'),
    openExternal: (url: string) => invoke<boolean>('open_external', { url }),
    requestMediaAccess: (kind: 'audio' | 'video' | 'audio-video' | 'camera' | 'enumerate') =>
        invoke<boolean>('request_media_access', { kind }),
    getScreenSources: () => invoke<NativeScreenSource[]>('get_screen_sources'),
};

export const power = {
    start: () => invoke<boolean>('power_save_blocker_start'),
    stop: () => invoke<boolean>('power_save_blocker_stop'),
};

export const session = {
    getBackgroundState: () => invoke<{ active: boolean }>('session_get_background_state'),
    setBackgroundState: (active: boolean) => invoke<boolean>('session_set_background_state', { active }),
};

export const database = {
    // Compare-and-drop only the expected owners native DB and Signal state
    lock: (accountOwner: string) => invoke<boolean>('db_lock', { accountOwner }),
    setSecure: (store: string, key: string, value: Uint8Array) => invoke<boolean>('db_set_secure', {
        store,
        key,
        valueB64: Base64.arrayBufferToBase64(value),
    }),
    getSecure: (store: string, key: string) =>
        invoke<string | null>('db_get_secure', { store, key })
            .then(value => value ? Base64.base64ToUint8Array(value) : null),
    hasSecure: (store: string, key: string) => invoke<boolean>('db_has_secure', { store, key }),
    listSecureKeys: (store: string) => invoke<string[]>('db_list_secure_keys', { store }),
    scanSecureKeys: (prefix: string) => invoke<[string, string][]>('db_scan_secure_keys', { prefix }),
    mutateSecure: (
        writes: Array<{ store: string; key: string; value: Uint8Array }>,
        deletions: Array<{ store: string; key: string }>,
    ) => invoke<boolean>('db_mutate_secure', {
        mutationJson: serializeJsonForNative({
            writes: writes.map(({ store, key, value }) => ({
                store,
                key,
                valueB64: Base64.arrayBufferToBase64(value),
            })),
            deletions,
        }),
    }),
    delete: (store: string, key: string) => invoke<boolean>('db_delete', { store, key }),
};
export const tray = {
    getCloseToTray: () => invoke<boolean>('get_close_to_tray'),
    setCloseToTray: (enabled: boolean) => invoke<boolean>('set_close_to_tray', { enabled }),
    incrementUnread: () => invoke<void>('tray_increment_unread'),
    clearUnread: () => invoke<void>('tray_clear_unread'),
};

export const events = {
    onWsMessage: (callback: (data: unknown) => void) => listen('ws-message', (e) => callback(e.payload)),
    onWsLifecycle: (callback: (data: unknown) => void) => listen('ws-lifecycle', (e) => callback(e.payload)),
    onP2PMessage: async (callback: (data: unknown) => void) => {
        const subscriptionId = crypto.randomUUID();
        let active = true;
        let consecutiveFailures = 0;
        await invoke<boolean>('p2p_subscribe', { subscriptionId });
        void (async () => {
            while (active) {
                try {
                    const data = await invoke<ArrayBuffer>('p2p_receive', { subscriptionId });
                    consecutiveFailures = 0;
                    if (active && data.byteLength > 0) callback(data);
                } catch {
                    if (!active) return;
                    consecutiveFailures += 1;
                    if (consecutiveFailures >= 3) return;
                    await new Promise(resolve => setTimeout(resolve, 250));
                }
            }
        })();
        return () => {
            active = false;
            void invoke<boolean>('p2p_unsubscribe', { subscriptionId }).catch(() => { });
        };
    },
};

export function isTauri(): boolean {
    if (typeof window === 'undefined') return false;
    return (
        '__TAURI__' in window ||
        '__TAURI_INTERNALS__' in window ||
        '__TAURI_IPC__' in window
    );
}

export async function requireNativeMediaAccess(
    kind: 'audio' | 'video' | 'audio-video' | 'camera'
): Promise<void> {
    if (!isTauri()) return;
    const granted = await system.requestMediaAccess(kind);
    if (!granted) {
        throw new DOMException('Native media access was denied', 'NotAllowedError');
    }
}
