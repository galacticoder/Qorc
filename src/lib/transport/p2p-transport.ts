/**
 * P2P Transport
 */

import { EventType } from '../types/event-types';
import { SignalType } from '../types/signal-types';
import { p2p, events, isTauri } from '../tauri-bindings';
import { UnlistenFn } from '@tauri-apps/api/event';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumSignature } from '../cryptography/signature';
import { tryDecodeCanonicalBase64 } from '../cryptography/base64';
import { PostQuantumUtils } from '../utils/pq-utils';
import { x25519 } from '@noble/curves/ed25519.js';
import { PQNoiseSession, clearP2PNoiseHandshakeReplayCache } from './pq-noise-session';
import { PeerKeys, OwnKeys } from '../types/noise-types';
import type { PeerCertificateBundle } from '../types/p2p-types';
import { parseP2PEndpointUrl } from '../utils/p2p-endpoint';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { computePeerCertificateFingerprint, validatePeerCertificateBundle } from '../utils/peer-certificate-utils';
import {
    isKeyTransparencyAuthorizedPeerCertificate,
    isKeyTransparencyPeerRevoked
} from '../key-transparency/verified-material';
import { blockingSystem } from '../blocking/blocking-system';
import {
    SecureTransport,
    SecureConnection,
    SecureStream,
    ConnectionState,
    ConnectOptions,
    StreamOptions,
    StreamWriteOptions,
    StreamType,
    TransportInitOptions,
    MessageHandler,
    IncomingMessage,
    PeerIdentity,
    AudioLaneTelemetry,
    MAX_MESSAGE_FRAME_SIZE,
    MAX_CALL_FRAME_SIZE,
    NOISE_FRAME_OVERHEAD
} from './secure-transport';
import {
    AUTH_USERNAME_REGEX,
    P2P_CONNECTION_TIMEOUT_MS,
    P2P_KEEPALIVE_INTERVAL_MS,
    P2P_MAX_STREAMS_PER_CONNECTION,
    P2P_STUCK_STATE_TIMEOUT_MS,
    PQ_KEM_CIPHERTEXT_SIZE,
    PQ_KEM_PUBLIC_KEY_SIZE,
    PQ_SIG_PUBLIC_KEY_SIZE,
    PQ_SIG_SIGNATURE_SIZE,
    X25519_PUBLIC_KEY_LENGTH
} from '../constants';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_STREAM_ID_BYTES = 96;
const NATIVE_BRIDGE_RAW_MAX_BYTES = 4 * 1024 * 1024;
const MAX_VISUAL_QUEUE_FRAMES = 6;
const INITIAL_BRIDGE_CONNECT_ATTEMPTS = 2;
const INITIAL_BRIDGE_RETRY_DELAY_MS = 250;
const AUDIO_LANE_MIN_RTT_GAIN_MS = 50;
const AUDIO_LANE_MIN_RTT_GAIN_RATIO = 0.1;
const AUDIO_LANE_PATH_SWITCH_CONFIRMATIONS = 3;
const AUDIO_LANE_HOLD_RTT_CEILING_MS = 60_000;
const STREAM_ID_REGEX = /^(message|call-audio|call-video|call-telemetry|call-screen):[a-f0-9]{16,64}$/;
const ALLOWED_STREAM_TYPES = new Set<string>([
    SignalType.MESSAGE,
    'call-audio',
    'call-video',
    'call-telemetry',
    'call-screen'
]);

const BRIDGE_PEER_ID_REGEX = /^(?:[a-z2-7]{56}\.onion|inbound:(?:0|[1-9][0-9]{0,19}))$/i;
const isNativeConnectionToken = (value: unknown): value is number => (
    Number.isSafeInteger(value) && (value as number) > 0
);

const hasMeaningfulAudioPathAdvantage = (currentRttMs: number, candidateRttMs: number): boolean => (
    currentRttMs - candidateRttMs >= Math.max(
        AUDIO_LANE_MIN_RTT_GAIN_MS,
        currentRttMs * AUDIO_LANE_MIN_RTT_GAIN_RATIO
    )
);

const isRetryableInitialBridgeError = (error: unknown): boolean => {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.trim().toLowerCase();
    return normalized.includes('bridge disconnected') ||
        normalized.includes('connection failed: disconnected') ||
        normalized.includes('p2p inbound adoption failed: disconnected') ||
        normalized.includes('connection closed');
};

interface P2PKeyConfirmation {
    version: typeof PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION;
    type: 'confirm';
    from: string;
    to: string;
    sessionId: string;
    frame: Uint8Array;
}

interface NativeBridgeContext {
    connectionId: string;
    connectionToken: number;
    generation: number;
}

function parseStreamType(streamId: string): StreamType | null {
    if (!STREAM_ID_REGEX.test(streamId)) return null;
    const type = streamId.slice(0, streamId.indexOf(':'));
    return ALLOWED_STREAM_TYPES.has(type) ? type as StreamType : null;
}

function parseNativeP2PBridgeEnvelope(value: unknown): any {
    const bytes = value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : value instanceof Uint8Array
            ? value
            : null;
    if (!bytes || bytes.length < 15) throw new Error('Invalid native P2P bridge envelope');
    if (
        bytes[0] !== 0x51 ||
        bytes[1] !== 0x50 ||
        bytes[2] !== 0x42 ||
        bytes[3] !== 0x31
    ) throw new Error('Invalid native P2P bridge version');
    const kind = bytes[4];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const token = Number(view.getBigUint64(5, false));
    const idLength = view.getUint16(13, false);
    if (!Number.isSafeInteger(token) || token <= 0 || idLength === 0 || 15 + idLength > bytes.length) {
        throw new Error('Invalid native P2P bridge metadata');
    }
    const connectionId = textDecoder.decode(bytes.subarray(15, 15 + idLength));
    const payload = bytes.subarray(15 + idLength);
    if (kind === 1 && payload.length === 0) {
        return { type: '__p2p_connected', connectionId, connectionToken: token };
    }
    if (kind === 2 && payload.length >= 4) {
        const payloadView = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
        const reasonLength = payloadView.getUint16(2, false);
        if (4 + reasonLength !== payload.length) throw new Error('Invalid native P2P close event');
        const reason = reasonLength > 0 ? textDecoder.decode(payload.subarray(4)) : undefined;
        return {
            type: '__p2p_closed',
            connectionId,
            connectionToken: token,
            code: payloadView.getUint16(0, false),
            ...(reason ? { reason } : {}),
        };
    }
    if (kind === 3 && payload.length > 0) {
        let data: unknown;
        if (payload[0] === 0x7b) {
            data = JSON.parse(textDecoder.decode(payload));
        } else {
            data = payload;
        }
        return { type: 'message', connectionId, connectionToken: token, data };
    }
    throw new Error('Invalid native P2P bridge event');
}

class P2PStream implements SecureStream {
    readonly id: string;
    readonly type: StreamType;
    readonly peerId: string;
    readonly lossy: boolean;

    private session: PQNoiseSession;
    private receiveQueue: Uint8Array[] = [];
    private receiveQueueBytes: number = 0;
    private readResolvers: Array<(value: Uint8Array | null) => void> = [];
    private _readable: boolean = true;
    private _writable: boolean = true;
    private _closed: boolean = false;
    private readonly maxReceiveQueueFrames: number;
    private readonly maxReceiveQueueBytes: number;
    private readonly MAX_PENDING_READS = 64;
    private pendingEncryptedFrames: Uint8Array[] = [];
    private pendingEncryptedBytes: number = 0;
    private decryptProcessing: boolean = false;
    private decryptFailureCount: number = 0;
    private lifecycleGeneration: number = 0;
    private readonly maxPendingEncryptedFrames: number;
    private readonly maxPendingEncryptedBytes: number;
    private readonly callStreamKeyContext: string | undefined;
    private readonly streamIdBytes: Uint8Array;
    private readonly maxWriteBytes: number;

    private transport: P2PConnection;

    constructor(
        id: string,
        type: StreamType,
        peerId: string,
        lossy: boolean,
        session: PQNoiseSession,
        transport: P2PConnection
    ) {
        this.id = id;
        this.type = type;
        this.peerId = peerId;
        this.lossy = lossy;
        this.session = session;
        this.transport = transport;
        this.streamIdBytes = textEncoder.encode(id);
        const isAudio = type === 'call-audio';
        const isVisual = type === 'call-video' || type === 'call-screen';
        const isTelemetry = type === 'call-telemetry';
        this.maxWriteBytes = Math.min(
            type.startsWith('call-') ? MAX_CALL_FRAME_SIZE : MAX_MESSAGE_FRAME_SIZE,
            NATIVE_BRIDGE_RAW_MAX_BYTES - 2 - this.streamIdBytes.byteLength,
        ) - NOISE_FRAME_OVERHEAD;
        this.maxReceiveQueueFrames = isAudio ? 5 : isVisual ? MAX_VISUAL_QUEUE_FRAMES : isTelemetry ? 16 : 256;
        this.maxReceiveQueueBytes = isAudio
            ? 64 * 1024
            : isVisual
                ? 2 * MAX_CALL_FRAME_SIZE
                : isTelemetry
                    ? 64 * 1024
                    : 4 * 1024 * 1024;
        this.maxPendingEncryptedFrames = isAudio ? 5 : isVisual ? MAX_VISUAL_QUEUE_FRAMES : isTelemetry ? 16 : 256;
        this.maxPendingEncryptedBytes = isAudio
            ? 64 * 1024
            : isVisual
                ? 2 * MAX_CALL_FRAME_SIZE
                : isTelemetry
                    ? 64 * 1024
                    : 4 * 1024 * 1024;
        this.callStreamKeyContext = type.startsWith('call-') ? id : undefined;
    }

    updateSession(session: PQNoiseSession): void {
        if (this.session !== session) {
            if (this.callStreamKeyContext) {
                this.session.releaseCallStreamContext(this.callStreamKeyContext);
            }
            this.lifecycleGeneration++;
            for (const frame of this.pendingEncryptedFrames) {
                this.transport.releaseStreamBuffer(frame.byteLength);
                frame.fill(0);
            }
            for (const frame of this.receiveQueue) {
                this.transport.releaseStreamBuffer(frame.byteLength);
                frame.fill(0);
            }
            this.pendingEncryptedFrames = [];
            this.pendingEncryptedBytes = 0;
            this.receiveQueue = [];
            this.receiveQueueBytes = 0;
            this.decryptFailureCount = 0;
        }
        this.session = session;
    }

    // Write data to stream
    async write(data: Uint8Array, options?: StreamWriteOptions): Promise<void> {

        if (this._closed || !this._writable) {
            console.error('[P2PStream] Stream not writable:', { closed: this._closed, writable: this._writable });
            throw new Error('Stream is not writable');
        }

        if (data.length > this.maxWriteBytes) {
            throw new Error(`Data too large for stream type ${this.type}`);
        }
        const generation = this.lifecycleGeneration;
        const session = this.session;
        let encrypted: Uint8Array;
        try {
            encrypted = await session.encrypt(
                data,
                this.streamIdBytes,
                options?.priority ?? 'normal',
                this.callStreamKeyContext,
                options?.transferOwnership ?? false,
            );
        } catch (error) {
            if (this.session === session && !session.isValid()) {
                void this.transport.close('P2P session expired');
            }
            throw error;
        }

        try {
            if (
                this._closed ||
                !this._writable ||
                generation !== this.lifecycleGeneration ||
                this.session !== session
            ) {
                throw new Error('P2P stream changed while encrypting');
            }
            await this.transport.sendData(this.streamIdBytes, encrypted, options);
        } finally {
            encrypted.fill(0);
        }
    }

    // Read data from stream
    async read(): Promise<Uint8Array | null> {
        if (this._closed && this.receiveQueue.length === 0) {
            return null;
        }

        if (this.receiveQueue.length > 0) {
            const next = this.receiveQueue.shift()!;
            this.receiveQueueBytes = Math.max(0, this.receiveQueueBytes - next.byteLength);
            this.transport.releaseStreamBuffer(next.byteLength);
            return next;
        }

        if (this.readResolvers.length >= this.MAX_PENDING_READS) {
            throw new Error('Too many pending P2P stream reads');
        }

        return new Promise<Uint8Array | null>((resolve) => {
            this.readResolvers.push(resolve);
        });
    }

    // Async iterator for stream
    async *[Symbol.asyncIterator](): AsyncIterableIterator<Uint8Array> {
        while (true) {
            const data = await this.read();
            if (data === null) {
                return;
            }
            yield data;
        }
    }

    // Close stream
    async close(): Promise<void> {
        if (this._closed) return;

        this._closed = true;
        this.lifecycleGeneration++;
        this._writable = false;
        this._readable = false;
        for (const frame of this.receiveQueue) {
            this.transport.releaseStreamBuffer(frame.byteLength);
            frame.fill(0);
        }
        for (const frame of this.pendingEncryptedFrames) {
            this.transport.releaseStreamBuffer(frame.byteLength);
            frame.fill(0);
        }
        this.receiveQueue = [];
        this.receiveQueueBytes = 0;
        this.pendingEncryptedFrames = [];
        this.pendingEncryptedBytes = 0;

        for (const resolver of this.readResolvers) {
            resolver(null);
        }
        this.readResolvers = [];

        if (this.callStreamKeyContext) {
            this.session.releaseCallStreamContext(this.callStreamKeyContext);
        }
        this.transport.closeStream(this.id);
    }

    // Abort stream immediately
    abort(reason?: string): void {
        if (this._closed) return;
        this._closed = true;
        this.lifecycleGeneration++;
        this._writable = false;
        this._readable = false;
        for (const frame of this.receiveQueue) {
            this.transport.releaseStreamBuffer(frame.byteLength);
            frame.fill(0);
        }
        for (const frame of this.pendingEncryptedFrames) {
            this.transport.releaseStreamBuffer(frame.byteLength);
            frame.fill(0);
        }
        this.receiveQueue = [];
        this.receiveQueueBytes = 0;
        this.pendingEncryptedFrames = [];
        this.pendingEncryptedBytes = 0;

        for (const resolver of this.readResolvers) {
            resolver(null);
        }
        this.readResolvers = [];

        if (this.callStreamKeyContext) {
            this.session.releaseCallStreamContext(this.callStreamKeyContext);
        }
        this.transport.abortStream(this.id, reason);
    }

    get readable(): boolean {
        return this._readable && !this._closed;
    }

    get writable(): boolean {
        return this._writable && !this._closed;
    }

    get closed(): boolean {
        return this._closed;
    }

    // deliver data from transport
    _deliverData(frameData: Uint8Array): void {
        if (this._closed) {
            return;
        }
        if (!frameData || frameData.byteLength === 0) return;
        const frameLimit = this.type.startsWith('call-') ? MAX_CALL_FRAME_SIZE : MAX_MESSAGE_FRAME_SIZE;
        if (frameData.byteLength > frameLimit) return;
        if (frameData.byteLength > this.maxPendingEncryptedBytes) {
            if (!this.lossy) void this.transport.close('Reliable P2P encrypted frame exceeds queue limit');
            return;
        }
        if (
            this.pendingEncryptedFrames.length >= this.maxPendingEncryptedFrames ||
            this.pendingEncryptedBytes + frameData.byteLength > this.maxPendingEncryptedBytes
        ) {
            if (!this.lossy) {
                void this.transport.close('Reliable P2P encrypted queue overflow');
                return;
            }
            while (
                this.pendingEncryptedFrames.length >= this.maxPendingEncryptedFrames ||
                (this.pendingEncryptedFrames.length > 0 &&
                    this.pendingEncryptedBytes + frameData.byteLength > this.maxPendingEncryptedBytes)
            ) {
                const dropped = this.pendingEncryptedFrames.shift();
                if (!dropped) break;
                this.pendingEncryptedBytes = Math.max(0, this.pendingEncryptedBytes - dropped.byteLength);
                this.transport.releaseStreamBuffer(dropped.byteLength);
                dropped.fill(0);
            }
        }

        if (!this.transport.reserveStreamBuffer(frameData.byteLength)) {
            if (!this.lossy) void this.transport.close('Reliable P2P connection buffer exhausted');
            return;
        }
        try {
            this.pendingEncryptedFrames.push(frameData.slice());
            this.pendingEncryptedBytes += frameData.byteLength;
        } catch (error) {
            this.transport.releaseStreamBuffer(frameData.byteLength);
            throw error;
        }

        if (!this.decryptProcessing) {
            void this.drainPendingEncryptedFrames();
        }
    }

    private enqueueDecryptedFrame(decrypted: Uint8Array): void {
        if (this._closed || !this._readable) {
            decrypted.fill(0);
            return;
        }
        if (this.readResolvers.length > 0) {
            const resolver = this.readResolvers.shift()!;
            resolver(decrypted);
            return;
        }

        if (decrypted.byteLength > this.maxReceiveQueueBytes) {
            decrypted.fill(0);
            if (!this.lossy) void this.transport.close('Reliable P2P receive frame exceeds queue limit');
            return;
        }
        if (!this.lossy && (
            this.receiveQueue.length >= this.maxReceiveQueueFrames ||
            this.receiveQueueBytes + decrypted.byteLength > this.maxReceiveQueueBytes
        )) {
            decrypted.fill(0);
            void this.transport.close('Reliable P2P receive queue overflow');
            return;
        }
        while (
            this.receiveQueue.length >= this.maxReceiveQueueFrames ||
            (this.receiveQueue.length > 0 &&
                this.receiveQueueBytes + decrypted.byteLength > this.maxReceiveQueueBytes)
        ) {
            const dropped = this.receiveQueue.shift();
            if (!dropped) break;
            this.receiveQueueBytes = Math.max(0, this.receiveQueueBytes - dropped.byteLength);
            this.transport.releaseStreamBuffer(dropped.byteLength);
            dropped.fill(0);
        }
        if (!this.transport.reserveStreamBuffer(decrypted.byteLength)) {
            decrypted.fill(0);
            if (!this.lossy) void this.transport.close('Reliable P2P connection buffer exhausted');
            return;
        }
        try {
            this.receiveQueue.push(decrypted);
            this.receiveQueueBytes += decrypted.byteLength;
        } catch (error) {
            this.transport.releaseStreamBuffer(decrypted.byteLength);
            decrypted.fill(0);
            throw error;
        }
    }

    private async drainPendingEncryptedFrames(): Promise<void> {
        if (this.decryptProcessing) return;
        this.decryptProcessing = true;
        try {
            while (!this._closed && this.pendingEncryptedFrames.length > 0) {
                const frames = this.pendingEncryptedFrames;
                this.pendingEncryptedFrames = [];
                this.pendingEncryptedBytes = 0;

                let processedSinceYield = 0;
                let stopBatch = false;
                for (const frame of frames) {
                    if (this._closed || stopBatch) {
                        this.transport.releaseStreamBuffer(frame.byteLength);
                        frame.fill(0);
                        continue;
                    }
                    const generation = this.lifecycleGeneration;
                    const session = this.session;
                    try {
                        const decrypted = await session.decrypt(
                            frame,
                            this.streamIdBytes,
                            this.callStreamKeyContext,
                            true,
                        );
                        if (
                            this._closed ||
                            generation !== this.lifecycleGeneration ||
                            this.session !== session
                        ) {
                            decrypted.fill(0);
                            continue;
                        }
                        this.decryptFailureCount = 0;
                        this.enqueueDecryptedFrame(decrypted);
                    } catch {
                        if (this._closed || generation !== this.lifecycleGeneration) {
                            stopBatch = true;
                        } else {
                            this.decryptFailureCount++;
                            console.warn('[P2P-RECV] authenticated frame decryption failed', {
                                frameSize: frame.byteLength
                            });
                            if (!this.session.isValid() || this.decryptFailureCount >= 3) {
                                void this.transport.close('P2P session failure');
                                stopBatch = true;
                            }
                        }
                    } finally {
                        this.transport.releaseStreamBuffer(frame.byteLength);
                        frame.fill(0);
                    }

                    processedSinceYield++;
                    if (processedSinceYield >= 3) {
                        processedSinceYield = 0;
                        await new Promise<void>((resolve) => setTimeout(resolve, 0));
                    }
                }
            }
        } finally {
            this.decryptProcessing = false;
            if (!this._closed && this.pendingEncryptedFrames.length > 0) {
                void this.drainPendingEncryptedFrames();
            }
        }
    }
}

// Connection
class P2PConnection implements SecureConnection {
    readonly peerId: string;
    peerIdentity: PeerIdentity;
    private _state: ConnectionState = 'connecting';
    private _transport: 'p2p' | 'unknown' = 'unknown';
    private _connectedAt: number | null = null;
    private _lastActivity: number = Date.now();

    private session: PQNoiseSession | null = null;
    private streams: Map<string, P2PStream> = new Map();
    private streamHandlers: Set<(stream: SecureStream) => void> = new Set();
    private stateHandlers: Set<(state: ConnectionState) => void> = new Set();

    private stuckStateWatchdog: ReturnType<typeof setTimeout> | null = null;

    // Keepalive
    private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
    private keepalivePromise: Promise<void> | null = null;
    private bridgeConnectionId: string | null = null;
    private nativeConnectionToken: number | null = null;
    private bridgeGeneration: number = 0;
    private nativeAuthenticatedConnectionId: string | null = null;
    private audioLaneTelemetry: AudioLaneTelemetry | null = null;
    private audioEndpointUrl: string | undefined;
    private sentAudioEndpointUrl: string | null = null;
    private primaryPathRttMs: number | null = null;
    private audioLaneEnterSamples = 0;
    private audioLaneExitSamples = 0;
    private _bridgeHandshakeResolve: ((data: any) => void) | null = null;
    private _bridgeHandshakeReject: ((err: any) => void) | null = null;
    private _bridgeHandshakeWaitKind: 'handshake' | 'confirm' | null = null;
    private _pendingHandshakeToRespond: any = null;
    private _pendingHandshakeMessage: any = null;
    private _pendingKeyConfirmation: P2PKeyConfirmation | null = null;
    private _expectedHandshakeSessionId: string | null = null;
    private connectPromise: Promise<void> | null = null;
    private incomingResponderPromise: Promise<void> | null = null;
    private incomingAdoptionVersion: number = 0;
    private stateUpdatedAt: number = Date.now();
    private role: 'responder' | 'auto' = 'auto';
    private pendingIncomingFrames: Uint8Array[] = [];
    private readonly MAX_PENDING_INCOMING_FRAMES = 8;
    private pendingIncomingFrameBytes: number = 0;
    private readonly MAX_PENDING_INCOMING_BYTES = NATIVE_BRIDGE_RAW_MAX_BYTES;
    private pendingIncomingFlushDraining: boolean = false;

    private bridgeMessageQueue: Array<{ message: any; checkHandshake: boolean; byteLength: number }> = [];
    private bridgeMessageQueueBytes: number = 0;
    private bridgeQueueDraining: boolean = false;
    private readonly MAX_BRIDGE_MESSAGE_QUEUE = 128;
    private readonly MAX_BRIDGE_MESSAGE_QUEUE_BYTES = 8 * 1024 * 1024;
    private streamBufferedFrames = 0;
    private streamBufferedBytes = 0;
    private protocolViolationCount = 0;
    private readonly MAX_STREAM_BUFFERED_FRAMES = 512;
    private readonly MAX_STREAM_BUFFERED_BYTES = 16 * 1024 * 1024;

    constructor(
        peerId: string,
        peerIdentity: PeerIdentity,
        private ownKeys: OwnKeys,
        private localPeerId: string,
        private owner: P2PTransport
    ) {
        this.peerId = peerId;
        this.peerIdentity = peerIdentity;
        this.audioEndpointUrl = parseP2PEndpointUrl(peerIdentity.endpointUrl)?.endpointUrl;
    }

    private hasTrustedPeerIdentity(): boolean {
        return this.peerIdentity?.certVerified === true &&
            Number.isSafeInteger(this.peerIdentity.certificateExpiresAt);
    }

    reserveStreamBuffer(byteLength: number): boolean {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength <= 0 ||
            this.streamBufferedFrames >= this.MAX_STREAM_BUFFERED_FRAMES ||
            this.streamBufferedBytes + byteLength > this.MAX_STREAM_BUFFERED_BYTES
        ) return false;
        this.streamBufferedFrames += 1;
        this.streamBufferedBytes += byteLength;
        return true;
    }

    releaseStreamBuffer(byteLength: number): void {
        if (!Number.isSafeInteger(byteLength) || byteLength <= 0) return;
        this.streamBufferedFrames = Math.max(0, this.streamBufferedFrames - 1);
        this.streamBufferedBytes = Math.max(0, this.streamBufferedBytes - byteLength);
    }

    // Update peer identity
    public updatePeerIdentity(identity: PeerIdentity, retainEndpoint = true): void {
        const existingSigningKey = this.peerIdentity?.dilithiumPublicKey;
        const nextSigningKey = identity?.dilithiumPublicKey;
        if (
            this.session &&
            existingSigningKey?.length &&
            nextSigningKey?.length &&
            !PostQuantumUtils.timingSafeEqual(existingSigningKey, nextSigningKey)
        ) {
            const error = new Error('Peer certificate does not match the active handshake');
            (error as any).code = 'PEER_HANDSHAKE_SIGNING_KEY_MISMATCH';
            void this.close('peer-certificate-key-mismatch').catch(() => {});
            throw error;
        }
        const endpointUrl = parseP2PEndpointUrl(identity.endpointUrl)?.endpointUrl;
        if (endpointUrl) {
            this.audioEndpointUrl = endpointUrl;
        } else if (!retainEndpoint) {
            this.audioEndpointUrl = undefined;
        }
        this.peerIdentity = this.audioEndpointUrl
            ? { ...identity, endpointUrl: this.audioEndpointUrl }
            : identity;
        if (this.hasTrustedPeerIdentity() && this._state === 'connected') {
            this.markNativeConnectionAuthenticated();
        }
    }

    get state(): ConnectionState {
        return this._state;
    }

    get transport(): 'p2p' | 'unknown' {
        return this._transport;
    }

    get connectedAt(): number | null {
        return this._connectedAt;
    }

    get lastActivity(): number {
        return this._lastActivity;
    }

    private resetForConnect(): void {
        this.bridgeGeneration += 1;
        this.protocolViolationCount = 0;
        this.nativeAuthenticatedConnectionId = null;
        this.resetAudioPathMetrics();
        if (this.session) {
            try { this.session.destroy(); } catch { }
            this.session = null;
        }

        // Close and clear old streams
        for (const stream of Array.from(this.streams.values())) {
            try { stream.abort('fresh-connect'); } catch { }
        }
        this.streams.clear();

        // Reset handshake state
        this.clearPendingHandshakes();
        this._pendingKeyConfirmation?.frame.fill(0);
        this._pendingKeyConfirmation = null;
        this._expectedHandshakeSessionId = null;
        if (this._bridgeHandshakeReject) {
            try { this._bridgeHandshakeReject(new Error('Connection reset for a fresh connect')); } catch { }
        }
        this._bridgeHandshakeResolve = null;
        this._bridgeHandshakeReject = null;
        this._bridgeHandshakeWaitKind = null;

        this.role = 'auto';
        this.incomingResponderPromise = null;

        // Clear queues
        this.bridgeMessageQueue = [];
        this.bridgeMessageQueueBytes = 0;
        for (const frame of this.pendingIncomingFrames) frame.fill(0);
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this._connectedAt = null;
        this._lastActivity = 0;
    }

    // Connect to peer
    async connect(): Promise<void> {
        if (this._state === 'connected' && this.session) {
            return;
        }

        if (this.connectPromise) {
            return this.connectPromise;
        }

        let connectPromise!: Promise<void>;
        const adoptionVersion = this.incomingAdoptionVersion;
        connectPromise = (async () => {
            try {
                this.setState('connecting');
                await this.connectViaP2PBridge();
            } catch (error) {
                if (
                    this.incomingAdoptionVersion !== adoptionVersion &&
                    this.role === 'responder'
                ) {
                    await this.waitForIncomingAdoption(this.incomingAdoptionVersion);
                    return;
                }
                throw error;
            } finally {
                if (this.connectPromise === connectPromise) {
                    this.connectPromise = null;
                }
            }
        })();
        this.connectPromise = connectPromise;

        return connectPromise;
    }

    private async waitForIncomingAdoption(version: number): Promise<void> {
        if (version !== this.incomingAdoptionVersion) {
            throw new Error('P2P inbound adoption was replaced');
        }
        if (this._state === 'connected' && this.session) return;
        if (this._state === 'failed' || this._state === 'disconnected') {
            throw new Error('P2P inbound adoption failed');
        }

        await new Promise<void>((resolve, reject) => {
            let settled = false;
            const finish = (error?: Error) => {
                if (settled) return;
                settled = true;
                clearTimeout(timeout);
                unsubscribe();
                if (error) reject(error);
                else resolve();
            };
            const unsubscribe = this.onStateChange((state) => {
                if (version !== this.incomingAdoptionVersion) {
                    finish(new Error('P2P inbound adoption was replaced'));
                } else if (state === 'connected' && this.session) {
                    finish();
                } else if (state === 'failed' || state === 'disconnected') {
                    finish(new Error(`P2P inbound adoption failed: ${state}`));
                }
            });
            const timeout = setTimeout(() => {
                finish(new Error('P2P inbound adoption timed out'));
            }, P2P_CONNECTION_TIMEOUT_MS);
        });
    }

    private getActiveBridgeConnectionId(): string {
        return this.bridgeConnectionId || this.peerId;
    }

    private captureBridgeContext(): NativeBridgeContext {
        if (!this.bridgeConnectionId || !isNativeConnectionToken(this.nativeConnectionToken)) {
            throw new Error('Native P2P bridge connection is unavailable');
        }
        return {
            connectionId: this.bridgeConnectionId,
            connectionToken: this.nativeConnectionToken,
            generation: this.bridgeGeneration
        };
    }

    private isBridgeContextCurrent(context: NativeBridgeContext): boolean {
        return context.generation === this.bridgeGeneration &&
            context.connectionId === this.bridgeConnectionId &&
            context.connectionToken === this.nativeConnectionToken;
    }

    private assertBridgeContextCurrent(context: NativeBridgeContext): void {
        if (!this.isBridgeContextCurrent(context)) {
            throw new Error('P2P bridge changed during handshake');
        }
    }

    private consumePendingHandshakeReference(message: any): void {
        if (this._pendingHandshakeMessage === message) {
            this._pendingHandshakeMessage = null;
        }
        if (this._pendingHandshakeToRespond === message) {
            this._pendingHandshakeToRespond = null;
        }
    }

    private clearHandshakeBytes(message: any): void {
        if (!message || typeof message !== 'object') return;
        if (message.ephemeralKyberPublic instanceof Uint8Array) message.ephemeralKyberPublic.fill(0);
        if (message.kemCiphertext instanceof Uint8Array) message.kemCiphertext.fill(0);
        if (message.ephemeralX25519Public instanceof Uint8Array) message.ephemeralX25519Public.fill(0);
        if (message.signature instanceof Uint8Array) message.signature.fill(0);
        if (message.signerPublicKey instanceof Uint8Array) message.signerPublicKey.fill(0);
    }

    private clearPendingHandshakes(): void {
        const pendingMessage = this._pendingHandshakeMessage;
        const pendingResponder = this._pendingHandshakeToRespond;
        this._pendingHandshakeMessage = null;
        this._pendingHandshakeToRespond = null;
        this.clearHandshakeBytes(pendingMessage);
        if (pendingResponder !== pendingMessage) this.clearHandshakeBytes(pendingResponder);
    }

    private logHandshakeFailure(
        role: 'initiator' | 'responder',
        phase: string,
        error: unknown
    ): void {
        const detail = error instanceof Error
            ? error.message
            : typeof error === 'string'
                ? error
                : 'unknown handshake failure';
        console.warn('[P2P-HS] handshake failed', {
            peer: this.peerId,
            role,
            phase,
            error: detail.slice(0, 160)
        });
    }

    private buildBridgeConnectionIdCandidates(endpointId?: string): Set<string> {
        const ids = new Set<string>();
        ids.add(this.peerId);

        const appPeerId = this.owner.resolveAppPeerId(this.peerId);
        if (appPeerId) ids.add(appPeerId);

        const alias = this.owner.resolveUsernameAlias(this.peerId);
        if (alias) ids.add(alias);

        if (endpointId) ids.add(endpointId);
        return ids;
    }

    private matchesBridgeConnectionId(connectionId: unknown, candidates: Set<string>): connectionId is string {
        if (typeof connectionId !== 'string' || !connectionId) return false;
        return candidates.has(connectionId);
    }

    public ownsBridgeConnection(connectionId: string, connectionToken: number): boolean {
        if (!isNativeConnectionToken(connectionToken) || this.nativeConnectionToken !== connectionToken) return false;
        if (typeof connectionId !== 'string' || !connectionId) return false;
        if (this.bridgeConnectionId && this.bridgeConnectionId === connectionId) return true;
        return this.matchesBridgeConnectionId(connectionId, this.buildBridgeConnectionIdCandidates());
    }

    public ownsExactBridgeConnection(connectionId: string, connectionToken: number): boolean {
        return !!connectionId &&
            this.bridgeConnectionId === connectionId &&
            this.nativeConnectionToken === connectionToken;
    }

    public hasNativeConnectionGeneration(): boolean {
        return this.bridgeConnectionId !== null && this.nativeConnectionToken !== null;
    }

    public attachBridgeConnection(connectionId: string, connectionToken: number): void {
        if (!connectionId || !isNativeConnectionToken(connectionToken)) {
            throw new Error('Invalid native P2P connection generation');
        }
        if (
            this.bridgeConnectionId !== connectionId ||
            this.nativeConnectionToken !== connectionToken
        ) {
            this.bridgeGeneration += 1;
            this.protocolViolationCount = 0;
            this.nativeAuthenticatedConnectionId = null;
            this.resetAudioPathMetrics();
        }
        this.bridgeConnectionId = connectionId;
        this.nativeConnectionToken = connectionToken;
        this._transport = 'p2p';

        // Register alias between peerId and connectionId
        if (connectionId !== this.peerId && connectionId && this.peerId) {
            this.owner.registerUsernameAlias(this.peerId, connectionId);
        }
    }

    public adoptIncomingBridgeConnection(connectionId: string, connectionToken: number): void {
        if (
            this._state === 'connected' ||
            (this._state !== 'connecting' && this._state !== 'handshaking')
        ) {
            throw new Error('P2P connection cannot adopt an inbound generation');
        }
        const previousConnectionId = this.bridgeConnectionId;
        const previousConnectionToken = this.nativeConnectionToken;
        this.resetForConnect();
        this.incomingAdoptionVersion += 1;
        this.role = 'responder';
        this.attachBridgeConnection(connectionId, connectionToken);
        this.setState('connecting');

        if (
            previousConnectionId &&
            previousConnectionToken &&
            previousConnectionToken !== connectionToken
        ) {
            void p2p.disconnect(previousConnectionId, previousConnectionToken).catch(() => { });
        }
    }

    public ensureIncomingResponderActive(): void {
        if (!this.bridgeConnectionId || !this.nativeConnectionToken) return;
        if (this.session || this._state === 'handshaking') return;
        if (this.incomingResponderPromise) return;

        this.role = 'responder';
        const context = this.captureBridgeContext();
        let responderPromise!: Promise<void>;
        responderPromise = (async () => {
            try {
                await new Promise<void>((resolve) => setTimeout(resolve, 0));
                this.assertBridgeContextCurrent(context);
                await this.waitForInitiatorHandshakeAndRespond();
            } catch (err) {
                if (this.isBridgeContextCurrent(context) && this._state !== 'connected') {
                    this.setState('failed');
                }
                throw err;
            } finally {
                if (this.incomingResponderPromise === responderPromise) {
                    this.incomingResponderPromise = null;
                }
            }
        })();
        this.incomingResponderPromise = responderPromise;
        responderPromise.catch(() => { });
    }

    public handleBridgeEventMessage(message: any): void {
        if (this.shouldProcessBridgeMessageImmediately(message)) {
            this.processBridgeEventMessage(message, true);
            return;
        }

        const byteLength = this.estimateBridgeMessageBytes(message);
        if (
            byteLength <= 0 ||
            byteLength > this.MAX_BRIDGE_MESSAGE_QUEUE_BYTES ||
            this.bridgeMessageQueue.length >= this.MAX_BRIDGE_MESSAGE_QUEUE ||
            this.bridgeMessageQueueBytes + byteLength > this.MAX_BRIDGE_MESSAGE_QUEUE_BYTES
        ) {
            void this.close('P2P bridge message queue overflow').catch(() => { });
            return;
        }
        this.bridgeMessageQueue.push({ message, checkHandshake: false, byteLength });
        this.bridgeMessageQueueBytes += byteLength;
        if (!this.bridgeQueueDraining) {
            this.bridgeQueueDraining = true;
            void this.drainBridgeMessageQueue();
        }
    }

    private estimateBridgeMessageBytes(message: unknown): number {
        if (typeof message === 'string') return message.length;
        try {
            return JSON.stringify(message)?.length ?? 0;
        } catch {
            return this.MAX_BRIDGE_MESSAGE_QUEUE_BYTES + 1;
        }
    }

    public handleBridgeEventClosed(): void {
        this.handleTauriBridgeClosed();
    }

    // Connect to a peer through their Tor onion service
    private async connectViaP2PBridge(): Promise<void> {
        if (!isTauri()) {
            throw new Error('P2P bridge unavailable in browser mode');
        }
        const endpoint = parseP2PEndpointUrl(this.peerIdentity.endpointUrl);
        if (!endpoint) {
            this.owner.requestPeerCertificate(this.peerId);
            const error = new Error(`No P2P endpoint available for ${this.peerId}`);
            (error as any).code = 'P2P_ENDPOINT_MISSING';
            throw error;
        }

        // Reset stale connection state before a fresh attempt
        this.resetForConnect();
        const dialGeneration = this.bridgeGeneration;
        let connectionToken: number | null = null;
        let context: NativeBridgeContext | null = null;

        try {
            const res = await p2p.connect(this.peerId, endpoint.endpointUrl);
            if (!res.success || !isNativeConnectionToken(res.connectionToken)) {
                throw new Error(res.error || 'P2P connect failed');
            }
            connectionToken = res.connectionToken;

            if (
                dialGeneration !== this.bridgeGeneration ||
                this._state === 'disconnected' ||
                this._state === 'failed'
            ) {
                throw new Error('P2P connection attempt was cancelled');
            }

            this.attachBridgeConnection(this.peerId, connectionToken);
            context = this.captureBridgeContext();

            await new Promise<void>((resolve, reject) => {
                let settled = false;
                const settle = (error?: unknown) => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timeout);
                    if (error === undefined) {
                        resolve();
                    } else {
                        reject(error instanceof Error ? error : new Error(String(error)));
                    }
                };
                const timeout = setTimeout(() => {
                    if (
                        context &&
                        this.isBridgeContextCurrent(context) &&
                        this._state !== 'failed' &&
                        this._state !== 'disconnected'
                    ) {
                        this.setState('failed');
                    }
                    settle(new Error('Handshake response timeout (bridge)'));
                }, P2P_CONNECTION_TIMEOUT_MS);

                void this.handleTauriBridgeOpened(context!).then(
                    () => settle(),
                    (error) => settle(error)
                );
            });
            this.assertBridgeContextCurrent(context);
        } catch (error) {
            const ownsCurrentAttempt = context
                ? this.isBridgeContextCurrent(context)
                : dialGeneration === this.bridgeGeneration;
            if (
                ownsCurrentAttempt &&
                (this._state === 'connecting' || this._state === 'handshaking')
            ) {
                this.setState('failed');
            }
            if (connectionToken && this.nativeConnectionToken !== connectionToken) {
                const connectionId = context?.connectionId || this.peerId;
                await p2p.disconnect(connectionId, connectionToken).catch(() => false);
            }
            throw error instanceof Error ? error : new Error(String(error));
        }
    }

    // Perform PQ handshake with peer
    private async performHandshake(): Promise<void> {
        const context = this.captureBridgeContext();
        this.setState('handshaking');

        const isDeterministicInitiator = this.localPeerId < this.peerId;
        let candidateSession: PQNoiseSession | null = null;
        let receivedHandshake: any = null;
        let phase = 'create-init';
        try {
            if (!this.hasTrustedPeerIdentity()) {
                throw new Error('Certified peer identity is unavailable');
            }
            const peerKeys: PeerKeys = {
                kyberPublicKey: this.peerIdentity.kyberPublicKey,
                dilithiumPublicKey: this.peerIdentity.dilithiumPublicKey!,
                x25519PublicKey: this.peerIdentity.x25519PublicKey!
            };

            if (!this.ownKeys) {
                throw new Error('Own keys missing for handshake');
            }

            const result = await PQNoiseSession.createInitiatorSession(
                this.localPeerId,
                this.peerId,
                this.ownKeys,
                peerKeys
            );
            candidateSession = result.session;
            const message = result.message;
            this.assertBridgeContextCurrent(context);
            this._expectedHandshakeSessionId = message.sessionId;

            const responsePromise = this.waitForHandshakeResponse(message.sessionId);
            phase = 'send-init';
            try {
                await this.sendRaw(this.prepareHandshakeObject(message));
            } catch (sendError) {
                console.warn('[P2P-HS] init send failed', {
                    error: sendError instanceof Error ? sendError.message : String(sendError),
                });
                if (this.isBridgeContextCurrent(context)) {
                    this._bridgeHandshakeReject?.(sendError);
                }
                void responsePromise.catch(() => { });
                throw sendError;
            }
            this.assertBridgeContextCurrent(context);

            phase = 'wait-response';
            let response = await responsePromise;
            receivedHandshake = response;
            this.assertBridgeContextCurrent(context);

            // both peers dialed and both sent init
            let glareGuard = 0;
            while (response.type === 'init') {
                if (!isDeterministicInitiator) {
                    candidateSession.destroy();
                    candidateSession = null;
                    await this.handleIncomingHandshake(response, context);
                    if (this.isBridgeContextCurrent(context)) {
                        this._expectedHandshakeSessionId = null;
                    }
                    return;
                }

                // id-lower ignore peers init
                if (++glareGuard > 3) {
                    throw new Error('Handshake glare did not converge');
                }
                this.clearHandshakeBytes(response);
                receivedHandshake = null;
                response = await this.waitForHandshakeResponse(message.sessionId);
                receivedHandshake = response;
                this.assertBridgeContextCurrent(context);
            }

            const expectedSignerPublicKey = this.peerIdentity?.dilithiumPublicKey;
            if (expectedSignerPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE) {
                throw new Error('Certified peer signing key unavailable');
            }
            phase = 'verify-response';
            await candidateSession.completeHandshake(response, expectedSignerPublicKey);
            this.clearHandshakeBytes(response);
            receivedHandshake = null;
            this.assertBridgeContextCurrent(context);
            this.session = candidateSession;
            const outgoingConfirmation = await candidateSession.createKeyConfirmation(
                this.localPeerId,
                this.peerId
            );
            this.assertBridgeContextCurrent(context);
            const confirmationPromise = this.waitForKeyConfirmation(context, candidateSession);
            phase = 'send-confirmation';
            try {
                await this.sendRaw(this.prepareKeyConfirmation(outgoingConfirmation));
            } catch (error) {
                void confirmationPromise.catch(() => { });
                throw error;
            } finally {
                outgoingConfirmation.fill(0);
            }

            phase = 'wait-confirmation';
            const confirmation = await confirmationPromise;
            try {
                this.assertBridgeContextCurrent(context);
                phase = 'verify-confirmation';
                await candidateSession.verifyKeyConfirmation(
                    confirmation.frame,
                    this.peerId,
                    this.localPeerId
                );
                this.assertBridgeContextCurrent(context);
            } finally {
                confirmation.frame.fill(0);
            }

            phase = 'authenticate-native';
            await this.authenticateNativeConnection();
            this.assertBridgeContextCurrent(context);
            if (!this.hasTrustedPeerIdentity()) {
                throw new Error('Certified peer identity became unavailable during handshake');
            }

            void this.flushPendingIncomingFrames();
            this._expectedHandshakeSessionId = null;

            for (const stream of Array.from(this.streams.values())) {
                stream.updateSession(candidateSession);
            }

            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
        } catch (err) {
            this.logHandshakeFailure('initiator', phase, err);
            if (this.session === candidateSession) this.session = null;
            candidateSession?.destroy();
            if (this.isBridgeContextCurrent(context)) {
                this._expectedHandshakeSessionId = null;
                this.setState('failed');
            }
            throw err;
        } finally {
            this.clearHandshakeBytes(receivedHandshake);
        }
    }

    // Prepare handshake object
    private prepareHandshakeObject(message: any): any {
        const toBase64 = (value?: Uint8Array | string): string | undefined => {
            if (!value) return undefined;
            if (typeof value === 'string') return value;
            return PostQuantumUtils.uint8ArrayToBase64(value);
        };

        return {
            version: message.version,
            type: message.type,
            from: message.from,
            to: message.to,
            sessionId: message.sessionId,
            timestamp: message.timestamp,
            kemCiphertext: toBase64(message.kemCiphertext),
            ...(message.type === 'init'
                ? { ephemeralKyberPublic: toBase64(message.ephemeralKyberPublic) }
                : {}),
            ephemeralX25519Public: toBase64(message.ephemeralX25519Public),
            signature: toBase64(message.signature)!,
            signerPublicKey: toBase64(message.signerPublicKey)!
        };
    }

    // Normalize handshake message
    private normalizeHandshakeMessage(json: any): any {
        if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
        if (json.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION || (json.type !== 'init' && json.type !== 'response')) return null;
        const expectedKeys = (json.type === 'init'
            ? ['ephemeralKyberPublic', 'ephemeralX25519Public', 'from', 'kemCiphertext', 'sessionId', 'signature', 'signerPublicKey', 'timestamp', 'to', 'type', 'version']
            : ['ephemeralX25519Public', 'from', 'kemCiphertext', 'sessionId', 'signature', 'signerPublicKey', 'timestamp', 'to', 'type', 'version'])
            .sort()
            .join(',');
        if (Object.keys(json).sort().join(',') !== expectedKeys) return null;
        if (
            typeof json.from !== 'string' ||
            !AUTH_USERNAME_REGEX.test(json.from) ||
            json.from !== this.peerId ||
            typeof json.to !== 'string' ||
            json.to !== this.localPeerId
        ) return null;
        if (typeof json.sessionId !== 'string' || !/^[a-f0-9]{32}$/.test(json.sessionId)) return null;
        if (!Number.isSafeInteger(json.timestamp)) return null;

        const toUint8 = (value: unknown, expectedLength: number): Uint8Array | null => {
            if (value instanceof Uint8Array) {
                return value.length === expectedLength ? value : null;
            }
            return tryDecodeCanonicalBase64(value, 'P2P handshake field', { exactBytes: expectedLength });
        };

        const kemCiphertext = toUint8(json.kemCiphertext, PQ_KEM_CIPHERTEXT_SIZE);
        const ephemeralX25519Public = toUint8(json.ephemeralX25519Public, X25519_PUBLIC_KEY_LENGTH);
        const signature = toUint8(json.signature, PQ_SIG_SIGNATURE_SIZE);
        const signerPublicKey = toUint8(json.signerPublicKey, PQ_SIG_PUBLIC_KEY_SIZE);
        const ephemeralKyberPublic = json.type === 'init'
            ? toUint8(json.ephemeralKyberPublic, PQ_KEM_PUBLIC_KEY_SIZE)
            : null;
        if (!kemCiphertext || !ephemeralX25519Public || !signature || !signerPublicKey || (json.type === 'init' && !ephemeralKyberPublic)) {
            kemCiphertext?.fill(0);
            ephemeralX25519Public?.fill(0);
            signature?.fill(0);
            signerPublicKey?.fill(0);
            ephemeralKyberPublic?.fill(0);
            return null;
        }

        return {
            from: json.from,
            to: json.to,
            version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
            type: json.type,
            sessionId: json.sessionId,
            timestamp: json.timestamp,
            kemCiphertext,
            ...(json.type === 'init' ? { ephemeralKyberPublic } : {}),
            ephemeralX25519Public,
            signature,
            signerPublicKey
        };
    }

    private prepareKeyConfirmation(frame: Uint8Array): Record<string, string> {
        if (!this.session || frame.byteLength < 44 || frame.byteLength > 512) {
            throw new Error('Invalid P2P key confirmation frame');
        }
        return {
            version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
            type: 'confirm',
            from: this.localPeerId,
            to: this.peerId,
            sessionId: this.session.getBindingId(),
            frame: PostQuantumUtils.uint8ArrayToBase64(frame)
        };
    }

    private normalizeKeyConfirmation(value: unknown): P2PKeyConfirmation | null {
        if (!value || typeof value !== 'object' || Array.isArray(value) || !this.session) return null;
        const json = value as Record<string, unknown>;
        if (Object.keys(json).sort().join(',') !== 'frame,from,sessionId,to,type,version') return null;
        if (
            json.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION ||
            json.type !== 'confirm' ||
            json.from !== this.peerId ||
            json.to !== this.localPeerId ||
            json.sessionId !== this.session.getBindingId() ||
            (!(json.frame instanceof Uint8Array) && typeof json.frame !== 'string')
        ) return null;

        if (json.frame instanceof Uint8Array) {
            if (json.frame.byteLength < 44 || json.frame.byteLength > 512) return null;
            return {
                version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
                type: 'confirm',
                from: json.from,
                to: json.to,
                sessionId: json.sessionId,
                frame: json.frame.slice()
            };
        }
        if (
            json.frame.length === 0 ||
            json.frame.length > 4 * Math.ceil(512 / 3) ||
            json.frame.length % 4 !== 0 ||
            !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(json.frame)
        ) return null;

        try {
            const frame = PostQuantumUtils.base64ToUint8Array(json.frame);
            if (
                frame.byteLength < 44 ||
                frame.byteLength > 512 ||
                PostQuantumUtils.uint8ArrayToBase64(frame) !== json.frame
            ) {
                frame.fill(0);
                return null;
            }
            return {
                version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
                type: 'confirm',
                from: json.from,
                to: json.to,
                sessionId: json.sessionId,
                frame
            };
        } catch {
            return null;
        }
    }

    // Wait for handshake response
    private async waitForHandshakeResponse(expectedSessionId?: string): Promise<any> {
        if (this._pendingHandshakeMessage) {
            const pendingMessage = this._pendingHandshakeMessage;
            this.consumePendingHandshakeReference(pendingMessage);
            const pending = this.normalizeHandshakeMessage(pendingMessage);
            if (!pending) {
                this.clearHandshakeBytes(pendingMessage);
                throw new Error('Invalid pending P2P handshake');
            }
            if (pending?.type === 'init') {
                return pending;
            }
            if (pending?.type === 'response') {
                if (!expectedSessionId || pending.sessionId === expectedSessionId) {
                    return pending;
                }
                this.clearHandshakeBytes(pending);
                throw new Error('Handshake response sessionId mismatch');
            }
        }

        if (!this.bridgeConnectionId || !this.nativeConnectionToken) {
            throw new Error('Native P2P bridge connection is unavailable');
        }
        const bridgeGeneration = this.bridgeGeneration;

        return new Promise((resolve, reject) => {
            this._bridgeHandshakeWaitKind = 'handshake';
            const timeout = setTimeout(() => {
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
                if (
                    bridgeGeneration === this.bridgeGeneration &&
                    (this._state === 'connecting' || this._state === 'handshaking')
                ) {
                    this.setState('failed');
                }
                reject(new Error('Handshake response timeout (bridge)'));
            }, P2P_CONNECTION_TIMEOUT_MS);

            this._bridgeHandshakeResolve = (data) => {
                if (bridgeGeneration !== this.bridgeGeneration) {
                    this.clearHandshakeBytes(data);
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    this._bridgeHandshakeWaitKind = null;
                    reject(new Error('P2P bridge changed during handshake'));
                    return;
                }
                const response = this.normalizeHandshakeMessage(data);
                if (!response) {
                    this.clearHandshakeBytes(data);
                    return;
                }

                if (response.type === 'response' && expectedSessionId
                    && response.sessionId !== expectedSessionId) {
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    this._bridgeHandshakeWaitKind = null;
                    this.clearHandshakeBytes(response);
                    reject(new Error('Handshake response sessionId mismatch'));
                    return;
                }

                clearTimeout(timeout);
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
                resolve(response);
            };
            this._bridgeHandshakeReject = (err) => {
                clearTimeout(timeout);
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
                reject(err);
            };

            if (this._pendingHandshakeMessage && this._bridgeHandshakeResolve) {
                const pending = this._pendingHandshakeMessage;
                this._pendingHandshakeMessage = null;
                this._bridgeHandshakeResolve(pending);
            }
        });
    }

    private async waitForKeyConfirmation(
        context: NativeBridgeContext,
        session: PQNoiseSession
    ): Promise<P2PKeyConfirmation> {
        this.assertBridgeContextCurrent(context);
        if (this.session !== session) {
            throw new Error('P2P session changed before key confirmation');
        }
        if (this._pendingKeyConfirmation) {
            const pending = this._pendingKeyConfirmation;
            this._pendingKeyConfirmation = null;
            return pending;
        }

        return new Promise<P2PKeyConfirmation>((resolve, reject) => {
            this._bridgeHandshakeWaitKind = 'confirm';
            const timeout = setTimeout(() => {
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
                if (this.isBridgeContextCurrent(context) && this._state === 'handshaking') {
                    this.setState('failed');
                }
                reject(new Error('P2P key confirmation timeout'));
            }, P2P_CONNECTION_TIMEOUT_MS);

            this._bridgeHandshakeResolve = (data) => {
                if (!this.isBridgeContextCurrent(context) || this.session !== session) {
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    this._bridgeHandshakeWaitKind = null;
                    reject(new Error('P2P bridge changed during key confirmation'));
                    return;
                }
                const confirmation = this.normalizeKeyConfirmation(data);
                if (!confirmation) {
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    this._bridgeHandshakeWaitKind = null;
                    reject(new Error('Invalid P2P key confirmation'));
                    return;
                }
                clearTimeout(timeout);
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
                resolve(confirmation);
            };
            this._bridgeHandshakeReject = (error) => {
                clearTimeout(timeout);
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
                reject(error);
            };

            if (this._pendingKeyConfirmation && this._bridgeHandshakeResolve) {
                const pending = this._pendingKeyConfirmation;
                this._pendingKeyConfirmation = null;
                this._bridgeHandshakeResolve(pending);
                pending.frame.fill(0);
            }
        });
    }

    // Wait for initiator handshake to arrive over direct channel then respond
    private async waitForInitiatorHandshakeAndRespond(): Promise<void> {
        const context = this.captureBridgeContext();
        this.setState('handshaking');

        // Check if init message already arrived before started waiting
        if (this._pendingHandshakeToRespond) {
            const msg = this._pendingHandshakeToRespond;
            this.consumePendingHandshakeReference(msg);
            await this.handleIncomingHandshake(msg, context);
            this.assertBridgeContextCurrent(context);
            return;
        }

        if (this._pendingHandshakeMessage) {
            const pendingMessage = this._pendingHandshakeMessage;
            this.consumePendingHandshakeReference(pendingMessage);
            const pending = this.normalizeHandshakeMessage(pendingMessage);
            if (pending?.type === 'init') {
                await this.handleIncomingHandshake(pending, context);
                this.assertBridgeContextCurrent(context);
                return;
            }
            this.clearHandshakeBytes(pending ?? pendingMessage);
            throw new Error('Invalid pending initiator handshake');
        }

        return new Promise<void>((resolve, reject) => {
            let settled = false;
            this._bridgeHandshakeWaitKind = 'handshake';
            const cleanup = () => {
                this._bridgeHandshakeResolve = null;
                this._bridgeHandshakeReject = null;
                this._bridgeHandshakeWaitKind = null;
            };
            const timeout = setTimeout(() => {
                if (settled) return;
                settled = true;
                cleanup();
                if (this.isBridgeContextCurrent(context) && (
                    this._state === 'connecting' || this._state === 'handshaking'
                )) {
                    this.setState('failed');
                }
                void p2p.disconnect(context.connectionId, context.connectionToken).catch(() => { });
                reject(new Error('Timeout waiting for initiator handshake (bridge)'));
            }, P2P_CONNECTION_TIMEOUT_MS);

            const acceptHandshake = async (data: unknown) => {
                if (settled) return;
                if (!this.isBridgeContextCurrent(context)) {
                    this.clearHandshakeBytes(data);
                    settled = true;
                    clearTimeout(timeout);
                    cleanup();
                    reject(new Error('P2P bridge changed during responder handshake'));
                    return;
                }
                const handshakeMsg = this.normalizeHandshakeMessage(data);
                if (!handshakeMsg || handshakeMsg.type !== 'init') {
                    this.clearHandshakeBytes(handshakeMsg ?? data);
                    settled = true;
                    clearTimeout(timeout);
                    cleanup();
                    reject(new Error('Invalid initiator handshake'));
                    return;
                }
                settled = true;
                clearTimeout(timeout);
                cleanup();
                try {
                    await this.handleIncomingHandshake(handshakeMsg, context);
                    this.assertBridgeContextCurrent(context);
                    resolve();
                } catch (err) {
                    reject(err);
                }
            };

            this._bridgeHandshakeResolve = (data) => {
                void acceptHandshake(data);
            };
            this._bridgeHandshakeReject = (err) => {
                if (settled) return;
                settled = true;
                clearTimeout(timeout);
                cleanup();
                reject(err);
            };

            const pending = this._pendingHandshakeToRespond ?? this._pendingHandshakeMessage;
            if (pending) this.consumePendingHandshakeReference(pending);
            if (pending) void acceptHandshake(pending);
        });
    }

    private async sendRaw(data: Uint8Array | any, options?: StreamWriteOptions): Promise<void> {
        if (!this.bridgeConnectionId || !this.nativeConnectionToken) {
            throw new Error('Native P2P bridge connection is unavailable');
        }

        if (data instanceof Uint8Array) {
            if (data.byteLength > NATIVE_BRIDGE_RAW_MAX_BYTES) {
                throw new Error('P2P frame exceeds native bridge limit');
            }
        }
        const bridgeId = this.getActiveBridgeConnectionId();
        const connectionToken = this.nativeConnectionToken;
        const bridgeGeneration = this.bridgeGeneration;
        const realtime = options?.priority === 'realtime';
        const visual = options?.priority === 'visual';
        const primaryPathRttMs = this.primaryPathRttMs;
        const previousSelectedAudioLane = this.audioLaneTelemetry?.selectedLane ?? null;
        const holdingAudioLane = realtime &&
            previousSelectedAudioLane !== null &&
            this.audioLaneTelemetry?.selectedPath === 'lane' &&
            this.audioLaneExitSamples < AUDIO_LANE_PATH_SWITCH_CONFIRMATIONS;
        const evaluatingAudioLanes = holdingAudioLane ||
            (realtime && previousSelectedAudioLane !== null) ||
            this.audioLaneEnterSamples >= AUDIO_LANE_PATH_SWITCH_CONFIRMATIONS;
        const mediaLaneRttCeiling = primaryPathRttMs === null
            ? undefined
            : visual
                ? Math.max(
                    1,
                    Math.floor(
                        primaryPathRttMs - Math.max(
                            AUDIO_LANE_MIN_RTT_GAIN_MS,
                            primaryPathRttMs * AUDIO_LANE_MIN_RTT_GAIN_RATIO
                        )
                    )
                )
                : realtime && evaluatingAudioLanes
                    ? holdingAudioLane
                        ? AUDIO_LANE_HOLD_RTT_CEILING_MS
                        : Math.max(
                            1,
                            Math.floor(
                                primaryPathRttMs - Math.max(
                                    AUDIO_LANE_MIN_RTT_GAIN_MS,
                                    primaryPathRttMs * AUDIO_LANE_MIN_RTT_GAIN_RATIO
                                )
                            )
                        )
                    : undefined;
        const audioEndpoint = (realtime || visual) &&
            this.audioEndpointUrl &&
            this.audioEndpointUrl !== this.sentAudioEndpointUrl
            ? this.audioEndpointUrl
            : undefined;
        const res = await p2p.send(bridgeId, connectionToken, data, {
            ...options,
            ...(audioEndpoint ? { audioEndpoint } : {}),
            ...(mediaLaneRttCeiling !== undefined
                ? { audioLaneRttCeiling: mediaLaneRttCeiling }
                : {}),
        });
        if (res.audioLanes) {
            const selectedPath = res.audioLanes.selectedLane ? 'lane' : 'primary';
            this.audioLaneTelemetry = {
                ...res.audioLanes,
                selectedPath,
                primaryRttMs: primaryPathRttMs,
                rttCeilingMs: mediaLaneRttCeiling ?? null,
            };
            if (!visual && selectedPath === 'lane') {
                this.audioLaneEnterSamples = 0;
                if (previousSelectedAudioLane !== res.audioLanes.selectedLane) {
                    this.audioLaneExitSamples = 0;
                }
            } else if (!visual) {
                this.audioLaneExitSamples = 0;
            }
        }

        if (
            bridgeGeneration !== this.bridgeGeneration ||
            bridgeId !== this.getActiveBridgeConnectionId() ||
            connectionToken !== this.nativeConnectionToken
        ) {
            throw new Error('P2P bridge changed while sending');
        }
        if (audioEndpoint && (res.success || res.audioLanes?.endpointAvailable)) {
            this.sentAudioEndpointUrl = audioEndpoint;
        }

        if (!res.success) {
            const errLower = (res.error || '').toLowerCase();
            const isConnectionDead =
                res.error === 'Connection not found' ||
                res.error === 'Not connected' ||
                errLower.includes('connection closed') ||
                errLower.includes('connection lost') ||
                errLower.includes('writer unavailable') ||
                errLower.includes('stream reset') ||
                errLower.includes('reset by peer') ||
                errLower.includes('send timed out') ||
                errLower.includes('identity changed');
            if (isConnectionDead) {
                this.handleDisconnect();
            }

            throw new Error(res.error || 'Failed to send through native P2P bridge');
        }
        this._lastActivity = Date.now();
    }

    // Send data over the socket
    async sendData(
        idBytes: Uint8Array,
        data: Uint8Array,
        options?: StreamWriteOptions,
    ): Promise<void> {

        if (!this.session) {
            throw new Error('Not connected');
        }

        if (this._state !== 'connected') {
            throw new Error('Not connected');
        }

        // Frame the data with stream ID
        if (
            idBytes.byteLength === 0 ||
            idBytes.byteLength > MAX_STREAM_ID_BYTES ||
            2 + idBytes.byteLength + data.byteLength > NATIVE_BRIDGE_RAW_MAX_BYTES
        ) {
            throw new Error('P2P stream frame exceeds native bridge limit');
        }
        const frame = new Uint8Array(2 + idBytes.length + data.length);
        const view = new DataView(frame.buffer);
        view.setUint16(0, idBytes.length, false);
        frame.set(idBytes, 2);
        frame.set(data, 2 + idBytes.length);

        try {
            await this.sendRaw(frame, options);
        } finally {
            frame.fill(0);
        }
    }

    private queueIncomingFrame(data: Uint8Array): void {
        if (!data || data.length === 0) return;
        const incomingSize = data.byteLength;
        if (incomingSize > this.MAX_PENDING_INCOMING_BYTES) {
            void this.close('P2P pre-session frame exceeds queue limit').catch(() => { });
            return;
        }
        if (
            this.pendingIncomingFrames.length >= this.MAX_PENDING_INCOMING_FRAMES ||
            this.pendingIncomingFrameBytes + incomingSize > this.MAX_PENDING_INCOMING_BYTES
        ) {
            void this.close('P2P pre-session queue overflow').catch(() => { });
            return;
        }

        const copy = data.slice();
        this.pendingIncomingFrames.push(copy);
        this.pendingIncomingFrameBytes += copy.byteLength;
    }

    private async flushPendingIncomingFrames(): Promise<void> {
        if (this.pendingIncomingFlushDraining) return;
        if (!this.session || this._state !== 'connected' || this.pendingIncomingFrames.length === 0) return;

        const bridgeGeneration = this.bridgeGeneration;
        this.pendingIncomingFlushDraining = true;
        try {
            while (
                bridgeGeneration === this.bridgeGeneration &&
                this.session &&
                this._state === 'connected' &&
                this.pendingIncomingFrames.length > 0
            ) {
                const buffered = this.pendingIncomingFrames;
                this.pendingIncomingFrames = [];
                this.pendingIncomingFrameBytes = 0;

                let processedSinceYield = 0;
                for (const frame of buffered) {
                    try {
                        if (bridgeGeneration === this.bridgeGeneration) {
                            this.handleIncomingData(frame);
                        }
                    } catch { }
                    finally { frame.fill(0); }
                    processedSinceYield++;
                    if (processedSinceYield >= 4) {
                        processedSinceYield = 0;
                        await new Promise<void>((resolve) => setTimeout(resolve, 0));
                    }
                }
            }
        } finally {
            this.pendingIncomingFlushDraining = false;
            if (this.session && this._state === 'connected' && this.pendingIncomingFrames.length > 0) {
                void this.flushPendingIncomingFrames();
            }
        }
    }

    private noteProtocolViolation(reason: string): void {
        this.protocolViolationCount += 1;
        if (this.protocolViolationCount >= 3) {
            void this.close(reason).catch(() => { });
        }
    }

    // Handle incoming data over the socket
    private handleIncomingData(data: Uint8Array): void {

        this._lastActivity = Date.now();

        if (this._state !== 'connected') {
            if (this._state !== 'handshaking' || (!this.session && !this._expectedHandshakeSessionId)) {
                void this.close('P2P data arrived outside authenticated session').catch(() => { });
                return;
            }
            this.queueIncomingFrame(data);
            return;
        }

        if (!this.session) {
            if (this._state === 'connected') {
                this.setState('failed');
            }
            return;
        }

        if (data.length < 2) {
            this.noteProtocolViolation('Repeated malformed P2P framing');
            return;
        }

        const view = new DataView(data.buffer, data.byteOffset);
        const idLength = view.getUint16(0, false);

        // Handle keep-alive frames
        if (idLength === 0) {
            if (data.byteLength === 2) return;
            this.noteProtocolViolation('Repeated malformed P2P keepalive framing');
            return;
        }

        if (idLength > MAX_STREAM_ID_BYTES || data.length < 2 + idLength) {
            this.noteProtocolViolation('Repeated malformed P2P stream framing');
            return;
        }

        const idBytes = data.subarray(2, 2 + idLength);
        let streamId: string;
        try {
            streamId = textDecoder.decode(idBytes);
        } catch {
            this.noteProtocolViolation('Repeated invalid P2P stream identifiers');
            return;
        }
        const payload = data.subarray(2 + idLength);
        const type = parseStreamType(streamId);
        if (!type) {
            this.noteProtocolViolation('Repeated invalid P2P stream identifiers');
            return;
        }
        const frameLimit = Math.min(
            type.startsWith('call-') ? MAX_CALL_FRAME_SIZE : MAX_MESSAGE_FRAME_SIZE,
            NATIVE_BRIDGE_RAW_MAX_BYTES - 2 - idLength
        );
        if (payload.byteLength > frameLimit) {
            this.noteProtocolViolation('Repeated oversized P2P stream frames');
            return;
        }

        // Route to stream
        let stream = this.streams.get(streamId);
        if (!stream) {
            if (this.streams.size >= P2P_MAX_STREAMS_PER_CONNECTION) {
                void this.close('P2P stream limit exceeded').catch(() => { });
                return;
            }

            stream = new P2PStream(
                streamId,
                type,
                this.peerId,
                type.startsWith('call-'),
                this.session!,
                this
            );

            this._deliverIncomingStream(stream);

            // Auto read control streams for the internal message hub
            if (type === SignalType.MESSAGE) {
                this.startControlMessageReader(stream);
            }
        }

        stream._deliverData(payload);
    }

    // Handle disconnect
    private handleDisconnect(): void {
        const disconnectedBridgeId = this.bridgeConnectionId;
        this.bridgeGeneration += 1;
        this.protocolViolationCount = 0;
        this.stopKeepalive();

        // Destroy old crypto session
        if (this.session) {
            try { this.session.destroy(); } catch { }
            this.session = null;
        }

        // A later explicit send creates a fresh connection and fresh streams.
        for (const stream of Array.from(this.streams.values())) {
            try { stream.abort('disconnect'); } catch { }
        }
        this.streams.clear();

        if (this._bridgeHandshakeReject) {
            try { this._bridgeHandshakeReject(new Error('Bridge disconnected')); } catch { }
        }
        this._bridgeHandshakeResolve = null;
        this._bridgeHandshakeReject = null;
        this._bridgeHandshakeWaitKind = null;
        this.clearPendingHandshakes();
        this._pendingKeyConfirmation?.frame.fill(0);
        this._pendingKeyConfirmation = null;
        this._expectedHandshakeSessionId = null;
        this.bridgeConnectionId = null;
        this.nativeConnectionToken = null;
        this.nativeAuthenticatedConnectionId = null;
        this.resetAudioPathMetrics();
        this.owner.releaseUnauthenticatedBridgeAlias(disconnectedBridgeId);
        this.bridgeMessageQueue = [];
        this.bridgeMessageQueueBytes = 0;
        for (const frame of this.pendingIncomingFrames) frame.fill(0);
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this.role = 'auto';
        this.incomingResponderPromise = null;
        this._connectedAt = null;
        this._lastActivity = 0;
        this.setState('disconnected');
    }

    private async handleTauriBridgeOpened(context: NativeBridgeContext): Promise<void> {
        try {
            this.assertBridgeContextCurrent(context);
            if (this._pendingHandshakeToRespond) {
                const msg = this._pendingHandshakeToRespond;
                this.consumePendingHandshakeReference(msg);
                await this.handleIncomingHandshake(msg, context);
            } else {
                await this.performHandshake();
            }
            this.assertBridgeContextCurrent(context);
            if (this._state !== 'connected' || !this.session) {
                throw new Error('P2P handshake did not establish a session');
            }
        } catch (err) {
            void p2p.disconnect(context.connectionId, context.connectionToken).catch(() => { });
            throw err;
        }
    }

    private handleTauriBridgeClosed(): void {
        this.handleDisconnect();
    }

    // Stop keepalive
    private stopKeepalive(): void {
        if (this.keepaliveTimer) {
            clearInterval(this.keepaliveTimer);
            this.keepaliveTimer = null;
        }
        this.keepalivePromise = null;
    }

    // Start keepalive
    private startKeepalive(): void {
        if (this.keepaliveTimer) return;

        this.keepaliveTimer = setInterval(() => {
            if (this._state !== 'connected') return;
            if (!this.bridgeConnectionId) return;
            if (this.keepalivePromise) return;
            const bridgeGeneration = this.bridgeGeneration;
            let keepalivePromise!: Promise<void>;
            keepalivePromise = this.sendRaw({ type: '__keepalive' })
                .catch(() => {
                    if (
                        bridgeGeneration === this.bridgeGeneration &&
                        this._state === 'connected'
                    ) {
                        this.handleDisconnect();
                    }
                })
                .finally(() => {
                    if (this.keepalivePromise === keepalivePromise) {
                        this.keepalivePromise = null;
                    }
                });
            this.keepalivePromise = keepalivePromise;
        }, P2P_KEEPALIVE_INTERVAL_MS);
    }

    // Handle incoming handshake as responder
    async handleIncomingHandshake(
        handshakeMsg: any,
        expectedContext?: NativeBridgeContext
    ): Promise<void> {
        const context = expectedContext ?? this.captureBridgeContext();
        this.assertBridgeContextCurrent(context);
        this.setState('handshaking');
        let candidateSession: PQNoiseSession | null = null;
        let normalized: any = null;
        let phase = 'verify-init-and-build-response';
        try {
            if (!this.hasTrustedPeerIdentity()) {
                throw new Error('Certified peer identity is unavailable');
            }
            normalized = this.normalizeHandshakeMessage(handshakeMsg);
            const expectedSignerPublicKey = this.peerIdentity?.dilithiumPublicKey;
            if (
                this.peerIdentity?.certVerified !== true ||
                expectedSignerPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE
            ) {
                throw new Error('Certified peer signing key unavailable');
            }
            if (!normalized || normalized.type !== 'init') {
                throw new Error('Invalid P2P initiator handshake');
            }
            const { session, response } = await PQNoiseSession.processInitiatorMessage(
                this.localPeerId,
                this.peerId,
                this.ownKeys,
                normalized,
                expectedSignerPublicKey
            );
            candidateSession = session;
            this.assertBridgeContextCurrent(context);

            this.session = session;
            const confirmationPromise = this.waitForKeyConfirmation(context, session);
            phase = 'send-response';
            try {
                this.assertBridgeContextCurrent(context);
                await this.sendRaw(this.prepareHandshakeObject(response));
            } catch (error) {
                void confirmationPromise.catch(() => { });
                throw error;
            }

            phase = 'wait-confirmation';
            const confirmation = await confirmationPromise;
            try {
                this.assertBridgeContextCurrent(context);
                phase = 'verify-confirmation';
                await session.verifyKeyConfirmation(
                    confirmation.frame,
                    this.peerId,
                    this.localPeerId
                );
                this.assertBridgeContextCurrent(context);
            } finally {
                confirmation.frame.fill(0);
            }

            const outgoingConfirmation = await session.createKeyConfirmation(
                this.localPeerId,
                this.peerId
            );
            try {
                this.assertBridgeContextCurrent(context);
                phase = 'send-confirmation';
                await this.sendRaw(this.prepareKeyConfirmation(outgoingConfirmation));
            } finally {
                outgoingConfirmation.fill(0);
            }

            phase = 'authenticate-native';
            await this.authenticateNativeConnection();
            this.assertBridgeContextCurrent(context);
            if (!this.hasTrustedPeerIdentity()) {
                throw new Error('Certified peer identity became unavailable during handshake');
            }

            void this.flushPendingIncomingFrames();

            for (const stream of Array.from(this.streams.values())) {
                stream.updateSession(session);
            }

            this.assertBridgeContextCurrent(context);
            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
        } catch (err) {
            this.logHandshakeFailure('responder', phase, err);
            candidateSession?.destroy();
            if (this.session === candidateSession) this.session = null;
            if (this.isBridgeContextCurrent(context)) {
                this.setState('failed');
            }
            throw err;
        } finally {
            this.clearHandshakeBytes(normalized);
        }
    }

    // Handle a signal arriving
    public handleBridgedSignal(msg: any): void {

        this._lastActivity = Date.now();
        if (!this._transport) this._transport = 'p2p';

        if (msg instanceof Uint8Array) {
            this.handleIncomingData(msg);
            return;
        }

        if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
            void this.close('Invalid P2P bridge message type').catch(() => { });
            return;
        }

        if (msg.type === '__keepalive') {
            if (Object.keys(msg).length !== 1 || this._state !== 'connected') {
                void this.close('Invalid P2P keepalive schema').catch(() => { });
            }
            return;
        }

        if (msg.type === 'confirm') {
            const confirmation = this.normalizeKeyConfirmation(msg);
            if (!confirmation || this._state !== 'handshaking') {
                confirmation?.frame.fill(0);
                void this.close('Invalid or out-of-order P2P key confirmation').catch(() => { });
                return;
            }
            if (this._bridgeHandshakeWaitKind === 'confirm' && this._bridgeHandshakeResolve) {
                this._bridgeHandshakeResolve(msg);
                confirmation.frame.fill(0);
                return;
            }
            this._pendingKeyConfirmation?.frame.fill(0);
            this._pendingKeyConfirmation = confirmation;
            return;
        }

        const handshake = this.normalizeHandshakeMessage(msg);
        if (!handshake) {
            void this.close('Invalid P2P handshake schema').catch(() => { });
            return;
        }
        if (this._state === 'connected' || this._state === 'disconnected' || this._state === 'failed') {
            this.clearHandshakeBytes(handshake);
            void this.close('P2P handshake arrived outside handshake state').catch(() => { });
            return;
        }
        if (this._bridgeHandshakeWaitKind === 'handshake' && this._bridgeHandshakeResolve) {
            this._bridgeHandshakeResolve(handshake);
            return;
        }

        if (handshake.type === 'response' || this._bridgeHandshakeWaitKind === 'confirm') {
            this.clearHandshakeBytes(handshake);
            void this.close('Out-of-order P2P handshake message').catch(() => { });
            return;
        }
        if (this.incomingResponderPromise || this._pendingHandshakeToRespond) {
            this.clearHandshakeBytes(handshake);
            void this.close('Repeated P2P handshake init').catch(() => { });
            return;
        }

        this._pendingHandshakeMessage = handshake;
        if (handshake.type === 'init') {
            this._pendingHandshakeToRespond = handshake;
        }
    }

    private clearFailedConnectionState(): void {
        this.stopKeepalive();

        if (this.session) {
            try { this.session.destroy(); } catch { }
            this.session = null;
        }
        for (const stream of Array.from(this.streams.values())) {
            try { stream.abort('connection-failed'); } catch { }
        }
        this.streams.clear();

        if (this._bridgeHandshakeReject) {
            try { this._bridgeHandshakeReject(new Error('P2P connection failed')); } catch { }
        }
        this._bridgeHandshakeResolve = null;
        this._bridgeHandshakeReject = null;
        this._bridgeHandshakeWaitKind = null;
        this.clearPendingHandshakes();
        this._pendingKeyConfirmation?.frame.fill(0);
        this._pendingKeyConfirmation = null;
        this._expectedHandshakeSessionId = null;

        this.bridgeMessageQueue = [];
        this.bridgeMessageQueueBytes = 0;
        for (const frame of this.pendingIncomingFrames) frame.fill(0);
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this._connectedAt = null;
        this._lastActivity = 0;
    }

    // Set state
    private setState(state: ConnectionState): void {
        if (this._state === state) return;

        this._state = state;
        this.stateUpdatedAt = Date.now();

        if (state === 'failed') {
            const failedConnectionId = this.bridgeConnectionId;
            const failedConnectionToken = this.nativeConnectionToken;
            this.bridgeGeneration += 1;
            this.bridgeConnectionId = null;
            this.nativeConnectionToken = null;
            this.nativeAuthenticatedConnectionId = null;
            this.resetAudioPathMetrics();
            this.owner.releaseUnauthenticatedBridgeAlias(failedConnectionId);
            
            this.clearFailedConnectionState();
            if (failedConnectionId && failedConnectionToken) {
                void p2p.disconnect(failedConnectionId, failedConnectionToken).catch(() => { });
            }
        }

        if (state === 'connected') {
            this.markNativeConnectionAuthenticated();
            void this.flushPendingIncomingFrames();
        }

        if (state === 'connected' || state === 'disconnected' || state === 'failed') {
            if (this.stuckStateWatchdog) {
                clearTimeout(this.stuckStateWatchdog);
                this.stuckStateWatchdog = null;
            }
        } else if (!this.stuckStateWatchdog) {
            this.stuckStateWatchdog = setTimeout(() => {
                this.stuckStateWatchdog = null;
                if (this._state !== 'connected' && this._state !== 'disconnected' && this._state !== 'failed') {
                    console.warn('[P2PConnection] wedged not-connected too long, forcing failed', {
                        state: this._state
                    });
                    this.setState('failed');
                }
            }, P2P_STUCK_STATE_TIMEOUT_MS);
        }

        for (const handler of Array.from(this.stateHandlers)) {
            try {
                handler(state);
            } catch { }
        }

        if (typeof window !== 'undefined') {
            const event = new CustomEvent(EventType.P2P_CONNECTION_STATE_CHANGE, {
                detail: { peerId: this.owner.resolveAppPeerId(this.peerId), state }
            });
            window.dispatchEvent(event);
        }

        if (state === 'failed') {
            this.streamHandlers.clear();
            this.stateHandlers.clear();
        }
    }

    private async authenticateNativeConnection(): Promise<void> {
        if (!isTauri()) return;
        if (
            this.bridgeConnectionId &&
            this.nativeAuthenticatedConnectionId === this.bridgeConnectionId
        ) return;
        if (
            !this.hasTrustedPeerIdentity() ||
            !this.bridgeConnectionId ||
            !this.nativeConnectionToken
        ) {
            throw new Error('Certified native P2P connection is unavailable');
        }

        const nativeConnectionId = this.bridgeConnectionId;
        const nativeConnectionToken = this.nativeConnectionToken;
        const bridgeGeneration = this.bridgeGeneration;
        const authenticated = await p2p.authenticateConnection(
            nativeConnectionId,
            nativeConnectionToken
        );
        if (
            !authenticated ||
            this.bridgeGeneration !== bridgeGeneration ||
            this.bridgeConnectionId !== nativeConnectionId ||
            this.nativeConnectionToken !== nativeConnectionToken ||
            this._state === 'failed' ||
            this._state === 'disconnected'
        ) {
            throw new Error('Native P2P authentication registration failed');
        }
        this.nativeAuthenticatedConnectionId = nativeConnectionId;
    }

    private markNativeConnectionAuthenticated(): void {
        if (this._state !== 'connected') return;
        void this.authenticateNativeConnection().catch(() => {
            if (this._state === 'connected') {
                void this.close('native-authentication-registration-failed').catch(() => { });
            }
        });
    }

    // Create a new stream
    async createStream(options: StreamOptions): Promise<SecureStream> {
        if (!this.session || this._state !== 'connected') {
            throw new Error('Not connected');
        }

        const id = options.id ?? `${options.type}:${PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(8))}`;
        const parsedType = parseStreamType(id);
        if (!parsedType || parsedType !== options.type) {
            throw new Error('Invalid stream ID');
        }

        const existing = this.streams.get(id);
        if (existing && !existing.closed) {
            if (existing.type !== options.type || existing.lossy !== (options.lossy || false)) {
                throw new Error('Stream ID is already in use with different options');
            }
            return existing;
        }
        if (existing) this.streams.delete(id);

        if (this.streams.size >= P2P_MAX_STREAMS_PER_CONNECTION) {
            throw new Error('Maximum streams reached');
        }

        const stream = new P2PStream(
            id,
            options.type,
            this.peerId,
            options.lossy || false,
            this.session,
            this
        );

        this.streams.set(id, stream);

        if (options.type === SignalType.MESSAGE) {
            this.startControlMessageReader(stream);
        }

        return stream;
    }

    // Get a stream by type
    getStream(type: StreamType): SecureStream | null {
        for (const stream of Array.from(this.streams.values())) {
            if (stream.type === type && !stream.closed) {
                return stream;
            }
        }
        return null;
    }

    getStreamById(id: string): SecureStream | null {
        const stream = this.streams.get(id);
        return stream && !stream.closed ? stream : null;
    }

    getSessionBinding(): string | null {
        return this.session?.isEstablished() ? this.session.getBindingId() : null;
    }

    getAudioLaneTelemetry(): AudioLaneTelemetry | null {
        return this.audioLaneTelemetry;
    }

    private resetAudioPathMetrics(): void {
        this.audioLaneTelemetry = null;
        this.sentAudioEndpointUrl = null;
        this.primaryPathRttMs = null;
        this.audioLaneEnterSamples = 0;
        this.audioLaneExitSamples = 0;
    }

    private updateAudioPathHysteresis(): void {
        const telemetry = this.audioLaneTelemetry;
        const primaryRttMs = this.primaryPathRttMs;
        if (!telemetry || primaryRttMs === null) {
            this.audioLaneEnterSamples = 0;
            this.audioLaneExitSamples = 0;
            return;
        }
        if (telemetry.selectedPath === 'lane' && telemetry.selectedLane) {
            this.audioLaneEnterSamples = 0;
            const selectedRttMs = telemetry.lanes.find(
                lane => lane.id === telemetry.selectedLane
            )?.rttMs;
            if (
                typeof selectedRttMs === 'number' &&
                Number.isFinite(selectedRttMs) &&
                selectedRttMs > 0 &&
                hasMeaningfulAudioPathAdvantage(selectedRttMs, primaryRttMs)
            ) {
                this.audioLaneExitSamples = Math.min(
                    AUDIO_LANE_PATH_SWITCH_CONFIRMATIONS,
                    this.audioLaneExitSamples + 1
                );
            } else {
                this.audioLaneExitSamples = 0;
            }
            return;
        }
        this.audioLaneExitSamples = 0;
        const measuredLaneRtts = telemetry.lanes
            .map(lane => lane.rttMs)
            .filter((rttMs): rttMs is number => (
                typeof rttMs === 'number' && Number.isFinite(rttMs) && rttMs > 0
            ));
        const fastestLaneRttMs = measuredLaneRtts.length > 0
            ? Math.min(...measuredLaneRtts)
            : null;
        if (
            fastestLaneRttMs !== null &&
            hasMeaningfulAudioPathAdvantage(primaryRttMs, fastestLaneRttMs)
        ) {
            this.audioLaneEnterSamples = Math.min(
                AUDIO_LANE_PATH_SWITCH_CONFIRMATIONS,
                this.audioLaneEnterSamples + 1
            );
        } else {
            this.audioLaneEnterSamples = 0;
        }
    }

    updatePrimaryPathRtt(rttMs: number): void {
        if (!Number.isFinite(rttMs) || rttMs <= 0 || rttMs > 60_000) return;
        const sample = Math.round(rttMs);
        this.primaryPathRttMs = this.primaryPathRttMs === null
            ? sample
            : Math.round((this.primaryPathRttMs * 7 + sample) / 8);
        this.updateAudioPathHysteresis();
    }

    // Close a stream
    closeStream(streamId: string): void {
        this.streams.delete(streamId);
    }

    // Abort a stream
    abortStream(streamId: string, _reason?: string): void {
        this.streams.delete(streamId);
    }

    // Close the connection
    async close(_reason?: string): Promise<void> {
        const nativeConnectionId = this.bridgeConnectionId || this.peerId;
        const nativeConnectionToken = this.nativeConnectionToken || undefined;
        const closingBridgeId = this.bridgeConnectionId;
        this.bridgeGeneration += 1;
        this.protocolViolationCount = 0;
        this.stopKeepalive();
        this.bridgeConnectionId = null;
        this.nativeConnectionToken = null;
        this.nativeAuthenticatedConnectionId = null;
        this.resetAudioPathMetrics();
        this.owner.releaseUnauthenticatedBridgeAlias(closingBridgeId);

        if (this._bridgeHandshakeReject) {
            try { this._bridgeHandshakeReject(new Error('P2P connection closed')); } catch { }
        }
        this._bridgeHandshakeResolve = null;
        this._bridgeHandshakeReject = null;
        this._bridgeHandshakeWaitKind = null;
        this.clearPendingHandshakes();
        this._pendingKeyConfirmation?.frame.fill(0);
        this._pendingKeyConfirmation = null;
        this._expectedHandshakeSessionId = null;
        this.bridgeMessageQueue = [];
        this.bridgeMessageQueueBytes = 0;
        this.incomingResponderPromise = null;

        for (const stream of Array.from(this.streams.values())) {
            stream.abort('connection-close');
        }
        this.streams.clear();
        this.streamHandlers.clear();

        if (this.session) {
            this.session.destroy();
            this.session = null;
        }
        for (const frame of this.pendingIncomingFrames) frame.fill(0);
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this._connectedAt = null;
        this._lastActivity = 0;

        this.setState('disconnected');
        this.stateHandlers.clear();

        try { await p2p.disconnect(nativeConnectionId, nativeConnectionToken); } catch { }
    }

    // Register a stream handler
    onStream(handler: (stream: SecureStream) => void): () => void {
        this.streamHandlers.add(handler);
        return () => this.streamHandlers.delete(handler);
    }

    // Register a state change handler
    onStateChange(handler: (state: ConnectionState) => void): () => void {
        this.stateHandlers.add(handler);
        return () => this.stateHandlers.delete(handler);
    }

    // Internal deliver incoming stream
    _deliverIncomingStream(stream: P2PStream): void {
        this.streams.set(stream.id, stream);
        for (const handler of Array.from(this.streamHandlers)) {
            try {
                handler(stream);
            } catch { }
        }
    }

    // Start reading control messages from a stream
    private async startControlMessageReader(stream: P2PStream): Promise<void> {
        try {
            let processedSinceYield = 0;
            for await (const data of stream) {
                if (!data || data.length === 0) {
                    continue;
                }

                let text = '';
                try {
                    text = textDecoder.decode(data);
                    const msg = JSON.parse(text);
                    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
                        throw new Error('Invalid P2P message object');
                    }
                    if (Object.keys(msg).sort().join(',') !== 'from,payload,routeProof,signature,timestamp,to,type') {
                        throw new Error('Invalid P2P message schema');
                    }
                    if (msg.type !== SignalType.SEALED_ENVELOPE) {
                        throw new Error('Unsupported P2P message type');
                    }

                    const from = this.owner.resolveAppPeerId(this.peerIdentity?.username || this.peerId);
                    if (typeof msg.from !== 'string' || this.owner.resolveAppPeerId(msg.from) !== from) {
                        throw new Error('P2P sender does not match authenticated connection');
                    }
                    const to = typeof msg.to === 'string'
                        ? this.owner.resolveAppPeerId(msg.to)
                        : '';
                    if (!to || to !== this.owner.getLocalUsername()) {
                        throw new Error('P2P recipient does not match local identity');
                    }


                    this.owner.dispatchMessage({
                        from,
                        to,
                        type: msg.type as SignalType,
                        payload: msg.payload,
                        timestamp: msg.timestamp,
                        sequence: BigInt(0),
                        verified: false,
                        routeProof: msg.routeProof,
                        signature: msg.signature,
                        wireBytes: data.byteLength
                    });
                } catch (err) {
                    console.warn('[P2P-RECV] malformed authenticated frame dropped', {
                        bytes: data.byteLength,
                        error: err instanceof Error ? err.message : String(err)
                    });
                    this.noteProtocolViolation('Repeated malformed authenticated P2P messages');
                } finally {
                    data.fill(0);
                }

                processedSinceYield++;
                if (processedSinceYield >= 8 || data.length > 32 * 1024) {
                    processedSinceYield = 0;
                    await new Promise<void>((resolve) => setTimeout(resolve, 0));
                }
            }
        } catch {
        }
    }

    private shouldProcessBridgeMessageImmediately(message: any): boolean {
        return message instanceof Uint8Array || (message && typeof message === 'object');
    }

    private processBridgeEventMessage(message: any, checkHandshake: boolean): void {
        this.handleBridgedSignal(message);
        if (!checkHandshake || this._state === 'connected') return;
        if (
            (this._state === 'connecting' || this._state === 'handshaking') &&
            this._pendingHandshakeToRespond?.type === 'init'
        ) {
            this.ensureIncomingResponderActive();
        }
    }

    private async drainBridgeMessageQueue(): Promise<void> {
        const bridgeGeneration = this.bridgeGeneration;
        try {
            while (
                bridgeGeneration === this.bridgeGeneration &&
                this.bridgeMessageQueue.length > 0
            ) {
                const batch = this.bridgeMessageQueue;
                this.bridgeMessageQueue = [];
                this.bridgeMessageQueueBytes = 0;

                let processedSinceYield = 0;
                for (const entry of batch) {
                    if (bridgeGeneration !== this.bridgeGeneration) break;
                    try {
                        this.processBridgeEventMessage(entry.message, entry.checkHandshake);
                    } catch {
                    }
                    processedSinceYield++;
                    if (processedSinceYield >= 8) {
                        processedSinceYield = 0;
                        await new Promise<void>((resolve) => setTimeout(resolve, 0));
                    }
                }
            }
        } finally {
            this.bridgeQueueDraining = false;
            if (this.bridgeMessageQueue.length > 0) {
                this.bridgeQueueDraining = true;
                void this.drainBridgeMessageQueue();
            }
        }
    }

    // Get the session
    getSession(): PQNoiseSession | null {
        return this.session;
    }

    public getStateAgeMs(): number {
        return Date.now() - this.stateUpdatedAt;
    }
}

/**
 * P2P Transport
 */
export class P2PTransport implements SecureTransport {
    private initialized: boolean = false;
    private initializing: boolean = false;
    private localUsername: string = '';
    private localPeerId: string = '';
    private ownKeys: OwnKeys | null = null;

    private connections: Map<string, P2PConnection> = new Map();
    private messageHandlers: Set<MessageHandler> = new Set();
    private connectHandlers: Set<(peerId: string) => void> = new Set();
    private disconnectHandlers: Set<(peerId: string, reason?: string) => void> = new Set();

    private usernameAliases: Map<string, string> = new Map();
    private authenticatedBridgeAliases: Set<string> = new Set();
    private knownPeerIdentities: Map<string, PeerIdentity> = new Map();
    private peerIdentityEpochs: Map<string, number> = new Map();
    private authenticatedEndpoints: Map<string, {
        endpointUrl: string | null;
        signerPublicKeyBase64: string;
        announcedAt: number;
    }> = new Map();
    private peerCertRequestTimestamps: Map<string, number> = new Map();
    private peerCertRequestWindow = { startedAt: 0, count: 0 };
    private connectSingleflight: Map<string, Promise<SecureConnection>> = new Map();
    private initializationPromise: Promise<void> | null = null;
    private shutdownPromise: Promise<void> | null = null;
    private lifecycleGeneration: number = 0;
    private nativeIdentityReady: boolean = true;
    private localEndpointCache: {
        generation: number;
        endpointUrl: string | undefined;
        expiresAt: number;
    } | null = null;
    private localEndpointPromise: Promise<string | undefined> | null = null;

    private readonly MAX_USERNAME_ALIASES = 500;
    private readonly MAX_KNOWN_IDENTITIES = 500;
    private readonly MAX_CERT_REQUEST_TIMESTAMPS = 200;
    private readonly MAX_CERT_REQUESTS_PER_MINUTE = 12;
    private readonly MAX_CONNECTIONS = 64;

    private bridgeEventUnlisten: UnlistenFn | null = null;
    private inboundBridgeEventQueue: Array<{
        data: any;
        byteLength: number;
        generation: number;
    }> = [];
    private inboundBridgeEventDraining: boolean = false;
    private readonly MAX_INBOUND_BRIDGE_EVENT_QUEUE = 1024;
    private inboundBridgeEventCount = 0;
    private inboundBridgeEventBytes = 0;
    private readonly MAX_INBOUND_BRIDGE_EVENT_BYTES = 16 * 1024 * 1024;

    private isOpaqueBridgeId(value: string): boolean {
        return BRIDGE_PEER_ID_REGEX.test(value);
    }

    private isSafePeerId(value: string): boolean {
        if (!value) return false;
        if (this.isOpaqueBridgeId(value)) return true;
        return /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(value);
    }

    private validateCertifiedPeerIdentity(peerId: string, identity: PeerIdentity): PeerIdentity {
        if (
            !AUTH_USERNAME_REGEX.test(peerId) ||
            identity?.certVerified !== true ||
            identity.username !== peerId ||
            identity.kyberPublicKey?.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            identity.dilithiumPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            identity.x25519PublicKey?.length !== X25519_PUBLIC_KEY_LENGTH ||
            !Number.isSafeInteger(identity.certificateExpiresAt)
        ) {
            throw new Error('Invalid certified P2P peer identity');
        }

        let endpointUrl: string | undefined;
        if (identity.endpointUrl !== undefined) {
            const parsed = parseP2PEndpointUrl(identity.endpointUrl);
            if (!parsed) throw new Error('Invalid certified P2P endpoint');
            endpointUrl = parsed.endpointUrl;
        }

        return {
            username: peerId,
            kyberPublicKey: identity.kyberPublicKey.slice(),
            dilithiumPublicKey: identity.dilithiumPublicKey.slice(),
            x25519PublicKey: identity.x25519PublicKey.slice(),
            ...(endpointUrl ? { endpointUrl } : {}),
            certificateExpiresAt: identity.certificateExpiresAt,
            certVerified: true
        };
    }

    private validateInitialization(options: TransportInitOptions): void {
        if (
            !AUTH_USERNAME_REGEX.test(options.localUsername) ||
            options.kyberPublicKey?.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            options.dilithiumPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            options.x25519PublicKey?.length !== X25519_PUBLIC_KEY_LENGTH ||
            typeof options.signTranscript !== 'function' ||
            typeof options.respondToHandshake !== 'function'
        ) {
            throw new Error('Invalid local P2P transport identity');
        }
    }

    private async validateInitializationKeyPairs(options: TransportInitOptions): Promise<void> {
        const challenge = textEncoder.encode(`${PROTOCOL_KEYS.P2P_LOCAL_KEY_SELF_TEST}\0${options.localUsername}`);
        let kemCiphertext: Uint8Array | null = null;
        let encapsulatedSecret: Uint8Array | null = null;
        let decapsulatedSecret: Uint8Array | null = null;
        let signature: Uint8Array | null = null;
        let testX25519Secret: Uint8Array | null = null;
        let testX25519Public: Uint8Array | null = null;
        let expectedX25519Secret: Uint8Array | null = null;
        let nativeX25519Secret: Uint8Array | null = null;
        try {
            const encapsulated = await (await import('../cryptography/kem')).PostQuantumKEM.encapsulate(
                options.kyberPublicKey
            );
            kemCiphertext = encapsulated.ciphertext;
            encapsulatedSecret = encapsulated.sharedSecret;
            testX25519Secret = PostQuantumRandom.randomBytes(X25519_PUBLIC_KEY_LENGTH);
            testX25519Public = new Uint8Array(x25519.getPublicKey(testX25519Secret));
            expectedX25519Secret = new Uint8Array(
                x25519.getSharedSecret(testX25519Secret, options.x25519PublicKey)
            );
            const nativeSecrets = await options.respondToHandshake(kemCiphertext, testX25519Public);
            decapsulatedSecret = nativeSecrets.pqSecret;
            nativeX25519Secret = nativeSecrets.x25519Secret;
            if (!PostQuantumUtils.timingSafeEqual(encapsulatedSecret, decapsulatedSecret)) {
                throw new Error('Local ML-KEM public/private key mismatch');
            }
            if (
                nativeX25519Secret.length !== X25519_PUBLIC_KEY_LENGTH ||
                !PostQuantumUtils.timingSafeEqual(expectedX25519Secret, nativeX25519Secret)
            ) {
                throw new Error('Local X25519 public/private key mismatch');
            }

            signature = await options.signTranscript(challenge);
            if (!await PostQuantumSignature.verify(
                signature,
                challenge,
                options.dilithiumPublicKey
            )) {
                throw new Error('Local ML-DSA public/private key mismatch');
            }
        } finally {
            challenge.fill(0);
            kemCiphertext?.fill(0);
            encapsulatedSecret?.fill(0);
            decapsulatedSecret?.fill(0);
            signature?.fill(0);
            testX25519Secret?.fill(0);
            testX25519Public?.fill(0);
            expectedX25519Secret?.fill(0);
            nativeX25519Secret?.fill(0);
        }
    }

    private matchesInitialization(options: TransportInitOptions): boolean {
        if (!this.ownKeys || this.localUsername !== options.localUsername || this.localPeerId !== options.localUsername) {
            return false;
        }
        const same = (left: Uint8Array, right: Uint8Array): boolean =>
            left.length === right.length && PostQuantumUtils.timingSafeEqual(left, right);
        return same(this.ownKeys.kyberPublicKey, options.kyberPublicKey) &&
            same(this.ownKeys.dilithiumPublicKey, options.dilithiumPublicKey) &&
            same(this.ownKeys.x25519PublicKey, options.x25519PublicKey);
    }

    private clearOwnKeys(): void {
        this.ownKeys?.kyberPublicKey.fill(0);
        this.ownKeys?.dilithiumPublicKey.fill(0);
        this.ownKeys?.x25519PublicKey.fill(0);
        this.ownKeys = null;
    }

    private inferPeerFromHandshakeInit(message: unknown): string | null {
        const parseCandidate = (candidate: any): string | null => {
            if (!candidate || typeof candidate !== 'object') return null;
            if (candidate.type !== 'init' || typeof candidate.from !== 'string') return null;
            const expectedKeys = [
                'ephemeralKyberPublic',
                'ephemeralX25519Public',
                'from',
                'kemCiphertext',
                'sessionId',
                'signature',
                'signerPublicKey',
                'timestamp',
                'to',
                'type',
                'version'
            ].sort().join(',');
            if (Object.keys(candidate).sort().join(',') !== expectedKeys) return null;
            if (candidate.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION) return null;
            if (typeof candidate.sessionId !== 'string' || !/^[a-f0-9]{32}$/.test(candidate.sessionId)) return null;
            if (!Number.isSafeInteger(candidate.timestamp)) return null;
            const from = candidate.from.trim();
            if (from !== candidate.from || !AUTH_USERNAME_REGEX.test(from)) return null;
            if (candidate.to !== this.localPeerId) return null;
            const fields: Array<[unknown, number]> = [
                [candidate.ephemeralKyberPublic, PQ_KEM_PUBLIC_KEY_SIZE],
                [candidate.kemCiphertext, PQ_KEM_CIPHERTEXT_SIZE],
                [candidate.ephemeralX25519Public, X25519_PUBLIC_KEY_LENGTH],
                [candidate.signature, PQ_SIG_SIGNATURE_SIZE],
                [candidate.signerPublicKey, PQ_SIG_PUBLIC_KEY_SIZE]
            ];
            for (const [value, length] of fields) {
                const decoded = tryDecodeCanonicalBase64(value, 'P2P certificate field', { exactBytes: length });
                if (!decoded) return null;
                decoded.fill(0);
            }
            return from;
        };

        if (message && typeof message === 'object' && !(message instanceof Uint8Array)) {
            return parseCandidate(message);
        }
        return null;
    }

    private resolvePeerKey(peerId: string): string | null {
        if (!peerId) return null;
        const alias = this.usernameAliases.get(peerId);
        if (this.isOpaqueBridgeId(peerId)) {
            return alias || peerId;
        }
        return peerId;
    }

    private getPeerIdentityEpoch(peerId: string): number {
        return this.peerIdentityEpochs.get(peerId) || 0;
    }

    private bumpPeerIdentityEpoch(peerId: string): number {
        const current = this.getPeerIdentityEpoch(peerId);
        const next = current >= Number.MAX_SAFE_INTEGER ? 1 : current + 1;
        this.peerIdentityEpochs.delete(peerId);
        this.peerIdentityEpochs.set(peerId, next);
        while (this.peerIdentityEpochs.size > this.MAX_KNOWN_IDENTITIES) {
            const oldest = this.peerIdentityEpochs.keys().next().value as string | undefined;
            if (!oldest) break;
            this.peerIdentityEpochs.delete(oldest);
        }
        return next;
    }

    private isCurrentConnection(peerKey: string, connection: P2PConnection): boolean {
        return this.connections.get(peerKey) === connection;
    }

    private connectionReadinessScore(connection: P2PConnection | null | undefined): number {
        if (!connection) return -1;
        const hasSession = !!connection.getSession();
        if (connection.state === 'connected' && hasSession) return 4;
        if (connection.state === 'handshaking' && hasSession) return 3;
        if (connection.state === 'connected') return 2;
        if (connection.state === 'handshaking' || connection.state === 'connecting') return 1;
        return 0;
    }

    private estimateBridgeEventBytes(data: any): number {
        const payload = data?.data;
        if (payload instanceof Uint8Array) return payload.byteLength;
        if (typeof payload === 'string') return payload.length;
        try {
            return JSON.stringify(data)?.length ?? 0;
        } catch {
            return this.MAX_INBOUND_BRIDGE_EVENT_BYTES + 1;
        }
    }

    private enqueueInboundBridgeEvent(data: any, generation: number): void {
        if (
            generation !== this.lifecycleGeneration ||
            (!this.initialized && !this.initializing) ||
            !this.ownKeys ||
            !data ||
            typeof data !== 'object'
        ) return;
        if (data.type === '__p2p_connected') return;

        const size = this.estimateBridgeEventBytes(data);
        if (!Number.isSafeInteger(size) || size <= 0 || size > this.MAX_INBOUND_BRIDGE_EVENT_BYTES) {
            const connectionId = data.connectionId;
            const connectionToken = data.connectionToken;
            if (
                typeof connectionId === 'string' &&
                this.isSafePeerId(connectionId) &&
                isNativeConnectionToken(connectionToken)
            ) {
                void p2p.disconnect(connectionId, connectionToken).catch(() => { });
            }
            return;
        }

        const isClosedEvent = data.type === '__p2p_closed';
        const isOverLimit = () =>
            this.inboundBridgeEventCount >= this.MAX_INBOUND_BRIDGE_EVENT_QUEUE ||
            this.inboundBridgeEventBytes + size > this.MAX_INBOUND_BRIDGE_EVENT_BYTES;

        if (isClosedEvent && isOverLimit()) {
            try {
                this.processInboundBridgeEvent(data);
            } catch { }
            return;
        } else if (isOverLimit()) {
            const connectionId = data.connectionId;
            const connectionToken = data.connectionToken;
            if (
                typeof connectionId === 'string' &&
                this.isSafePeerId(connectionId) &&
                isNativeConnectionToken(connectionToken)
            ) {
                void p2p.disconnect(connectionId, connectionToken).catch(() => { });
            }
            return;
        }

        this.inboundBridgeEventQueue.push({ data, byteLength: size, generation });
        this.inboundBridgeEventCount += 1;
        this.inboundBridgeEventBytes += size;
        if (!this.inboundBridgeEventDraining) {
            this.inboundBridgeEventDraining = true;
            void this.drainInboundBridgeEventQueue();
        }
    }

    private async drainInboundBridgeEventQueue(): Promise<void> {
        try {
            while (this.inboundBridgeEventQueue.length > 0) {
                const batch = this.inboundBridgeEventQueue;
                this.inboundBridgeEventQueue = [];

                let processedSinceYield = 0;
                for (const entry of batch) {
                    try {
                        if (
                            entry.generation === this.lifecycleGeneration &&
                            (this.initialized || this.initializing) &&
                            this.ownKeys
                        ) {
                            this.processInboundBridgeEvent(entry.data);
                        }
                    } catch {
                    } finally {
                        entry.data = null;
                        this.inboundBridgeEventCount = Math.max(
                            0,
                            this.inboundBridgeEventCount - 1
                        );
                        this.inboundBridgeEventBytes = Math.max(
                            0,
                            this.inboundBridgeEventBytes - entry.byteLength
                        );
                    }
                    processedSinceYield++;
                    if (processedSinceYield >= 4) {
                        processedSinceYield = 0;
                        await new Promise<void>((resolve) => setTimeout(resolve, 0));
                    }
                }
            }
        } finally {
            this.inboundBridgeEventDraining = false;
            if (this.inboundBridgeEventQueue.length > 0) {
                this.inboundBridgeEventDraining = true;
                void this.drainInboundBridgeEventQueue();
            }
        }
    }

    private processInboundBridgeEvent(data: any): void {
        if (!data || typeof data !== 'object') return;
        const connectionId = (data as any).connectionId;
        if (typeof connectionId !== 'string' || !connectionId) {
            console.warn('[P2P-RECV] DROP: event missing connectionId', { type: data?.type });
            return;
        }
        const connectionToken = (data as any).connectionToken;
        if (!isNativeConnectionToken(connectionToken)) {
            console.warn('[P2P-RECV] DROP: event missing connection generation', { type: data?.type });
            return;
        }
        const inferredHandshakePeer = data.type === 'message'
            ? this.inferPeerFromHandshakeInit(data.data)
            : null;

        if (
            inferredHandshakePeer &&
            (
                !blockingSystem.isEnforcementReady() ||
                blockingSystem.isBlockedSync(inferredHandshakePeer)
            )
        ) {
            void p2p.disconnect(connectionId, connectionToken).catch(() => { });
            return;
        }

        let connection = this.connections.get(connectionId);
        let adoptedInboundGeneration = false;
        const alias = this.usernameAliases.get(connectionId);
        const aliasConnection = alias ? this.connections.get(alias) : undefined;
        if (!connection && aliasConnection && (
            this.authenticatedBridgeAliases.has(connectionId) ||
            aliasConnection.ownsExactBridgeConnection(connectionId, connectionToken)
        )) {
            connection = aliasConnection;
        } else if (connection && aliasConnection && aliasConnection !== connection) {
            const directScore = this.connectionReadinessScore(connection);
            const aliasScore = this.connectionReadinessScore(aliasConnection);
            if (aliasScore > directScore) {
                if (this.connections.get(connectionId) === connection) {
                    this.connections.delete(connectionId);
                }
                connection = aliasConnection;
            }
        }

        if (!connection) {
            for (const conn of this.connections.values()) {
                if (conn.ownsBridgeConnection(connectionId, connectionToken)) {
                    connection = conn;
                    break;
                }
            }
        }

        if (
            connection &&
            inferredHandshakePeer &&
            !connection.hasNativeConnectionGeneration() &&
            (connection.state === 'connecting' || connection.state === 'handshaking') &&
            connection.peerIdentity?.username === inferredHandshakePeer
        ) {
            try {
                connection.adoptIncomingBridgeConnection(connectionId, connectionToken);
                adoptedInboundGeneration = true;
            } catch {
                void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                return;
            }
        }

        if (!connection && data.type === 'message') {
            const inferredPeer = inferredHandshakePeer || '';

            if (inferredPeer && this.ownKeys) {
                const peerKey = this.resolvePeerKey(inferredPeer) || inferredPeer;
                let existingForPeer = this.connections.get(peerKey);
                if (existingForPeer && !existingForPeer.ownsExactBridgeConnection(connectionId, connectionToken)) {
                    const readiness = this.connectionReadinessScore(existingForPeer);
                    const keepExistingGeneration =
                        readiness >= 4 ||
                        this.localPeerId < inferredPeer;
                    if (readiness > 0 && keepExistingGeneration) {
                        if (!this.authenticatedBridgeAliases.has(connectionId)) {
                            this.usernameAliases.delete(connectionId);
                        }
                        void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                        return;
                    }
                    if (readiness > 0) {
                        try {
                            existingForPeer.adoptIncomingBridgeConnection(connectionId, connectionToken);
                            connection = existingForPeer;
                            adoptedInboundGeneration = true;
                        } catch {
                            void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                            return;
                        }
                    } else {
                        this.connections.delete(peerKey);
                        void existingForPeer.close('replace-terminal-inbound-connection').catch(() => { });
                        existingForPeer = undefined;
                    }
                }

                if (connection) {
                } else if (existingForPeer) {
                    connection = existingForPeer;
                } else if (this.connections.size >= this.MAX_CONNECTIONS) {
                    console.warn('[P2P-RECV] DROP: connection cap reached; refusing new inbound peer', {
                        cap: this.MAX_CONNECTIONS
                    });
                    void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                    return;
                } else {
                    if (inferredPeer !== connectionId && !this.registerUsernameAlias(inferredPeer, connectionId, false)) {
                        void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                        return;
                    }
                    const knownIdentity =
                        this.knownPeerIdentities.get(peerKey) ||
                        this.knownPeerIdentities.get(inferredPeer);
                    if (!knownIdentity?.certVerified) {
                        if (!this.authenticatedBridgeAliases.has(connectionId)) {
                            this.usernameAliases.delete(connectionId);
                        }
                        void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                        return;
                    }
                    let identity: PeerIdentity;
                    try {
                        identity = this.validateCertifiedPeerIdentity(inferredPeer, knownIdentity);
                    } catch {
                        void p2p.disconnect(connectionId, connectionToken).catch(() => { });
                        return;
                    }

                    const appPeerId = this.resolveAppPeerId(peerKey);
                    const incomingConnection = new P2PConnection(
                        peerKey,
                        identity,
                        this.ownKeys,
                        this.localPeerId,
                        this
                    );

                    incomingConnection.onStateChange((state) => {
                        if (state === 'connected') {
                            if (!this.isCurrentConnection(peerKey, incomingConnection)) return;
                            if (incomingConnection.peerIdentity?.certVerified !== true) {
                                this.requestPeerCertificate(inferredPeer);
                                return;
                            }
                            for (const handler of Array.from(this.connectHandlers)) {
                                try { handler(appPeerId); } catch { }
                            }
                        } else if (state === 'disconnected' || state === 'failed') {
                            if (!this.isCurrentConnection(peerKey, incomingConnection)) return;
                            this.connections.delete(peerKey);
                            for (const handler of Array.from(this.disconnectHandlers)) {
                                try { handler(appPeerId, state); } catch { }
                            }
                        }
                    });

                    this.connections.set(peerKey, incomingConnection);
                    connection = incomingConnection;
                }
            }
        }

        if (!connection) {
            if (data.type === '__p2p_closed') return;
            console.warn('[P2P-RECV] DROP: no connection for event', {
                type: data?.type
            });

            if (data.type === 'message') {
                void p2p.disconnect(connectionId, connectionToken).catch(() => { });
            }
            return;
        }

        if (
            !adoptedInboundGeneration &&
            connection.hasNativeConnectionGeneration() &&
            !connection.ownsBridgeConnection(connectionId, connectionToken)
        ) {
            void p2p.disconnect(connectionId, connectionToken).catch(() => { });
            return;
        }

        if (data.type === '__p2p_closed') {
            if (!connection.ownsExactBridgeConnection(connectionId, connectionToken)) {
                return;
            }
            connection.handleBridgeEventClosed();
            if (!this.authenticatedBridgeAliases.has(connectionId)) {
                this.usernameAliases.delete(connectionId);
            }
            return;
        }
        if (!adoptedInboundGeneration) {
            connection.attachBridgeConnection(connectionId, connectionToken);
        }
        if (data.type === 'message') {
            connection.handleBridgeEventMessage(data.data);
        }
    }

    public resolveAppPeerId(peerId: string): string {
        if (!peerId) return peerId;
        if (!this.isOpaqueBridgeId(peerId)) return peerId;
        const alias = this.usernameAliases.get(peerId);
        if (alias) return alias;
        return peerId;
    }

    public releaseUnauthenticatedBridgeAlias(connectionId: string | null): void {
        if (
            !connectionId ||
            !this.isOpaqueBridgeId(connectionId) ||
            this.authenticatedBridgeAliases.has(connectionId)
        ) return;
        this.usernameAliases.delete(connectionId);
        this.knownPeerIdentities.delete(connectionId);
    }

    public getLocalUsername(): string {
        return this.localUsername;
    }

    async getLocalEndpointForIdentity(localUsername: string): Promise<string | undefined> {
        if (
            !isTauri() ||
            !this.initialized ||
            this.initializing ||
            !!this.shutdownPromise ||
            !this.nativeIdentityReady ||
            this.localUsername !== localUsername
        ) return undefined;

        const generation = this.lifecycleGeneration;
        if (
            this.localEndpointCache?.generation === generation &&
            this.localEndpointCache.expiresAt > Date.now()
        ) {
            return this.localEndpointCache.endpointUrl;
        }
        if (this.localEndpointPromise) {
            const endpointUrl = await this.localEndpointPromise;
            return this.lifecycleGeneration === generation && this.localUsername === localUsername
                ? endpointUrl
                : undefined;
        }

        const endpointTask = (async (): Promise<string | undefined> => {
            try {
                const parsed = parseP2PEndpointUrl(await p2p.getLocalEndpoint());
                if (
                    generation !== this.lifecycleGeneration ||
                    !this.initialized ||
                    this.initializing ||
                    !!this.shutdownPromise ||
                    !this.nativeIdentityReady ||
                    this.localUsername !== localUsername
                ) return undefined;
                const endpointUrl = parsed?.hasDirectAddress ? parsed.endpointUrl : undefined;
                
                this.localEndpointCache = {
                    generation,
                    endpointUrl,
                    expiresAt: Date.now() + 5_000
                };
                return endpointUrl;
            } catch {
                return undefined;
            }
        })();
        this.localEndpointPromise = endpointTask;
        try {
            return await endpointTask;
        } finally {
            if (this.localEndpointPromise === endpointTask) {
                this.localEndpointPromise = null;
            }
        }
    }

    // Initialize transport
    async initialize(options: TransportInitOptions): Promise<void> {
        if (this.shutdownPromise) {
            await this.shutdownPromise;
        }
        if (isTauri() && !this.nativeIdentityReady) {
            throw new Error('Native P2P identity rotation has not completed');
        }

        if (this.initialized) {
            if (this.matchesInitialization(options)) return;
            throw new Error('P2P transport is initialized for a different local identity');
        }

        if (this.initializationPromise) {
            await this.initializationPromise;
            if (this.initialized) {
                if (this.matchesInitialization(options)) return;
                throw new Error('P2P transport initialization raced with a different local identity');
            }
            if (this.shutdownPromise) {
                await this.shutdownPromise;
            }
            if (isTauri() && !this.nativeIdentityReady) {
                throw new Error('Native P2P identity rotation has not completed');
            }
        }

        this.validateInitialization(options);
        this.initializing = true;
        const generation = ++this.lifecycleGeneration;
        const initializationTask = (async () => {
            try {
                await this.validateInitializationKeyPairs(options);
                if (generation !== this.lifecycleGeneration) {
                    throw new Error('P2P transport lifecycle changed during key validation');
                }
                this.localUsername = options.localUsername;
                this.localPeerId = options.localUsername;
                this.ownKeys = {
                    kyberPublicKey: options.kyberPublicKey.slice(),
                    dilithiumPublicKey: options.dilithiumPublicKey.slice(),
                    x25519PublicKey: options.x25519PublicKey.slice(),
                    signTranscript: options.signTranscript,
                    respondToHandshake: options.respondToHandshake,
                };

                if (isTauri() && !this.bridgeEventUnlisten) {
                    const unlisten = await events.onP2PMessage((evtData: unknown) => {
                        try {
                            this.enqueueInboundBridgeEvent(
                                parseNativeP2PBridgeEnvelope(evtData),
                                generation
                            );
                        } catch { }
                    });
                    if (generation !== this.lifecycleGeneration) {
                        try { unlisten(); } catch { }
                        throw new Error('P2P transport lifecycle changed during initialization');
                    }
                    this.bridgeEventUnlisten = unlisten;
                }

                this.initialized = true;
            } catch (err) {
                if (generation === this.lifecycleGeneration) {
                    this.initialized = false;
                    this.localUsername = '';
                    this.localPeerId = '';
                    this.clearOwnKeys();
                }
                throw new Error(`Failed to initialize P2P transport: ${String((err as any)?.message || err)}`);
            } finally {
                if (generation === this.lifecycleGeneration) {
                    this.initializing = false;
                }
            }
        })();
        this.initializationPromise = initializationTask;
        try {
            await initializationTask;
        } finally {
            if (this.initializationPromise === initializationTask) {
                this.initializationPromise = null;
            }
        }
    }

    // Connect to a peer
    async connect(peerId: string, options: ConnectOptions): Promise<SecureConnection> {
        if (!this.initialized || !this.ownKeys) { throw new Error('Transport not initialized'); }
        const generation = this.lifecycleGeneration;
        const localUsername = this.localUsername;
        const localPeerId = this.localPeerId;
        const ownKeys = this.ownKeys;

        const peerKey = this.resolvePeerKey(peerId);
        if (!peerKey) {
            this.requestPeerCertificate(peerId);
            throw new Error(`Missing peer key for ${peerId}`);
        }
        const peerAlias = this.usernameAliases.get(peerId);
        const certifiedPeerIdentity = this.knownPeerIdentities.get(peerId) ||
            this.knownPeerIdentities.get(peerKey) ||
            (peerAlias ? this.knownPeerIdentities.get(peerAlias) : undefined);
        if (!certifiedPeerIdentity?.certVerified) {
            throw new Error('Certified peer identity required');
        }
        const certifiedUsername = certifiedPeerIdentity.username;
        if (
            !blockingSystem.isEnforcementReady() ||
            blockingSystem.isBlockedSync(certifiedUsername)
        ) {
            throw new Error('P2P connection denied by local policy');
        }
        const peerIdentityEpoch = this.getPeerIdentityEpoch(certifiedUsername);
        const isCurrent = () =>
            generation === this.lifecycleGeneration &&
            this.initialized &&
            this.localUsername === localUsername &&
            this.localPeerId === localPeerId &&
            this.ownKeys === ownKeys &&
            this.getPeerIdentityEpoch(certifiedUsername) === peerIdentityEpoch &&
            !isKeyTransparencyPeerRevoked(localUsername, certifiedUsername);
        const assertCurrent = () => {
            if (!isCurrent()) {
                throw new Error('P2P connect crossed an account or peer-identity transition');
            }
        };
        assertCurrent();
        const inflight = this.connectSingleflight.get(peerKey);
        if (inflight) return inflight;

        const connectPromise = (async (): Promise<SecureConnection> => {
            let lastError: unknown = new Error('P2P connection failed');
            for (let attempt = 0; attempt < INITIAL_BRIDGE_CONNECT_ATTEMPTS; attempt += 1) {
                try {
                    assertCurrent();
                    const appPeerId = this.resolveAppPeerId(peerId);

                    let existing = this.connections.get(peerKey);
                    if (!existing) {
                        const alias = this.usernameAliases.get(peerId);
                        if (alias) existing = this.connections.get(alias);
                    }
                    if (existing) {
                        if (existing.state === 'failed' || existing.state === 'disconnected') {
                            try { await existing.close('stale-state-cleanup'); } catch { }
                            assertCurrent();
                            if (this.isCurrentConnection(peerKey, existing)) {
                                this.connections.delete(peerKey);
                            }
                            existing = undefined;
                        } else if (existing.state === 'connecting' || existing.state === 'handshaking') {
                            if (certifiedPeerIdentity.kyberPublicKey?.length > 0) {
                                existing.updatePeerIdentity(certifiedPeerIdentity);
                            }
                            const stateAgeMs = typeof (existing as any).getStateAgeMs === 'function'
                                ? (existing as any).getStateAgeMs()
                                : 0;
                            if (stateAgeMs > (options.timeout || P2P_CONNECTION_TIMEOUT_MS)) {
                                try { await existing.close('stale-connecting-timeout'); } catch { }
                                assertCurrent();
                                if (this.isCurrentConnection(peerKey, existing)) {
                                    this.connections.delete(peerKey);
                                }
                                existing = undefined;
                            }
                        } else if (existing.state === 'connected') {
                            if (certifiedPeerIdentity.kyberPublicKey?.length > 0) {
                                existing.updatePeerIdentity(certifiedPeerIdentity);
                            }
                        }
                    }

                    if (existing) {
                        if (existing.state === 'connected') {
                            assertCurrent();
                            return existing;
                        }

                        if (existing.state === 'connecting' || existing.state === 'handshaking') {
                            if (certifiedPeerIdentity.kyberPublicKey?.length > 0) {
                                existing.updatePeerIdentity(certifiedPeerIdentity);
                            }

                            return await new Promise<SecureConnection>((resolve, reject) => {
                                let settled = false;
                                const unsubscribe = existing.onStateChange((state) => {
                                    if (settled) return;
                                    if (!isCurrent()) {
                                        settled = true;
                                        clearTimeout(timeout);
                                        try { unsubscribe(); } catch { }
                                        reject(new Error('P2P connect crossed an account transition'));
                                        return;
                                    }
                                    if (state === 'connected') {
                                        settled = true;
                                        clearTimeout(timeout);
                                        try { unsubscribe(); } catch { }
                                        resolve(existing);
                                    } else if (state === 'failed' || state === 'disconnected') {
                                        settled = true;
                                        clearTimeout(timeout);
                                        try { unsubscribe(); } catch { }
                                        reject(new Error(`Connection failed: ${state}`));
                                    }
                                });

                                const timeout = setTimeout(() => {
                                    if (settled) return;
                                    settled = true;
                                    try { unsubscribe(); } catch { }
                                    existing.close('stale-connecting-timeout').catch(() => { });
                                    if (isCurrent() && this.isCurrentConnection(peerKey, existing)) {
                                        this.connections.delete(peerKey);
                                    }
                                    reject(new Error(
                                        isCurrent()
                                            ? 'Connection timeout waiting for existing connection'
                                            : 'P2P connect crossed an account transition'
                                    ));
                                }, options.timeout || P2P_CONNECTION_TIMEOUT_MS);
                            });
                        }

                        if (this.isCurrentConnection(peerKey, existing)) {
                            this.connections.delete(peerKey);
                        }
                    }

                    assertCurrent();
                    if (new Set(this.connections.values()).size >= this.MAX_CONNECTIONS) {
                        throw new Error(`Maximum P2P connections reached (${this.MAX_CONNECTIONS})`);
                    }
                    const connection = new P2PConnection(
                        peerKey,
                        certifiedPeerIdentity,
                        ownKeys,
                        localPeerId,
                        this
                    );

                    connection.onStateChange((state) => {
                        if (!isCurrent()) return;
                        if (state === 'connected') {
                            if (!this.isCurrentConnection(peerKey, connection)) return;
                            for (const handler of Array.from(this.connectHandlers)) {
                                try { handler(appPeerId); } catch { }
                            }
                        } else if (state === 'disconnected' || state === 'failed') {
                            if (!this.isCurrentConnection(peerKey, connection)) return;
                            this.connections.delete(peerKey);
                            for (const handler of Array.from(this.disconnectHandlers)) {
                                try { handler(appPeerId, state); } catch { }
                            }
                        }

                        if (options.onStateChange) {
                            options.onStateChange(state);
                        }
                    });

                    this.connections.set(peerKey, connection);

                    try {
                        await connection.connect();
                        assertCurrent();
                    } catch (error) {
                        try {
                            if (connection.state !== 'disconnected') {
                                await connection.close('connect-attempt-failed');
                            }
                        } catch { }
                        if (this.isCurrentConnection(peerKey, connection)) {
                            this.connections.delete(peerKey);
                        }
                        throw error;
                    }

                    return connection;
                } catch (error) {
                    lastError = error;
                    if (
                        attempt + 1 >= INITIAL_BRIDGE_CONNECT_ATTEMPTS ||
                        !isRetryableInitialBridgeError(error)
                    ) {
                        throw error;
                    }
                    assertCurrent();
                    console.info('[P2P-HS] retrying transient initial bridge failure', {
                        peer: peerId,
                        attempt: attempt + 2,
                        error: error instanceof Error ? error.message : String(error)
                    });
                    await new Promise<void>((resolve) => {
                        setTimeout(resolve, INITIAL_BRIDGE_RETRY_DELAY_MS);
                    });
                }
            }
            throw lastError;
        })();

        this.connectSingleflight.set(peerKey, connectPromise);
        try {
            return await connectPromise;
        } finally {
            if (this.connectSingleflight.get(peerKey) === connectPromise) {
                this.connectSingleflight.delete(peerKey);
            }
        }
    }

    // Disconnect from a peer
    async disconnect(peerId: string): Promise<void> {
        const peerKey = this.resolvePeerKey(peerId) || peerId;
        let connection = this.connections.get(peerKey);
        if (!connection) {
            const alias = this.usernameAliases.get(peerId);
            if (alias) connection = this.connections.get(alias);
        }
        if (connection) {
            await connection.close();
            this.connections.delete(peerKey);
            this.connections.delete(peerId);
        }
    }

    // Shutdown the transport
    async shutdown(): Promise<void> {
        if (this.shutdownPromise) return this.shutdownPromise;
        const hasRendererIdentity = this.initialized ||
            this.initializing ||
            !!this.ownKeys ||
            this.connections.size > 0 ||
            this.knownPeerIdentities.size > 0 ||
            this.authenticatedEndpoints.size > 0 ||
            this.usernameAliases.size > 0 ||
            this.connectSingleflight.size > 0 ||
            !!this.bridgeEventUnlisten;
        const mustRotateNativeIdentity = isTauri() && (hasRendererIdentity || !this.nativeIdentityReady);
        if (!hasRendererIdentity && !mustRotateNativeIdentity) return;

        this.initialized = false;
        this.initializing = false;
        this.lifecycleGeneration++;
        this.localEndpointCache = null;
        this.localEndpointPromise = null;
        clearP2PNoiseHandshakeReplayCache();
        if (mustRotateNativeIdentity) this.nativeIdentityReady = false;

        const shutdownTask = (async () => {
            this.messageHandlers.clear();
            this.connectHandlers.clear();
            this.disconnectHandlers.clear();
            const uniqueConnections = new Set(this.connections.values());
            const connectionClosures = Array.from(uniqueConnections, connection => connection.close());
            this.connections.clear();

            if (this.bridgeEventUnlisten) {
                try { this.bridgeEventUnlisten(); } catch { }
                this.bridgeEventUnlisten = null;
            }
            for (const entry of this.inboundBridgeEventQueue) {
                this.inboundBridgeEventCount = Math.max(0, this.inboundBridgeEventCount - 1);
                this.inboundBridgeEventBytes = Math.max(
                    0,
                    this.inboundBridgeEventBytes - entry.byteLength
                );
                entry.data = null;
            }
            this.inboundBridgeEventQueue = [];
            this.connectSingleflight.clear();
            this.peerCertRequestTimestamps.clear();
            this.peerCertRequestWindow = { startedAt: 0, count: 0 };
            this.usernameAliases.clear();
            this.authenticatedBridgeAliases.clear();
            this.knownPeerIdentities.clear();
            this.peerIdentityEpochs.clear();
            this.authenticatedEndpoints.clear();
            this.localUsername = '';
            this.localPeerId = '';
            this.clearOwnKeys();
            clearP2PNoiseHandshakeReplayCache();

            await Promise.allSettled(connectionClosures);

            if (mustRotateNativeIdentity) {
                const endpointUrl = await p2p.rotateIdentity();
                if (!parseP2PEndpointUrl(endpointUrl)) {
                    throw new Error('Native P2P identity rotation returned an invalid endpoint');
                }
                this.nativeIdentityReady = true;
            }
        })();

        this.shutdownPromise = shutdownTask;
        try {
            await shutdownTask;
        } finally {
            if (this.shutdownPromise === shutdownTask) this.shutdownPromise = null;
        }
    }

    getConnection(peerId: string): SecureConnection | null {
        const conn = this.connections.get(peerId);
        if (conn) return conn;
        const alias = this.usernameAliases.get(peerId);
        if (alias) return this.connections.get(alias) || null;
        return null;
    }

    isConnected(peerId: string): boolean {
        let connection = this.connections.get(peerId);
        if (!connection) {
            const alias = this.usernameAliases.get(peerId);
            if (alias) connection = this.connections.get(alias);
        }

        const state = connection?.state;
        const result = state === 'connected';
        return result;
    }

    // Check if there is an active or pending connection
    hasActiveConnection(peerId: string): boolean {
        let connection = this.connections.get(peerId);
        if (!connection) {
            const alias = this.usernameAliases.get(peerId);
            if (alias) connection = this.connections.get(alias);
        }

        if (!connection) return false;

        return connection.state === 'connected' ||
            connection.state === 'handshaking' ||
            connection.state === 'connecting';
    }

    private pruneStaleMaps(): void {
        if (this.usernameAliases.size > this.MAX_USERNAME_ALIASES) {
            let toRemove = this.usernameAliases.size - this.MAX_USERNAME_ALIASES;
            for (const key of this.usernameAliases.keys()) {
                if (toRemove <= 0) break;
                if (!this.connections.has(key)) {
                    this.usernameAliases.delete(key);
                    this.authenticatedBridgeAliases.delete(key);
                    toRemove--;
                }
            }
        }
        
        if (this.knownPeerIdentities.size > this.MAX_KNOWN_IDENTITIES) {
            let toRemove = this.knownPeerIdentities.size - this.MAX_KNOWN_IDENTITIES;
            for (const key of this.knownPeerIdentities.keys()) {
                if (toRemove <= 0) break;
                if (!this.connections.has(key)) {
                    this.knownPeerIdentities.delete(key);
                    toRemove--;
                }
            }
        }
        
        if (this.peerCertRequestTimestamps.size > this.MAX_CERT_REQUEST_TIMESTAMPS) {
            let toRemove = this.peerCertRequestTimestamps.size - this.MAX_CERT_REQUEST_TIMESTAMPS;
            for (const key of this.peerCertRequestTimestamps.keys()) {
                if (toRemove <= 0) break;
                if (!this.connections.has(key)) {
                    this.peerCertRequestTimestamps.delete(key);
                    toRemove--;
                }
            }
        }
    }

    registerUsernameAlias(originalUsername: string, peerKey: string, authenticated = false): boolean {
        if (!originalUsername || !peerKey || originalUsername === peerKey) return false;
        this.pruneStaleMaps();

        const bridgeId = peerKey;
        const username = originalUsername;
        if (!this.isOpaqueBridgeId(bridgeId)) return false;
        if (!AUTH_USERNAME_REGEX.test(username)) return false;

        const existingUsername = this.usernameAliases.get(bridgeId);
        if (existingUsername && existingUsername !== username) {
            if (!authenticated || this.authenticatedBridgeAliases.has(bridgeId)) return false;
        }

        this.usernameAliases.set(bridgeId, username);
        if (authenticated) {
            this.authenticatedBridgeAliases.add(bridgeId);
            const existing = this.knownPeerIdentities.get(username);
            if (existing?.certVerified) this.knownPeerIdentities.set(bridgeId, existing);
        }
        return true;
    }

    private evictAuthenticatedEndpoint(peerId: string): void {
        const endpoint = this.authenticatedEndpoints.get(peerId);
        if (!endpoint) return;
        this.authenticatedEndpoints.delete(peerId);

        const endpointId = endpoint.endpointUrl
            ? parseP2PEndpointUrl(endpoint.endpointUrl)?.endpointId
            : undefined;
        if (endpointId && this.usernameAliases.get(endpointId) === peerId) {
            this.usernameAliases.delete(endpointId);
            this.authenticatedBridgeAliases.delete(endpointId);
        }

        for (const [key, identity] of Array.from(this.knownPeerIdentities.entries())) {
            if (identity.username !== peerId || identity.endpointUrl !== endpoint.endpointUrl) continue;
            if (key === endpointId) {
                this.knownPeerIdentities.delete(key);
                continue;
            }
            this.knownPeerIdentities.set(key, {
                username: identity.username,
                kyberPublicKey: identity.kyberPublicKey,
                dilithiumPublicKey: identity.dilithiumPublicKey,
                x25519PublicKey: identity.x25519PublicKey,
                certificateExpiresAt: identity.certificateExpiresAt,
                certVerified: identity.certVerified
            });
        }
    }

    // Resolve alias
    resolveUsernameAlias(alias: string): string | undefined {
        return this.usernameAliases.get(alias);
    }

    hasAuthenticatedEndpoint(peerId: string): boolean {
        const alias = this.usernameAliases.get(peerId);
        const endpoint = this.authenticatedEndpoints.get(peerId) ||
            (alias ? this.authenticatedEndpoints.get(alias) : undefined);
        return !!endpoint?.endpointUrl;
    }

    async registerPeerCertificate(peerId: string, certificate: PeerCertificateBundle): Promise<void> {
        if (!this.initialized || !this.ownKeys || !this.localUsername) {
            throw new Error('P2P transport is not initialized');
        }
        const generation = this.lifecycleGeneration;
        const localUsername = this.localUsername;
        let peerIdentityEpoch = this.getPeerIdentityEpoch(peerId);
        const validated = await validatePeerCertificateBundle(
            certificate,
            peerId,
            Date.now(),
            true,
        );
        if (!validated) throw new Error('Invalid P2P peer certificate');
        if (!isKeyTransparencyAuthorizedPeerCertificate({
            account: localUsername,
            peer: peerId,
            kyberPublicBase64: validated.kyberPublicKey,
            dilithiumPublicBase64: validated.dilithiumPublicKey,
            x25519PublicBase64: validated.x25519PublicKey,
            peerCertificateFingerprint: computePeerCertificateFingerprint(validated)
        })) {
            throw new Error('P2P peer certificate is not authorized by key transparency');
        }
        if (
            generation !== this.lifecycleGeneration ||
            !this.initialized ||
            !this.ownKeys ||
            this.localUsername !== localUsername ||
            this.getPeerIdentityEpoch(peerId) !== peerIdentityEpoch
        ) {
            throw new Error('P2P peer certificate verification crossed an account or identity transition');
        }
        const nextIdentity: PeerIdentity = {
            username: peerId,
            kyberPublicKey: PostQuantumUtils.base64ToUint8Array(validated.kyberPublicKey),
            dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(validated.dilithiumPublicKey),
            x25519PublicKey: PostQuantumUtils.base64ToUint8Array(validated.x25519PublicKey),
            certificateExpiresAt: validated.expiresAt,
            certVerified: true
        };
        const alias = this.usernameAliases.get(peerId);
        const existing = this.knownPeerIdentities.get(peerId) ||
            (alias ? this.knownPeerIdentities.get(alias) : undefined);
        const identityChanged = existing?.certVerified === true && (
            !PostQuantumUtils.timingSafeEqual(existing.kyberPublicKey, nextIdentity.kyberPublicKey) ||
            !PostQuantumUtils.timingSafeEqual(existing.dilithiumPublicKey, nextIdentity.dilithiumPublicKey) ||
            !PostQuantumUtils.timingSafeEqual(existing.x25519PublicKey, nextIdentity.x25519PublicKey)
        );
        if (identityChanged) {
            peerIdentityEpoch = this.bumpPeerIdentityEpoch(peerId);
            await this.revokePeerCertificate(localUsername, peerId, false);
            if (
                generation !== this.lifecycleGeneration ||
                !this.initialized ||
                !this.ownKeys ||
                this.localUsername !== localUsername ||
                this.getPeerIdentityEpoch(peerId) !== peerIdentityEpoch
            ) throw new Error('P2P peer certificate rotation crossed an account or identity transition');
        }
        this.installCertifiedPeerIdentity(peerId, nextIdentity);
    }

    async revokePeerCertificate(
        localUsername: string,
        peerId: string,
        advanceEpoch = true
    ): Promise<void> {
        if (
            !AUTH_USERNAME_REGEX.test(localUsername) ||
            !AUTH_USERNAME_REGEX.test(peerId) ||
            peerId === localUsername
        ) throw new Error('Invalid P2P peer-certificate revocation');
        if (this.localUsername && this.localUsername !== localUsername) {
            throw new Error('P2P peer-certificate revocation crossed an account transition');
        }
        if (advanceEpoch) this.bumpPeerIdentityEpoch(peerId);

        const aliasKeys = new Set<string>();
        for (const [key, username] of this.usernameAliases.entries()) {
            if (username === peerId) aliasKeys.add(key);
        }
        const connectionsToClose = new Set<P2PConnection>();
        for (const [key, connection] of this.connections.entries()) {
            if (
                key === peerId ||
                aliasKeys.has(key) ||
                connection.peerIdentity?.username === peerId ||
                this.knownPeerIdentities.get(key)?.username === peerId
            ) {
                connectionsToClose.add(connection);
                this.connections.delete(key);
            }
        }

        this.connectSingleflight.delete(peerId);
        this.peerCertRequestTimestamps.delete(peerId);
        this.evictAuthenticatedEndpoint(peerId);
        this.authenticatedEndpoints.delete(peerId);
        for (const alias of aliasKeys) {
            this.connectSingleflight.delete(alias);
            this.usernameAliases.delete(alias);
            this.authenticatedBridgeAliases.delete(alias);
        }
        for (const [key, identity] of Array.from(this.knownPeerIdentities.entries())) {
            if (identity.username === peerId) this.knownPeerIdentities.delete(key);
        }

        await Promise.allSettled(
            Array.from(connectionsToClose, connection => connection.close('key-transparency-root-changed'))
        );
    }

    private installCertifiedPeerIdentity(peerId: string, identity: PeerIdentity): void {
        const certifiedIdentity = this.validateCertifiedPeerIdentity(peerId, identity);
        this.pruneStaleMaps();
        const alias = this.usernameAliases.get(peerId);
        const existing = this.knownPeerIdentities.get(peerId) || (alias ? this.knownPeerIdentities.get(alias) : undefined);
        const cachedEndpoint = this.authenticatedEndpoints.get(peerId) ||
            (alias ? this.authenticatedEndpoints.get(alias) : undefined);
        const certifiedKeyBase64 = PostQuantumUtils.uint8ArrayToBase64(certifiedIdentity.dilithiumPublicKey);
        const authenticatedEndpointUrl = cachedEndpoint &&
            cachedEndpoint.signerPublicKeyBase64 === certifiedKeyBase64
            ? cachedEndpoint.endpointUrl || undefined
            : undefined;
            
        const mergedIdentity: PeerIdentity = {
            ...certifiedIdentity,
            endpointUrl: certifiedIdentity.endpointUrl || existing?.endpointUrl || authenticatedEndpointUrl,
            certVerified: true
        };

        this.knownPeerIdentities.set(peerId, mergedIdentity);
        this.peerCertRequestTimestamps.delete(peerId);
        if (alias) {
            this.knownPeerIdentities.set(alias, mergedIdentity);
            this.peerCertRequestTimestamps.delete(alias);
        }
        const parsedEndpoint = parseP2PEndpointUrl(mergedIdentity.endpointUrl);
        if (parsedEndpoint?.endpointId) {
            if (!this.registerUsernameAlias(peerId, parsedEndpoint.endpointId, true)) {
                throw new Error('Authenticated P2P endpoint is already bound to another identity');
            }
            this.knownPeerIdentities.set(parsedEndpoint.endpointId, mergedIdentity);
        }

        let connection = this.connections.get(peerId);
        if (!connection) {
            if (alias) connection = this.connections.get(alias);
        }

        if (connection) {
            const wasCertified = connection.peerIdentity?.certVerified === true;
            connection.updatePeerIdentity(mergedIdentity);
            if (!wasCertified && connection.state === 'connected') {
                for (const handler of Array.from(this.connectHandlers)) {
                    try { handler(peerId); } catch { }
                }
            }
        }
    }

    updateAuthenticatedEndpoint(
        peerId: string,
        endpointUrl: string | null,
        signerPublicKeyBase64: string,
        announcedAt: number
    ): boolean {
        if (
            !this.initialized ||
            !this.ownKeys ||
            !this.localUsername ||
            !AUTH_USERNAME_REGEX.test(peerId) ||
            !Number.isSafeInteger(announcedAt) ||
            announcedAt < 0
        ) return false;
        const parsedEndpoint = endpointUrl === null ? null : parseP2PEndpointUrl(endpointUrl);
        if (endpointUrl !== null && !parsedEndpoint?.hasDirectAddress) {
            return false;
        }
        const signerPublicKey = tryDecodeCanonicalBase64(
            signerPublicKeyBase64,
            'P2P endpoint signer public key',
            { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE }
        );
        if (!signerPublicKey) return false;
        const alias = this.usernameAliases.get(peerId);
        const existing = this.knownPeerIdentities.get(peerId) ||
            (alias ? this.knownPeerIdentities.get(alias) : undefined);
        if (existing?.certVerified && (
            existing.username !== peerId ||
            !PostQuantumUtils.timingSafeEqual(existing.dilithiumPublicKey, signerPublicKey)
        )) {
            signerPublicKey.fill(0);
            return false;
        }
        signerPublicKey.fill(0);

        const currentEndpoint = this.authenticatedEndpoints.get(peerId);
        if (currentEndpoint) {
            if (currentEndpoint.signerPublicKeyBase64 !== signerPublicKeyBase64) return false;
            if (announcedAt < currentEndpoint.announcedAt) return true;
            if (
                announcedAt === currentEndpoint.announcedAt &&
                (parsedEndpoint?.endpointUrl ?? null) !== currentEndpoint.endpointUrl
            ) return false;
        }

        if (parsedEndpoint && !this.registerUsernameAlias(peerId, parsedEndpoint.endpointId, true)) return false;

        const previousEndpointId = currentEndpoint?.endpointUrl
            ? parseP2PEndpointUrl(currentEndpoint.endpointUrl)?.endpointId
            : undefined;
        if (previousEndpointId && previousEndpointId !== parsedEndpoint?.endpointId) {
            if (this.usernameAliases.get(previousEndpointId) === peerId) {
                this.usernameAliases.delete(previousEndpointId);
                this.authenticatedBridgeAliases.delete(previousEndpointId);
            }
            this.knownPeerIdentities.delete(previousEndpointId);
        }

        if (this.authenticatedEndpoints.size >= this.MAX_KNOWN_IDENTITIES && !this.authenticatedEndpoints.has(peerId)) {
            const oldest = this.authenticatedEndpoints.keys().next().value;
            if (oldest !== undefined) this.evictAuthenticatedEndpoint(oldest);
        }
        this.authenticatedEndpoints.set(peerId, {
            endpointUrl: parsedEndpoint?.endpointUrl ?? null,
            signerPublicKeyBase64,
            announcedAt
        });
        if (!existing?.certVerified) return true;

        const updated: PeerIdentity = {
            username: existing.username,
            kyberPublicKey: existing.kyberPublicKey,
            dilithiumPublicKey: existing.dilithiumPublicKey,
            x25519PublicKey: existing.x25519PublicKey,
            ...(parsedEndpoint ? { endpointUrl: parsedEndpoint.endpointUrl } : {}),
            certificateExpiresAt: existing.certificateExpiresAt,
            certVerified: true
        };
        this.knownPeerIdentities.set(peerId, updated);
        if (alias) this.knownPeerIdentities.set(alias, updated);
        if (parsedEndpoint) this.knownPeerIdentities.set(parsedEndpoint.endpointId, updated);

        const connection = this.connections.get(peerId) ||
            (alias ? this.connections.get(alias) : undefined) ||
            (parsedEndpoint ? this.connections.get(parsedEndpoint.endpointId) : undefined);
        if (connection) {
            connection.updatePeerIdentity(updated, endpointUrl !== null);
        }
        return true;
    }

    public requestPeerCertificate(peerId: string): void {
        if (typeof window === 'undefined' || !this.initialized || !this.localUsername || !peerId) return;
        const appPeerId = this.resolveAppPeerId(peerId);
        if (!this.isSafePeerId(appPeerId)) return;
        const now = Date.now();
        const last = this.peerCertRequestTimestamps.get(appPeerId) || 0;
        if (now - last < 30_000) return;
        if (now - this.peerCertRequestWindow.startedAt >= 60_000) {
            this.peerCertRequestWindow = { startedAt: now, count: 0 };
        }
        if (this.peerCertRequestWindow.count >= this.MAX_CERT_REQUESTS_PER_MINUTE) return;
        this.peerCertRequestWindow.count++;
        if (
            this.peerCertRequestTimestamps.size >= this.MAX_CERT_REQUEST_TIMESTAMPS &&
            !this.peerCertRequestTimestamps.has(appPeerId)
        ) {
            const oldest = this.peerCertRequestTimestamps.keys().next().value;
            if (oldest !== undefined) this.peerCertRequestTimestamps.delete(oldest);
        }
        this.peerCertRequestTimestamps.set(appPeerId, now);
        try {
            window.dispatchEvent(new CustomEvent(EventType.P2P_FETCH_PEER_CERT, {
                detail: { account: this.localUsername, peer: appPeerId }
            }));
        } catch { }
    }

    // Internal dispatch a message to all handlers
    dispatchMessage(message: IncomingMessage): void {
        if (this.messageHandlers.size === 0) {
            console.warn('[P2P-RECV] DROP: no app message handlers registered');
        }

        for (const handler of Array.from(this.messageHandlers)) {
            try {
                handler(message);
            } catch (err) {
                console.error('[P2P-RECV] app message handler threw:', err);
            }
        }
    }

    // Register a message handler
    onMessage(handler: MessageHandler): () => void {
        this.messageHandlers.add(handler);
        return () => this.messageHandlers.delete(handler);
    }

    // Register a connection handler
    onPeerConnected(handler: (peerId: string) => void): () => void {
        this.connectHandlers.add(handler);
        return () => this.connectHandlers.delete(handler);
    }

    // Register a disconnection handler
    onPeerDisconnected(handler: (peerId: string, reason?: string) => void): () => void {
        this.disconnectHandlers.add(handler);
        return () => this.disconnectHandlers.delete(handler);
    }

}

export const p2pTransport = new P2PTransport();
