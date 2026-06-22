/**
 * P2P Transport
 */

import { EventType } from '../types/event-types';
import { SignalType } from '../types/signal-types';
import { p2p, events, isTauri } from '../tauri-bindings';
import { UnlistenFn } from '@tauri-apps/api/event';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PQNoiseSession } from './pq-noise-session';
import { PeerKeys, OwnKeys } from '../types/noise-types';
import { parseP2PEndpointUrl } from '../utils/p2p-endpoint';
import {
    SecureTransport,
    SecureConnection,
    SecureStream,
    ConnectionState,
    ConnectOptions,
    StreamOptions,
    StreamType,
    TransportInitOptions,
    MessageHandler,
    IncomingMessage,
    PeerIdentity,
    MAX_MESSAGE_FRAME_SIZE,
    MAX_CALL_FRAME_SIZE,
    FRAME_OVERHEAD
} from './secure-transport';
import {
    P2P_CONNECTION_TIMEOUT_MS,
    P2P_KEEPALIVE_INTERVAL_MS,
    P2P_MAX_STREAMS_PER_CONNECTION,
    P2P_RECONNECT_BACKOFF_BASE_MS,
    P2P_MAX_RECONNECT_ATTEMPTS,
    P2P_STUCK_STATE_TIMEOUT_MS,
    P2P_BUFFER_LOW_THRESHOLD
} from '../constants';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const MAX_HANDSHAKE_MESSAGE_CHARS = 8192;
const FRAME_DEDUP_CLEANUP_INTERVAL = 64;

const INBOX_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/i;
const BRIDGE_PEER_ID_REGEX = /^[a-f0-9]{64}$/i;

class P2PStream implements SecureStream {
    readonly id: string;
    readonly type: StreamType;
    readonly peerId: string;
    readonly lossy: boolean;

    private session: PQNoiseSession;
    private sendBuffer: Uint8Array[] = [];
    private receiveQueue: Uint8Array[] = [];
    private receiveQueueBytes: number = 0;
    private readResolvers: Array<(value: Uint8Array | null) => void> = [];
    private _readable: boolean = true;
    private _writable: boolean = true;
    private _closed: boolean = false;
    private readonly MAX_RECEIVE_QUEUE_FRAMES = 256;
    private readonly MAX_RECEIVE_QUEUE_BYTES = 4 * 1024 * 1024;
    private pendingEncryptedFrames: Uint8Array[] = [];
    private pendingEncryptedBytes: number = 0;
    private decryptProcessing: boolean = false;
    private readonly MAX_PENDING_ENCRYPTED_FRAMES = 256;
    private readonly MAX_PENDING_ENCRYPTED_BYTES = 4 * 1024 * 1024;

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
    }

    updateSession(session: PQNoiseSession): void {
        this.session = session;
    }

    // Write data to stream
    async write(data: Uint8Array): Promise<void> {

        if (this._closed || !this._writable) {
            console.error('[P2PStream] Stream not writable:', { closed: this._closed, writable: this._writable });
            throw new Error('Stream is not writable');
        }

        const maxSize = this.type.startsWith('call-') ? MAX_CALL_FRAME_SIZE : MAX_MESSAGE_FRAME_SIZE;
        if (data.length + FRAME_OVERHEAD > maxSize) {
            throw new Error(`Data too large for stream type ${this.type}`);
        }
        const aad = textEncoder.encode(this.id);
        const encrypted = await this.session.encrypt(data, aad);
        console.log('[P2P-SEND] stream.write encrypted', {
            peer: this.peerId.slice(0, 24), streamId: this.id,
            plainBytes: data.byteLength, encBytes: encrypted.byteLength
        });

        await this.transport.sendData(this.id, encrypted);
    }

    // Backpressure handling
    async writeWithBackpressure(data: Uint8Array): Promise<void> {
        while (this.transport.getBufferedAmount() > P2P_BUFFER_LOW_THRESHOLD) {
            await new Promise(resolve => setTimeout(resolve, 10));
            if (this._closed) {
                throw new Error('Stream closed while waiting for buffer');
            }
        }

        return this.write(data);
    }

    // Read data from stream
    async read(): Promise<Uint8Array | null> {
        if (this._closed && this.receiveQueue.length === 0) {
            return null;
        }

        if (this.receiveQueue.length > 0) {
            const next = this.receiveQueue.shift()!;
            this.receiveQueueBytes = Math.max(0, this.receiveQueueBytes - next.byteLength);
            return next;
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
        this._writable = false;
        this._readable = false;
        this.receiveQueue = [];
        this.receiveQueueBytes = 0;
        this.pendingEncryptedFrames = [];
        this.pendingEncryptedBytes = 0;

        for (const resolver of this.readResolvers) {
            resolver(null);
        }
        this.readResolvers = [];

        this.transport.closeStream(this.id);
    }

    // Abort stream immediately
    abort(reason?: string): void {
        this._closed = true;
        this._writable = false;
        this._readable = false;
        this.receiveQueue = [];
        this.receiveQueueBytes = 0;
        this.pendingEncryptedFrames = [];
        this.pendingEncryptedBytes = 0;

        for (const resolver of this.readResolvers) {
            resolver(null);
        }
        this.readResolvers = [];

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
        if (frameData.byteLength > this.MAX_PENDING_ENCRYPTED_BYTES) return;
        if (
            this.pendingEncryptedFrames.length >= this.MAX_PENDING_ENCRYPTED_FRAMES ||
            this.pendingEncryptedBytes + frameData.byteLength > this.MAX_PENDING_ENCRYPTED_BYTES
        ) {
            return;
        }

        this.pendingEncryptedFrames.push(frameData.slice());
        this.pendingEncryptedBytes += frameData.byteLength;

        if (!this.decryptProcessing) {
            void this.drainPendingEncryptedFrames();
        }
    }

    private enqueueDecryptedFrame(decrypted: Uint8Array): void {
        if (this.readResolvers.length > 0) {
            const resolver = this.readResolvers.shift()!;
            resolver(decrypted);
            return;
        }

        if (decrypted.byteLength > this.MAX_RECEIVE_QUEUE_BYTES) {
            return;
        }
        while (
            this.receiveQueue.length >= this.MAX_RECEIVE_QUEUE_FRAMES ||
            (this.receiveQueue.length > 0 &&
                this.receiveQueueBytes + decrypted.byteLength > this.MAX_RECEIVE_QUEUE_BYTES)
        ) {
            const dropped = this.receiveQueue.shift();
            if (!dropped) break;
            this.receiveQueueBytes = Math.max(0, this.receiveQueueBytes - dropped.byteLength);
        }
        this.receiveQueue.push(decrypted);
        this.receiveQueueBytes += decrypted.byteLength;
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
                for (const frame of frames) {
                    if (this._closed) break;
                    try {
                        const aad = textEncoder.encode(this.id);
                        const decrypted = await this.session.decrypt(frame, aad);
                        console.log('[P2P-RECV] frame decrypted OK', {
                            peer: this.peerId.slice(0, 24), streamId: this.id, plainBytes: decrypted.byteLength
                        });
                        this.enqueueDecryptedFrame(decrypted);
                    } catch (err) {
                        console.warn('[P2P-RECV] frame decrypt FAILED:', {
                            streamId: this.id,
                            peerId: this.peerId,
                            frameSize: frame.byteLength,
                            error: (err as Error)?.message || String(err)
                        });
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

    // Transport layer
    private socket: WebSocket | null = null;
    private sendQueue: Array<{ streamId: string; data: Uint8Array }> = [];
    private bufferedAmount: number = 0;

    // Reconnection
    private reconnectAttempts: number = 0;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private stuckStateWatchdog: ReturnType<typeof setTimeout> | null = null;

    // Keepalive
    private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
    private tauriUnlisten: UnlistenFn | null = null;
    private bridgeConnectionId: string | null = null;
    private _bridgeHandshakeResolve: ((data: any) => void) | null = null;
    private _bridgeHandshakeReject: ((err: any) => void) | null = null;
    private _isResponderPending: boolean = false;
    private _pendingHandshakeToRespond: any = null;
    private _pendingHandshakeMessage: any = null;
    private _expectedHandshakeSessionId: string | null = null;
    private connectPromise: Promise<void> | null = null;
    private incomingResponderPromise: Promise<void> | null = null;
    private stateUpdatedAt: number = Date.now();
    public role: 'initiator' | 'responder' | 'auto' = 'auto';
    private collisionDetected: boolean = false;
    private pendingIncomingFrames: Uint8Array[] = [];
    private readonly MAX_PENDING_INCOMING_FRAMES = 256;
    private pendingIncomingFrameBytes: number = 0;
    private readonly MAX_PENDING_INCOMING_BYTES = 2 * 1024 * 1024;
    private pendingIncomingFlushDraining: boolean = false;

    private processedFrameHashes: Map<string, number> = new Map();
    private readonly FRAME_DEDUP_EXPIRY_MS = 5000;
    private frameDedupCleanupTick: number = 0;
    private bridgeMessageQueue: Array<{ message: any; checkHandshake: boolean }> = [];
    private bridgeQueueDraining: boolean = false;
    private readonly MAX_BRIDGE_MESSAGE_QUEUE = 512;
    private pendingBase64PayloadQueue: string[] = [];
    private base64PayloadDraining: boolean = false;
    private readonly MAX_PENDING_BASE64_PAYLOADS = 512;

    constructor(
        peerId: string,
        peerIdentity: PeerIdentity,
        private ownKeys: OwnKeys,
        private localPeerId: string,
        private owner: P2PTransport
    ) {
        this.peerId = peerId;
        this.peerIdentity = peerIdentity;
    }

    public notifyCollision(): void {
        this.collisionDetected = true;
    }

    public getEffectiveRole(): 'initiator' | 'responder' {
        // lower username initiates
        const isLower = this.localPeerId < this.peerId;
        const detRole = isLower ? 'initiator' : 'responder';

        // If no collision and role is explicit then use that
        if (this.role !== 'auto' && !this.collisionDetected) return this.role;

        // else use deterministic arbitration
        return detRole;
    }

    // Update peer identity
    public updatePeerIdentity(identity: PeerIdentity): void {
        this.peerIdentity = identity;
    }

    private pinPeerSigningKey(candidate?: Uint8Array): void {
        if (!candidate?.length) return;
        const existing = this.peerIdentity?.dilithiumPublicKey;
        if (existing?.length) {
            if (!PostQuantumUtils.timingSafeEqual(existing, candidate)) {
                const error = new Error('Peer handshake signing key mismatch');
                (error as any).code = 'PEER_HANDSHAKE_SIGNING_KEY_MISMATCH';
                throw error;
            }
            return;
        }
        this.updatePeerIdentity({
            ...this.peerIdentity,
            dilithiumPublicKey: candidate
        });
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

    // Establish connection to peer
    public async connectAsResponder(handshakeMsg: any): Promise<void> {
        if (this._state === 'connected') { return; }
        this._pendingHandshakeToRespond = handshakeMsg;
        return this.connect(false);
    }

    // Connect as responder and wait for the initiator handshake to arrive over direct channel
    public async connectAsResponderPending(): Promise<void> {
        this.role = 'responder';
        this._isResponderPending = true;
        return this.connect(false);
    }

    // Reset stale state before a reconnection attempt
    private resetForReconnect(): void {
        if (this.session) {
            try { this.session.destroy(); } catch { }
            this.session = null;
        }

        // Close and clear old streams
        for (const stream of Array.from(this.streams.values())) {
            try { stream.abort('reconnect'); } catch { }
        }
        this.streams.clear();
        this.streamHandlers.clear();

        // Reset handshake state
        this._pendingHandshakeToRespond = null;
        this._pendingHandshakeMessage = null;
        this._expectedHandshakeSessionId = null;
        if (this._bridgeHandshakeReject) {
            try { this._bridgeHandshakeReject(new Error('Connection reset for reconnect')); } catch { }
        }
        this._bridgeHandshakeResolve = null;
        this._bridgeHandshakeReject = null;

        // Reset role/collision state for clean deterministic role selection
        this.role = 'auto';
        this.collisionDetected = false;
        this._isResponderPending = false;
        this.incomingResponderPromise = null;

        // Clear queues
        this.bridgeMessageQueue = [];
        this.bridgeQueueDraining = false;
        this.pendingBase64PayloadQueue = [];
        this.base64PayloadDraining = false;
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this.pendingIncomingFlushDraining = false;
        this.processedFrameHashes.clear();
    }

    // Connect to peer
    async connect(localDial: boolean = true): Promise<void> {
        if (this.role === 'responder' && localDial) {
            this.role = 'auto';
            this.collisionDetected = true;
        }

        if (this._state === 'connected' && this.session) {
            return;
        }

        if (this.connectPromise) {
            return this.connectPromise;
        }

        this.connectPromise = (async () => {
            try {
                this.setState('connecting');
                await this.connectViaP2PBridge();
            } finally {
                this.connectPromise = null;
            }
        })();

        return this.connectPromise;
    }

    private getActiveBridgeConnectionId(): string {
        return this.bridgeConnectionId || this.peerId;
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

    public ownsBridgeConnection(connectionId: string): boolean {
        if (typeof connectionId !== 'string' || !connectionId) return false;
        if (this.bridgeConnectionId && this.bridgeConnectionId === connectionId) return true;
        return this.matchesBridgeConnectionId(connectionId, this.buildBridgeConnectionIdCandidates());
    }

    public attachBridgeConnection(connectionId: string): void {
        if (!connectionId) return;
        this.bridgeConnectionId = connectionId;
        this._transport = 'p2p';
        if (!this.tauriUnlisten) {
            this.tauriUnlisten = (() => { }) as UnlistenFn;
        }

        // Register alias between peerId and connectionId
        if (connectionId !== this.peerId && connectionId && this.peerId) {
            this.owner.registerUsernameAlias(this.peerId, connectionId);
        }
    }

    public ensureIncomingResponderActive(): void {
        this.attachBridgeConnection(this.getActiveBridgeConnectionId());
        if (this.session || this._state === 'handshaking') return;
        if (this.incomingResponderPromise) return;

        console.log('[P2P-HS] acceptor: init received -> activating responder', {
            peer: this.peerId.slice(0, 24), state: this._state
        });
        this.role = 'responder';
        this._isResponderPending = true;
        this.incomingResponderPromise = (async () => {
            try {
                await new Promise<void>((resolve) => setTimeout(resolve, 0));
                await this.waitForInitiatorHandshakeAndRespond();
            } catch (err) {
                if (this._state !== 'connected') {
                    this.setState('failed');
                }
                throw err;
            } finally {
                this.incomingResponderPromise = null;
            }
        })();
        this.incomingResponderPromise.catch(() => { });
    }

    public handleBridgeEventMessage(message: any): void {
        if (this.shouldProcessBridgeMessageImmediately(message)) {
            this.processBridgeEventMessage(message, true);
            return;
        }

        if (this.bridgeMessageQueue.length >= this.MAX_BRIDGE_MESSAGE_QUEUE) {
            return;
        }
        this.bridgeMessageQueue.push({ message, checkHandshake: false });
        if (!this.bridgeQueueDraining) {
            this.bridgeQueueDraining = true;
            void this.drainBridgeMessageQueue();
        }
    }

    public handleBridgeEventClosed(): void {
        this.handleTauriBridgeClosed();
    }

    // Connect to peer via the libp2p bridge endpoint.
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
        this.resetForReconnect();

        return new Promise<void>(async (resolve, reject) => {
            let settled = false;
            let handshakeTimeout: ReturnType<typeof setTimeout> | null = null;

            const finishError = async (err: unknown) => {
                if (settled) return;
                settled = true;
                if (handshakeTimeout) { clearTimeout(handshakeTimeout); handshakeTimeout = null; }
                if (this._state === 'connecting' || this._state === 'handshaking') {
                    this.setState('failed');
                }
                
                reject(err instanceof Error ? err : new Error(String(err)));
            };

            const finishOk = () => {
                if (settled) return;
                settled = true;
                if (handshakeTimeout) { clearTimeout(handshakeTimeout); handshakeTimeout = null; }
                resolve();
            };

            try {
                const res = await p2p.connect(this.peerId, endpoint.endpointUrl);
                if (!res.success) {
                    await finishError(new Error(res.error || 'P2P connect failed'));
                    return;
                }
                this.attachBridgeConnection(this.peerId);

                
                handshakeTimeout = setTimeout(() => {
                    finishError(new Error('Handshake response timeout (bridge)'));
                }, P2P_CONNECTION_TIMEOUT_MS);

                this.handleTauriBridgeOpened(
                    () => {
                        finishOk();
                    },
                    (err) => {
                        finishError(err);
                    }
                );
            } catch (err) {
                await finishError(err);
            }
        });
    }

    // Perform PQ handshake with peer
    private async performHandshake(): Promise<void> {
        this.setState('handshaking');

        const isDeterministicInitiator = this.localPeerId < this.peerId;

        if (!this.peerIdentity.kyberPublicKey || this.peerIdentity.kyberPublicKey.length === 0) {
            const start = Date.now();
            while ((!this.peerIdentity.kyberPublicKey || this.peerIdentity.kyberPublicKey.length === 0) && (Date.now() - start) < 10000) {
                if (this._state === 'disconnected' || this._state === 'failed') {
                    throw new Error('Connection closed while waiting for peer identity');
                }
                await new Promise(resolve => setTimeout(resolve, 200));
            }
        }

        if (!this.peerIdentity.kyberPublicKey || this.peerIdentity.kyberPublicKey.length === 0) {
            if (isDeterministicInitiator) {
                this.setState('failed');
                throw new Error('Peer Kyber public key missing after timeout');
            } else {
                return this.waitForInitiatorHandshakeAndRespond();
            }
        }

        const peerKeys: PeerKeys = {
            kyberPublicKey: this.peerIdentity.kyberPublicKey!,
            dilithiumPublicKey: this.peerIdentity.dilithiumPublicKey!,
            x25519PublicKey: this.peerIdentity.x25519PublicKey!
        };

        if (!isDeterministicInitiator && this.collisionDetected) {
            console.log('[P2P-HS] glare: deferring to peer as responder', { peer: this.peerId.slice(0, 24) });
            return this.waitForInitiatorHandshakeAndRespond();
        }

        if (!this.ownKeys) {
            throw new Error('Own keys missing for handshake');
        }

        // Create initiator session
        let session, message;
        try {
            const result = await PQNoiseSession.createInitiatorSession(
                this.peerId,
                this.ownKeys,
                peerKeys
            );
            session = result.session;
            message = result.message;
            this._expectedHandshakeSessionId = message.sessionId;
        } catch (err) {
            throw err;
        }

        const isBridgeMode = !!(this.tauriUnlisten || this.bridgeConnectionId);
        const handshakeData = isBridgeMode ? this.prepareHandshakeObject(message) : this.serializeHandshakeMessage(message);
        const responsePromise = this.waitForHandshakeResponse(this._expectedHandshakeSessionId || undefined);
        console.log('[P2P-HS] sending handshake init (initiator)', {
            peer: this.peerId.slice(0, 24), sessionId: this._expectedHandshakeSessionId
        });
        try {
            await this.sendRaw(handshakeData);
            console.log('[P2P-HS] init sent, awaiting response', { peer: this.peerId.slice(0, 24) });
        } catch (sendErr) {
            console.warn('[P2P-HS] init send FAILED', { peer: this.peerId.slice(0, 24), error: (sendErr as Error)?.message || String(sendErr) });
            void responsePromise.catch(() => { });
            throw sendErr;
        }

        let response = await responsePromise;

        // both peers dialed and both sent init
        let glareGuard = 0;
        while (response.type === 'init') {
            if (!isDeterministicInitiator) {
                console.log('[P2P-HS] glare: we are id higher, responding to peer init', { peer: this.peerId.slice(0, 24) });
                await this.handleIncomingHandshake(response);
                this._expectedHandshakeSessionId = null;
                return;
            }

            // id-lower ignore peer's init
            if (++glareGuard > 3) {
                throw new Error('Handshake glare did not converge');
            }
            console.log('[P2P-HS] glare: we are id-lower, ignoring peer init and re-awaiting response', { peer: this.peerId.slice(0, 24) });
            response = await this.waitForHandshakeResponse(this._expectedHandshakeSessionId || undefined);
        }

        try {
            await session.completeHandshake(response);
            this.session = session;
            void this.flushPendingIncomingFrames();
            this._expectedHandshakeSessionId = null;

            if (response.signerPublicKey) {
                this.pinPeerSigningKey(response.signerPublicKey);
            }

            for (const stream of Array.from(this.streams.values())) {
                stream.updateSession(session);
            }

            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
        } catch (err) {
            this.setState('failed');
            this._expectedHandshakeSessionId = null;
            throw err;
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
            ...message,
            from: this.localPeerId,
            version: message.version || 'hybrid-session-v1',
            type: message.type,
            sessionId: message.sessionId,
            timestamp: message.timestamp || Date.now(),
            kemCiphertext: toBase64(message.kemCiphertext),
            ephemeralKyberPublic: toBase64(message.ephemeralKyberPublic),
            ephemeralX25519Public: toBase64(message.ephemeralX25519Public),
            signature: toBase64(message.signature)!,
            signerPublicKey: toBase64(message.signerPublicKey)!
        };
    }

    // Serialize handshake message
    private serializeHandshakeMessage(message: any): Uint8Array {
        const obj = this.prepareHandshakeObject(message);
        const json = JSON.stringify(obj);
        return new TextEncoder().encode(json);
    }

    // Normalize handshake message
    private normalizeHandshakeMessage(json: any): any {
        if (!json || typeof json !== 'object') return json;
        const toUint8 = (value?: string | Uint8Array): Uint8Array | undefined => {
            if (!value) return undefined;
            if (value instanceof Uint8Array) return value;
            try {
                return PostQuantumUtils.base64ToUint8Array(value);
            } catch {
                return undefined;
            }
        };

        return {
            ...json,
            version: json.version || 'hybrid-session-v1',
            type: json.type,
            sessionId: json.sessionId,
            timestamp: json.timestamp,
            kemCiphertext: toUint8(json.kemCiphertext),
            ephemeralKyberPublic: toUint8(json.ephemeralKyberPublic),
            ephemeralX25519Public: toUint8(json.ephemeralX25519Public),
            signature: toUint8(json.signature),
            signerPublicKey: toUint8(json.signerPublicKey)
        };
    }

    private deserializeHandshakeMessage(data: Uint8Array | string | any): any {
        if (!data) return null;

        // If it is already an object then normalize it.
        if (data && typeof data === 'object' && !(data instanceof Uint8Array)) {
            return this.normalizeHandshakeMessage(data);
        }

        const parseJsonHandshake = (value: string): any | null => {
            try {
                const parsed = JSON.parse(value);
                return this.normalizeHandshakeMessage(parsed);
            } catch {
                return null;
            }
        };

        if (typeof data === 'string') {
            let trimmed = data.trim();
            if (!trimmed || trimmed.length > MAX_HANDSHAKE_MESSAGE_CHARS) {
                return null;
            }

            if (trimmed.startsWith('{')) {
                return parseJsonHandshake(trimmed);
            }

            if (/^[-A-Za-z0-9_+/=]+$/.test(trimmed)) {
                try {
                    const bytes = PostQuantumUtils.base64ToUint8Array(trimmed);
                    if (bytes.length > MAX_HANDSHAKE_MESSAGE_CHARS) return null;
                    trimmed = textDecoder.decode(bytes).trim();
                    if (trimmed.startsWith('{')) {
                        return parseJsonHandshake(trimmed);
                    }
                } catch { }
            }

            return null;
        }

        if (!(data instanceof Uint8Array)) {
            return null;
        }

        try {
            let trimmed = textDecoder.decode(data).trim();
            if (!trimmed) return null;

            if (trimmed.startsWith('{')) {
                return parseJsonHandshake(trimmed);
            }

            if (trimmed.length > MAX_HANDSHAKE_MESSAGE_CHARS) {
                return null;
            }

            if (/^[-A-Za-z0-9_+/=]+$/.test(trimmed)) {
                const bin = PostQuantumUtils.base64ToUint8Array(trimmed);
                if (bin.length > MAX_HANDSHAKE_MESSAGE_CHARS) return null;
                const text = textDecoder.decode(bin).trim();
                if (text.startsWith('{')) {
                    return parseJsonHandshake(text);
                }
            }
        } catch { }

        return null;
    }

    // Wait for handshake response
    private async waitForHandshakeResponse(expectedSessionId?: string): Promise<any> {
        if (this._pendingHandshakeMessage) {
            const pending = this.normalizeHandshakeMessage(this._pendingHandshakeMessage);
            this._pendingHandshakeMessage = null;
            if (pending?.type === 'init') {
                return pending;
            }
            if (pending?.type === 'response') {
                if (!expectedSessionId || pending.sessionId === expectedSessionId) {
                    return pending;
                }
            }
        }

        if (this.tauriUnlisten || this.bridgeConnectionId) {
            return new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    console.error('[P2PConnection] Handshake response timeout (bridge)');
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    if (this._state === 'connecting' || this._state === 'handshaking') {
                        this.setState('failed');
                    }
                    reject(new Error('Handshake response timeout (bridge)'));
                }, P2P_CONNECTION_TIMEOUT_MS);

                this._bridgeHandshakeResolve = (data) => {
                    const response = (data && typeof data === 'object' && !(data instanceof Uint8Array))
                        ? this.normalizeHandshakeMessage(data)
                        : this.deserializeHandshakeMessage(data);
                    if (!response) return;

                    if (response.type === 'response' && expectedSessionId
                        && (!response.sessionId || response.sessionId !== expectedSessionId)) {
                        console.warn('[P2P-HS] initiator: response sessionId mismatch', {
                            peer: this.peerId.slice(0, 24),
                            expected: expectedSessionId,
                            got: response.sessionId || '(none)'
                        });
                        clearTimeout(timeout);
                        this._bridgeHandshakeResolve = null;
                        this._bridgeHandshakeReject = null;
                        reject(new Error('Handshake response sessionId mismatch'));
                        return;
                    }

                    console.log('[P2P-HS] initiator: response accepted', {
                        peer: this.peerId.slice(0, 24), type: response.type, sessionId: response.sessionId
                    });
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    resolve(response);
                };
                this._bridgeHandshakeReject = (err) => {
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    reject(err);
                };

                if (this._pendingHandshakeMessage) {
                    const pending = this._pendingHandshakeMessage;
                    this._pendingHandshakeMessage = null;
                    if (this._bridgeHandshakeResolve) {
                        this._bridgeHandshakeResolve(pending);
                    }
                }
            });
        }

        return new Promise((resolve, reject) => {
            const socket = this.socket;
            if (!socket) {
                return reject(new Error('Socket vanished before handshake wait'));
            }

            const originalCloseHandler = socket.onclose;
            const cleanup = () => {
                if (socket === this.socket) {
                    socket.onmessage = (evt) => {
                        if (this.socket !== socket) return;
                        const d = new Uint8Array(evt.data as ArrayBuffer);
                        this.handleIncomingData(d);
                    };
                    socket.onclose = originalCloseHandler;
                }
            };

            const timeout = setTimeout(() => {
                cleanup();
                if (this._state === 'connecting' || this._state === 'handshaking') {
                    this.setState('failed');
                }
                reject(new Error('Handshake response timeout'));
            }, P2P_CONNECTION_TIMEOUT_MS);

            socket.onclose = (event) => {
                if (this.socket !== socket) return;
                clearTimeout(timeout);
                cleanup();
                reject(new Error(`Socket closed while waiting for handshake response (${event.code}${event.reason ? `: ${event.reason}` : ''})`));

                if (typeof originalCloseHandler === 'function') {
                    try {
                        originalCloseHandler.call(socket, event);
                    } catch { }
                }
            };

            socket.onmessage = (event) => {
                if (this.socket !== socket) return;
                try {
                    const arrayBuffer = event.data as ArrayBuffer | undefined;
                    if (!arrayBuffer || arrayBuffer.byteLength === 0) { return; }

                    const data = new Uint8Array(arrayBuffer);
                    if (!data.length) { return; }

                    const response = this.deserializeHandshakeMessage(data);

                    if (!response) {
                        return;
                    }

                    if (response.type === 'init') {
                        this.collisionDetected = true;

                        clearTimeout(timeout);
                        cleanup();
                        resolve(response);
                        return;
                    }

                    if (response.type === 'response') {
                        if (expectedSessionId) {
                            if (!response.sessionId || response.sessionId !== expectedSessionId) {
                                return;
                            }
                        }
                        clearTimeout(timeout);
                        cleanup();
                        resolve(response);
                        return;
                    }
                } catch { }
            };
        });
    }

    // Wait for initiator handshake to arrive over direct channel then respond
    private async waitForInitiatorHandshakeAndRespond(): Promise<void> {
        this.setState('handshaking');

        // Check if init message already arrived before started waiting
        if (this._pendingHandshakeToRespond) {
            const msg = this._pendingHandshakeToRespond;
            this._pendingHandshakeToRespond = null;
            await this.handleIncomingHandshake(msg);
            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
            return;
        }

        if (this._pendingHandshakeMessage) {
            const pending = this.normalizeHandshakeMessage(this._pendingHandshakeMessage);
            this._pendingHandshakeMessage = null;
            if (pending?.type === 'init') {
                await this.handleIncomingHandshake(pending);
                this._connectedAt = Date.now();
                this.setState('connected');
                this.startKeepalive();
                return;
            }
        }

        if (this.tauriUnlisten || this.bridgeConnectionId) {
            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    if (this._state === 'connecting' || this._state === 'handshaking') {
                        this.setState('failed');
                    }
                    p2p.disconnect(this.getActiveBridgeConnectionId()).catch(() => { });
                    reject(new Error('Timeout waiting for initiator handshake (bridge)'));
                }, P2P_CONNECTION_TIMEOUT_MS);

                this._bridgeHandshakeResolve = async (data) => {
                    if (data && typeof data === 'object' && !(data instanceof Uint8Array)) {
                        const handshakeMsg = this.normalizeHandshakeMessage(data);
                        if (handshakeMsg && handshakeMsg.type === 'init') {
                            clearTimeout(timeout);
                            this._bridgeHandshakeResolve = null;
                            this._bridgeHandshakeReject = null;
                            try {
                                await this.handleIncomingHandshake(handshakeMsg);
                                this._connectedAt = Date.now();
                                this.setState('connected');
                                this.startKeepalive();
                                resolve();
                            } catch (err) {
                                reject(err);
                            }
                        }
                        return;
                    }

                    const handshakeMsg = this.deserializeHandshakeMessage(data);
                    if (handshakeMsg && handshakeMsg.type === 'init') {
                        clearTimeout(timeout);
                        this._bridgeHandshakeResolve = null;
                        this._bridgeHandshakeReject = null;
                        try {
                            await this.handleIncomingHandshake(handshakeMsg);
                            this._connectedAt = Date.now();
                            this.setState('connected');
                            this.startKeepalive();
                            resolve();
                        } catch (err) {
                            reject(err);
                        }
                    }
                };

                this._bridgeHandshakeReject = (err) => {
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    reject(err);
                };

                // Check again if an init arrived in window between the first check and setting up the resolver
                if (this._pendingHandshakeToRespond) {
                    const msg = this._pendingHandshakeToRespond;
                    this._pendingHandshakeToRespond = null;
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    this.handleIncomingHandshake(msg).then(() => {
                        this._connectedAt = Date.now();
                        this.setState('connected');
                        this.startKeepalive();
                        resolve();
                    }).catch((err) => {
                        reject(err);
                    });
                }

                if (this._pendingHandshakeMessage) {
                    const pending = this.normalizeHandshakeMessage(this._pendingHandshakeMessage);
                    this._pendingHandshakeMessage = null;
                    if (pending?.type === 'init') {
                        clearTimeout(timeout);
                        this._bridgeHandshakeResolve = null;
                        this._bridgeHandshakeReject = null;
                        this.handleIncomingHandshake(pending).then(() => {
                            this._connectedAt = Date.now();
                            this.setState('connected');
                            this.startKeepalive();
                            resolve();
                        }).catch((err) => {
                            reject(err);
                        });
                    }
                }
            });
        }

        return new Promise<void>((resolve, reject) => {
            const socket = this.socket;
            if (!socket) {
                return reject(new Error('Socket vanished before handshake wait'));
            }

            const originalCloseHandler = socket.onclose;

            const timeout = setTimeout(() => {
                if (this.socket !== socket) return;
                if (this._state === 'connecting' || this._state === 'handshaking') {
                    this.setState('failed');
                }
                try { socket.close(4001, 'Handshake timeout'); } catch { }
                reject(new Error('Timeout waiting for initiator handshake'));
            }, P2P_CONNECTION_TIMEOUT_MS);

            socket.onclose = (event) => {
                if (this.socket !== socket) return;
                clearTimeout(timeout);
                reject(new Error(`Socket closed while waiting for initiator handshake (${event.code}${event.reason ? `: ${event.reason}` : ''})`));

                if (typeof originalCloseHandler === 'function') {
                    try { originalCloseHandler.call(socket, event); } catch { }
                }
            };

            socket.onmessage = async (event) => {
                if (this.socket !== socket) return;
                try {
                    const arrayBuffer = event.data as ArrayBuffer | undefined;
                    if (!arrayBuffer || arrayBuffer.byteLength === 0) {
                        return;
                    }

                    const data = new Uint8Array(arrayBuffer);

                    // Skip keepalive pings
                    if (data.length <= 2) {
                        return;
                    }

                    let handshakeMsg;
                    try {
                        handshakeMsg = this.deserializeHandshakeMessage(data);
                        if (!handshakeMsg) {
                            return;
                        }
                    } catch { return; }

                    // Verify is an init message from the initiator
                    if (handshakeMsg.type !== 'init') {
                        return;
                    }

                    clearTimeout(timeout);

                    // Set up the normal data handler after handshake completes
                    socket.onmessage = (evt) => {
                        if (this.socket !== socket) return;
                        const d = new Uint8Array(evt.data as ArrayBuffer);
                        this.handleIncomingData(d);
                    };
                    socket.onclose = originalCloseHandler;

                    try {
                        await this.handleIncomingHandshake(handshakeMsg);
                        this._connectedAt = Date.now();
                        this.setState('connected');
                        this.startKeepalive();
                        resolve();
                    } catch (err) {
                        reject(err instanceof Error ? err : new Error(String(err)));
                    }
                } catch (err) {
                    clearTimeout(timeout);
                    reject(err instanceof Error ? err : new Error(String(err)));
                }
            };
        });
    }

    // Send raw data over the socket
    private async sendRaw(data: Uint8Array | any): Promise<void> {
        // Use bridge path if tauriUnlisten sentinel is set or bridgeConnectionId is known
        if (this.tauriUnlisten || this.bridgeConnectionId) {
            let messageToSend: any = data;
            if (data instanceof Uint8Array) {
                messageToSend = PostQuantumUtils.uint8ArrayToBase64(messageToSend);
            }
            const bridgeId = this.getActiveBridgeConnectionId();
            const res = await p2p.send(bridgeId, messageToSend);
            console.log('[P2P-SEND] p2p.send(rust) result', {
                peer: this.peerId.slice(0, 24), bridgeId: String(bridgeId).slice(0, 16),
                wireBytes: typeof messageToSend === 'string' ? messageToSend.length : undefined,
                success: res.success, error: res.error
            });

            if (!res.success) {
                console.error('[P2P-SEND] FAILED via Tauri P2P bridge:', res.error);

                const errLower = (res.error || '').toLowerCase();
                const isConnectionDead =
                    res.error === 'Connection not found' ||
                    res.error === 'Not connected' ||
                    errLower.includes('closed by peer') ||
                    errLower.includes('connection closed') ||
                    errLower.includes('connection lost') ||
                    errLower.includes('stream reset') ||
                    errLower.includes('reset by peer') ||
                    errLower.includes('send timeout') ||
                    errLower.includes('open stream');
                if (isConnectionDead) {
                    this.handleDisconnect();
                }

                throw new Error(res.error || 'Failed to send via Tauri P2P bridge');
            }

            const sentSize = data instanceof Uint8Array ? data.length : (typeof data === 'string' ? data.length : 0);
            this.bufferedAmount += sentSize;
            this._lastActivity = Date.now();
            return;
        }
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
            console.error('[P2PConnection] WebSocket not available:', {
                hasSocket: !!this.socket,
                readyState: this.socket?.readyState
            });
            throw new Error('Not connected');
        }

        this.socket.send(data);
        const sentSize = data instanceof Uint8Array ? data.length : (typeof data === 'string' ? data.length : 0);
        this.bufferedAmount += sentSize;
        this._lastActivity = Date.now();
    }

    // Send data over the socket
    async sendData(streamId: string, data: Uint8Array): Promise<void> {

        if (!this.session) {
            throw new Error('Not connected');
        }

        if (this._state !== 'connected') {
            throw new Error('Not connected');
        }

        // Frame the data with stream ID
        const idBytes = textEncoder.encode(streamId);
        const frame = new Uint8Array(2 + idBytes.length + data.length);
        const view = new DataView(frame.buffer);
        view.setUint16(0, idBytes.length, false);
        frame.set(idBytes, 2);
        frame.set(data, 2 + idBytes.length);

        await this.sendRaw(frame);
    }

    private quickHash(data: Uint8Array): string {
        let hash = 0;
        const len = data.length;
        const step = Math.max(1, Math.floor(len / 42));
        for (let i = 0; i < len; i += step) {
            hash = ((hash << 5) - hash + data[i]) | 0;
        }
        return `${len}:${hash}`;
    }

    private queueIncomingFrame(data: Uint8Array): void {
        if (!data || data.length === 0) return;
        const incomingSize = data.byteLength;
        if (incomingSize > this.MAX_PENDING_INCOMING_BYTES) {
            return;
        }
        if (
            this.pendingIncomingFrames.length >= this.MAX_PENDING_INCOMING_FRAMES ||
            this.pendingIncomingFrameBytes + incomingSize > this.MAX_PENDING_INCOMING_BYTES
        ) {
            return;
        }

        const copy = data.slice();
        this.pendingIncomingFrames.push(copy);
        this.pendingIncomingFrameBytes += copy.byteLength;
    }

    private async flushPendingIncomingFrames(): Promise<void> {
        if (this.pendingIncomingFlushDraining) return;
        if (!this.session || this.pendingIncomingFrames.length === 0) return;

        this.pendingIncomingFlushDraining = true;
        try {
            while (this.session && this.pendingIncomingFrames.length > 0) {
                const buffered = this.pendingIncomingFrames;
                this.pendingIncomingFrames = [];
                this.pendingIncomingFrameBytes = 0;

                let processedSinceYield = 0;
                for (const frame of buffered) {
                    try {
                        this.handleIncomingData(frame);
                    } catch { }
                    processedSinceYield++;
                    if (processedSinceYield >= 4) {
                        processedSinceYield = 0;
                        await new Promise<void>((resolve) => setTimeout(resolve, 0));
                    }
                }
            }
        } finally {
            this.pendingIncomingFlushDraining = false;
            if (this.session && this.pendingIncomingFrames.length > 0) {
                void this.flushPendingIncomingFrames();
            }
        }
    }

    private enqueueBase64Payload(encoded: string): void {
        if (!encoded) return;
        if (this.pendingBase64PayloadQueue.length >= this.MAX_PENDING_BASE64_PAYLOADS) {
            return;
        }
        this.pendingBase64PayloadQueue.push(encoded);
        if (!this.base64PayloadDraining) {
            this.base64PayloadDraining = true;
            void this.drainPendingBase64Payloads();
        }
    }

    private async drainPendingBase64Payloads(): Promise<void> {
        try {
            while (this.pendingBase64PayloadQueue.length > 0) {
                const batch = this.pendingBase64PayloadQueue;
                this.pendingBase64PayloadQueue = [];

                let processedSinceYield = 0;
                for (const encoded of batch) {
                    try {
                        const bytes = PostQuantumUtils.base64ToUint8Array(encoded);
                        this.handleIncomingData(bytes);
                    } catch { }

                    processedSinceYield++;
                    if (processedSinceYield >= 8) {
                        processedSinceYield = 0;
                        await new Promise<void>((resolve) => setTimeout(resolve, 0));
                    }
                }
            }
        } finally {
            this.base64PayloadDraining = false;
            if (this.pendingBase64PayloadQueue.length > 0) {
                this.base64PayloadDraining = true;
                void this.drainPendingBase64Payloads();
            }
        }
    }

    // Handle incoming data over the socket
    private handleIncomingData(data: Uint8Array): void {

        this._lastActivity = Date.now();

        // Deduplication check
        const frameHash = this.quickHash(data);
        const now = Date.now();
        const seenUntil = this.processedFrameHashes.get(frameHash) || 0;
        if (seenUntil > now) {
            return;
        }

        this.processedFrameHashes.set(frameHash, now + this.FRAME_DEDUP_EXPIRY_MS);

        this.frameDedupCleanupTick++;
        if (
            this.frameDedupCleanupTick % FRAME_DEDUP_CLEANUP_INTERVAL === 0 ||
            this.processedFrameHashes.size > 2048
        ) {
            for (const [hash, expiresAt] of this.processedFrameHashes) {
                if (expiresAt <= now) {
                    this.processedFrameHashes.delete(hash);
                }
            }

            if (this.processedFrameHashes.size > 8192) {
                let extra = this.processedFrameHashes.size - 4096;
                for (const hash of this.processedFrameHashes.keys()) {
                    this.processedFrameHashes.delete(hash);
                    extra--;
                    if (extra <= 0) break;
                }
            }
        }

        if (!this.session) {
            if (this._state === 'connected') {
                console.warn('[P2P-RECV] connected but session lost (desync) -> forcing immediate re-handshake', {
                    peer: this.peerId.slice(0, 24), bytes: data.byteLength
                });
                this.setState('failed');
                return;
            }
            
            console.warn('[P2P-RECV] no session yet — frame queued (handshake incomplete)', {
                peer: this.peerId.slice(0, 24), state: this._state, bytes: data.byteLength
            });
            this.queueIncomingFrame(data);
            return;
        }

        if (data.length < 2) {
            return;
        }

        const view = new DataView(data.buffer, data.byteOffset);
        const idLength = view.getUint16(0, false);

        // Handle keep-alive frames
        if (idLength === 0 && data.byteLength === 2) {
            return;
        }

        if (data.length < 2 + idLength) {
            return;
        }

        const idBytes = data.slice(2, 2 + idLength);
        const streamId = textDecoder.decode(idBytes);
        const payload = data.slice(2 + idLength);

        // Route to stream
        let stream = this.streams.get(streamId);
        if (!stream) {
            let type: StreamType = SignalType.MESSAGE;
            if (streamId.includes(':')) {
                const parts = streamId.split(':');
                type = parts[0] as StreamType;
            }

            stream = new P2PStream(
                streamId,
                type,
                this.peerId,
                type.startsWith('call-'),
                this.session!,
                this
            );

            this.streams.set(streamId, stream);
            this._deliverIncomingStream(stream);

            // Auto read control streams for the internal message hub
            const isSignaling = type === SignalType.MESSAGE || type === SignalType.CALL_SIGNAL || type === SignalType.SIGNAL || type === SignalType.CHAT;
            if (isSignaling) {
                this.startControlMessageReader(stream);
            }
        }

        if (stream) {
            console.log('[P2P-RECV] frame -> stream decrypt', {
                peer: this.peerId.slice(0, 24), streamId, encBytes: payload.byteLength
            });
            stream._deliverData(payload);
        } else {
        }
    }

    // Handle disconnect
    private handleDisconnect(triggeringSocket?: WebSocket): void {
        if (triggeringSocket && this.socket !== triggeringSocket) {
            return;
        }

        this.stopKeepalive();

        // Destroy old crypto session
        if (this.session) {
            try { this.session.destroy(); } catch { }
            this.session = null;
        }

        // Close and clear old streams so reconnect starts fresh
        for (const stream of Array.from(this.streams.values())) {
            try { stream.abort('disconnect'); } catch { }
        }
        this.streams.clear();
        this.streamHandlers.clear();

        if (this._bridgeHandshakeReject) {
            try { this._bridgeHandshakeReject(new Error('Bridge disconnected')); } catch { }
        }
        this._bridgeHandshakeResolve = null;
        this._bridgeHandshakeReject = null;
        this._pendingHandshakeMessage = null;
        this._pendingHandshakeToRespond = null;
        this._expectedHandshakeSessionId = null;
        this.bridgeConnectionId = null;
        this.bridgeMessageQueue = [];
        this.bridgeQueueDraining = false;
        this.pendingBase64PayloadQueue = [];
        this.base64PayloadDraining = false;
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this.pendingIncomingFlushDraining = false;
        this.processedFrameHashes.clear();

        // Reset role/collision state
        this.role = 'auto';
        this.collisionDetected = false;
        this._isResponderPending = false;
        this.incomingResponderPromise = null;

        const shouldAutoReconnect = this._state === 'connected' && this.getEffectiveRole() === 'initiator';
        if (shouldAutoReconnect) {
            this.setState('reconnecting');
            this.attemptReconnect();
        } else {
            this.setState('disconnected');
        }
    }

    private async handleTauriBridgeOpened(resolve: () => void, reject: (err: any) => void): Promise<void> {
        try {
            const effectiveRole = this.getEffectiveRole();

            // lone outbound dialer must initiate PQ noise handshake
            const shouldRespond =
                this._isResponderPending ||
                (this.collisionDetected && effectiveRole === 'responder');

            console.log('[P2P-HS] bridge opened -> handshake role decision', {
                peer: this.peerId.slice(0, 24), localPeerId: this.localPeerId.slice(0, 24),
                effectiveRole, role: this.role, collisionDetected: this.collisionDetected,
                isResponderPending: this._isResponderPending,
                hasPendingInit: !!this._pendingHandshakeToRespond,
                decision: this._pendingHandshakeToRespond ? 'respond-to-pending' : (shouldRespond ? 'wait-as-responder' : 'INITIATE')
            });

            if (this._pendingHandshakeToRespond) {
                const msg = this._pendingHandshakeToRespond;
                this._pendingHandshakeToRespond = null;
                await this.handleIncomingHandshake(msg);
            } else if (shouldRespond) {
                await this.waitForInitiatorHandshakeAndRespond();
            } else {
                await this.performHandshake();
            }

            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
            resolve();
        } catch (err) {
            p2p.disconnect(this.getActiveBridgeConnectionId()).catch(() => { });
            reject(err);
        }
    }

    private handleTauriBridgeClosed(): void {
        this.handleDisconnect();
    }

    // Attempt to reconnect
    private async attemptReconnect(error?: any): Promise<void> {
        // Stop reconnecting on errors
        if (error && (
            String(error).includes('Invalid public key') ||
            String(error).includes('Handshake failed') ||
            String(error).includes('incompatible')
        )) {
            this.setState('failed');
            return;
        }

        if (this.reconnectAttempts >= P2P_MAX_RECONNECT_ATTEMPTS) {
            this.setState('failed');
            return;
        }

        // Clear any pending reconnect timer to prevent zombie timers
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        const backoff = P2P_RECONNECT_BACKOFF_BASE_MS * Math.pow(2, this.reconnectAttempts);
        this.reconnectAttempts++;
        this.reconnectTimer = setTimeout(async () => {
            try {
                await this.connectViaP2PBridge();
                this.reconnectAttempts = 0;
            } catch (err) {
                this.attemptReconnect(err);
            }
        }, backoff);
    }

    // Stop keepalive
    private stopKeepalive(): void {
        if (this.keepaliveTimer) {
            clearInterval(this.keepaliveTimer);
            this.keepaliveTimer = null;
        }
    }

    // Start keepalive
    private startKeepalive(): void {
        if (this.keepaliveTimer) return;

        this.keepaliveTimer = setInterval(() => {
            if (this._state !== 'connected') return;

            if (this.tauriUnlisten || this.bridgeConnectionId) {
                p2p.send(this.getActiveBridgeConnectionId(), { type: '__keepalive' }).catch(() => { });
            } else if (this.socket?.readyState === WebSocket.OPEN) {
                const ping = new Uint8Array([0x00, 0x00]);
                this.socket.send(ping);
            }
        }, P2P_KEEPALIVE_INTERVAL_MS);
    }

    // Handle incoming handshake as responder
    async handleIncomingHandshake(handshakeMsg: any): Promise<void> {
        this.setState('handshaking');
        try {
            const normalized = this.normalizeHandshakeMessage(handshakeMsg);
            const { session, response } = await PQNoiseSession.processInitiatorMessage(
                this.peerId,
                this.ownKeys,
                normalized
            );

            if (normalized.signerPublicKey) {
                this.pinPeerSigningKey(normalized.signerPublicKey);
            }

            const isBridgeMode = !!(this.tauriUnlisten || this.bridgeConnectionId);
            const responseData = isBridgeMode ? this.prepareHandshakeObject(response) : this.serializeHandshakeMessage(response);
            await this.sendRaw(responseData);

            this.session = session;
            void this.flushPendingIncomingFrames();

            for (const stream of Array.from(this.streams.values())) {
                stream.updateSession(session);
            }

            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
        } catch (err) {
            this.setState('failed');
            throw err;
        }
    }

    // Handle a signal arriving
    public handleBridgedSignal(msg: any): void {

        this._lastActivity = Date.now();
        if (!this._transport) this._transport = 'p2p';

        // Ignore keepalive pings
        if (msg && typeof msg === 'object' && msg.type === '__keepalive') return;

        console.log('[P2P-RECV] handleBridgedSignal', {
            peer: this.peerId.slice(0, 24),
            kind: typeof msg === 'string' ? 'string' : (msg?.type || typeof msg),
            len: typeof msg === 'string' ? msg.length : (typeof msg?.data === 'string' ? msg.data.length : undefined),
            state: this._state,
            hasSession: !!this.session
        });

        if (typeof msg === 'string') {
            const trimmed = msg.trim();
            if (!trimmed) return;

            const shouldInspectHandshake =
                this._state !== 'connected' ||
                !!this._bridgeHandshakeResolve ||
                !!this._bridgeHandshakeReject ||
                this._isResponderPending;

            // Only inspect for handshake payloads while handshaking/recovering
            if (shouldInspectHandshake && trimmed.length <= MAX_HANDSHAKE_MESSAGE_CHARS) {
                const decoded = this.deserializeHandshakeMessage(trimmed);
                if (decoded?.type === 'init' || decoded?.type === 'response') {
                    if (this._bridgeHandshakeResolve) {
                        this._bridgeHandshakeResolve(decoded);
                        return;
                    }
                    console.warn('[P2P-HS] handshake msg arrived with NO active waiter (stashed)', {
                        peer: this.peerId.slice(0, 24), type: decoded.type, sessionId: decoded.sessionId,
                        state: this._state, expecting: this._expectedHandshakeSessionId
                    });
                    this._pendingHandshakeMessage = decoded;
                    if (decoded.type === 'init') {
                        this._pendingHandshakeToRespond = decoded;
                    }
                    return;
                }
            }

            try {
                this.enqueueBase64Payload(trimmed);
                return;
            } catch { }
        }

        if (this._bridgeHandshakeResolve) {
            this._bridgeHandshakeResolve(msg);
            return;
        }

        if (msg && (msg.type === 'init' || msg.type === 'response')) {
            console.warn('[P2P-HS] handshake msg arrived with NO active waiter (stashed, obj)', {
                peer: this.peerId.slice(0, 24), type: msg.type, sessionId: msg.sessionId,
                state: this._state, expecting: this._expectedHandshakeSessionId
            });
            this._pendingHandshakeMessage = msg;
            if (msg.type === 'init') {
                this._pendingHandshakeToRespond = msg;
            }
            return;
        }

        // Handle object wrapped data payloads from bridge
        if (msg && typeof msg === 'object' && !(msg instanceof Uint8Array)) {
            const payload = msg.data || msg.payload || msg.message;
            if (typeof payload === 'string' && payload.length > 0) {
                try {
                    this.enqueueBase64Payload(payload);
                    return;
                } catch { }
            }
            
            if (typeof msg.content === 'string' && msg.content.length > 0) {
                try {
                    this.enqueueBase64Payload(msg.content);
                    return;
                } catch { }
            }
        }
    }

    // Set state
    private setState(state: ConnectionState): void {
        if (this._state === state) return;

        this._state = state;
        this.stateUpdatedAt = Date.now();

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
                        state: this._state, peer: this.peerId.slice(0, 24)
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
    }

    // Create a new stream
    async createStream(options: StreamOptions): Promise<SecureStream> {
        if (!this.session || this._state !== 'connected') {
            throw new Error('Not connected');
        }

        if (this.streams.size >= P2P_MAX_STREAMS_PER_CONNECTION) {
            throw new Error('Maximum streams reached');
        }

        const id = `${options.type}:${PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(8))}`;
        const stream = new P2PStream(
            id,
            options.type,
            this.peerId,
            options.lossy || false,
            this.session,
            this
        );

        this.streams.set(id, stream);

        const isSignaling = options.type === SignalType.MESSAGE || options.type === SignalType.CALL_SIGNAL || options.type === SignalType.SIGNAL || options.type === SignalType.CHAT;
        if (isSignaling) {
            this.startControlMessageReader(stream);
        }

        return stream;
    }

    // Get buffered amount
    getBufferedAmount(): number {
        if (this.tauriUnlisten || this.bridgeConnectionId) return 0;
        return this.socket?.bufferedAmount || 0;
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
        this.setState('disconnected');
        this.stopKeepalive();

        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        // Close all streams
        for (const stream of Array.from(this.streams.values())) {
            await stream.close();
        }
        this.streams.clear();
        this.streamHandlers.clear();
        this.stateHandlers.clear();

        // Close socket
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }

        // Close bridge if using Tauri
        if (this.tauriUnlisten || this.bridgeConnectionId) {
            if (this.tauriUnlisten) {
                try { this.tauriUnlisten(); } catch { }
                this.tauriUnlisten = null;
            }
            p2p.disconnect(this.getActiveBridgeConnectionId()).catch(() => { });
        }
        this.bridgeConnectionId = null;

        // Destroy session
        if (this.session) {
            this.session.destroy();
            this.session = null;
        }
        this.pendingBase64PayloadQueue = [];
        this.base64PayloadDraining = false;
        this.pendingIncomingFrames = [];
        this.pendingIncomingFrameBytes = 0;
        this.pendingIncomingFlushDraining = false;
    }

    // Rotate session keys
    async rotateSessionKeys(): Promise<void> {
        if (this.session) {
            this.session.rotateKeys();
        }
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

                if (data.length > 32 * 1024) {
                    // yield after processing large message
                    await new Promise<void>((resolve) => setTimeout(resolve, 0));
                }

                let text = '';
                try {
                    text = textDecoder.decode(data);
                    const msg = JSON.parse(text);

                    // Dispatch to transport level handlers
                    const from = this.owner.resolveAppPeerId(msg.from || this.peerId);
                    const to = msg.to ? this.owner.resolveAppPeerId(msg.to) : this.owner.getLocalUsername();

                    console.log('[P2P-RECV] decoded message -> dispatch', {
                        type: msg.type, from: String(from).slice(0, 24), to: String(to).slice(0, 24),
                        payloadLen: typeof msg.payload === 'string' ? msg.payload.length : undefined,
                        streamId: stream.id
                    });

                    this.owner.dispatchMessage({
                        from,
                        to,
                        type: msg.type as SignalType,
                        payload: msg.payload,
                        timestamp: msg.timestamp || Date.now(),
                        sequence: BigInt(0),
                        verified: true,
                        routeProof: msg.routeProof,
                        signature: msg.signature
                    });
                } catch (err) {
                    console.warn('[P2P-RECV] decoded frame NOT valid JSON (dropped)', {
                        peer: this.peerId.slice(0, 24), bytes: data.byteLength,
                        head: text.slice(0, 48), error: (err as Error)?.message || String(err)
                    });
                }

                processedSinceYield++;
                if (processedSinceYield >= 8) {
                    processedSinceYield = 0;
                    await new Promise<void>((resolve) => setTimeout(resolve, 0));
                }
            }
        } catch {
        }
    }

    private shouldProcessBridgeMessageImmediately(message: any): boolean {
        if (message && typeof message === 'object') {
            const msgType = (message as any).type;
            if (msgType === '__keepalive' || msgType === 'init' || msgType === 'response') {
                return true;
            }
            return false;
        }

        // Route all string payloads through queued path
        if (typeof message === 'string') return false;

        return false;
    }

    private processBridgeEventMessage(message: any, checkHandshake: boolean): void {
        this.handleBridgedSignal(message);
        if (!checkHandshake || this._state === 'connected') return;

        let handshake: any = null;
        if (message && typeof message === 'object' && !(message instanceof Uint8Array)) {
            handshake = this.normalizeHandshakeMessage(message);
        } else if (typeof message === 'string' && message.length <= MAX_HANDSHAKE_MESSAGE_CHARS) {
            handshake = this.deserializeHandshakeMessage(message);
        }

        if (handshake?.type === 'init') {
            this.ensureIncomingResponderActive();
        }
    }

    private async drainBridgeMessageQueue(): Promise<void> {
        try {
            while (this.bridgeMessageQueue.length > 0) {
                const batch = this.bridgeMessageQueue;
                this.bridgeMessageQueue = [];

                let processedSinceYield = 0;
                for (const entry of batch) {
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
    private knownPeerIdentities: Map<string, PeerIdentity> = new Map();
    private peerCertRequestTimestamps: Map<string, number> = new Map();
    private connectSingleflight: Map<string, Promise<SecureConnection>> = new Map();
    
    private readonly MAX_USERNAME_ALIASES = 500;
    private readonly MAX_KNOWN_IDENTITIES = 500;
    private readonly MAX_CERT_REQUEST_TIMESTAMPS = 200;
    
    private bridgeEventUnlisten: UnlistenFn | null = null;
    private inboundBridgeEventQueue: any[] = [];
    private inboundBridgeEventDraining: boolean = false;
    private readonly MAX_INBOUND_BRIDGE_EVENT_QUEUE = 2048;

    private isInboxId(value: string): boolean {
        return INBOX_ID_REGEX.test(value) || BRIDGE_PEER_ID_REGEX.test(value);
    }

    private isSafePeerId(value: string): boolean {
        if (!value) return false;
        if (this.isInboxId(value)) return true;
        return /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(value);
    }

    private inferPeerFromHandshakeInit(message: unknown): string | null {
        const parseCandidate = (candidate: any): string | null => {
            if (!candidate || typeof candidate !== 'object') return null;
            if (candidate.type !== 'init' || typeof candidate.from !== 'string') return null;
            const from = candidate.from.trim();
            if (!this.isSafePeerId(from)) return null;
            return from;
        };

        if (message && typeof message === 'object' && !(message instanceof Uint8Array)) {
            return parseCandidate(message);
        }

        if (typeof message !== 'string') return null;

        // skip expensive decode attempts
        if (message.length > 8192) return null;

        let jsonStr = message.trim();
        if (!jsonStr) return null;

        if (!jsonStr.startsWith('{')) {
            try {
                const bytes = PostQuantumUtils.base64ToUint8Array(jsonStr);
                jsonStr = textDecoder.decode(bytes).trim();
            } catch {
                return null;
            }
        }

        if (!jsonStr.startsWith('{')) return null;

        try {
            const parsed = JSON.parse(jsonStr);
            return parseCandidate(parsed);
        } catch {
            return null;
        }
    }

    private resolvePeerKey(peerId: string): string | null {
        if (!peerId) return null;
        const alias = this.usernameAliases.get(peerId);
        if (this.isInboxId(peerId)) {
            return alias || peerId;
        }
        return peerId;
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
        if (connection.state === 'handshaking' || connection.state === 'connecting' || connection.state === 'reconnecting') return 1;
        return 0;
    }

    private enqueueInboundBridgeEvent(data: any): void {
        if (this.inboundBridgeEventQueue.length >= this.MAX_INBOUND_BRIDGE_EVENT_QUEUE) {
            return;
        }
        this.inboundBridgeEventQueue.push(data);
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
                for (const data of batch) {
                    try {
                        this.processInboundBridgeEvent(data);
                    } catch {
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

        // Inbound QUIC connection accepted by Rust
        if (data.type === '__p2p_connected') {
            console.log('[P2P-RECV] inbound QUIC connected (awaiting dialer init)', {
                connectionId: connectionId.slice(0, 24),
                alreadyKnown: this.connections.has(connectionId)
            });
            return;
        }

        let connection = this.connections.get(connectionId);
        const alias = this.usernameAliases.get(connectionId);
        const aliasConnection = alias ? this.connections.get(alias) : undefined;
        if (!connection && aliasConnection) {
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
                if (conn.ownsBridgeConnection(connectionId)) {
                    connection = conn;
                    break;
                }
            }
        }

        if (!connection && data.type === 'message') {
            let inferredPeer = '';

            inferredPeer = this.inferPeerFromHandshakeInit(data.data) || '';

            if (inferredPeer && this.ownKeys) {
                const peerKey = this.resolvePeerKey(inferredPeer) || inferredPeer;

                if (inferredPeer !== connectionId) {
                    this.registerUsernameAlias(inferredPeer, connectionId);
                }

                const existingForPeer = this.connections.get(peerKey);
                if (existingForPeer) {
                    connection = existingForPeer;
                } else {
                    const knownIdentity =
                        this.knownPeerIdentities.get(peerKey) ||
                        this.knownPeerIdentities.get(inferredPeer);
                    const identity: PeerIdentity = knownIdentity || {
                        username: inferredPeer,
                        kyberPublicKey: new Uint8Array(),
                        dilithiumPublicKey: new Uint8Array(),
                        x25519PublicKey: new Uint8Array(),
                        endpointUrl: undefined
                    };

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
            console.warn('[P2P-RECV] DROP: no connection for event', {
                type: data?.type,
                connectionId: connectionId.slice(0, 16),
                knownKeys: Array.from(this.connections.keys()).map(k => k.slice(0, 16)),
                aliases: Array.from(this.usernameAliases.keys()).map(k => k.slice(0, 16))
            });
            return;
        }

        connection.attachBridgeConnection(connectionId);
        if (data.type === '__p2p_closed') {
            console.log('[P2P-RECV] bridge connection closed', { connectionId: connectionId.slice(0, 16), peer: connection.peerId.slice(0, 24) });
            connection.handleBridgeEventClosed();
            return;
        }
        if (data.type === 'message') {
            console.log('[P2P-RECV] routed to connection', { connectionId: connectionId.slice(0, 16), peer: connection.peerId.slice(0, 24) });
            connection.handleBridgeEventMessage(data.data);
        }
    }

    public resolveAppPeerId(peerId: string): string {
        if (!peerId) return peerId;
        if (!this.isInboxId(peerId)) return peerId;
        const alias = this.usernameAliases.get(peerId);
        if (alias) return alias;
        return peerId;
    }

    public getLocalUsername(): string {
        return this.localUsername;
    }

    // Initialize transport
    async initialize(options: TransportInitOptions): Promise<void> {
        if (this.initialized) {
            return;
        }

        if (this.initializing) {
            while (this.initializing) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }

            if (this.initialized) {
                const nextPeerId = options.localPeerId || this.localPeerId || '';
                if (this.localUsername === options.localUsername &&
                    this.localPeerId === nextPeerId) {
                    return;
                }
            }

        }

        this.initializing = true;

        this.localUsername = options.localUsername;
        this.localPeerId = options.localUsername || options.localPeerId || '';
        this.ownKeys = {
            kyberKeyPair: options.kyberKeyPair,
            dilithiumKeyPair: options.dilithiumKeyPair,
            x25519KeyPair: options.x25519KeyPair
        };

        if (!this.localPeerId) {
            this.initializing = false;
            throw new Error('Missing local peer ID for QUIC transport initialization');
        }
        if (this.localUsername && this.localPeerId) {
            this.registerUsernameAlias(this.localUsername, this.localPeerId);
        }

        this.initialized = true;
        this.initializing = false;

        if (isTauri() && !this.bridgeEventUnlisten) {
            try {
                this.bridgeEventUnlisten = await events.onP2PMessage((evtData: unknown) => {
                    const data = evtData as any;
                    try {
                        const dlen = typeof data?.data === 'string' ? data.data.length
                            : (data?.data?.byteLength ?? data?.data?.length ?? 0);
                        console.log('[P2P-RECV] bridge<-rust event', {
                            type: data?.type,
                            connectionId: typeof data?.connectionId === 'string' ? data.connectionId.slice(0, 16) : data?.connectionId,
                            dataLen: dlen,
                            knownConnections: this.connections.size
                        });
                    } catch { }
                    this.enqueueInboundBridgeEvent(data);
                });
            } catch (err) {
                this.initialized = false;
                this.initializing = false;
                throw new Error(`Failed to attach global P2P bridge listener: ${String((err as any)?.message || err)}`);
            }
        }
    }

    // Connect to a peer
    async connect(peerId: string, options: ConnectOptions): Promise<SecureConnection> {
        if (!this.initialized || !this.ownKeys) { throw new Error('Transport not initialized'); }

        if (options.peerIdentity) {
            this.registerPeerIdentity(peerId, options.peerIdentity);
        }

        const peerKey = this.resolvePeerKey(peerId);
        if (!peerKey) {
            this.requestPeerCertificate(peerId);
            throw new Error(`Missing peer key for ${peerId}`);
        }
        const inflight = this.connectSingleflight.get(peerKey);
        if (inflight) return inflight;

        const connectPromise = (async (): Promise<SecureConnection> => {
            const appPeerId = this.resolveAppPeerId(peerId);

            // Check for existing connection
            let existing = this.connections.get(peerKey);
            if (!existing) {
                const alias = this.usernameAliases.get(peerId);
                if (alias) existing = this.connections.get(alias);
            }
            if (existing) {
                // Clean up connections in terminal or reconnecting states
                if (existing.state === 'failed' || existing.state === 'disconnected' || existing.state === 'reconnecting') {
                    try { await existing.close('stale-state-cleanup'); } catch { }
                    if (this.isCurrentConnection(peerKey, existing)) {
                        this.connections.delete(peerKey);
                    }
                    existing = undefined;
                } else if (existing.state === 'connecting' || existing.state === 'handshaking') {
                    if (options.peerIdentity && options.peerIdentity.kyberPublicKey?.length > 0) {
                        existing.updatePeerIdentity(options.peerIdentity);
                    }
                    const stateAgeMs = typeof (existing as any).getStateAgeMs === 'function'
                        ? (existing as any).getStateAgeMs()
                        : 0;
                    if (stateAgeMs > (options.timeout || P2P_CONNECTION_TIMEOUT_MS)) {
                        try { await existing.close('stale-connecting-timeout'); } catch { }
                        if (this.isCurrentConnection(peerKey, existing)) {
                            this.connections.delete(peerKey);
                        }
                        existing = undefined;
                    }
                } else if (existing.state === 'connected') {
                    if (options.peerIdentity && options.peerIdentity.kyberPublicKey?.length > 0) {
                        existing.updatePeerIdentity(options.peerIdentity);
                    }
                }
            }

            if (existing) {
                if (existing.state === 'connected') {
                    return existing;
                }

                if (existing.state === 'connecting' || existing.state === 'handshaking') {
                    if (options.peerIdentity && options.peerIdentity.kyberPublicKey?.length > 0) {
                        existing.updatePeerIdentity(options.peerIdentity);
                    }

                    return new Promise((resolve, reject) => {
                        let settled = false;
                        const unsubscribe = existing.onStateChange((state) => {
                            if (settled) return;
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
                            if (this.isCurrentConnection(peerKey, existing)) {
                                this.connections.delete(peerKey);
                            }
                            reject(new Error('Connection timeout waiting for existing connection'));
                        }, options.timeout || P2P_CONNECTION_TIMEOUT_MS);
                    });
                }

                // Any other state, remove and create fresh
                if (this.isCurrentConnection(peerKey, existing)) {
                    this.connections.delete(peerKey);
                }
            }

            // Create new connection
            const connection = new P2PConnection(
                peerKey,
                options.peerIdentity,
                this.ownKeys,
                this.localPeerId,
                this
            );

            // id ordering
            const isInitiator = this.localPeerId < peerKey;

            connection.onStateChange((state) => {
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

            const timeout = options.timeout || P2P_CONNECTION_TIMEOUT_MS;
            let timeoutId: ReturnType<typeof setTimeout> | null = null;
            const timeoutPromise = new Promise<never>((_, reject) => {
                timeoutId = setTimeout(() => reject(new Error('Connection timeout')), timeout);
            });

            try {
                // dialer always inits PQ noise handshake
                console.log('[P2P-HS] dialing peer -> will initiate handshake', {
                    peer: String(peerKey).slice(0, 24), idLower: isInitiator
                });
                await Promise.race([connection.connect(true), timeoutPromise]);
            } catch (error) {
                try {
                    if (connection.state !== 'failed' && connection.state !== 'disconnected') {
                        await connection.close('connect-attempt-failed');
                    }
                } catch { }
                // Connection map keyed by peerKey,
                if (this.isCurrentConnection(peerKey, connection)) {
                    this.connections.delete(peerKey);
                }
                throw error;
            } finally {
                if (timeoutId) {
                    clearTimeout(timeoutId);
                    timeoutId = null;
                }
            }

            return connection;
        })();

        this.connectSingleflight.set(peerKey, connectPromise);
        try {
            return await connectPromise;
        } finally {
            this.connectSingleflight.delete(peerKey);
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
        const closePromises = Array.from(this.connections.values()).map(c => c.close());
        await Promise.all(closePromises);
        this.connections.clear();

        if (this.bridgeEventUnlisten) {
            try { this.bridgeEventUnlisten(); } catch { }
            this.bridgeEventUnlisten = null;
        }
        this.inboundBridgeEventQueue = [];
        this.inboundBridgeEventDraining = false;
        this.connectSingleflight.clear();
        this.peerCertRequestTimestamps.clear();
        this.usernameAliases.clear();
        this.knownPeerIdentities.clear();
        this.messageHandlers.clear();
        this.connectHandlers.clear();
        this.disconnectHandlers.clear();
        this.localUsername = '';
        this.localPeerId = '';
        this.ownKeys = null;

        this.initialized = false;
        this.initializing = false;
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
            connection.state === 'connecting' ||
            connection.state === 'reconnecting';
    }

    private pruneStaleMaps(): void {
        if (this.usernameAliases.size > this.MAX_USERNAME_ALIASES) {
            let toRemove = this.usernameAliases.size - this.MAX_USERNAME_ALIASES;
            for (const key of this.usernameAliases.keys()) {
                if (toRemove <= 0) break;
                if (!this.connections.has(key)) {
                    this.usernameAliases.delete(key);
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

    // Register a bidirectional alias between username and inbox identifier
    registerUsernameAlias(originalUsername: string, peerKey: string): void {
        if (!originalUsername || !peerKey) return;
        this.pruneStaleMaps();
        
        if (originalUsername === peerKey) return;
        this.usernameAliases.set(originalUsername, peerKey);
        this.usernameAliases.set(peerKey, originalUsername);
        const existing = this.knownPeerIdentities.get(originalUsername) || this.knownPeerIdentities.get(peerKey);
        if (existing) {
            this.knownPeerIdentities.set(originalUsername, existing);
            this.knownPeerIdentities.set(peerKey, existing);
        }
    }

    // Resolve a potential alias (hash -> username or username -> hash)
    resolveUsernameAlias(alias: string): string | undefined {
        return this.usernameAliases.get(alias);
    }

    // Register or update a known peer identity for future connections
    registerPeerIdentity(peerId: string, identity: PeerIdentity): void {
        if (!peerId || !identity) return;
        this.pruneStaleMaps();
        const alias = this.usernameAliases.get(peerId);
        const existing = this.knownPeerIdentities.get(peerId) || (alias ? this.knownPeerIdentities.get(alias) : undefined);
        const mergedIdentity: PeerIdentity = (!identity.endpointUrl && existing?.endpointUrl)
            ? { ...identity, endpointUrl: existing.endpointUrl }
            : identity;

        this.knownPeerIdentities.set(peerId, mergedIdentity);
        this.peerCertRequestTimestamps.delete(peerId);
        if (alias) {
            this.knownPeerIdentities.set(alias, mergedIdentity);
            this.peerCertRequestTimestamps.delete(alias);
        }
        const parsedEndpoint = parseP2PEndpointUrl(mergedIdentity.endpointUrl);
        if (parsedEndpoint?.endpointId) {
            this.registerUsernameAlias(peerId, parsedEndpoint.endpointId);
            if (alias && alias !== parsedEndpoint.endpointId) {
                this.registerUsernameAlias(alias, parsedEndpoint.endpointId);
            }
        }

        let connection = this.connections.get(peerId);
        if (!connection) {
            if (alias) connection = this.connections.get(alias);
        }

        if (connection) {
            try { connection.updatePeerIdentity(mergedIdentity); } catch { }
        }
    }

    public requestPeerCertificate(peerId: string): void {
        if (typeof window === 'undefined' || !peerId) return;
        const appPeerId = this.resolveAppPeerId(peerId);
        if (!this.isSafePeerId(appPeerId)) return;
        const now = Date.now();
        const last = this.peerCertRequestTimestamps.get(appPeerId) || 0;
        if (now - last < 30_000) return;
        this.peerCertRequestTimestamps.set(appPeerId, now);
        try {
            window.dispatchEvent(new CustomEvent(EventType.P2P_FETCH_PEER_CERT, { detail: { peer: appPeerId } }));
        } catch { }
    }

    // Send a message to a peer
    async sendMessage(
        peerId: string,
        message: unknown,
        type: SignalType = SignalType.CHAT
    ): Promise<void> {
        let connection = this.connections.get(peerId);
        if (!connection) {
            const alias = this.usernameAliases.get(peerId);
            if (alias) connection = this.connections.get(alias);
        }

        if (!connection || connection.state !== 'connected') {
            throw new Error(`Not connected to ${peerId}`);
        }

        let stream = connection.getStream(type as any);
        if (!stream) {
            stream = await connection.createStream({ type: type as any });
        }

        const toUser = this.resolveAppPeerId(peerId);
        const payload = JSON.stringify({
            type,
            from: this.localUsername,
            to: toUser,
            payload: message,
            timestamp: Date.now()
        });

        const data = new TextEncoder().encode(payload);
        await stream.write(data);
    }

    // Internal dispatch a message to all handlers
    dispatchMessage(message: IncomingMessage): void {
        console.log('[P2P-RECV] dispatchMessage -> app handlers', {
            type: message.type, from: String(message.from).slice(0, 24),
            handlerCount: this.messageHandlers.size
        });
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
