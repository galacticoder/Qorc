/**
 * QUIC Transport
 */

import { EventType } from '../types/event-types';
import { SignalType } from '../types/signal-types';
import { p2p, events, isTauri } from '../tauri-bindings';
import { UnlistenFn } from '@tauri-apps/api/event';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PQNoiseSession } from './pq-noise-session';
import { PeerKeys, OwnKeys } from '../types/noise-types';
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
    QUIC_CONNECTION_TIMEOUT_MS,
    QUIC_KEEPALIVE_INTERVAL_MS,
    QUIC_MAX_STREAMS_PER_CONNECTION,
    QUIC_RECONNECT_BACKOFF_BASE_MS,
    QUIC_MAX_RECONNECT_ATTEMPTS,
    QUIC_BUFFER_LOW_THRESHOLD,
    BASE64_STANDARD_REGEX
} from '../constants';

class QuicStream implements SecureStream {
    readonly id: string;
    readonly type: StreamType;
    readonly peerId: string;
    readonly lossy: boolean;

    private session: PQNoiseSession;
    private sendBuffer: Uint8Array[] = [];
    private receiveQueue: Uint8Array[] = [];
    private readResolvers: Array<(value: Uint8Array | null) => void> = [];
    private _readable: boolean = true;
    private _writable: boolean = true;
    private _closed: boolean = false;

    private transport: QuicConnection;

    constructor(
        id: string,
        type: StreamType,
        peerId: string,
        lossy: boolean,
        session: PQNoiseSession,
        transport: QuicConnection
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
            throw new Error('Stream is not writable');
        }

        const maxSize = this.type.startsWith('call-') ? MAX_CALL_FRAME_SIZE : MAX_MESSAGE_FRAME_SIZE;
        if (data.length + FRAME_OVERHEAD > maxSize) {
            throw new Error(`Data too large for stream type ${this.type}`);
        }

        const aad = new TextEncoder().encode(this.id);
        const encrypted = this.session.encrypt(data, aad);

        await this.transport.sendData(this.id, encrypted);
    }

    // Backpressure handling
    async writeWithBackpressure(data: Uint8Array): Promise<void> {
        while (this.transport.getBufferedAmount() > QUIC_BUFFER_LOW_THRESHOLD) {
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
            return this.receiveQueue.shift()!;
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

    // Internal: deliver data from transport
    _deliverData(frameData: Uint8Array): void {
        if (this._closed) return;

        // Decrypt
        try {
            const aad = new TextEncoder().encode(this.id);
            const decrypted = this.session.decrypt(frameData, aad);

            if (this.readResolvers.length > 0) {
                const resolver = this.readResolvers.shift()!;
                resolver(decrypted);
            } else {
                this.receiveQueue.push(decrypted);
            }
        } catch { }
    }
}

// Connection
class QuicConnection implements SecureConnection {
    readonly peerId: string;
    peerIdentity: PeerIdentity;
    private _state: ConnectionState = 'connecting';
    private _transport: 'quic' | 'relay' | 'unknown' = 'unknown';
    private _connectedAt: number | null = null;
    private _lastActivity: number = Date.now();

    private session: PQNoiseSession | null = null;
    private streams: Map<string, QuicStream> = new Map();
    private streamHandlers: Set<(stream: SecureStream) => void> = new Set();
    private stateHandlers: Set<(state: ConnectionState) => void> = new Set();

    // Transport layer
    private socket: WebSocket | null = null;
    private sendQueue: Array<{ streamId: string; data: Uint8Array }> = [];
    private bufferedAmount: number = 0;

    // Reconnection
    private reconnectAttempts: number = 0;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    // Keepalive
    private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
    private tauriUnlisten: UnlistenFn | null = null;
    private _bridgeHandshakeResolve: ((data: any) => void) | null = null;
    private _bridgeHandshakeReject: ((err: any) => void) | null = null;
    private _isResponderPending: boolean = false;
    private _pendingHandshakeToRespond: any = null;
    private connectPromise: Promise<void> | null = null;
    public role: 'initiator' | 'responder' | 'auto' = 'auto';
    private collisionDetected: boolean = false;

    private processedFrameHashes: Set<string> = new Set();
    private readonly FRAME_DEDUP_EXPIRY_MS = 5000;

    constructor(
        peerId: string,
        peerIdentity: PeerIdentity,
        private ownKeys: OwnKeys,
        private relayUrl: string,
        private localUsername: string,
        private owner: QuicTransport
    ) {
        this.peerId = peerId;
        this.peerIdentity = peerIdentity;
    }

    public notifyCollision(): void {
        this.collisionDetected = true;
    }

    public getEffectiveRole(): 'initiator' | 'responder' {
        // lower username initiates
        const isLower = this.localUsername < this.peerId;
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

    get state(): ConnectionState {
        return this._state;
    }

    get transport(): 'quic' | 'relay' | 'unknown' {
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

    // Connect as responder but wait for the initiator handshake to arrive over the relay
    public async connectAsResponderPending(): Promise<void> {
        this.role = 'responder';
        this._isResponderPending = true;
        return this.connect(false);
    }

    // Connect to peer
    async connect(localDial: boolean = true): Promise<void> {
        if (this.role === 'responder' && localDial) {
            this.role = 'auto';
            this.collisionDetected = true;
        }

        if (this.connectPromise) {
            return this.connectPromise;
        }

        this.connectPromise = (async () => {
            try {
                this.setState('connecting');
                await this.connectViaRelay();
            } finally {
                this.connectPromise = null;
            }
        })();

        return this.connectPromise;
    }

    // Connect with websocket relay
    private async connectViaRelay(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(() => {
                console.error(`[QuicConnection] connectViaRelay to ${this.peerId} timed out`);
                reject(new Error('Handshake response timeout'));
            }, QUIC_CONNECTION_TIMEOUT_MS);

            try {
                // Connect to relay server
                const url = `${this.relayUrl}/relay?peer=${encodeURIComponent(this.peerId)}&username=${encodeURIComponent(this.localUsername)}&ts=${Date.now()}`;

                const isOnion = this.relayUrl.toLowerCase().includes('.onion');
                const useTauriBridge = isOnion && isTauri();

                if (useTauriBridge) {
                    (async () => {
                        try {
                            this.tauriUnlisten = await events.onP2PMessage((evt: any) => {
                                const isMatch = evt?.connectionId === this.peerId;

                                // Filter by connection ID
                                if (!isMatch) {
                                    return;
                                }

                                if (evt?.type === '__p2p_signaling_connected') {
                                    clearTimeout(timeout);
                                    this._transport = 'relay';
                                    this.handleTauriBridgeOpened(resolve, reject);
                                } else if (evt?.type === '__p2p_signaling_closed') {
                                    console.warn(`[P2P Bridge] ${this.peerId} signaling closed:`, evt.reason);
                                    this.handleTauriBridgeClosed();
                                    reject(new Error(evt.reason || 'Signaling closed'));
                                } else if (evt?.type === 'message' || !evt?.type) {
                                    let data: any = evt.data;
                                    let binaryData: Uint8Array | null = null;
                                    let signalObj: any = null;

                                    // Type Analysis
                                    if (typeof data === 'string') {
                                        const trimmed = data.trim();
                                        if (trimmed.startsWith('{')) {
                                            try { signalObj = JSON.parse(trimmed); } catch { }
                                        } else {
                                            try {
                                                binaryData = PostQuantumUtils.base64ToUint8Array(data);

                                                if (binaryData.length > 4) {
                                                    const view = new DataView(binaryData.buffer, binaryData.byteOffset, binaryData.byteLength);
                                                    const len = view.getUint32(0, false);

                                                    if (len > 50 * 1024 * 1024) {
                                                        try {
                                                            const text = new TextDecoder().decode(binaryData);

                                                            if (BASE64_STANDARD_REGEX.test(text.trim())) {
                                                                const innerDecoded = PostQuantumUtils.base64ToUint8Array(text);
                                                                if (innerDecoded.length > 4) {
                                                                    const innerView = new DataView(innerDecoded.buffer, innerDecoded.byteOffset, innerDecoded.byteLength);
                                                                    const innerLen = innerView.getUint32(0, false);
                                                                    if (innerLen <= 50 * 1024 * 1024) {
                                                                        binaryData = innerDecoded;
                                                                    }
                                                                }
                                                            }
                                                        } catch { }
                                                    }
                                                }
                                            } catch (err) {
                                                console.error(`[QuicConnection] Base64 decoding failed for ${this.peerId}:`, err, { dataPrefix: data.substring(0, 50) });
                                            }
                                        }
                                    } else if (data instanceof Uint8Array) {
                                        binaryData = data;
                                    } else if (data && typeof data === 'object' && !Array.isArray(data)) {
                                        signalObj = data;
                                    }

                                    // Binary analysis
                                    if (binaryData && !signalObj) {
                                        if (binaryData[0] === 123) {
                                            try {
                                                const text = new TextDecoder().decode(binaryData);
                                                const parsed = JSON.parse(text);
                                                if (parsed && typeof parsed === 'object' && parsed.type) {
                                                    signalObj = parsed;
                                                }
                                            } catch { }
                                        }

                                        if (!signalObj && binaryData.length > 4 && binaryData[0] === 101 && binaryData[1] === 121 && binaryData[2] === 74) {
                                            try {
                                                const text = new TextDecoder().decode(binaryData);
                                                const decodedBin = PostQuantumUtils.base64ToUint8Array(text);
                                                const decodedText = new TextDecoder().decode(decodedBin);
                                                if (decodedText.trim().startsWith('{')) {
                                                    signalObj = JSON.parse(decodedText);
                                                }
                                            } catch { }
                                        }
                                    }

                                    // Dispatching
                                    if (signalObj && (signalObj.type === 'init' || signalObj.type === 'response' || signalObj.type === 'ice' || signalObj.type === 'relay-request')) {
                                        this.handleBridgedSignal(signalObj);
                                    } else if (binaryData) {
                                        if (this._bridgeHandshakeResolve) {
                                            this.handleIncomingData(binaryData);
                                        } else {
                                            this.handleIncomingData(binaryData);
                                        }
                                    } else if (signalObj) {
                                        console.warn(`[QuicConnection] Received unknown signal/data for ${this.peerId}:`, signalObj);
                                    }
                                }
                            });

                            const wsUrl = url.replace(/^http/, 'ws');
                            const res = await p2p.connect(this.peerId, wsUrl, {
                                username: this.localUsername,
                                registrationPayload: { peer: this.peerId }
                            });

                            if (!res.success) {
                                throw new Error(res.error || 'Failed to connect via Tauri P2P bridge');
                            }
                        } catch (err) {
                            clearTimeout(timeout);
                            reject(err);
                        }
                    })();
                    return;
                }

                const socket = new WebSocket(url);
                socket.binaryType = 'arraybuffer';
                this.socket = socket;

                // When the socket opens start as initiator or respond to a pending handshake
                socket.onopen = async () => {
                    if (this.socket !== socket) {
                        return;
                    }
                    clearTimeout(timeout);
                    this._transport = 'relay';

                    socket.onmessage = (evt) => {
                        if (this.socket !== socket) return;
                        const d = new Uint8Array(evt.data as ArrayBuffer);
                        this.handleIncomingData(d);
                    };

                    try {
                        const effectiveRole = this.getEffectiveRole();

                        if (this._pendingHandshakeToRespond) {
                            const msg = this._pendingHandshakeToRespond;
                            this._pendingHandshakeToRespond = null;
                            await this.handleIncomingHandshake(msg);
                        } else if (effectiveRole === 'responder') {
                            await this.waitForInitiatorHandshakeAndRespond();
                        } else {
                            await this.performHandshake();
                        }

                        this._connectedAt = Date.now();
                        this.setState('connected');
                        this.startKeepalive();
                        resolve();
                    } catch (err) {
                        socket.close();
                        reject(err);
                    }
                };

                socket.onclose = () => {
                    if (this.socket !== socket) {
                        return;
                    }

                    this.handleDisconnect(socket);
                };

                socket.onerror = () => {
                    if (this.socket !== socket) return;

                    clearTimeout(timeout);
                    reject(new Error('WebSocket error'));
                };

            } catch (err) {
                console.error('[QuicConnection] Exception during connectViaRelay:', err);
                clearTimeout(timeout);
                reject(err);
            }

        });
    }

    // Perform PQ handshake with peer
    private async performHandshake(): Promise<void> {
        this.setState('handshaking');

        const isDeterministicInitiator = this.localUsername < this.peerId;

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

        if (!isDeterministicInitiator && this.role === 'auto') {
            return this.waitForInitiatorHandshakeAndRespond();
        }

        if (!this.ownKeys) {
            throw new Error('Own keys missing for handshake');
        }

        // Create initiator session
        let session, message;
        try {
            const result = PQNoiseSession.createInitiatorSession(
                this.peerId,
                this.ownKeys,
                peerKeys
            );
            session = result.session;
            message = result.message;
        } catch (err) {
            throw err;
        }

        const handshakeData = this.tauriUnlisten ? this.prepareHandshakeObject(message) : this.serializeHandshakeMessage(message);
        await this.sendRaw(handshakeData);

        const response = await this.waitForHandshakeResponse();

        if (response.type === 'init') {
            await this.handleIncomingHandshake(response);
            return;
        }

        try {
            session.completeHandshake(response);
            this.session = session;

            if (response.signerPublicKey) {
                const harvestedIdentity: PeerIdentity = {
                    ...this.peerIdentity,
                    dilithiumPublicKey: response.signerPublicKey || this.peerIdentity.dilithiumPublicKey
                };
                this.updatePeerIdentity(harvestedIdentity);
            }

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

    // Prepare handshake object
    private prepareHandshakeObject(message: any): any {
        const toBase64 = (value?: Uint8Array | string): string | undefined => {
            if (!value) return undefined;
            if (typeof value === 'string') return value;
            return PostQuantumUtils.uint8ArrayToBase64(value);
        };

        return {
            ...message,
            from: this.localUsername,
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
        if (json.type === 'relay-request') return json;

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

    private deserializeHandshakeMessage(data: Uint8Array | any): any {
        if (!data) return null;

        // If its already an object then normalize it
        if (data && typeof data === 'object' && !(data instanceof Uint8Array)) {
            return this.normalizeHandshakeMessage(data);
        }

        try {
            const decoded = new TextDecoder().decode(data);
            const trimmed = decoded.trim();

            if (trimmed.startsWith('{')) {
                const json = JSON.parse(trimmed);
                return this.normalizeHandshakeMessage(json);
            }

            if (trimmed.startsWith('ey')) {
                try {
                    const bin = PostQuantumUtils.base64ToUint8Array(trimmed);
                    const text = new TextDecoder().decode(bin);
                    if (text.trim().startsWith('{')) {
                        return this.normalizeHandshakeMessage(JSON.parse(text));
                    }
                } catch { }
            }

            return null;
        } catch (err) {
            return null;
        }
    }

    // Wait for handshake response
    private async waitForHandshakeResponse(): Promise<any> {
        if (this.tauriUnlisten) {
            return new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    console.error(`[QuicConnection] Handshake response timeout (bridge) from ${this.peerId}`);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    reject(new Error('Handshake response timeout (bridge)'));
                }, QUIC_CONNECTION_TIMEOUT_MS);

                this._bridgeHandshakeResolve = (data) => {
                    if (data && typeof data === 'object' && !(data instanceof Uint8Array)) {
                        const response = this.normalizeHandshakeMessage(data);
                        clearTimeout(timeout);
                        this._bridgeHandshakeResolve = null;
                        this._bridgeHandshakeReject = null;
                        resolve(response);
                        return;
                    }

                    const response = this.deserializeHandshakeMessage(data);
                    if (response) {
                        clearTimeout(timeout);
                        this._bridgeHandshakeResolve = null;
                        this._bridgeHandshakeReject = null;
                        resolve(response);
                    }
                };
                this._bridgeHandshakeReject = (err) => {
                    clearTimeout(timeout);
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    reject(err);
                };
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
                reject(new Error('Handshake response timeout'));
            }, QUIC_CONNECTION_TIMEOUT_MS);

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
                        clearTimeout(timeout);
                        cleanup();
                        resolve(response);
                        return;
                    }
                } catch (err) { }
            };
        });
    }

    // Wait for initiator handshake to arrive over the relay then respond
    private async waitForInitiatorHandshakeAndRespond(): Promise<void> {
        this.setState('handshaking');

        // Check if an init message already arrived before started waiting
        if (this._pendingHandshakeToRespond) {
            const msg = this._pendingHandshakeToRespond;
            this._pendingHandshakeToRespond = null;
            await this.handleIncomingHandshake(msg);
            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
            return;
        }

        if (this.tauriUnlisten) {
            return new Promise<void>((resolve, reject) => {
                const timeout = setTimeout(() => {
                    this._bridgeHandshakeResolve = null;
                    this._bridgeHandshakeReject = null;
                    reject(new Error('Timeout waiting for initiator handshake (bridge)'));
                }, QUIC_CONNECTION_TIMEOUT_MS);

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
                try { socket.close(4001, 'Handshake timeout'); } catch { }
                reject(new Error('Timeout waiting for initiator handshake'));
            }, QUIC_CONNECTION_TIMEOUT_MS);

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
        if (this.tauriUnlisten) {
            let messageToSend: any = data;
            if (data instanceof Uint8Array) {
                messageToSend = PostQuantumUtils.uint8ArrayToBase64(messageToSend);
            }

            const res = await p2p.send(this.peerId, messageToSend);
            if (!res.success) {
                console.error('[QuicConnection] Failed to send via Tauri P2P bridge:', res.error);

                // If the Rust side lost the connection sync JS state
                if (res.error === 'Connection not found' || res.error === 'Not connected') {
                    this.handleDisconnect();
                }

                throw new Error(res.error || 'Failed to send via Tauri P2P bridge');
            }

            this.bufferedAmount += data.length;
            this._lastActivity = Date.now();
            return;
        }

        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
            throw new Error('Not connected');
        }

        this.socket.send(data);
        this.bufferedAmount += data.length;
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
        const idBytes = new TextEncoder().encode(streamId);
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

    // Handle incoming data over the socket
    private handleIncomingData(data: Uint8Array): void {
        this._lastActivity = Date.now();

        // Deduplication check
        const frameHash = this.quickHash(data);
        if (this.processedFrameHashes.has(frameHash)) {
            return;
        }

        this.processedFrameHashes.add(frameHash);

        setTimeout(() => {
            this.processedFrameHashes.delete(frameHash);
        }, this.FRAME_DEDUP_EXPIRY_MS);

        if (!this.session) {
            return;
        }

        if (data.length < 2) return;

        const view = new DataView(data.buffer, data.byteOffset);
        const idLength = view.getUint16(0, false);

        // Handle keep-alive frames
        if (idLength === 0 && data.byteLength === 2) {
            return;
        }

        if (data.length < 2 + idLength) return;

        const idBytes = data.slice(2, 2 + idLength);
        const streamId = new TextDecoder().decode(idBytes);
        const payload = data.slice(2 + idLength);

        // Route to stream
        let stream = this.streams.get(streamId);
        if (!stream) {
            let type: StreamType = SignalType.MESSAGE;
            if (streamId.includes(':')) {
                const parts = streamId.split(':');
                type = parts[0] as StreamType;
            }

            stream = new QuicStream(
                streamId,
                type,
                this.peerId,
                type.startsWith('call-'),
                this.session!,
                this
            );

            this.streams.set(streamId, stream);
            this._deliverIncomingStream(stream);

            // Auto read signaling streams for the internal message hub
            const isSignaling = type === SignalType.MESSAGE || type === SignalType.CALL_SIGNAL || type === SignalType.SIGNAL || type === SignalType.CHAT;
            if (isSignaling) {
                this.startControlMessageReader(stream);
            }
        }

        if (stream) {
            stream._deliverData(payload);
        }
    }

    // Handle disconnect
    private handleDisconnect(triggeringSocket?: WebSocket): void {
        if (triggeringSocket && this.socket !== triggeringSocket) {
            return;
        }

        this.stopKeepalive();

        if (this.tauriUnlisten) {
            this.tauriUnlisten();
            this.tauriUnlisten = null;
        }

        if (this._state === 'connected') {
            this.setState('reconnecting');
            this.attemptReconnect();
        } else {
            this.setState('disconnected');
        }
    }

    private async handleTauriBridgeOpened(resolve: () => void, reject: (err: any) => void): Promise<void> {
        try {
            const effectiveRole = this.getEffectiveRole();

            if (this._pendingHandshakeToRespond) {
                const msg = this._pendingHandshakeToRespond;
                this._pendingHandshakeToRespond = null;
                await this.handleIncomingHandshake(msg);
            } else if (effectiveRole === 'responder') {
                await this.waitForInitiatorHandshakeAndRespond();
            } else {
                await this.performHandshake();
            }

            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
            resolve();
        } catch (err) {
            p2p.disconnect(this.peerId);
            reject(err);
        }
    }

    private handleTauriBridgeClosed(): void {
        this.handleDisconnect();
    }

    // Attempt to reconnect
    private async attemptReconnect(error?: any): Promise<void> {
        // Stop reconnecting on fatal errors
        if (error && (
            String(error).includes('Invalid public key') ||
            String(error).includes('Handshake failed') ||
            String(error).includes('incompatible')
        )) {
            this.setState('failed');
            return;
        }

        if (this.reconnectAttempts >= QUIC_MAX_RECONNECT_ATTEMPTS) {
            this.setState('failed');
            return;
        }

        const backoff = QUIC_RECONNECT_BACKOFF_BASE_MS * Math.pow(2, this.reconnectAttempts);
        this.reconnectAttempts++;
        this.reconnectTimer = setTimeout(async () => {
            try {
                await this.connectViaRelay();
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
            if (this._state === 'connected' && this.socket?.readyState === WebSocket.OPEN) {
                const ping = new Uint8Array([0x00, 0x00]);
                this.socket.send(ping);
            }
        }, QUIC_KEEPALIVE_INTERVAL_MS);
    }

    // Set the socket for incoming connections
    setIncomingSocket(socket: WebSocket): void {
        this.socket = socket;
        this._transport = 'relay';
    }

    // Handle incoming handshake as responder
    async handleIncomingHandshake(handshakeMsg: any): Promise<void> {
        this.setState('handshaking');
        try {
            const normalized = this.normalizeHandshakeMessage(handshakeMsg);
            const { session, response } = PQNoiseSession.processInitiatorMessage(
                this.peerId,
                this.ownKeys,
                normalized
            );

            const responseData = this.tauriUnlisten ? this.prepareHandshakeObject(response) : this.serializeHandshakeMessage(response);
            await this.sendRaw(responseData);

            this.session = session;

            if (normalized.signerPublicKey) {
                const harvestedIdentity: PeerIdentity = {
                    ...this.peerIdentity,
                    dilithiumPublicKey: normalized.signerPublicKey || this.peerIdentity.dilithiumPublicKey
                };
                this.updatePeerIdentity(harvestedIdentity);
            }

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
        if (!this._transport) this._transport = 'relay';

        if (this._bridgeHandshakeResolve) {
            this._bridgeHandshakeResolve(msg);
            return;
        }

        if (msg.type === 'init') {
            this._pendingHandshakeToRespond = msg;
        }
    }

    // Set state
    private setState(state: ConnectionState): void {
        if (this._state === state) return;

        this._state = state;
        for (const handler of Array.from(this.stateHandlers)) {
            try {
                handler(state);
            } catch { }
        }

        if (typeof window !== 'undefined') {
            const event = new CustomEvent(EventType.P2P_CONNECTION_STATE_CHANGE, {
                detail: { peerId: this.peerId, state }
            });
            window.dispatchEvent(event);
        }
    }

    // Create a new stream
    async createStream(options: StreamOptions): Promise<SecureStream> {
        if (!this.session || this._state !== 'connected') {
            throw new Error('Not connected');
        }

        if (this.streams.size >= QUIC_MAX_STREAMS_PER_CONNECTION) {
            throw new Error('Maximum streams reached');
        }

        const id = `${options.type}:${PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(8))}`;
        const stream = new QuicStream(
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
        if (this.tauriUnlisten) return 0;
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
    abortStream(streamId: string, reason?: string): void {
        this.streams.delete(streamId);
    }

    // Close the connection
    async close(reason?: string): Promise<void> {
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

        // Close socket
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }

        // Close bridge if using Tauri
        if (this.tauriUnlisten) {
            try { this.tauriUnlisten(); } catch (e) { }
            this.tauriUnlisten = null;
            p2p.disconnect(this.peerId).catch(() => { });
        }

        // Destroy session
        if (this.session) {
            this.session.destroy();
            this.session = null;
        }
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

    // Internal: deliver incoming stream
    _deliverIncomingStream(stream: QuicStream): void {
        this.streams.set(stream.id, stream);
        for (const handler of Array.from(this.streamHandlers)) {
            try {
                handler(stream);
            } catch { }
        }
    }

    // Start reading control messages from a stream
    private async startControlMessageReader(stream: QuicStream): Promise<void> {
        try {
            for await (const data of stream) {
                if (!data || data.length === 0) continue;
                
                let text = '';
                try {
                    text = new TextDecoder().decode(data);
                    const msg = JSON.parse(text);

                    // Dispatch to transport level handlers
                    this.owner.dispatchMessage({
                        from: msg.from || this.peerId,
                        to: msg.to || this.localUsername,
                        type: msg.type as SignalType,
                        payload: msg.payload, 
                        timestamp: msg.timestamp || Date.now(),
                        sequence: BigInt(0),
                        verified: true,
                        routeProof: msg.routeProof,
                        signature: msg.signature
                    });
                } catch (err) { }
            }
        } catch (err) { }
    }

    // Get the session
    getSession(): PQNoiseSession | null {
        return this.session;
    }
}

/**
 * QUIC Transport
 */
export class QuicTransport implements SecureTransport {
    private initialized: boolean = false;
    private initializing: boolean = false;
    private localUsername: string = '';
    private ownKeys: OwnKeys | null = null;
    private relayServerUrl: string = '';
    private signalServerUrl: string = '';

    private connections: Map<string, QuicConnection> = new Map();
    private messageHandlers: Set<MessageHandler> = new Set();
    private connectHandlers: Set<(peerId: string) => void> = new Set();
    private disconnectHandlers: Set<(peerId: string, reason?: string) => void> = new Set();

    private usernameAliases: Map<string, string> = new Map();
    private recentRelayFailures: Map<string, { count: number, lastTime: number }> = new Map();
    private registrationSocket: WebSocket | null = null;

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
                if (this.localUsername === options.localUsername &&
                    this.relayServerUrl === (options.relayServerUrl || '') &&
                    this.signalServerUrl === (options.signalServerUrl || '')) {
                    return;
                }
            }

        }

        this.initializing = true;

        this.localUsername = options.localUsername;
        this.ownKeys = {
            kyberKeyPair: options.kyberKeyPair,
            dilithiumKeyPair: options.dilithiumKeyPair,
            x25519KeyPair: options.x25519KeyPair
        };
        this.relayServerUrl = options.relayServerUrl || '';
        this.signalServerUrl = options.signalServerUrl || '';

        await this.registerWithRelay();

        this.initialized = true;
        this.initializing = false;
    }

    // Keepalive interval for registration socket
    private registrationKeepaliveTimer: ReturnType<typeof setInterval> | null = null;

    // Register with relay server
    private async registerWithRelay(): Promise<void> {
        if (!this.relayServerUrl) return;

        if (this.registrationSocket) {
            if (this.registrationSocket.readyState === WebSocket.OPEN ||
                this.registrationSocket.readyState === WebSocket.CONNECTING) {
                return;
            }
        }

        const url = `${this.relayServerUrl}/relay?register=true&username=${encodeURIComponent(this.localUsername)}`;
        const isTor = typeof window !== 'undefined' && window.location.hostname.endsWith('.onion');
        const isTauriEnv = isTauri();

        if (isTauriEnv && (url.includes('.onion') || isTor)) {
            const wsUrl = url.replace(/^http/, 'ws');
            const connectionId = 'registration';

            // Unlisten previous if exists
            if ((this as any).tauriRegUnlisten) {
                (this as any).tauriRegUnlisten();
            }

            (this as any).tauriRegUnlisten = await events.onP2PMessage(async (event: any) => {
                if (event.connectionId !== connectionId) {
                    return;
                }

                if (event.type === '__p2p_signaling_connected') {
                } else if (event.type === 'message') {
                    let data = event.data;
                    if (typeof data === 'string' && !data.trim().startsWith('{')) {
                        try {
                            data = PostQuantumUtils.base64ToUint8Array(data);
                        } catch { }
                    }
                    this.handleRegistrationMessage(data);
                } else if (event.type === '__p2p_signaling_closed') {
                    console.warn('[QUIC Transport] Registration bridge closed');
                    if (this.initialized) {
                        const retryUrl = wsUrl;
                        p2p.connect(connectionId, retryUrl, { username: this.localUsername }).catch(() => { });
                    }
                }
            });

            p2p.connect(connectionId, wsUrl, { username: this.localUsername }).then(res => {
                if (!res.success) console.error('[QUIC Transport] P2P bridge registration failed:', res.error);
            }).catch(err => {
                console.error('[QUIC Transport] P2P bridge registration error:', err);
            });

            return;
        }

        return new Promise<void>((resolve) => {
            this.registrationSocket = new WebSocket(url);
            this.registrationSocket.binaryType = 'arraybuffer';

            // Start keepalive interval
            if (this.registrationKeepaliveTimer) {
                clearInterval(this.registrationKeepaliveTimer);
            }
            this.registrationKeepaliveTimer = setInterval(() => {
                if (this.registrationSocket && this.registrationSocket.readyState === WebSocket.OPEN) {
                    try {
                        const pingFrame = new Uint8Array([0x00, 0x00]);
                        this.registrationSocket.send(pingFrame);
                    } catch { }
                }
            }, 5_000);

            this.registrationSocket.onopen = () => {
                resolve();
            };

            this.registrationSocket.onmessage = (event) => this.handleRegistrationMessage(event.data);

            this.registrationSocket.onerror = () => {
                resolve();
            };

            this.registrationSocket.onclose = (event) => {
                this.registrationSocket = null;
                if (this.registrationKeepaliveTimer) {
                    clearInterval(this.registrationKeepaliveTimer);
                    this.registrationKeepaliveTimer = null;
                }

                if (this.initialized && event.code !== 1000) {
                    setTimeout(() => {
                        this.registerWithRelay().catch(() => { });
                    }, 5000);
                }
            };
        });
    }

    // Deserialize a handshake message
    private deserializeHandshakeMessage(data: Uint8Array): any {
        try {
            const decoded = new TextDecoder().decode(data);
            const json = JSON.parse(decoded);
            return {
                ...json,
                kemCiphertext: json.kemCiphertext ? PostQuantumUtils.base64ToUint8Array(json.kemCiphertext) : undefined,
                ephemeralX25519Public: json.ephemeralX25519Public ? PostQuantumUtils.base64ToUint8Array(json.ephemeralX25519Public) : undefined,
                signature: json.signature ? PostQuantumUtils.base64ToUint8Array(json.signature) : undefined,
                dilithiumPublicKey: json.dilithiumPublicKey ? PostQuantumUtils.base64ToUint8Array(json.dilithiumPublicKey) : undefined
            };
        } catch (err) {
            console.error('[QUIC Transport] Deserialization failed:', err, 'Data len:', data.length);
            return null;
        }
    }

    // Connect to a peer
    async connect(peerId: string, options: ConnectOptions): Promise<SecureConnection> {
        if (!this.initialized || !this.ownKeys) { throw new Error('Transport not initialized'); }

        // Check for existing connection
        const existing = this.connections.get(peerId);
        if (existing) {
            if (existing.state === 'connected' || existing.state === 'connecting' || existing.state === 'handshaking') {
                if (options.peerIdentity && options.peerIdentity.kyberPublicKey?.length > 0) {
                    existing.updatePeerIdentity(options.peerIdentity);
                }

                if (existing.state === 'connecting' || existing.state === 'handshaking') {
                    return new Promise((resolve, reject) => {
                        const timeout = setTimeout(() => {
                            console.error(`[QUIC Transport] connect(${peerId}) timed out waiting for existing connection (state was ${existing.state})`);
                            reject(new Error('Connection timeout waiting for existing connection'));
                        }, options.timeout || QUIC_CONNECTION_TIMEOUT_MS);

                        existing.onStateChange((state) => {
                            if (state === 'connected') {
                                clearTimeout(timeout);
                                resolve(existing);
                            } else if (state === 'failed' || state === 'disconnected') {
                                clearTimeout(timeout);
                                reject(new Error(`Connection failed: ${state}`));
                            }
                        });
                    });
                }
                const isInitiator = this.localUsername < peerId;
                if (isInitiator && existing.role === 'responder') {
                    existing.connect(true).catch(() => { });
                }
                return existing;
            }

            this.connections.delete(peerId);
        }

        // Create new connection
        const connection = new QuicConnection(
            peerId,
            options.peerIdentity,
            this.ownKeys,
            this.relayServerUrl,
            this.localUsername,
            this
        );

        // Deterministic initiator
        const isInitiator = this.localUsername < peerId;

        connection.onStateChange((state) => {
            if (state === 'connected') {
                for (const handler of Array.from(this.connectHandlers)) {
                    try { handler(peerId); } catch { }
                }
            } else if (state === 'disconnected' || state === 'failed') {
                this.connections.delete(peerId);
                for (const handler of Array.from(this.disconnectHandlers)) {
                    try { handler(peerId, state); } catch { }
                }
            }

            if (options.onStateChange) {
                options.onStateChange(state);
            }
        });

        this.connections.set(peerId, connection);

        const timeout = options.timeout || QUIC_CONNECTION_TIMEOUT_MS;
        const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Connection timeout')), timeout);
        });

        try {
            if (isInitiator) {
                await Promise.race([connection.connect(true), timeoutPromise]);
            } else {
                await Promise.race([connection.connectAsResponderPending(), timeoutPromise]);
            }
        } catch (error) {
            this.connections.delete(peerId);
            throw error;
        }

        return connection;
    }

    // Disconnect from a peer
    async disconnect(peerId: string): Promise<void> {
        const connection = this.connections.get(peerId);
        if (connection) {
            await connection.close();
            this.connections.delete(peerId);
        }
    }

    // Shutdown the transport
    async shutdown(): Promise<void> {
        const closePromises = Array.from(this.connections.values()).map(c => c.close());
        await Promise.all(closePromises);
        this.connections.clear();

        if (this.registrationKeepaliveTimer) {
            clearInterval(this.registrationKeepaliveTimer);
            this.registrationKeepaliveTimer = null;
        }
        if (this.registrationSocket) {
            this.registrationSocket.close();
            this.registrationSocket = null;
        }

        if ((this as any).tauriRegUnlisten) {
            try { (this as any).tauriRegUnlisten(); } catch (e) { }
            (this as any).tauriRegUnlisten = null;
            p2p.disconnect('registration').catch(() => { });
        }

        this.initialized = false;
    }

    getConnection(peerId: string): SecureConnection | null {
        const conn = this.connections.get(peerId);
        if (conn) return conn;
        const alias = this.usernameAliases.get(peerId);
        if (alias) return this.connections.get(alias) || null;
        return null;
    }

    getRelayServerUrl(): string {
        return this.relayServerUrl;
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

    // Register a bidirectional alias between original username and hashed peerId
    registerUsernameAlias(originalUsername: string, hashedPeerId: string): void {
        this.usernameAliases.set(originalUsername, hashedPeerId);
        this.usernameAliases.set(hashedPeerId, originalUsername);
    }

    // Resolve a potential alias (hash -> username or username -> hash)
    resolveUsernameAlias(alias: string): string | undefined {
        return this.usernameAliases.get(alias);
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

        const payload = JSON.stringify({
            type,
            from: this.localUsername,
            to: peerId,
            payload: message,
            timestamp: Date.now()
        });

        const data = new TextEncoder().encode(payload);
        await stream.write(data);
    }

    // Internal: dispatch a message to all handlers
    dispatchMessage(message: IncomingMessage): void {
        if (typeof window !== 'undefined') {
            try {
                window.dispatchEvent(new CustomEvent(EventType.P2P_MESSAGE_RECEIVED, {
                    detail: message
                }));
            } catch { }
        }

        for (const handler of Array.from(this.messageHandlers)) {
            try {
                handler(message);
            } catch { }
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

    // Handle registration message shared between WebSocket and P2P bridge
    private async handleRegistrationMessage(eventData: any): Promise<void> {
        let data: Uint8Array;
        if (eventData instanceof Uint8Array) {
            data = eventData;
        } else if (eventData instanceof ArrayBuffer) {
            data = new Uint8Array(eventData);
        } else if (typeof eventData === 'string') {
            data = new TextEncoder().encode(eventData);
        } else if (typeof eventData === 'object' && eventData !== null) {
            const msg = eventData;
            return this.processRegistrationSignal(msg);
        } else {
            return;
        }

        if (data.length <= 2) return;

        try {
            const msg = this.deserializeHandshakeMessage(data);
            if (msg) this.processRegistrationSignal(msg);
        } catch { }
    }

    private async processRegistrationSignal(msg: any): Promise<void> {
        if (msg.type === 'relay-request') {
            const failures = this.recentRelayFailures.get(msg.from);
            if (failures) {
                if (failures.count > 4 && Date.now() - failures.lastTime < 60000) {
                    console.warn(`[QUIC Transport] Ignoring relay-request from ${msg.from} due to rate limiting`);
                    return;
                }
                if (Date.now() - failures.lastTime >= 60000) this.recentRelayFailures.delete(msg.from);
            }

            let connection = this.connections.get(msg.from) as QuicConnection | undefined;

            const peerIdentity: PeerIdentity = {
                username: msg.from,
                kyberPublicKey: msg.ephemeralKyberPublic ? PostQuantumUtils.asUint8Array(msg.ephemeralKyberPublic) : new Uint8Array(0),
                dilithiumPublicKey: msg.signerPublicKey ? PostQuantumUtils.asUint8Array(msg.signerPublicKey) : new Uint8Array(0),
                x25519PublicKey: msg.ephemeralX25519Public ? PostQuantumUtils.asUint8Array(msg.ephemeralX25519Public) : new Uint8Array(0)
            };

            const isInitiator = this.localUsername < msg.from;

            if (connection && (connection.state === 'connected' || connection.state === 'handshaking' || connection.state === 'connecting')) {
                // If we are initiator but existing connection is responder then upgrade it
                if (isInitiator && connection.role === 'responder') {
                    connection.connect(true).catch(() => { });
                }

                return;
            }

            if (!connection || connection.state === 'disconnected' || connection.state === 'failed') {
                connection = new QuicConnection(
                    msg.from,
                    peerIdentity,
                    this.ownKeys!,
                    this.relayServerUrl,
                    this.localUsername,
                    this
                );
                connection.onStateChange((state) => {
                    if (state === 'connected') {
                        for (const handler of Array.from(this.connectHandlers)) {
                            try { handler(msg.from); } catch { }
                        }
                    } else if (state === 'disconnected' || state === 'failed') {
                        this.connections.delete(msg.from);
                        for (const handler of Array.from(this.disconnectHandlers)) {
                            try { handler(msg.from, state); } catch { }
                        }
                    }
                });

                this.connections.set(msg.from, connection);

                const isInitiator = this.localUsername < msg.from;
                const connectAction = isInitiator ? connection.connect(true) : connection.connectAsResponderPending();

                connectAction.then(() => {
                    this.recentRelayFailures.delete(msg.from);
                }).catch(() => {
                    this.connections.delete(msg.from);
                    const current = this.recentRelayFailures.get(msg.from) || { count: 0, lastTime: 0 };
                    this.recentRelayFailures.set(msg.from, {
                        count: current.count + 1,
                        lastTime: Date.now()
                    });
                });
            }
        } else if (msg.from && (msg.type === 'init' || msg.type === 'response' || msg.type === 'ice')) {
            const connection = this.connections.get(msg.from) as QuicConnection | undefined;
            if (connection) {
                connection.handleBridgedSignal(msg);
            }
        }
    }
}

export const quicTransport = new QuicTransport();
