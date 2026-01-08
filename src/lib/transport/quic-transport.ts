/**
 * QUIC Transport
 */

import { EventType } from '../types/event-types';
import { SignalType } from '../types/signal-types';
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
    QUIC_BUFFER_LOW_THRESHOLD
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
    private _pendingHandshakeToRespond: any = null;
    private _isResponderPending: boolean = false;
    private connectPromise: Promise<void> | null = null;
    private role: 'initiator' | 'responder' | 'auto' = 'auto';
    private collisionDetected: boolean = false;

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
        // If no collision occurred we are initiator
        if (this.role !== 'auto') return this.role;
        if (!this.collisionDetected) return 'initiator';

        // Lexicographical arbitration lower username initiates
        const isLower = this.localUsername < this.peerId;
        return isLower ? 'initiator' : 'responder';
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
                reject(new Error('Handshake response timeout'));
            }, QUIC_CONNECTION_TIMEOUT_MS);

            try {
                // Connect to relay server
                const url = `${this.relayUrl}/relay?peer=${encodeURIComponent(this.peerId)}&username=${encodeURIComponent(this.localUsername)}&ts=${Date.now()}`;

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

        if (!this.peerIdentity.kyberPublicKey || this.peerIdentity.kyberPublicKey.length === 0) {
            return this.waitForInitiatorHandshakeAndRespond();
        }

        const peerKeys: PeerKeys = {
            kyberPublicKey: this.peerIdentity.kyberPublicKey,
            dilithiumPublicKey: this.peerIdentity.dilithiumPublicKey,
            x25519PublicKey: this.peerIdentity.x25519PublicKey
        };

        // Create initiator session
        const { session, message } = PQNoiseSession.createInitiatorSession(
            this.peerId,
            this.ownKeys,
            peerKeys
        );

        // Send handshake
        const handshakeData = this.serializeHandshakeMessage(message);
        await this.sendRaw(handshakeData);

        const response = await this.waitForHandshakeResponse();

        if (response.type === 'init') {
            await this.handleIncomingHandshake(response);
            this._connectedAt = Date.now();
            this.setState('connected');
            this.startKeepalive();
            return;
        }

        session.completeHandshake(response);
        this.session = session;

        if (response.signerPublicKey) {
            const harvestedIdentity: PeerIdentity = {
                ...this.peerIdentity,
                dilithiumPublicKey: response.signerPublicKey || this.peerIdentity.dilithiumPublicKey
            };
            this.updatePeerIdentity(harvestedIdentity);
        }
    }

    // Serialize handshake message
    private serializeHandshakeMessage(message: any): Uint8Array {
        const toBase64 = (value?: Uint8Array | string): string | undefined => {
            if (!value) return undefined;
            if (typeof value === 'string') return value;
            return PostQuantumUtils.uint8ArrayToBase64(value);
        };

        const json = JSON.stringify({
            ...message,
            version: message.version || 'hybrid-session-v1',
            type: message.type,
            sessionId: message.sessionId,
            timestamp: message.timestamp || Date.now(),
            kemCiphertext: toBase64(message.kemCiphertext),
            ephemeralKyberPublic: toBase64(message.ephemeralKyberPublic),
            ephemeralX25519Public: toBase64(message.ephemeralX25519Public),
            signature: toBase64(message.signature)!,
            signerPublicKey: toBase64(message.signerPublicKey)!
        });
        return new TextEncoder().encode(json);
    }

    // Deserialize handshake message
    private deserializeHandshakeMessage(data: Uint8Array): any {
        try {
            const decoded = new TextDecoder().decode(data);
            const json = JSON.parse(decoded);

            if (json.type === 'relay-request') {
                return json;
            }

            const toUint8 = (value?: string): Uint8Array | undefined => {
                if (!value) return undefined;
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
        } catch {
            return null;
        }
    }

    // Wait for handshake response
    private async waitForHandshakeResponse(): Promise<any> {
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

                        // Force a re-evaluation of role given the new collision context
                        const role = this.getEffectiveRole();
                        if (role === 'responder') {
                            clearTimeout(timeout);
                            cleanup();
                            resolve(response);
                            return;
                        } else {
                            return;
                        }
                    }

                    if (response.type !== 'response') {
                        return;
                    }

                    clearTimeout(timeout);
                    cleanup();
                    resolve(response);
                } catch (err) {
                    clearTimeout(timeout);
                    cleanup();
                    reject(err);
                }
            };
        });
    }

    // Wait for initiator handshake to arrive over the relay then respond
    private async waitForInitiatorHandshakeAndRespond(): Promise<void> {
        this.setState('handshaking');

        return new Promise<void>((resolve, reject) => {
            const socket = this.socket;
            if (!socket) return reject(new Error('Socket vanished before handshake wait'));

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
    private async sendRaw(data: Uint8Array): Promise<void> {
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

    // Handle incoming data over the socket
    private handleIncomingData(data: Uint8Array): void {
        this._lastActivity = Date.now();

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

        if (this._state === 'connected') {
            this.setState('reconnecting');
            this.attemptReconnect();
        } else {
            this.setState('disconnected');
        }
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
            const { session, response } = PQNoiseSession.processInitiatorMessage(
                this.peerId,
                this.ownKeys,
                handshakeMsg
            );

            const responseData = this.serializeHandshakeMessage(response);
            await this.sendRaw(responseData);

            this.session = session;

            if (handshakeMsg.signerPublicKey) {
                const harvestedIdentity: PeerIdentity = {
                    ...this.peerIdentity,
                    dilithiumPublicKey: handshakeMsg.signerPublicKey || this.peerIdentity.dilithiumPublicKey
                };
                this.updatePeerIdentity(harvestedIdentity);
            }

            for (const stream of this.streams.values()) {
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

    // Set state
    private setState(state: ConnectionState): void {
        if (this._state === state) return;

        this._state = state;
        for (const handler of this.stateHandlers) {
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
        return this.socket?.bufferedAmount || 0;
    }

    // Get a stream by type
    getStream(type: StreamType): SecureStream | null {
        for (const stream of this.streams.values()) {
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
        for (const stream of this.streams.values()) {
            await stream.close();
        }
        this.streams.clear();

        // Close socket
        if (this.socket) {
            this.socket.close();
            this.socket = null;
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
        for (const handler of this.streamHandlers) {
            try {
                handler(stream);
            } catch { }
        }
    }

    // Start reading control messages from a stream
    private async startControlMessageReader(stream: QuicStream): Promise<void> {
        try {
            for await (const data of stream) {
                try {
                    const text = new TextDecoder().decode(data);
                    const msg = JSON.parse(text);

                    // Dispatch to transport level handlers
                    this.owner.dispatchMessage({
                        from: msg.from,
                        to: msg.to || this.localUsername,
                        type: msg.type as SignalType,
                        payload: msg.payload,
                        timestamp: msg.timestamp || Date.now(),
                        sequence: BigInt(0),
                        verified: true,
                        routeProof: msg.routeProof,
                        signature: msg.signature
                    });
                } catch { }
            }
        } catch { }
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

        return new Promise<void>((resolve, reject) => {
            const url = `${this.relayServerUrl}/relay?register=true&username=${encodeURIComponent(this.localUsername)}`;
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
                console.log('[QUIC Transport] Registered with relay');
                resolve();
            };

            // Handle incoming connection attempts from others
            this.registrationSocket.onmessage = async (event) => {
                let data: Uint8Array;
                if (typeof event.data === 'string') {
                    data = new TextEncoder().encode(event.data);
                } else {
                    data = new Uint8Array(event.data as ArrayBuffer);
                }

                if (data.length <= 2) {
                    return;
                }

                try {
                    const msg = this.deserializeHandshakeMessage(data);
                    if (!msg) { return; }

                    // Handle relay matchmaking request
                    if (msg.type === 'relay-request') {
                        const failures = this.recentRelayFailures.get(msg.from);
                        if (failures) {
                            if (failures.count > 4 && Date.now() - failures.lastTime < 60000) {
                                return;
                            }
                            if (Date.now() - failures.lastTime >= 60000) { this.recentRelayFailures.delete(msg.from); }
                        }

                        // Check if already has a connection to this peer
                        let connection = this.connections.get(msg.from) as QuicConnection | undefined;

                        // Extract peer metadata
                        const peerIdentity: PeerIdentity = {
                            username: msg.from,
                            kyberPublicKey: msg.ephemeralKyberPublic ? PostQuantumUtils.asUint8Array(msg.ephemeralKyberPublic) : new Uint8Array(0),
                            dilithiumPublicKey: msg.signerPublicKey ? PostQuantumUtils.asUint8Array(msg.signerPublicKey) : new Uint8Array(0),
                            x25519PublicKey: msg.ephemeralX25519Public ? PostQuantumUtils.asUint8Array(msg.ephemeralX25519Public) : new Uint8Array(0)
                        };

                        if (connection && (connection.state === 'connected' || connection.state === 'handshaking' || connection.state === 'connecting')) {
                            connection.notifyCollision();
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
                                    for (const handler of this.connectHandlers) {
                                        try { handler(msg.from); } catch { }
                                    }
                                } else if (state === 'disconnected' || state === 'failed') {
                                    this.connections.delete(msg.from);
                                    for (const handler of this.disconnectHandlers) {
                                        try { handler(msg.from, state); } catch { }
                                    }
                                }
                            });

                            this.connections.set(msg.from, connection);
                            connection.connectAsResponderPending().then(() => {
                                this.recentRelayFailures.delete(msg.from);
                            }).catch(err => {
                                this.connections.delete(msg.from);

                                const current = this.recentRelayFailures.get(msg.from) || { count: 0, lastTime: 0 };
                                this.recentRelayFailures.set(msg.from, {
                                    count: current.count + 1,
                                    lastTime: Date.now()
                                });
                            });
                        }
                    }
                } catch { }
            };

            this.registrationSocket.onerror = () => {
                resolve();
            };

            this.registrationSocket.onclose = (event) => {
                this.registrationSocket = null;

                // Clear keepalive timer
                if (this.registrationKeepaliveTimer) {
                    clearInterval(this.registrationKeepaliveTimer);
                    this.registrationKeepaliveTimer = null;
                }

                // Auto-reconnect if unexpected closure and still initialized
                if (this.initialized && event.code !== 1000) {
                    setTimeout(() => {
                        this.registerWithRelay().catch(err => { });
                    }, 500);
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
        } catch { return null; }
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

        connection.onStateChange((state) => {
            if (state === 'connected') {
                for (const handler of this.connectHandlers) {
                    try {
                        handler(peerId);
                    } catch { }
                }
            } else if (state === 'disconnected' || state === 'failed') {
                this.connections.delete(peerId);
                for (const handler of this.disconnectHandlers) {
                    try {
                        handler(peerId, state);
                    } catch { }
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

        await Promise.race([connection.connect(), timeoutPromise]);

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
        return connection?.state === 'connected' || false;
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

        for (const handler of this.messageHandlers) {
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
}

export const quicTransport = new QuicTransport();
