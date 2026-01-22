/**
 * Secure Messaging P2P Service 
 */

import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumKEM } from '../cryptography/kem';
import { CryptoUtils } from '../utils/crypto-utils';
import { X25519KeyPair } from '../types/noise-types';
import { generateX25519KeyPair } from '../utils/noise-utils';
import { HybridKeys, PeerSession, P2PMessage } from '../types/p2p-types';
import { toUint8, getChannelId, buildRouteProof } from '../utils/p2p-utils';
import { P2P_MESSAGE_RATE_LIMIT, P2P_MESSAGE_RATE_WINDOW_MS, P2P_MAX_PEERS } from '../constants';
import {
    isPlainObject,
    hasPrototypePollutionKeys,
    sanitizeEventUsername
} from '../sanitizers';
import {
    DEFAULT_EVENT_RATE_WINDOW_MS,
    DEFAULT_EVENT_RATE_MAX,
    MAX_EVENT_USERNAME_LENGTH,
} from '../constants';
import { QuicTransport, quicTransport } from './quic-transport';
import {
    ConnectionState,
    PeerIdentity,
} from './secure-transport';
    
// Deterministic JSON stringifier
const stringifyDeterministic = (obj: any): string | undefined => {
    if (obj === undefined) return undefined;
    if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);

    if (Array.isArray(obj)) {
        return '[' + obj.map(item => {
            const val = stringifyDeterministic(item);
            return val === undefined ? 'null' : val;
        }).join(',') + ']';
    }

    const keys = Object.keys(obj).sort();
    const props = keys.map(key => {
        const val = stringifyDeterministic(obj[key]);
        if (val === undefined) return undefined;
        return JSON.stringify(key) + ':' + val;
    }).filter(v => v !== undefined);

    return '{' + props.join(',') + '}';
};

export class SecureP2PService {
    private localUsername: string = '';
    private peers: Map<string, PeerSession> = new Map();
    private channelSequence: Map<string, number> = new Map();
    private transport: QuicTransport;

    // Callbacks
    private onMessageCallback: ((message: P2PMessage) => void) | null = null;
    private onPeerConnectedCallback: ((username: string) => void) | null = null;
    private onPeerDisconnectedCallback: ((username: string) => void) | null = null;

    // Crypto keys
    private dilithiumKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private peerDilithiumKeys: Map<string, Uint8Array> = new Map();
    private kyberKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private x25519KeyPair: X25519KeyPair | null = null;

    // Event handling
    private readonly userBlockedEventRateState = { windowStart: Date.now(), count: 0 };
    private messageRateLimiter: Map<string, { count: number; resetTime: number }> = new Map();
    private userBlockedListener: ((event: Event) => void) | null = null;

    // Heartbeat
    private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
    private dummyTrafficInterval: ReturnType<typeof setInterval> | null = null;

    constructor(username: string) {
        this.localUsername = username;
        this.transport = quicTransport;

        // Set up blocked user handler
        if (typeof window !== 'undefined') {
            this.userBlockedListener = (event: Event) => {
                try {
                    const now = Date.now();
                    const bucket = this.userBlockedEventRateState;
                    if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
                        bucket.windowStart = now;
                        bucket.count = 0;
                    }
                    bucket.count++;
                    if (bucket.count > DEFAULT_EVENT_RATE_MAX) {
                        return;
                    }

                    if (!(event instanceof CustomEvent)) return;
                    const detail = event.detail;
                    if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
                    const blockedUsername = sanitizeEventUsername((detail as any).username, MAX_EVENT_USERNAME_LENGTH);
                    if (blockedUsername) {
                        this.disconnectPeer(blockedUsername);
                    }
                } catch { }
            };

            window.addEventListener(EventType.USER_BLOCKED, this.userBlockedListener);
        }
    }

    // Initialize the P2P service
    async initialize(
        signalingServerUrl: string,
        options?: {
            registerPayload: Record<string, unknown>;
            registrationSignature: string;
            registrationPublicKey: string;
        }
    ): Promise<void> {
        try {
            // Generate Kyber key
            if (!this.kyberKeyPair) {
                const kp = PostQuantumKEM.generateKeyPair();
                this.kyberKeyPair = { publicKey: kp.publicKey, secretKey: kp.secretKey };
            }

            // Generate X25519 key
            if (!this.x25519KeyPair) { this.x25519KeyPair = generateX25519KeyPair(); }

            // Initialize transport
            if (this.dilithiumKeys && this.kyberKeyPair && this.x25519KeyPair) {
                await this.transport.initialize({
                    localUsername: this.localUsername,
                    kyberKeyPair: this.kyberKeyPair,
                    dilithiumKeyPair: this.dilithiumKeys,
                    x25519KeyPair: this.x25519KeyPair,
                    relayServerUrl: signalingServerUrl.replace('wss://', 'https://').replace('ws://', 'http://'),
                    signalServerUrl: signalingServerUrl
                });
            }

            // Set up transport handlers
            this.transport.onPeerConnected((peerId) => {
                const connection = this.transport.getConnection(peerId);
                if (connection) {
                    const existingStream = connection.getStream(SignalType.MESSAGE);
                    const session = this.peers.get(peerId);
                    if (session && !session.messageStream && existingStream) {
                        session.messageStream = existingStream;
                    }

                    // Populate peer Dilithium key from connection identity
                    if (connection.peerIdentity?.dilithiumPublicKey) {
                        this.peerDilithiumKeys.set(peerId, connection.peerIdentity.dilithiumPublicKey);
                    }
                }

                const session = this.peers.get(peerId);
                if (session) {
                    session.state = 'connected';
                    session.lastSeen = Date.now();
                } else if (connection) {
                    const existingStream = connection.getStream(SignalType.MESSAGE);
                    this.peers.set(peerId, {
                        connection,
                        messageStream: existingStream || undefined,
                        lastSeen: Date.now(),
                        state: 'connected'
                    });
                }
                this.onPeerConnectedCallback?.(peerId);
            });

            this.transport.onPeerDisconnected((peerId, reason) => {
                const session = this.peers.get(peerId);
                if (session) {
                    session.state = 'disconnected';
                }
                this.onPeerDisconnectedCallback?.(peerId);
                this.cleanupPeer(peerId);
            });

            this.transport.onMessage((ctx) => {
                if (ctx.type === SignalType.CHAT ||
                    ctx.type === SignalType.MESSAGE ||
                    ctx.type === SignalType.TEXT ||
                    ctx.type === SignalType.P2P_ENCRYPTED_MESSAGE ||
                    ctx.type === SignalType.SIGNAL ||
                    ctx.type === SignalType.TYPING ||
                    ctx.type === SignalType.TYPING_START ||
                    ctx.type === SignalType.TYPING_STOP ||
                    ctx.type === SignalType.DELIVERY_ACK ||
                    ctx.type === SignalType.READ_RECEIPT ||
                    ctx.type === SignalType.CALL_SIGNAL ||
                    ctx.type === SignalType.REACTION ||
                    ctx.type === SignalType.FILE ||
                    ctx.type === SignalType.EDIT ||
                    ctx.type === SignalType.DELETE) {
                    const p2pMsg: P2PMessage = {
                        type: ctx.type,
                        from: ctx.from,
                        to: this.localUsername,
                        timestamp: ctx.timestamp,
                        payload: ctx.payload,
                        routeProof: ctx.routeProof,
                        signature: ctx.signature
                    };
                    this.handleP2PMessage(p2pMsg).catch(() => { });
                }
            });

            this.startDummyTraffic();
            this.startHeartbeat();
        } catch (error) {
            console.error('[SecureP2PService] Failed to initialize:', error);
            throw error;
        }
    }

    // Connects the service to the shared sequence map from the messaging hook
    public setChannelSequenceMap(map: Map<string, number>): void {
        this.channelSequence = map;
    }

    // Set Dilithium signing keys
    setDilithiumKeys(keys: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
        this.dilithiumKeys = keys;
    }

    // Set hybrid keys
    setHybridKeys(keys: HybridKeys): void {
        if (keys.dilithium) {
            this.dilithiumKeys = {
                publicKey: toUint8(keys.dilithium.publicKeyBase64)!,
                secretKey: keys.dilithium.secretKey
            };
        }
        if (keys.kyber) {
            this.kyberKeyPair = {
                publicKey: keys.kyber.publicKey,
                secretKey: keys.kyber.secretKey
            };
        }
        if (keys.x25519) {
            this.x25519KeyPair = {
                publicKey: keys.x25519.publicKey,
                secretKey: keys.x25519.private
            };
        }
    }

    // Add peer Dilithium public key for verification
    addPeerDilithiumKey(username: string, publicKey: Uint8Array): void {
        this.peerDilithiumKeys.set(username, publicKey);
    }

    // Connect to a peer
    async connectToPeer(
        username: string,
        options?: {
            peerCertificate?: {
                dilithiumPublicKey: string;
                kyberPublicKey: string;
                x25519PublicKey: string;
            };
            routeProof?: { payload: any; signature: string };
        }
    ): Promise<void> {
        // Check blocked status
        try {
            const { blockStatusCache } = await import('../blocking/block-status-cache');
            const isBlocked = blockStatusCache.get(username);
            if (isBlocked === true) {
                throw new Error(`Cannot connect to blocked user: ${username}`);
            }
        } catch (error) {
            if ((error as Error).message?.includes('blocked')) {
                throw error;
            }
        }

        // Check if already connected
        const existing = this.peers.get(username);
        if (existing?.state === 'connected') {
            return;
        }

        // Check peer limit
        if (this.peers.size >= P2P_MAX_PEERS) {
            throw new Error(`Maximum peer connections reached (${P2P_MAX_PEERS})`);
        }

        // Build peer identity from certificate
        if (!options?.peerCertificate) {
            throw new Error('Peer certificate required for connection');
        }

        const peerIdentity: PeerIdentity = {
            username,
            kyberPublicKey: PostQuantumUtils.base64ToUint8Array(options.peerCertificate.kyberPublicKey),
            dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(options.peerCertificate.dilithiumPublicKey),
            x25519PublicKey: PostQuantumUtils.base64ToUint8Array(options.peerCertificate.x25519PublicKey)
        };

        // Store dilithium key for verification
        this.peerDilithiumKeys.set(username, peerIdentity.dilithiumPublicKey);

        try {
            const connection = await this.transport.connect(username, {
                peerIdentity,
                timeout: 30_000,
                onStateChange: (state) => {
                    const session = this.peers.get(username);
                    if (session) {
                        session.state = this.connectionStateToSessionState(state);
                    }
                }
            });

            // Create message stream
            const messageStream = await connection.createStream({ type: SignalType.MESSAGE });

            this.peers.set(username, {
                connection,
                messageStream,
                lastSeen: Date.now(),
                state: 'connected'
            });

            if (typeof window !== 'undefined') {
                window.dispatchEvent(new CustomEvent(EventType.P2P_PQ_ESTABLISHED, {
                    detail: { peer: username }
                }));
            }
        } catch (error) {
            throw error;
        }
    }

    // Convert connection state to session state
    private connectionStateToSessionState(state: ConnectionState): 'connecting' | 'connected' | 'disconnected' | 'failed' {
        switch (state) {
            case 'connecting':
            case 'handshaking':
            case 'reconnecting':
                return 'connecting';
            case 'connected':
                return 'connected';
            case 'disconnected':
                return 'disconnected';
            case 'failed':
                return 'failed';
            default:
                return 'disconnected';
        }
    }

    // Send a message to peer
    async sendMessage(
        to: string,
        message: any,
        messageType: SignalType = SignalType.CHAT,
        messageId?: string
    ): Promise<void> {
        let session = this.peers.get(to);

        if (!session) {
            // Check if transport has an active/pending connection that hasnt been mapped to a session yet
            if (this.transport.hasActiveConnection(to)) {
                try {
                    let attempts = 0;
                    while (attempts < 30) {
                        session = this.peers.get(to);

                        if (!session) {
                            const alias = this.transport.resolveUsernameAlias(to);
                            if (alias) session = this.peers.get(alias);
                        }

                        if (session && session.state === 'connected') break;
                        // Early exit if connection is failing
                        if (session && (session.state === 'failed' || session.state === 'disconnected')) {
                            console.warn(`[SecureP2PService] session for ${to} entered ${session.state} state, aborting wait`);
                            break;
                        }
                        // Exit if transport is no longer active
                        if (!this.transport.hasActiveConnection(to)) {
                            console.warn('[SecureP2PService] transport no longer active, aborting wait');
                            break;
                        }
                        attempts++;
                        await new Promise(r => setTimeout(r, 100));
                    }
                } catch (err) {
                    console.warn('[SecureP2PService] wait for P2P session interrupted:', err);
                }
            }
        }

        // Re-fetch session after potential wait
        if (!session) {
            const alias = this.transport.resolveUsernameAlias(to);
            if (alias && alias !== to) {
                session = this.peers.get(alias);
            }
        }

        if (!session) { throw new Error(`No active P2P connection to ${to}`); }

        // Wait for session to be fully connected if it exists but looks roughly ready
        if (session.state === 'connecting' || session.connection.state === 'handshaking') {
            try {
                // Wait up to 3 seconds for connection
                let attempts = 0;
                while (attempts < 30) {
                    if (session.state === 'connected' && session.connection.state === 'connected') break;
                    // Early exit on failure
                    if (session.state === 'failed' || session.state === 'disconnected') {
                        console.warn(`[SecureP2PService] connection entered ${session.state} state during wait`);
                        break;
                    }
                    if (session.connection.state === 'failed' || session.connection.state === 'disconnected') {
                        console.warn(`[SecureP2PService] underlying connection entered ${session.connection.state} state`);
                        break;
                    }
                    attempts++;
                    await new Promise(r => setTimeout(r, 100));
                }
            } catch (err) {
                console.warn('[SecureP2PService] wait for P2P connection interrupted:', err);
            }
        }

        if (session.state !== 'connected') { throw new Error(`P2P connection to ${to} is not connected (state: ${session.state})`); }

        if (!session.messageStream || session.messageStream.closed) {
            session.messageStream = await session.connection.createStream({ type: SignalType.MESSAGE });
        }

        const isTransient = messageType === SignalType.TYPING ||
            messageType === SignalType.TYPING_START ||
            messageType === SignalType.TYPING_STOP ||
            messageType === SignalType.READ_RECEIPT ||
            messageType === SignalType.DELIVERY_ACK ||
            messageType === SignalType.SIGNAL;

        // Generate route proof (only for persistent/data messages)
        let routeProof: any = undefined;
        const peerIdentity = (session.connection as any).peerIdentity;

        if (!isTransient && this.dilithiumKeys && peerIdentity?.dilithiumPublicKey) {
            try {
                const peerDilithiumBase64 = CryptoUtils.Base64.arrayBufferToBase64(peerIdentity.dilithiumPublicKey);
                const localDilithiumBase64 = CryptoUtils.Base64.arrayBufferToBase64(this.dilithiumKeys.publicKey);

                const channelId = getChannelId(localDilithiumBase64, peerDilithiumBase64);

                const currentSeq = this.channelSequence.get(channelId) || 0;
                const nextSeq = currentSeq + 1;
                this.channelSequence.set(channelId, nextSeq);

                routeProof = await buildRouteProof(
                    this.dilithiumKeys.secretKey,
                    localDilithiumBase64,
                    peerDilithiumBase64,
                    channelId,
                    nextSeq
                );
            } catch (err) {
                console.warn('[SecureP2PService] Failed to generate route proof:', err);
            }
        }

        const p2pMessage: P2PMessage = {
            id: messageId || (typeof message === 'object' ? message.messageId || message.id : undefined),
            type: messageType as any,
            from: this.localUsername,
            to,
            timestamp: Date.now(),
            p2p: true,
            encrypted: true,
            payload: message,
            routeProof,
        };

        // Sign message 
        if (!isTransient) {
            if (!this.dilithiumKeys) {
                throw new Error('Dilithium keys not available; cannot send unsigned P2P message');
            }

            try {
                const messageBytes = new TextEncoder().encode(stringifyDeterministic({
                    type: p2pMessage.type,
                    from: p2pMessage.from,
                    to: p2pMessage.to,
                    timestamp: p2pMessage.timestamp,
                    payload: p2pMessage.payload,
                    routeProof: p2pMessage.routeProof
                }));
                const signature = await CryptoUtils.Dilithium.sign(
                    this.dilithiumKeys.secretKey,
                    messageBytes
                );
                p2pMessage.signature = CryptoUtils.Base64.arrayBufferToBase64(signature);
            } catch (err) {
                console.error('[SecureP2PService] Failed to sign P2P message:', err);
                throw new Error('Failed to sign P2P message');
            }
        }

        const data = new TextEncoder().encode(JSON.stringify(p2pMessage));
        await session.messageStream.write(data);

        session.lastSeen = Date.now();
    }

    // Handle incoming P2P message
    private async handleP2PMessage(message: P2PMessage): Promise<void> {
        if (!this.checkMessageRateLimit(message.from)) return;

        // Verify signature
        if (message.signature && message.from) {
            const peerPublicKey = this.peerDilithiumKeys.get(message.from);
            if (peerPublicKey) {
                try {
                    const messageBytes = new TextEncoder().encode(stringifyDeterministic({
                        type: message.type,
                        from: message.from,
                        to: message.to,
                        timestamp: message.timestamp,
                        payload: message.payload,
                        routeProof: message.routeProof,
                    }));
                    const signature = CryptoUtils.Base64.base64ToUint8Array(message.signature);
                    const isValid = await CryptoUtils.Dilithium.verify(signature, messageBytes, peerPublicKey);

                    if (!isValid) {
                        console.warn('[SecureP2PService] Signature verification failed for:', message.from, {
                            type: message.type,
                            timestamp: message.timestamp
                        });
                        return;
                    }
                } catch (err) {
                    console.error('[SecureP2PService] Error verifying signature:', err);
                    return;
                }
            } else {
                console.warn('[SecureP2PService] Received signed message but no public key for:', message.from);
            }
        }

        const session = this.peers.get(message.from);
        if (session) {
            session.lastSeen = Date.now();
        }

        switch (message.type) {
            case SignalType.SIGNAL: {
                const kind = message.payload?.kind;
                if (kind === SignalType.SESSION_RESET_REQUEST) {
                    window.dispatchEvent(new CustomEvent(EventType.P2P_SESSION_RESET_REQUEST, {
                        detail: { from: message.from, reason: message.payload?.reason }
                    }));
                } else if (kind === 'session-reset-ack') {
                    window.dispatchEvent(new CustomEvent(EventType.P2P_SESSION_RESET_ACK, {
                        detail: { from: message.from }
                    }));
                } else {
                    this.onMessageCallback?.(message);
                }
                break;
            }

            // Ignored on purpose. Heartbeat already handled
            case 'heartbeat':
            case 'dummy':
                break;
            default:
                this.onMessageCallback?.(message);
                break;
        }
    }

    // Check message rate limit
    private checkMessageRateLimit(from: string): boolean {
        const now = Date.now();
        const limit = this.messageRateLimiter.get(from);

        if (!limit || now > limit.resetTime) {
            this.messageRateLimiter.set(from, {
                count: 1,
                resetTime: now + P2P_MESSAGE_RATE_WINDOW_MS
            });
            return true;
        }

        if (limit.count >= P2P_MESSAGE_RATE_LIMIT) {
            return false;
        }

        limit.count++;
        return true;
    }

    // Disconnect from a peer
    async disconnectPeer(username: string): Promise<void> {
        const session = this.peers.get(username);
        if (!session) return;

        try {
            if (session.messageStream) {
                await session.messageStream.close();
            }
            await session.connection.close();
        } catch { }

        this.peers.delete(username);
        this.onPeerDisconnectedCallback?.(username);
    }

    // Clean up peer resources
    private cleanupPeer(username: string): void {
        this.peers.delete(username);
        this.messageRateLimiter.delete(username);
    }

    // Start dummy traffic generation
    private startDummyTraffic(): void {
        if (this.dummyTrafficInterval) return;

        // Schedule next dummy traffic generation with 30% chance of sending
        const scheduleNext = () => {
            const delay = 10_000 + Math.random() * 20_000;
            this.dummyTrafficInterval = setTimeout(() => {
                for (const [username, session] of this.peers) {
                    if (session.state === 'connected' && session.messageStream) {
                        if (Math.random() < 0.3) {
                            const dummy: P2PMessage = {
                                type: 'dummy',
                                from: this.localUsername,
                                to: username,
                                timestamp: Date.now(),
                                payload: { padding: PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(64)) }
                            };

                            const data = new TextEncoder().encode(JSON.stringify(dummy));
                            session.messageStream.write(data).catch(() => { });
                        }
                    }
                }
                scheduleNext();
            }, delay);
        };

        scheduleNext();
    }

    // Start heartbeat
    private startHeartbeat(): void {
        if (this.heartbeatInterval) return;

        this.heartbeatInterval = setInterval(() => {
            for (const [username, session] of this.peers) {
                if (session.state === 'connected' && session.messageStream) {
                    const heartbeat: P2PMessage = {
                        type: 'heartbeat',
                        from: this.localUsername,
                        to: username,
                        timestamp: Date.now(),
                        payload: {}
                    };
                    const data = new TextEncoder().encode(JSON.stringify(heartbeat));
                    session.messageStream.write(data).catch(() => { });
                }
            }
        }, 25_000);
    }

    // Check if service is compatible with given configuration
    isCompatible(username: string, signalingUrl: string): boolean {
        if (this.localUsername !== username) return false;

        // Check transport compatibility
        const currentRelayUrl = this.transport.getRelayServerUrl();
        const targetRelayUrl = signalingUrl.replace('wss://', 'https://').replace('ws://', 'http://');

        if (currentRelayUrl !== targetRelayUrl) return false;

        return true;
    }

    // Set message callback
    onMessage(callback: (message: P2PMessage) => void): void {
        this.onMessageCallback = callback;
    }

    // Set peer connected callback
    onPeerConnected(callback: (username: string) => void): void {
        this.onPeerConnectedCallback = callback;
    }

    // Set peer disconnected callback
    onPeerDisconnected(callback: (username: string) => void): void {
        this.onPeerDisconnectedCallback = callback;
    }

    // Shutdown service
    async shutdown(): Promise<void> {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }

        if (this.dummyTrafficInterval) {
            clearInterval(this.dummyTrafficInterval);
            this.dummyTrafficInterval = null;
        }

        if (this.userBlockedListener && typeof window !== 'undefined') {
            window.removeEventListener(EventType.USER_BLOCKED, this.userBlockedListener);
        }

        // Disconnect all peers
        for (const username of this.peers.keys()) {
            await this.disconnectPeer(username);
        }

        await this.transport.shutdown();
    }

    // Destroy the service
    destroy(): void {
        this.shutdown().catch(() => { });
    }

    // Get list of connected peer usernames
    getConnectedPeers(): string[] {
        const connected: string[] = [];
        for (const [username, session] of this.peers) {
            if (session.state === 'connected') {
                connected.push(username);
            }
        }
        return connected;
    }

    // Check if specific peer is P2P-connected
    isConnected(username: string): boolean {
        const session = this.peers.get(username);
        return !!session && session.state === 'connected';
    }
}

export function createSecureP2PService(username: string): SecureP2PService {
    return new SecureP2PService(username);
}
