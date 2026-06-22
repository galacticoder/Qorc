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
import { HybridKeys, PeerCertificateBundle, PeerSession, P2PMessage } from '../types/p2p-types';
import { toUint8, getChannelId, buildRouteProof, verifyRouteProof } from '../utils/p2p-utils';
import { normalizeP2PEndpointUrl } from '../utils/p2p-endpoint';
import { blockingSystem } from '../blocking/blocking-system';
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
import { P2PTransport, p2pTransport } from './p2p-transport';
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
    private transport: P2PTransport;

    // Callbacks
    private onMessageCallback: ((message: P2PMessage) => void) | null = null;
    private onPeerConnectedCallback: ((username: string) => void) | null = null;
    private onPeerDisconnectedCallback: ((username: string) => void) | null = null;

    // Crypto keys
    private dilithiumKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private peerDilithiumKeys: Map<string, Uint8Array> = new Map();
    private incomingRouteProofSequence: Map<string, number> = new Map();
    private kyberKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
    private x25519KeyPair: X25519KeyPair | null = null;

    // Event handling
    private readonly userBlockedEventRateState = { windowStart: Date.now(), count: 0 };
    private messageRateLimiter: Map<string, { count: number; resetTime: number }> = new Map();
    private userBlockedListener: ((event: Event) => void) | null = null;

    // Heartbeat
    private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
    private dummyTrafficInterval: ReturnType<typeof setTimeout> | null = null;
    private connectInFlight: Map<string, Promise<void>> = new Map();
    private sessionWatchers: Map<string, Set<(session: PeerSession | null) => void>> = new Map();
    private transportUnsubscribers: Array<() => void> = [];
    private initialized: boolean = false;

    constructor(username: string) {
        this.localUsername = username;
        this.transport = p2pTransport;

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

    private clearTransportSubscriptions(): void {
        if (this.transportUnsubscribers.length === 0) return;
        for (const unsubscribe of this.transportUnsubscribers.splice(0)) {
            try { unsubscribe(); } catch { }
        }
    }

    // Is peer in any of its id/alias forms currently blocked
    private isBlockedPeer(peerId: string): boolean {
        try {
            const appPeerId = this.transport.resolveAppPeerId(peerId);
            if (blockingSystem.isBlockedSync(appPeerId)) return true;
            if (peerId !== appPeerId && blockingSystem.isBlockedSync(peerId)) return true;
        } catch { }
        return false;
    }

    private emitSessionUpdate(peer: string): void {
        const listeners = this.sessionWatchers.get(peer);
        if (!listeners || listeners.size === 0) return;
        const session = this.getSessionForPeer(peer) || null;
        for (const fn of Array.from(listeners)) {
            try { fn(session); } catch { }
        }
    }

    private resolvePeerKeys(peer: string): string[] {
        const keys = new Set<string>();
        const push = (value?: string | null) => {
            if (!value || typeof value !== 'string') return;
            const normalized = value.trim();
            if (!normalized) return;
            keys.add(normalized);
        };

        push(peer);
        try { push(this.transport.resolveUsernameAlias(peer)); } catch { }
        try { push(this.transport.resolveAppPeerId(peer)); } catch { }

        for (const key of Array.from(keys)) {
            try { push(this.transport.resolveUsernameAlias(key)); } catch { }
            try { push(this.transport.resolveAppPeerId(key)); } catch { }
        }

        return Array.from(keys);
    }

    private getSessionForPeer(peer: string): PeerSession | null {
        const candidates = this.resolvePeerKeys(peer);
        for (const candidate of candidates) {
            const session = this.peers.get(candidate);
            if (session) return session;
        }
        return null;
    }

    private setSessionForPeer(peer: string, session: PeerSession): string {
        const candidates = this.resolvePeerKeys(peer);
        const canonical = this.transport.resolveAppPeerId(peer) || peer;
        const canonicalCandidates = this.resolvePeerKeys(canonical);

        for (const candidate of [...candidates, ...canonicalCandidates]) {
            this.peers.set(candidate, session);
        }

        // fresh authenticated handshake/session with peer restarts the route proof sequence
        try {
            const peerDilithium = (session.connection as any)?.peerIdentity?.dilithiumPublicKey;
            if (this.dilithiumKeys?.publicKey && peerDilithium?.length) {
                const channelId = getChannelId(
                    CryptoUtils.Base64.arrayBufferToBase64(this.dilithiumKeys.publicKey),
                    CryptoUtils.Base64.arrayBufferToBase64(peerDilithium)
                );
                this.incomingRouteProofSequence.delete(channelId);
            }
        } catch { }

        return canonical;
    }

    private emitSessionUpdatesForPeer(peer: string): void {
        for (const candidate of this.resolvePeerKeys(peer)) {
            this.emitSessionUpdate(candidate);
        }
    }

    private removeSessionAliases(session: PeerSession): void {
        for (const [key, value] of Array.from(this.peers.entries())) {
            if (value === session || value.connection === session.connection) {
                this.peers.delete(key);
                this.messageRateLimiter.delete(key);
                this.emitSessionUpdate(key);
            }
        }
    }

    private hasConnectInFlight(peer: string): boolean {
        for (const candidate of this.resolvePeerKeys(peer)) {
            if (this.connectInFlight.has(candidate)) return true;
        }
        return false;
    }

    private watchSession(peer: string, handler: (session: PeerSession | null) => void): () => void {
        let set = this.sessionWatchers.get(peer);
        if (!set) {
            set = new Set();
            this.sessionWatchers.set(peer, set);
        }
        set.add(handler);
        return () => {
            const current = this.sessionWatchers.get(peer);
            if (!current) return;
            current.delete(handler);
            if (current.size === 0) this.sessionWatchers.delete(peer);
        };
    }

    private async waitForConnectedSession(peer: string, timeoutMs: number = 5000): Promise<PeerSession | null> {
        const initial = this.getSessionForPeer(peer);
        if (initial?.state === 'connected' && initial.connection.state === 'connected') {
            return initial;
        }

        return new Promise<PeerSession | null>((resolve) => {
            let settled = false;
            let connectionUnsub: (() => void) | null = null;

            const finish = (session: PeerSession | null) => {
                if (settled) return;
                settled = true;
                try { clearTimeout(timeoutId); } catch { }
                try { unwatch(); } catch { }
                if (connectionUnsub) {
                    try { connectionUnsub(); } catch { }
                    connectionUnsub = null;
                }
                resolve(session);
            };

            const evaluate = (session: PeerSession | null) => {
                if (!session) {
                    finish(null);
                    return;
                }
                if (!connectionUnsub) {
                    connectionUnsub = session.connection.onStateChange((state) => {
                        if (state === 'connected') {
                            finish(this.getSessionForPeer(peer));
                        } else if (state === 'failed' || state === 'disconnected') {
                            finish(null);
                        }
                    });
                }
                if (session.state === 'connected' && session.connection.state === 'connected') {
                    finish(session);
                    return;
                }
                if (session.state === 'failed' || session.state === 'disconnected' || session.connection.state === 'failed' || session.connection.state === 'disconnected') {
                    finish(null);
                }
            };

            const timeoutId = setTimeout(() => finish(null), Math.max(1000, timeoutMs | 0));
            const unwatch = this.watchSession(peer, evaluate);
            evaluate(this.getSessionForPeer(peer));
        });
    }

    // Initialize the P2P service
    async initialize(): Promise<void> {
        if (this.initialized) {
            return;
        }
        try {
            // Generate Kyber key
            if (!this.kyberKeyPair) {
                const kp = await PostQuantumKEM.generateKeyPair();
                this.kyberKeyPair = { publicKey: kp.publicKey, secretKey: kp.secretKey };
            }

            // Generate X25519 key
            if (!this.x25519KeyPair) { this.x25519KeyPair = generateX25519KeyPair(); }

            // Initialize transport
            if (this.dilithiumKeys && this.kyberKeyPair && this.x25519KeyPair) {
                await this.transport.initialize({
                    localUsername: this.localUsername,
                    localPeerId: this.localUsername,
                    kyberKeyPair: this.kyberKeyPair,
                    dilithiumKeyPair: this.dilithiumKeys,
                    x25519KeyPair: this.x25519KeyPair,
                });
            }

            // Set up transport handlers
            this.clearTransportSubscriptions();
            const offPeerConnected = this.transport.onPeerConnected((peerId) => {
                const appPeerId = this.transport.resolveAppPeerId(peerId);
                // Refuse to form a session with a blocked peer
                if (this.isBlockedPeer(peerId)) {
                    try { this.transport.getConnection(peerId)?.close(); } catch { }
                    void this.disconnectPeer(appPeerId).catch(() => { });
                    return;
                }
                const connection = this.transport.getConnection(peerId);
                let session = this.getSessionForPeer(peerId);
                if (connection) {
                    const existingStream = connection.getStream(SignalType.MESSAGE);
                    if (session && !session.messageStream && existingStream) {
                        session.messageStream = existingStream;
                    }

                    // Populate peer Dilithium key from connection identity
                    if (connection.peerIdentity?.dilithiumPublicKey?.length) {
                        const candidates = this.resolvePeerKeys(peerId);
                        for (const candidate of candidates) {
                            this.peerDilithiumKeys.set(candidate, connection.peerIdentity.dilithiumPublicKey);
                        }
                    }
                }

                if (session) {
                    session.state = 'connected';
                    session.lastSeen = Date.now();
                } else if (connection) {
                    const existingStream = connection.getStream(SignalType.MESSAGE);
                    session = {
                        connection,
                        messageStream: existingStream || undefined,
                        lastSeen: Date.now(),
                        state: 'connected'
                    };
                }

                if (session) {
                    this.setSessionForPeer(peerId, session);
                    this.setSessionForPeer(appPeerId, session);
                    this.emitSessionUpdatesForPeer(peerId);
                    this.emitSessionUpdatesForPeer(appPeerId);
                    this.onPeerConnectedCallback?.(appPeerId);
                }
            });
            this.transportUnsubscribers.push(offPeerConnected);

            const offPeerDisconnected = this.transport.onPeerDisconnected((peerId, _reason) => {
                const appPeerId = this.transport.resolveAppPeerId(peerId);
                const session = this.getSessionForPeer(peerId);
                if (session) {
                    session.state = 'disconnected';
                }
                this.emitSessionUpdatesForPeer(peerId);
                this.emitSessionUpdatesForPeer(appPeerId);
                this.onPeerDisconnectedCallback?.(appPeerId);
                this.cleanupPeer(peerId);
            });
            this.transportUnsubscribers.push(offPeerDisconnected);

            const offMessage = this.transport.onMessage((ctx) => {
                // Drop any frame from a blocked peer at the transport boundary and sever the channel
                if (this.isBlockedPeer(ctx.from)) {
                    void this.disconnectPeer(this.transport.resolveAppPeerId(ctx.from)).catch(() => { });
                    return;
                }
                console.log('[MSG-RECV] SecureP2PService.onMessage', {
                    type: ctx.type, from: String(ctx.from).slice(0, 24),
                    payloadLen: typeof ctx.payload === 'string' ? ctx.payload.length : undefined
                });
                const messageType = String(ctx.type);
                if (messageType === 'heartbeat' || messageType === 'dummy') {
                    return;
                }
                if (ctx.type !== SignalType.SEALED_ENVELOPE) {
                    console.warn('[MSG-RECV] DROP: not a SEALED_ENVELOPE', { type: ctx.type });
                    return;
                }

                const p2pMsg: P2PMessage = {
                    type: ctx.type,
                    from: ctx.from,
                    to: ctx.to || this.localUsername,
                    timestamp: ctx.timestamp,
                    payload: ctx.payload,
                    routeProof: ctx.routeProof,
                    signature: ctx.signature
                };
                this.handleP2PMessage(p2pMsg).catch((err) => {
                    console.error('[MSG-RECV] handleP2PMessage threw:', (err as Error)?.message || err);
                });
            });
            this.transportUnsubscribers.push(offMessage);

            this.startDummyTraffic();
            this.startHeartbeat();
            this.initialized = true;
        } catch (error) {
            console.error('[SecureP2PService] Failed to initialize:', error);
            this.clearTransportSubscriptions();
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
        for (const candidate of this.resolvePeerKeys(username)) {
            this.peerDilithiumKeys.set(candidate, publicKey);
        }
    }

    // Connect to a peer
    async connectToPeer(
        username: string,
        options?: {
            peerCertificate?: PeerCertificateBundle;
            routeProof?: { payload: any; signature: string };
        }
    ): Promise<void> {
        const existingInflight = this.connectInFlight.get(username);
        if (existingInflight) {
            return existingInflight;
        }

        const singleflight = (async () => {

        // Refuse outbound connections to blocked users
        if (blockingSystem.isBlockedSync(username)) {
            throw new Error(`Cannot connect to blocked user: ${username}`);
        }

        // Check if already connected
        const existing = this.getSessionForPeer(username);
        if (existing?.state === 'connected' && existing.connection.state === 'connected') {
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
            x25519PublicKey: PostQuantumUtils.base64ToUint8Array(options.peerCertificate.x25519PublicKey),
            endpointUrl: normalizeP2PEndpointUrl(options.peerCertificate.p2pEndpointUrl)
        };

        // Store dilithium key for verification
        this.peerDilithiumKeys.set(username, peerIdentity.dilithiumPublicKey);

        try {
            const connection = await this.transport.connect(username, {
                peerIdentity,
                timeout: 30_000,
                onStateChange: (state) => {
                    const session = this.getSessionForPeer(username);
                    if (session) {
                        session.state = this.connectionStateToSessionState(state);
                        this.emitSessionUpdatesForPeer(username);
                    }
                }
            });

            const existingSession = this.getSessionForPeer(username);
            if (
                existingSession &&
                existingSession.connection === connection &&
                existingSession.messageStream &&
                !existingSession.messageStream.closed
            ) {
                existingSession.state = 'connected';
                existingSession.lastSeen = Date.now();
                this.setSessionForPeer(username, existingSession);
                this.emitSessionUpdatesForPeer(username);
                return;
            }

            // Reuse existing stream when possible
            let messageStream = connection.getStream(SignalType.MESSAGE);
            if (!messageStream || messageStream.closed) {
                messageStream = await connection.createStream({ type: SignalType.MESSAGE });
            }

            const session: PeerSession = {
                connection,
                messageStream,
                lastSeen: Date.now(),
                state: 'connected'
            };
            this.setSessionForPeer(username, session);
            this.emitSessionUpdatesForPeer(username);

        } catch (error) {
            throw error;
        }
        })();

        this.connectInFlight.set(username, singleflight);
        try {
            await singleflight;
        } finally {
            this.connectInFlight.delete(username);
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
        messageType: SignalType = SignalType.SEALED_ENVELOPE,
        messageId?: string
    ): Promise<void> {
        
        console.log('[MSG-SEND] SecureP2PService.sendMessage', {
            to: String(to).slice(0, 24), type: messageType, messageId
        });

        if (messageType !== SignalType.SEALED_ENVELOPE) {
            throw new Error('Invalid message type');
        }

        let session = this.getSessionForPeer(to);

        if (!session) {
            if (this.transport.isConnected(to) || this.hasConnectInFlight(to)) {
                session = await this.waitForConnectedSession(to, 1200);
            }
        }

        if (!session) { 
            console.error('[SecureP2PService] No active P2P connection');
            throw new Error('No active P2P connection'); 
        }

        if (session.state === 'connecting' || session.connection.state === 'handshaking') {
            const readySession = await this.waitForConnectedSession(to, 1000);
            if (readySession) {
                session = readySession;
            }
        }

        if (session.state !== 'connected' || session.connection.state !== 'connected') {
            console.error('[SecureP2PService] P2P connection not connected:', { 
                sessionState: session.state, 
                connectionState: session.connection.state 
            });
            throw new Error(`P2P connection is not connected (state: ${session.state})`);
        }

        if (!session.messageStream || session.messageStream.closed) {
            session.messageStream = await session.connection.createStream({ type: SignalType.MESSAGE });
        }

        // Generate route proof
        let routeProof: any = undefined;
        const peerIdentity = (session.connection as any).peerIdentity;

        if (this.dilithiumKeys && peerIdentity?.dilithiumPublicKey) {
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
            } catch {
                console.warn('[SecureP2PService] Failed to generate route proof');
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
        } catch {
            console.error('[SecureP2PService] Failed to sign P2P message');
            throw new Error('Failed to sign P2P message');
        }

        const data = new TextEncoder().encode(JSON.stringify(p2pMessage));
        console.log('[MSG-SEND] writing to P2P message stream', {
            to: String(to).slice(0, 24), bytes: data.byteLength,
            streamId: (session.messageStream as any)?.id, hasSig: !!p2pMessage.signature, hasRouteProof: !!routeProof
        });
        await session.messageStream.write(data);
        console.log('[MSG-SEND] write() resolved OK', { to: String(to).slice(0, 24) });

        session.lastSeen = Date.now();
    }

    // Handle incoming P2P message
    private async handleP2PMessage(message: P2PMessage): Promise<void> {
        console.log('[MSG-RECV] handleP2PMessage enter', {
            type: message.type, from: String(message.from).slice(0, 24),
            hasSig: !!message.signature, hasRouteProof: !!message.routeProof
        });
        if (!this.checkMessageRateLimit(message.from)) {
            console.warn('[MSG-RECV] DROP: rate limited', { from: String(message.from).slice(0, 24) });
            return;
        }

        if (message.type === SignalType.SEALED_ENVELOPE) {
            if (!message.from || !message.signature || !message.routeProof) {
                console.warn('[SecureP2PService] Rejecting unsigned or unauthenticated P2P sealed envelope');
                return;
            }
            if (message.to && message.to !== this.localUsername) {
                console.warn('[SecureP2PService] Rejecting P2P sealed envelope addressed to a different local identity');
                return;
            }
        }

        const session = this.getSessionForPeer(message.from);
        const expectedPeerUsername = session?.connection?.peerIdentity?.username;
        if (expectedPeerUsername && expectedPeerUsername !== message.from) {
            console.warn('[SecureP2PService] Rejecting P2P message with mismatched peer identity');
            return;
        }

        // Verify signature
        if (message.signature && message.from) {
            const keyCandidates = this.resolvePeerKeys(message.from);
            let peerPublicKey: Uint8Array | undefined;
            for (const candidate of keyCandidates) {
                const key = this.peerDilithiumKeys.get(candidate);
                if (key?.length) {
                    peerPublicKey = key;
                    break;
                }
            }

            // Resolve key from connection identity if not cached
            if (!peerPublicKey) {
                try {
                    let connection = this.transport.getConnection(message.from);
                    if (!connection) {
                        for (const candidate of keyCandidates) {
                            connection = this.transport.getConnection(candidate);
                            if (connection) break;
                        }
                    }
                    if (connection?.peerIdentity?.dilithiumPublicKey?.length) {
                        peerPublicKey = connection.peerIdentity.dilithiumPublicKey;
                        for (const candidate of keyCandidates) {
                            this.peerDilithiumKeys.set(candidate, peerPublicKey);
                        }
                    }
                } catch { }
            }

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
                        console.warn('[SecureP2PService] Signature verification failed', {
                            type: message.type,
                            hasTimestamp: !!message.timestamp
                        });
                        return;
                    }
                } catch {
                    console.error('[SecureP2PService] Error verifying signature');
                    return;
                }
            } else {
                console.warn('[SecureP2PService] Received signed message but no public key');
                this.transport.requestPeerCertificate(message.from);
                return;
            }

            if (message.type === SignalType.SEALED_ENVELOPE) {
                if (!this.dilithiumKeys?.publicKey) {
                    console.warn('[SecureP2PService] Rejecting P2P sealed envelope without local certified identity');
                    return;
                }
                try {
                    const peerDilithiumBase64 = CryptoUtils.Base64.arrayBufferToBase64(peerPublicKey);
                    const localDilithiumBase64 = CryptoUtils.Base64.arrayBufferToBase64(this.dilithiumKeys.publicKey);
                    const channelId = getChannelId(localDilithiumBase64, peerDilithiumBase64);
                    const minSequence = (this.incomingRouteProofSequence.get(channelId) || 0) + 1;
                    const routeProofValid = await verifyRouteProof(
                        message.routeProof,
                        localDilithiumBase64,
                        peerDilithiumBase64,
                        channelId,
                        minSequence
                    );
                    if (!routeProofValid) {
                        console.warn('[SecureP2PService] Rejecting P2P sealed envelope with invalid route proof', {
                            proofSequence: Number(message.routeProof?.payload?.sequence ?? -1),
                            expectedMinSequence: minSequence,
                            expiresAt: message.routeProof?.payload?.expiresAt,
                            now: Date.now()
                        });
                        return;
                    }
                    this.incomingRouteProofSequence.set(
                        channelId,
                        Math.max(minSequence, Number(message.routeProof?.payload?.sequence || minSequence))
                    );

                    // Hand cryptographically verified sender identity to message handler
                    (message as any).__p2pVerifiedSender = {
                        username: message.from,
                        dilithiumBase64: peerDilithiumBase64
                    };
                } catch {
                    console.warn('[SecureP2PService] Rejecting P2P sealed envelope after route proof verification error');
                    return;
                }
            }
        }

        if (session) {
            session.lastSeen = Date.now();
        }

        switch (message.type) {
            // Ignored on purpose. Heartbeat already handled
            case 'heartbeat':
            case 'dummy':
                break;
            default:
                console.log('[MSG-RECV] verified -> onMessageCallback (to app)', {
                    type: message.type, from: String(message.from).slice(0, 24),
                    hasCallback: !!this.onMessageCallback
                });
                if (!this.onMessageCallback) {
                    console.warn('[MSG-RECV] DROP: onMessageCallback not set (app not listening)');
                }
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
        const session = this.getSessionForPeer(username);
        if (!session) return;

        try {
            if (session.messageStream) {
                await session.messageStream.close();
            }
            await session.connection.close();
        } catch { }

        this.removeSessionAliases(session);
        this.onPeerDisconnectedCallback?.(username);
    }

    // Clean up peer resources
    private cleanupPeer(username: string): void {
        const session = this.getSessionForPeer(username);
        if (!session) {
            this.messageRateLimiter.delete(username);
            this.emitSessionUpdate(username);
            return;
        }
        this.removeSessionAliases(session);
    }

    private getUniqueConnectedSessions(): Array<{ peer: string; session: PeerSession }> {
        const seen = new Set<PeerSession>();
        const unique: Array<{ peer: string; session: PeerSession }> = [];
        for (const [username, session] of this.peers) {
            if (session.state !== 'connected' || !session.messageStream) continue;
            if (seen.has(session)) continue;
            seen.add(session);
            unique.push({
                peer: this.transport.resolveAppPeerId(username),
                session
            });
        }
        return unique;
    }

    // Start dummy traffic generation
    private startDummyTraffic(): void {
        if (this.dummyTrafficInterval) return;

        // Schedule next dummy traffic generation with 30% chance of sending
        const scheduleNext = () => {
            const delay = 10_000 + Math.random() * 20_000;
            this.dummyTrafficInterval = setTimeout(() => {
                for (const { peer, session } of this.getUniqueConnectedSessions()) {
                    if (Math.random() < 0.3) {
                        const dummy: P2PMessage = {
                            type: 'dummy',
                            from: this.localUsername,
                            to: peer,
                            timestamp: Date.now(),
                            payload: { padding: PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(64)) }
                        };

                        const data = new TextEncoder().encode(JSON.stringify(dummy));
                        session.messageStream.write(data).catch(() => { });
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
            for (const { peer, session } of this.getUniqueConnectedSessions()) {
                const heartbeat: P2PMessage = {
                    type: 'heartbeat',
                    from: this.localUsername,
                    to: peer,
                    timestamp: Date.now(),
                    payload: {}
                };
                const data = new TextEncoder().encode(JSON.stringify(heartbeat));
                session.messageStream.write(data).catch(() => { });
            }
        }, 25_000);
    }

    // Check if service is compatible with given configuration
    isCompatible(username: string): boolean {
        if (this.localUsername !== username) return false;
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
        this.initialized = false;
        this.clearTransportSubscriptions();
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }

        if (this.dummyTrafficInterval) {
            clearTimeout(this.dummyTrafficInterval);
            this.dummyTrafficInterval = null;
        }

        if (this.userBlockedListener && typeof window !== 'undefined') {
            window.removeEventListener(EventType.USER_BLOCKED, this.userBlockedListener);
        }

        this.connectInFlight.clear();
        this.sessionWatchers.clear();
        this.incomingRouteProofSequence.clear();

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
        const connected = new Set<string>();
        for (const [username, session] of this.peers) {
            if (session.state === 'connected') {
                connected.add(this.transport.resolveAppPeerId(username));
            }
        }
        return Array.from(connected);
    }

    // Check if specific peer is P2P connected
    isConnected(username: string): boolean {
        const session = this.getSessionForPeer(username);
        if (!session || session.state !== 'connected') return false;
        const connState = session.connection?.state;
        if (connState && connState !== 'connected') return false;
        if (session.messageStream && session.messageStream.closed) return false;
        return true;
    }
}

export function createSecureP2PService(username: string): SecureP2PService {
    return new SecureP2PService(username);
}
