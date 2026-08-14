/**
 * Secure Messaging P2P Service
 */

import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { PostQuantumUtils } from '../utils/pq-utils';
import { CryptoUtils } from '../utils/crypto-utils';
import { HybridKeys, PeerCertificateBundle, PeerSession, P2PMessage } from '../types/p2p-types';
import {
    toUint8,
    getChannelId,
    buildRouteProof,
    verifyRouteProof,
    createP2PRouteReplayState,
    canAcceptP2PRouteSequence,
    commitP2PRouteSequence,
    type P2PRouteReplayState
} from '../utils/p2p-utils';
import { blockingSystem } from '../blocking/blocking-system';
import {
    AUTH_USERNAME_REGEX,
    CERT_CLOCK_SKEW_MS,
    MAX_CONCURRENT_P2P_CONNECTS,
    P2P_GLOBAL_MESSAGE_RATE_LIMIT,
    P2P_CONNECTION_TIMEOUT_MS,
    P2P_MAX_PEERS,
    P2P_MESSAGE_RATE_LIMIT,
    P2P_MESSAGE_RATE_WINDOW_MS,
    P2P_RATE_LIMITER_MAX_ENTRIES,
    P2P_ROUTE_PROOF_TTL_MS,
    PQ_KEM_PUBLIC_KEY_SIZE,
    PQ_SIG_PUBLIC_KEY_SIZE,
    PQ_SIG_SIGNATURE_SIZE
} from '../constants';
import {
    isPlainObject,
    hasPrototypePollutionKeys,
    hasExactObjectKeys as exactObjectKeys,
    sanitizeMessageId,
    sanitizeEventUsername
} from '../sanitizers';
import {
    MAX_EVENT_USERNAME_LENGTH,
} from '../constants';
import { P2PTransport, p2pTransport } from './p2p-transport';
import { ConnectionState, MAX_MESSAGE_FRAME_SIZE, type SecureConnection } from './secure-transport';
import { canonicalBase64Shape, isHybridEnvelopeWireShape } from './envelope-shape';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const MAX_PENDING_P2P_VERIFICATIONS_PER_PEER = 16;
const MAX_PENDING_P2P_VERIFICATION_BYTES_PER_PEER = 8 * 1024 * 1024;
const MAX_PENDING_P2P_VERIFICATIONS_GLOBAL = 64;
const MAX_PENDING_P2P_VERIFICATION_BYTES_GLOBAL = 16 * 1024 * 1024;
const P2P_ROUTE_REPLAY_WINDOW = 4096;

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

const isDirectP2PPayload = (value: unknown): value is P2PMessage['payload'] => {
    if (!exactObjectKeys(value, ['type', 'messageId', 'envelope']) &&
        !exactObjectKeys(value, ['type', 'messageId', 'fileTransferId', 'envelope'])) return false;
    if (value.type !== SignalType.SEALED_ENVELOPE) return false;
    if (sanitizeMessageId(value.messageId) !== value.messageId) return false;
    if ('fileTransferId' in value && (
        sanitizeMessageId(value.fileTransferId) !== value.fileTransferId ||
        value.fileTransferId.length > 128 ||
        value.fileTransferId.length < 1
    )) return false;
    return isHybridEnvelopeWireShape(value.envelope);
};

const isSignedP2PMessageHeaderShape = (message: unknown): message is P2PMessage => {
    if (!exactObjectKeys(message, ['type', 'from', 'to', 'timestamp', 'payload', 'routeProof', 'signature'])) return false;
    if (
        message.type !== SignalType.SEALED_ENVELOPE ||
        typeof message.from !== 'string' || !AUTH_USERNAME_REGEX.test(message.from) ||
        typeof message.to !== 'string' || !AUTH_USERNAME_REGEX.test(message.to) ||
        !Number.isSafeInteger(message.timestamp) ||
        typeof message.signature !== 'string' ||
        message.signature.length !== 4 * Math.ceil(PQ_SIG_SIGNATURE_SIZE / 3) ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(message.signature) ||
        !isPlainObject(message.payload) ||
        !isPlainObject(message.routeProof)
    ) return false;
    return true;
};

const isSignedP2PMessageShape = (message: unknown): message is P2PMessage => {
    if (!isSignedP2PMessageHeaderShape(message)) return false;
    if (!canonicalBase64Shape(message.signature, { exactBytes: PQ_SIG_SIGNATURE_SIZE }) || !isDirectP2PPayload(message.payload)) return false;
    return exactObjectKeys(message.routeProof, ['kind', 'at', 'expiresAt', 'channelId', 'sequence']) &&
        message.routeProof.kind === PROTOCOL_KEYS.ROUTE_PROOF_KIND &&
        Number.isSafeInteger(message.routeProof.at) &&
        Number.isSafeInteger(message.routeProof.expiresAt) &&
        typeof message.routeProof.channelId === 'string' && /^[a-f0-9]{64}$/.test(message.routeProof.channelId) &&
        Number.isSafeInteger(message.routeProof.sequence) && message.routeProof.sequence >= 1;
};

export class SecureP2PService {
    private localUsername: string = '';
    private peers: Map<string, PeerSession> = new Map();
    private channelSequence: Map<string, number> = new Map();
    private transport: P2PTransport;

    // Callbacks
    private onMessageCallback: ((message: P2PMessage) => Promise<boolean>) | null = null;
    private onPeerConnectedCallback: ((username: string) => void) | null = null;
    private onPeerDisconnectedCallback: ((username: string) => void) | null = null;

    // Crypto keys
    private dilithiumPublicKey: Uint8Array | null = null;
    private incomingRouteProofReplay: Map<string, P2PRouteReplayState> = new Map();
    private activeRouteChannelBySession: Map<PeerSession, string> = new Map();
    private kyberPublicKey: Uint8Array | null = null;
    private x25519PublicKey: Uint8Array | null = null;
    private signTranscript: ((message: Uint8Array) => Promise<Uint8Array>) | null = null;
    private respondToHandshake: HybridKeys['respondToHandshake'] | null = null;

    // Event handling
    private messageRateLimiter: Map<string, { count: number; resetTime: number }> = new Map();
    private messageRateLimiterNextPruneAt = 0;
    private globalMessageRateState = { count: 0, resetTime: 0 };
    private userBlockedListener: ((event: Event) => void) | null = null;

    private connectInFlight: Map<string, Promise<void>> = new Map();
    private disconnectInFlight: Map<PeerSession, Promise<void>> = new Map();
    private connectedSessionWaits: Map<string, Promise<PeerSession | null>> = new Map();
    private connectedSessionWaitCancels: Set<() => void> = new Set();
    private incomingMessageChains: Map<string, Promise<void>> = new Map();
    private incomingMessageQueueUsage: Map<string, { count: number; bytes: number }> = new Map();
    private incomingMessageQueueGlobal = { count: 0, bytes: 0 };
    private sessionWatchers: Map<string, Set<(session: PeerSession | null) => void>> = new Map();
    private transportUnsubscribers: Array<() => void> = [];
    private initialized: boolean = false;
    private initializationPromise: Promise<void> | null = null;
    private shutdownPromise: Promise<void> | null = null;
    private lifecycleGeneration = 0;
    private shuttingDown = false;

    constructor(username: string) {
        const normalized = typeof username === 'string' ? username.trim().toLowerCase() : '';
        if (normalized !== username || !AUTH_USERNAME_REGEX.test(normalized)) {
            throw new Error('Invalid local P2P identity');
        }
        this.localUsername = normalized;
        this.transport = p2pTransport;

        // Set up blocked user handler
        if (typeof window !== 'undefined') {
            this.userBlockedListener = (event: Event) => {
                try {
                    if (!(event instanceof CustomEvent)) return;
                    const detail = event.detail;
                    if (
                        !isPlainObject(detail) ||
                        hasPrototypePollutionKeys(detail) ||
                        Object.keys(detail).sort().join(',') !== 'username'
                    ) return;
                    const blockedUsername = sanitizeEventUsername((detail as any).username, MAX_EVENT_USERNAME_LENGTH);
                    if (blockedUsername) {
                        void this.disconnectPeer(blockedUsername).catch(() => { });
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

    private clearOwnedHybridKeys(): void {
        this.dilithiumPublicKey?.fill(0);
        this.kyberPublicKey?.fill(0);
        this.x25519PublicKey?.fill(0);
        this.dilithiumPublicKey = null;
        this.kyberPublicKey = null;
        this.x25519PublicKey = null;
        this.signTranscript = null;
        this.respondToHandshake = null;
    }

    private enqueueIncomingMessage(
        peer: string,
        message: P2PMessage,
        wireBytes: number | undefined,
        generation: number,
        sourceConnection: SecureConnection
    ): void {
        if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
        if (!this.getCurrentCertifiedSession(peer, sourceConnection)) return;
        const queueKey = this.transport.resolveAppPeerId(peer) || peer;
        const bytes = Number.isSafeInteger(wireBytes) && (wireBytes as number) > 0
            ? Math.min(wireBytes as number, MAX_MESSAGE_FRAME_SIZE)
            : MAX_MESSAGE_FRAME_SIZE;
        const usage = this.incomingMessageQueueUsage.get(queueKey) || { count: 0, bytes: 0 };
        if (
            usage.count >= MAX_PENDING_P2P_VERIFICATIONS_PER_PEER ||
            usage.bytes + bytes > MAX_PENDING_P2P_VERIFICATION_BYTES_PER_PEER ||
            this.incomingMessageQueueGlobal.count >= MAX_PENDING_P2P_VERIFICATIONS_GLOBAL ||
            this.incomingMessageQueueGlobal.bytes + bytes > MAX_PENDING_P2P_VERIFICATION_BYTES_GLOBAL
        ) {
            void sourceConnection.close('P2P verification queue overflow').catch(() => { });
            return;
        }

        usage.count++;
        usage.bytes += bytes;
        this.incomingMessageQueueUsage.set(queueKey, usage);
        this.incomingMessageQueueGlobal.count++;
        this.incomingMessageQueueGlobal.bytes += bytes;

        const previous = this.incomingMessageChains.get(queueKey) || Promise.resolve();
        const next = previous
            .then(() => {
                if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
                return this.handleP2PMessage(message, generation, sourceConnection, bytes);
            })
            .catch((error) => {
                console.error('[MSG-RECV] P2P message verification failed', {
                    error: error instanceof Error ? error.message : String(error)
                });
            });
        this.incomingMessageChains.set(queueKey, next);
        void next.finally(() => {
            if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
            const currentUsage = this.incomingMessageQueueUsage.get(queueKey);
            if (currentUsage) {
                currentUsage.count = Math.max(0, currentUsage.count - 1);
                currentUsage.bytes = Math.max(0, currentUsage.bytes - bytes);
                if (currentUsage.count === 0) this.incomingMessageQueueUsage.delete(queueKey);
            }
            this.incomingMessageQueueGlobal.count = Math.max(0, this.incomingMessageQueueGlobal.count - 1);
            this.incomingMessageQueueGlobal.bytes = Math.max(0, this.incomingMessageQueueGlobal.bytes - bytes);
            if (this.incomingMessageChains.get(queueKey) === next) {
                this.incomingMessageChains.delete(queueKey);
            }
        });
    }

    // Is peer in any of its id/alias forms currently blocked
    private isBlockedPeer(peerId: string): boolean {
        if (!blockingSystem.isEnforcementReady()) return true;
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

    private getCurrentCertifiedSession(
        peer: string,
        expectedConnection?: SecureConnection
    ): PeerSession | null {
        const session = this.getSessionForPeer(peer);
        const connection = session?.connection;
        const identity = connection?.peerIdentity;
        if (
            !session ||
            !connection ||
            (expectedConnection && connection !== expectedConnection) ||
            session.state !== 'connected' ||
            connection.state !== 'connected' ||
            identity?.certVerified !== true ||
            identity.username !== peer ||
            identity.kyberPublicKey?.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            identity.dilithiumPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            identity.x25519PublicKey?.length !== 32 ||
            !Number.isSafeInteger(identity.certificateExpiresAt) ||
            identity.certificateExpiresAt <= Date.now() - CERT_CLOCK_SKEW_MS
        ) return null;
        return session;
    }

    private getRouteChannelId(session: PeerSession, peerDilithiumPublicKey: Uint8Array): string {
        if (!this.dilithiumPublicKey || peerDilithiumPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE) {
            throw new Error('Certified route identity unavailable');
        }
        const sessionBinding = session.connection.getSessionBinding();
        if (!sessionBinding) throw new Error('P2P session binding unavailable');
        const channelId = getChannelId(
            CryptoUtils.Base64.arrayBufferToBase64(this.dilithiumPublicKey),
            CryptoUtils.Base64.arrayBufferToBase64(peerDilithiumPublicKey),
            sessionBinding
        );
        const previousChannelId = this.activeRouteChannelBySession.get(session);
        if (previousChannelId && previousChannelId !== channelId) {
            this.channelSequence.delete(previousChannelId);
            this.incomingRouteProofReplay.delete(previousChannelId);
        }
        this.activeRouteChannelBySession.set(session, channelId);
        return channelId;
    }

    private clearRouteStateForSession(session: PeerSession): void {
        const channelId = this.activeRouteChannelBySession.get(session);
        if (channelId) {
            this.channelSequence.delete(channelId);
            this.incomingRouteProofReplay.delete(channelId);
        }
        this.activeRouteChannelBySession.delete(session);
    }

    private setSessionForPeer(peer: string, session: PeerSession): string {
        const candidates = this.resolvePeerKeys(peer);
        const canonical = this.transport.resolveAppPeerId(peer) || peer;
        const canonicalCandidates = this.resolvePeerKeys(canonical);

        const displaced = new Set<PeerSession>();
        for (const candidate of [...candidates, ...canonicalCandidates]) {
            const existing = this.peers.get(candidate);
            if (existing && existing !== session) displaced.add(existing);
            this.peers.set(candidate, session);
        }
        for (const previous of displaced) {
            if (!Array.from(this.peers.values()).some((value) => value === previous)) {
                this.clearRouteStateForSession(previous);
            }
        }

        return canonical;
    }

    private emitSessionUpdatesForPeer(peer: string): void {
        for (const candidate of this.resolvePeerKeys(peer)) {
            this.emitSessionUpdate(candidate);
        }
    }

    private removeSessionAliases(session: PeerSession): void {
        this.clearRouteStateForSession(session);
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

        const waitKey = this.transport.resolveAppPeerId(peer) || peer;
        const existingWait = this.connectedSessionWaits.get(waitKey);
        if (existingWait) return existingWait;

        let cancelWait: (() => void) | null = null;
        const waitPromise = new Promise<PeerSession | null>((resolve) => {
            let settled = false;
            let connectionUnsub: (() => void) | null = null;
            let watchedConnection: SecureConnection | null = null;

            const clearConnectionWatch = () => {
                if (connectionUnsub) {
                    try { connectionUnsub(); } catch { }
                    connectionUnsub = null;
                }
                watchedConnection = null;
            };

            const finish = (session: PeerSession | null) => {
                if (settled) return;
                settled = true;
                try { clearTimeout(timeoutId); } catch { }
                try { unwatch(); } catch { }
                clearConnectionWatch();
                resolve(session);
            };

            const evaluate = (session: PeerSession | null, missingIsTerminal: boolean) => {
                if (!session) {
                    if (missingIsTerminal) finish(null);
                    return;
                }
                const candidateConnection = session.connection;
                if (watchedConnection !== candidateConnection) {
                    clearConnectionWatch();
                    watchedConnection = candidateConnection;
                    connectionUnsub = candidateConnection.onStateChange((state) => {
                        const current = this.getSessionForPeer(peer);
                        if (current?.connection !== candidateConnection) {
                            evaluate(current, false);
                            return;
                        }
                        if (state === 'connected') {
                            finish(current);
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
            const unwatch = this.watchSession(peer, (session) => evaluate(session, true));
            cancelWait = () => finish(null);
            this.connectedSessionWaitCancels.add(cancelWait);
            evaluate(this.getSessionForPeer(peer), false);
        });
        this.connectedSessionWaits.set(waitKey, waitPromise);
        try {
            return await waitPromise;
        } finally {
            if (cancelWait) this.connectedSessionWaitCancels.delete(cancelWait);
            if (this.connectedSessionWaits.get(waitKey) === waitPromise) {
                this.connectedSessionWaits.delete(waitKey);
            }
        }
    }

    // Initialize the P2P service
    async initialize(): Promise<void> {
        if (this.initialized) {
            return;
        }
        if (this.initializationPromise) return this.initializationPromise;
        if (this.shuttingDown) throw new Error('P2P service is shut down');
        const generation = ++this.lifecycleGeneration;
        const initializationTask = (async () => {
            try {
            if (
                !this.dilithiumPublicKey || !this.kyberPublicKey || !this.x25519PublicKey ||
                !this.signTranscript || !this.respondToHandshake
            ) {
                throw new Error('Complete certified P2P key material is required');
            }
            await this.transport.initialize({
                localUsername: this.localUsername,
                kyberPublicKey: this.kyberPublicKey,
                dilithiumPublicKey: this.dilithiumPublicKey,
                x25519PublicKey: this.x25519PublicKey,
                signTranscript: this.signTranscript,
                respondToHandshake: this.respondToHandshake,
            });
            if (generation !== this.lifecycleGeneration || this.shuttingDown) {
                throw new Error('P2P initialization was cancelled');
            }

            // Set up transport handlers
            this.clearTransportSubscriptions();
            const offPeerConnected = this.transport.onPeerConnected((peerId) => {
                if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
                const appPeerId = this.transport.resolveAppPeerId(peerId);
                // Refuse to form a session with a blocked peer
                if (this.isBlockedPeer(peerId)) {
                    try { this.transport.getConnection(peerId)?.close(); } catch { }
                    void this.disconnectPeer(appPeerId).catch(() => { });
                    return;
                }
                const connection = this.transport.getConnection(peerId);
                const certifiedIdentity = connection?.peerIdentity;
                if (
                    !connection ||
                    certifiedIdentity?.certVerified !== true ||
                    certifiedIdentity.username !== appPeerId ||
                    certifiedIdentity.kyberPublicKey?.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
                    certifiedIdentity.dilithiumPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
                    certifiedIdentity.x25519PublicKey?.length !== 32 ||
                    !Number.isSafeInteger(certifiedIdentity.certificateExpiresAt) ||
                    certifiedIdentity.certificateExpiresAt <= Date.now() - CERT_CLOCK_SKEW_MS
                ) {
                    this.transport.requestPeerCertificate(appPeerId);
                    return;
                }
                let session = this.getSessionForPeer(peerId);
                if (session && session.connection !== connection) {
                    this.removeSessionAliases(session);
                    session = null;
                }
                const existingStream = connection.getStream(SignalType.MESSAGE);
                if (session && !session.messageStream && existingStream) {
                    session.messageStream = existingStream;
                }

                if (session) {
                    session.state = 'connected';
                    session.lastSeen = Date.now();
                } else {
                    session = {
                        connection,
                        messageStream: existingStream || null,
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
                if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
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
                if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
                // Drop any frame from a blocked peer at the transport boundary and sever the channel
                if (this.isBlockedPeer(ctx.from)) {
                    void this.disconnectPeer(this.transport.resolveAppPeerId(ctx.from)).catch(() => { });
                    return;
                }
                if (ctx.type !== SignalType.SEALED_ENVELOPE) {
                    console.warn('[MSG-RECV] DROP: not a SEALED_ENVELOPE', { type: ctx.type });
                    return;
                }
                if (!isDirectP2PPayload(ctx.payload)) {
                    console.warn('[MSG-RECV] DROP: invalid sealed P2P payload');
                    return;
                }
                const sourceConnection = this.transport.getConnection(ctx.from);
                if (!sourceConnection) return;

                const p2pMsg: P2PMessage = {
                    type: ctx.type,
                    from: ctx.from,
                    to: ctx.to || this.localUsername,
                    timestamp: ctx.timestamp,
                    payload: ctx.payload,
                    routeProof: ctx.routeProof,
                    signature: ctx.signature
                };
                this.enqueueIncomingMessage(
                    ctx.from,
                    p2pMsg,
                    ctx.wireBytes,
                    generation,
                    sourceConnection
                );
            });
            this.transportUnsubscribers.push(offMessage);

            if (generation !== this.lifecycleGeneration || this.shuttingDown) {
                throw new Error('P2P initialization was cancelled');
            }
            this.initialized = true;
        } catch (error) {
            console.error('[SecureP2PService] Failed to initialize:', error);
            this.clearTransportSubscriptions();
            if (generation === this.lifecycleGeneration && !this.shuttingDown) {
                try { await this.transport.shutdown(); } catch { }
            }
                throw error;
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

    // Connects the service to the shared sequence map from the messaging hook
    public setChannelSequenceMap(map: Map<string, number>): void {
        this.channelSequence = map;
    }

    // Set hybrid keys
    setHybridKeys(keys: HybridKeys): void {
        if (this.shuttingDown) throw new Error('P2P service is shut down');
        if (this.initialized || this.initializationPromise) {
            throw new Error('P2P key material cannot change after initialization');
        }
        const dilithiumPublic = toUint8(keys.dilithium?.publicKeyBase64, PQ_SIG_PUBLIC_KEY_SIZE);
        if (
            keys.native !== true ||
            !dilithiumPublic || dilithiumPublic.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            keys.kyber?.publicKey?.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            keys.x25519?.publicKey?.length !== 32 ||
            typeof keys.signTranscript !== 'function' ||
            typeof keys.respondToHandshake !== 'function'
        ) {
            dilithiumPublic?.fill(0);
            throw new Error('Invalid certified P2P key material');
        }
        this.clearOwnedHybridKeys();
        this.dilithiumPublicKey = dilithiumPublic.slice();
        dilithiumPublic.fill(0);
        this.kyberPublicKey = keys.kyber.publicKey.slice();
        this.x25519PublicKey = keys.x25519.publicKey.slice();
        this.signTranscript = keys.signTranscript;
        this.respondToHandshake = keys.respondToHandshake;
    }

    // Connect to a peer
    async connectToPeer(
        username: string,
        options: {
            peerCertificate: PeerCertificateBundle;
        }
    ): Promise<void> {
        const normalizedUsername = typeof username === 'string' ? username.trim().toLowerCase() : '';
        if (normalizedUsername !== username || !AUTH_USERNAME_REGEX.test(normalizedUsername)) {
            throw new Error('Invalid P2P peer identity');
        }
        if (!this.initialized || this.shuttingDown) throw new Error('P2P service is not initialized');
        username = normalizedUsername;
        const generation = this.lifecycleGeneration;
        const existingInflight = this.connectInFlight.get(username);
        if (existingInflight) {
            return existingInflight;
        }
        if (this.connectInFlight.size >= MAX_CONCURRENT_P2P_CONNECTS) {
            throw new Error('Too many concurrent P2P connections');
        }

        const singleflight = (async () => {

        // Refuse outbound connections to blocked users
        if (!blockingSystem.isEnforcementReady() || blockingSystem.isBlockedSync(username)) {
            throw new Error('P2P connection denied by local policy');
        }

        // Check if already connected
        const existing = this.getSessionForPeer(username);
        if (existing?.state === 'connected' && existing.connection.state === 'connected') {
            return;
        }

        if (new Set(this.peers.values()).size >= P2P_MAX_PEERS) {
            throw new Error(`Maximum peer connections reached (${P2P_MAX_PEERS})`);
        }

        // Build peer identity from certificate
        if (!options?.peerCertificate) {
            throw new Error('Peer certificate required for connection');
        }
        await this.transport.registerPeerCertificate(username, options.peerCertificate);
        if (generation !== this.lifecycleGeneration || this.shuttingDown) {
            throw new Error('P2P connection was cancelled');
        }

        const connection = await this.transport.connect(username, {
                timeout: P2P_CONNECTION_TIMEOUT_MS,
                onStateChange: (state) => {
                    if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
                    const session = this.getSessionForPeer(username);
                    if (session) {
                        session.state = this.connectionStateToSessionState(state);
                        this.emitSessionUpdatesForPeer(username);
                    }
                }
            });
            if (generation !== this.lifecycleGeneration || this.shuttingDown) {
                try { await connection.close('account-transition'); } catch { }
                throw new Error('P2P connection was cancelled');
            }

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
            if (generation !== this.lifecycleGeneration || this.shuttingDown) {
                try { await connection.close('account-transition'); } catch { }
                throw new Error('P2P connection was cancelled');
            }

            const session: PeerSession = existingSession?.connection === connection
                ? existingSession
                : {
                    connection,
                    messageStream: null,
                    lastSeen: Date.now(),
                    state: 'connected'
                };
            session.messageStream = messageStream;
            session.lastSeen = Date.now();
            session.state = 'connected';
            this.setSessionForPeer(username, session);
            this.emitSessionUpdatesForPeer(username);
        })();

        this.connectInFlight.set(username, singleflight);
        try {
            await singleflight;
        } finally {
            if (this.connectInFlight.get(username) === singleflight) {
                this.connectInFlight.delete(username);
            }
        }
    }

    // Convert connection state to session state
    private connectionStateToSessionState(state: ConnectionState): 'connecting' | 'connected' | 'disconnected' | 'failed' {
        switch (state) {
            case 'connecting':
            case 'handshaking':
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
        messageType: SignalType = SignalType.SEALED_ENVELOPE
    ): Promise<void> {
        const normalizedRecipient = typeof to === 'string' ? to.trim().toLowerCase() : '';
        if (normalizedRecipient !== to || !AUTH_USERNAME_REGEX.test(normalizedRecipient)) {
            throw new Error('Invalid P2P recipient');
        }
        if (!this.initialized || this.shuttingDown) throw new Error('P2P service is not initialized');
        const generation = this.lifecycleGeneration;

        if (messageType !== SignalType.SEALED_ENVELOPE) {
            throw new Error('Invalid message type');
        }
        if (!isDirectP2PPayload(message)) {
            throw new Error('Invalid direct P2P payload');
        }

        let session = this.getSessionForPeer(to);

        if (!session) {
            if (this.transport.isConnected(to) || this.hasConnectInFlight(to)) {
                session = await this.waitForConnectedSession(to, 1200);
            }
        }
        if (generation !== this.lifecycleGeneration || this.shuttingDown) {
            throw new Error('P2P send was cancelled');
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

        const certifiedSession = this.getCurrentCertifiedSession(to, session.connection);
        if (!certifiedSession) {
            throw new Error('P2P connection is not bound to the requested recipient');
        }
        session = certifiedSession;

        let messageStream = session.messageStream;
        if (!messageStream || messageStream.closed) {
            messageStream = await session.connection.createStream({ type: SignalType.MESSAGE });
        }
        if (generation !== this.lifecycleGeneration || this.shuttingDown) {
            throw new Error('P2P send was cancelled');
        }
        const sessionAfterStream = this.getCurrentCertifiedSession(to, session.connection);
        if (!sessionAfterStream || messageStream.closed) {
            throw new Error('P2P connection changed while opening the message stream');
        }
        sessionAfterStream.messageStream = messageStream;
        session = sessionAfterStream;

        let routeProof: P2PMessage['routeProof'];
        const peerIdentity = (session.connection as any).peerIdentity;
        if (
            !this.dilithiumPublicKey ||
            peerIdentity?.certVerified !== true ||
            peerIdentity.username !== to ||
            peerIdentity.dilithiumPublicKey?.length !== PQ_SIG_PUBLIC_KEY_SIZE
        ) {
            throw new Error('Certified peer identity is unavailable');
        }
        const channelId = this.getRouteChannelId(session, peerIdentity.dilithiumPublicKey);
        const currentSeq = this.channelSequence.get(channelId) || 0;
        if (!Number.isSafeInteger(currentSeq) || currentSeq >= Number.MAX_SAFE_INTEGER) {
            throw new Error('P2P sequence exhausted');
        }
        const nextSeq = currentSeq + 1;
        this.channelSequence.set(channelId, nextSeq);
        routeProof = buildRouteProof(channelId, nextSeq);

        const unsignedMessage: Omit<P2PMessage, 'signature'> = {
            type: SignalType.SEALED_ENVELOPE,
            from: this.localUsername,
            to,
            timestamp: Date.now(),
            payload: message,
            routeProof,
        };

        // Sign message
        if (!this.signTranscript) {
            throw new Error('Dilithium keys not available, cannot send unsigned P2P message');
        }

        let messageBytes: Uint8Array | null = null;
        let signature: Uint8Array | null = null;
        let signatureBase64 = '';
        try {
            messageBytes = new TextEncoder().encode(stringifyDeterministic({
                type: unsignedMessage.type,
                from: unsignedMessage.from,
                to: unsignedMessage.to,
                timestamp: unsignedMessage.timestamp,
                payload: unsignedMessage.payload,
                routeProof: unsignedMessage.routeProof
            }));
            signature = await this.signTranscript(messageBytes);
            if (signature.length !== PQ_SIG_SIGNATURE_SIZE) {
                throw new Error('Native P2P signer returned an invalid signature');
            }
            if (generation !== this.lifecycleGeneration || this.shuttingDown) {
                throw new Error('P2P send was cancelled');
            }
            signatureBase64 = CryptoUtils.Base64.arrayBufferToBase64(signature);
        } catch {
            console.error('[SecureP2PService] Failed to sign P2P message');
            throw new Error('Failed to sign P2P message');
        } finally {
            messageBytes?.fill(0);
            signature?.fill(0);
        }

        const p2pMessage: P2PMessage = { ...unsignedMessage, signature: signatureBase64 };
        const data = new TextEncoder().encode(JSON.stringify(p2pMessage));
        try {
            if (
                generation !== this.lifecycleGeneration ||
                this.shuttingDown ||
                messageStream.closed ||
                !this.getCurrentCertifiedSession(to, session.connection)
            ) {
                throw new Error('P2P send was cancelled');
            }
            await messageStream.write(data);
        } finally {
            data.fill(0);
        }
        const currentSession = this.getCurrentCertifiedSession(to, session.connection);
        if (currentSession) currentSession.lastSeen = Date.now();
    }

    // Handle incoming P2P message
    private async handleP2PMessage(
        message: P2PMessage,
        generation: number,
        sourceConnection: SecureConnection,
        verifiedWireBytes: number
    ): Promise<void> {
        if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
        if (!isSignedP2PMessageHeaderShape(message)) {
            console.warn('[SecureP2PService] Rejecting malformed P2P message');
            return;
        }
        const now = Date.now();
        if (
            !Number.isSafeInteger(message.timestamp) ||
            message.timestamp < now - P2P_ROUTE_PROOF_TTL_MS - CERT_CLOCK_SKEW_MS ||
            message.timestamp > now + CERT_CLOCK_SKEW_MS
        ) {
            return;
        }
        if (!this.checkMessageRateLimit(message.from)) {
            console.warn('[MSG-RECV] DROP: P2P rate limited');
            return;
        }
        if (!isSignedP2PMessageShape(message)) {
            console.warn('[SecureP2PService] Rejecting malformed P2P message');
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

        let session = this.getCurrentCertifiedSession(message.from, sourceConnection);
        if (!session) return;
        const expectedPeerUsername = session?.connection?.peerIdentity?.username;
        if (expectedPeerUsername && expectedPeerUsername !== message.from) {
            console.warn('[SecureP2PService] Rejecting P2P message with mismatched peer identity');
            return;
        }

        let verifiedRouteChannel: string | null = null;
        let verifiedRouteSequence: number | null = null;

        // Verify signature
        if (message.signature && message.from) {
            const activeIdentity = session?.connection?.peerIdentity;
            const peerPublicKey = activeIdentity?.certVerified &&
                activeIdentity.username === message.from &&
                activeIdentity.dilithiumPublicKey?.length === PQ_SIG_PUBLIC_KEY_SIZE
                ? activeIdentity.dilithiumPublicKey
                : undefined;

            if (peerPublicKey) {
                let messageBytes: Uint8Array | null = null;
                let signature: Uint8Array | null = null;
                try {
                    messageBytes = new TextEncoder().encode(stringifyDeterministic({
                        type: message.type,
                        from: message.from,
                        to: message.to,
                        timestamp: message.timestamp,
                        payload: message.payload,
                        routeProof: message.routeProof,
                    }));
                    signature = CryptoUtils.Base64.base64ToUint8Array(message.signature);
                    if (signature.length !== PQ_SIG_SIGNATURE_SIZE) return;
                    const isValid = await CryptoUtils.Dilithium.verify(signature, messageBytes, peerPublicKey);
                    if (generation !== this.lifecycleGeneration || this.shuttingDown) return;
                    session = this.getCurrentCertifiedSession(message.from, sourceConnection);
                    if (!session) return;

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
                } finally {
                    messageBytes?.fill(0);
                    signature?.fill(0);
                }
            } else {
                console.warn('[SecureP2PService] Received signed message but no public key');
                this.transport.requestPeerCertificate(message.from);
                return;
            }

            if (message.type === SignalType.SEALED_ENVELOPE) {
                if (!this.dilithiumPublicKey) {
                    console.warn('[SecureP2PService] Rejecting P2P sealed envelope without local certified identity');
                    return;
                }
                try {
                    const peerDilithiumBase64 = CryptoUtils.Base64.arrayBufferToBase64(peerPublicKey);
                    const channelId = this.getRouteChannelId(session!, peerPublicKey);
                    const replayState = this.incomingRouteProofReplay.get(channelId) ||
                        createP2PRouteReplayState(P2P_ROUTE_REPLAY_WINDOW);
                    if (!Number.isSafeInteger(replayState.highest) || replayState.highest >= Number.MAX_SAFE_INTEGER) {
                        return;
                    }
                    const routeProofValid = verifyRouteProof(
                        message.routeProof,
                        channelId,
                        1
                    );
                    if (
                        !routeProofValid ||
                        !canAcceptP2PRouteSequence(
                            replayState,
                            message.routeProof.sequence,
                            P2P_ROUTE_REPLAY_WINDOW
                        )
                    ) {
                        console.warn('[SecureP2PService] Rejecting P2P sealed envelope with invalid route proof');
                        return;
                    }
                    verifiedRouteChannel = channelId;
                    verifiedRouteSequence = message.routeProof.sequence;

                    // Hand cryptographically verified sender identity to message handler
                    (message as any).__p2pVerifiedSender = {
                        username: message.from,
                        dilithiumBase64: peerDilithiumBase64
                    };
                    Object.defineProperty(message, '__p2pVerifiedWireBytes', {
                        value: verifiedWireBytes,
                        enumerable: false,
                        configurable: true,
                    });
                } catch {
                    console.warn('[SecureP2PService] Rejecting P2P sealed envelope after route proof verification error');
                    return;
                }
            }
        }

        const messageCallback = this.onMessageCallback;
        if (!messageCallback) {
            console.warn('[MSG-RECV] DROP: onMessageCallback not set (app not listening)');
            return;
        }
        if (!this.getCurrentCertifiedSession(message.from, sourceConnection)) {
            return;
        }
        const accepted = await messageCallback(message);
        if (
            !accepted ||
            generation !== this.lifecycleGeneration ||
            this.shuttingDown ||
            !this.getCurrentCertifiedSession(message.from, sourceConnection)
        ) return;

        if (verifiedRouteChannel && verifiedRouteSequence !== null) {
            let replayState = this.incomingRouteProofReplay.get(verifiedRouteChannel);
            if (!replayState) {
                replayState = createP2PRouteReplayState(P2P_ROUTE_REPLAY_WINDOW);
                this.incomingRouteProofReplay.set(verifiedRouteChannel, replayState);
            }
            commitP2PRouteSequence(
                replayState,
                verifiedRouteSequence,
                P2P_ROUTE_REPLAY_WINDOW
            );
        }
        session.lastSeen = Date.now();
    }

    // Check message rate limit
    private checkMessageRateLimit(from: string): boolean {
        const now = Date.now();

        if (now >= this.messageRateLimiterNextPruneAt) {
            let nextPruneAt = Number.POSITIVE_INFINITY;
            for (const [key, entry] of this.messageRateLimiter) {
                if (now > entry.resetTime) {
                    this.messageRateLimiter.delete(key);
                } else {
                    nextPruneAt = Math.min(nextPruneAt, entry.resetTime + 1);
                }
            }
            this.messageRateLimiterNextPruneAt = Number.isFinite(nextPruneAt)
                ? nextPruneAt
                : now + P2P_MESSAGE_RATE_WINDOW_MS;
        }
        let senderState = this.messageRateLimiter.get(from);
        if (!senderState || now > senderState.resetTime) {
            senderState = { count: 0, resetTime: now + P2P_MESSAGE_RATE_WINDOW_MS };
        }
        if (senderState.count >= P2P_MESSAGE_RATE_LIMIT) return false;

        if (now > this.globalMessageRateState.resetTime) {
            this.globalMessageRateState = { count: 0, resetTime: now + P2P_MESSAGE_RATE_WINDOW_MS };
        }
        if (this.globalMessageRateState.count >= P2P_GLOBAL_MESSAGE_RATE_LIMIT) return false;

        if (!this.messageRateLimiter.has(from) && this.messageRateLimiter.size >= P2P_RATE_LIMITER_MAX_ENTRIES) {
            const oldest = this.messageRateLimiter.keys().next().value;
            if (oldest !== undefined) this.messageRateLimiter.delete(oldest);
        }
        senderState.count++;
        this.messageRateLimiter.set(from, senderState);
        this.messageRateLimiterNextPruneAt = Math.min(
            this.messageRateLimiterNextPruneAt,
            senderState.resetTime + 1
        );
        this.globalMessageRateState.count++;
        return true;
    }

    // Disconnect from a peer
    async disconnectPeer(username: string): Promise<void> {
        const session = this.getSessionForPeer(username);
        if (!session) return;
        const existing = this.disconnectInFlight.get(session);
        if (existing) return existing;

        let disconnectTask!: Promise<void>;
        disconnectTask = (async () => {
            try {
                if (session.messageStream) {
                    await session.messageStream.close();
                }
                await session.connection.close();
            } catch { }

            this.removeSessionAliases(session);
        })();
        this.disconnectInFlight.set(session, disconnectTask);
        try {
            await disconnectTask;
        } finally {
            if (this.disconnectInFlight.get(session) === disconnectTask) {
                this.disconnectInFlight.delete(session);
            }
        }
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

    // Check if service is compatible with given configuration
    isCompatible(username: string, keys: HybridKeys | null): boolean {
        if (
            !this.initialized ||
            this.shuttingDown ||
            this.localUsername !== username ||
            !keys ||
            !this.dilithiumPublicKey ||
            !this.kyberPublicKey ||
            !this.x25519PublicKey
        ) return false;

        const dilithiumPublic = toUint8(keys.dilithium?.publicKeyBase64, PQ_SIG_PUBLIC_KEY_SIZE);
        try {
            return !!dilithiumPublic &&
                dilithiumPublic.length === PQ_SIG_PUBLIC_KEY_SIZE &&
                keys.kyber?.publicKey?.length === PQ_KEM_PUBLIC_KEY_SIZE &&
                keys.x25519?.publicKey?.length === 32 &&
                PostQuantumUtils.timingSafeEqual(this.dilithiumPublicKey, dilithiumPublic) &&
                PostQuantumUtils.timingSafeEqual(this.kyberPublicKey, keys.kyber.publicKey) &&
                PostQuantumUtils.timingSafeEqual(this.x25519PublicKey, keys.x25519.publicKey);
        } finally {
            dilithiumPublic?.fill(0);
        }
    }

    // Set message callback
    onMessage(callback: (message: P2PMessage) => Promise<boolean>): void {
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
        if (this.shutdownPromise) return this.shutdownPromise;
        if (this.shuttingDown) return;
        this.shuttingDown = true;
        this.lifecycleGeneration += 1;
        this.initialized = false;
        this.clearTransportSubscriptions();
        if (this.userBlockedListener && typeof window !== 'undefined') {
            window.removeEventListener(EventType.USER_BLOCKED, this.userBlockedListener);
        }
        
        this.clearOwnedHybridKeys();

        const transportShutdown = this.transport.shutdown();

        const shutdownTask = (async () => {
            for (const cancel of Array.from(this.connectedSessionWaitCancels)) {
                try { cancel(); } catch { }
            }
            this.connectedSessionWaitCancels.clear();
            this.connectInFlight.clear();
            this.disconnectInFlight.clear();
            this.connectedSessionWaits.clear();
            this.incomingMessageChains.clear();
            this.incomingMessageQueueUsage.clear();
            this.incomingMessageQueueGlobal = { count: 0, bytes: 0 };
            this.sessionWatchers.clear();
            this.channelSequence.clear();
            this.incomingRouteProofReplay.clear();
            this.activeRouteChannelBySession.clear();
            this.peers.clear();
            this.messageRateLimiter.clear();
            this.messageRateLimiterNextPruneAt = 0;
            this.globalMessageRateState = { count: 0, resetTime: 0 };
            this.onMessageCallback = null;
            this.onPeerConnectedCallback = null;
            this.onPeerDisconnectedCallback = null;
            await transportShutdown;
        })();
        this.shutdownPromise = shutdownTask;
        try {
            await shutdownTask;
        } finally {
            if (this.shutdownPromise === shutdownTask) {
                this.shutdownPromise = null;
            }
        }
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
