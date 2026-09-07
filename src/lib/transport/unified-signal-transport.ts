import { SignalType } from '../types/signal-types';
import { LIVE_ONLY_DELIVERY_POLICY } from '../config/audiences';
import websocketClient from '../websocket/websocket';
import { p2pTransport } from './p2p-transport';
import { getBlindRoutingClient } from './blind-routing-client';
import { nextOutboundTag } from '../spool/tag-sender';
import {
    clearDetectionKeyCaches,
    resolvePeerDetectionKey,
} from '../spool/detection-key';
import { PostQuantumUtils } from '../utils/pq-utils';
import { EventType } from '../types/event-types';
import {
    AUTH_USERNAME_REGEX,
    CERT_CLOCK_SKEW_MS,
    HYBRID_ENVELOPE_MAX_AGE_MS,
    FILE_RETRANSMIT_RETENTION_MS,
    MAX_BLOCK_LIST_SIZE,
    OUTBOUND_RETRY_MAX_AGE_MS,
    PQ_KEM_PUBLIC_KEY_SIZE,
} from '../constants';
import {
    hasExactObjectKeys as exactObjectKeys,
    isCanonicalAuthUsername as isCanonicalUsername,
    sanitizeMessageId,
} from '../sanitizers';
import { blockingSystem } from '../blocking/blocking-system';
import { canonicalBase64Shape, isHybridEnvelopeWireShape } from './envelope-shape';

const ENCRYPTION_DENIAL_FRESH_MS = 60_000;
const REDELIVER_MAX_AGE_MS = OUTBOUND_RETRY_MAX_AGE_MS;
const CALL_SIGNAL_QUEUE_MAX_WAIT_MS = 5_000;
const REDELIVER_FLUSH_INTERVAL_MS = 3000;
const REDELIVER_MAX_PENDING = 400;
const DELIVERY_ACK_TIMEOUT_MS = 25_000;
const BLIND_ROUTE_ACK_TIMEOUT_MS = 45_000;
const BLIND_ROUTE_ACK_LIVENESS_POLL_MS = 1_000;
const MAX_AWAITING_ACK = 500;
const MAX_EARLY_ACKS_PER_PEER = 32;
const SPOOL_MAX_ATTEMPTS = 3;
const SPOOL_RETRY_BASE_MS = 1500;
const MAX_ACKED_CHUNK_TRANSFERS = 64;

const MAX_QUEUED_SENDS_PER_PEER = 100;
const MAX_QUEUED_PRIORITY_SENDS = 256;
const MAX_TOTAL_SEND_TASKS = 512;
const MAX_CONCURRENT_SEND_TASKS = 8;
const MAX_CONCURRENT_ACK_SPOOLS = 4;
const MAX_BLIND_ACK_WAITERS = 512;
const MAX_ACK_SPOOL_QUEUE = MAX_AWAITING_ACK;
const MAX_PRIORITY_BURST = 4;
const MAX_DURABLE_ACK_BYTES = 16 * 1024 * 1024;
const DURABLE_ACK_RETRY_MS = 30_000;
const DURABLE_ACK_RESTORE_RETRY_BASE_MS = 1000;

const ACK_TRACKED_SIGNAL_TYPES: ReadonlySet<SignalType> = new Set([
    SignalType.MESSAGE,
    SignalType.EDIT_MESSAGE, SignalType.DELETE_MESSAGE,
    SignalType.REACTION_ADD, SignalType.REACTION_REMOVE,
    SignalType.FILE_MESSAGE_CHUNK
]);

export function isAckTrackedSignalType(type: unknown): type is SignalType {
    return ACK_TRACKED_SIGNAL_TYPES.has(type as SignalType);
}

const LIVE_ONLY_SIGNAL_TYPES: ReadonlySet<SignalType> = new Set([
    SignalType.CALL_SIGNAL,
    SignalType.TYPING_START, SignalType.TYPING_STOP,
    SignalType.FILE_MESSAGE_CHUNK, SignalType.FILE_TRANSFER_CANCEL
]);

export function isLiveOnlySignalType(type: unknown): type is SignalType {
    return LIVE_ONLY_SIGNAL_TYPES.has(type as SignalType);
}

type SendResult = { success: boolean; transport: 'p2p' | 'server'; error?: string };
type QueuedSend = { run: () => Promise<void>; cancel: (error?: string) => void };
type SendPolicyContext = {
    accountGeneration: number;
    policyGeneration: number;
    recipientEpoch: number;
};
type DurableAckEntry = {
    messageId: string;
    to: string;
    envelopeToSend: any;
    type: SignalType;
    createdAt: number;
};
type DeliveryAckPersistence = {
    load: () => Promise<unknown>;
    save: (entries: DurableAckEntry[]) => Promise<void>;
    clearRecovery: (peer: string, messageIds: string[]) => Promise<void>;
};

// Unified Signal Transport
class UnifiedSignalTransport {
    private accountGeneration = 0;
    private recipientPolicyGeneration = 0;
    private recipientPolicyEpochs = new Map<string, number>();
    private deliveryAckGeneration = 0;
    private encryptionProvider: ((to: string, payload: any, type: SignalType) => Promise<any>) | null = null;
    private lastEncryptionDenial: { to: string; type: string; reason: string; at: number } | null = null;
    private p2pSender: ((to: string, payload: any, type: SignalType) => Promise<void>) | null = null;
    private peerPreparer: ((to: string) => Promise<void>) | null = null;
    private pendingRedelivery: Map<string, {
        to: string;
        envelope: any;
        type: SignalType;
        firstAt: number;
        generation: number;
        reconnectOnly?: boolean;
        attempts?: number;
        nextAttemptAt?: number;
    }> = new Map();
    private redeliveryFlusher: ReturnType<typeof setInterval> | null = null;
    private redeliveryPeerListenerBound = false;
    private redeliveryFlushPromise: Promise<void> | null = null;
    private redeliveryNormalFlushRequested = false;
    private redeliveryReconnectFlushRequested = false;
    private redeliveryNormalAllRequested = false;
    private redeliveryNormalPeerRequests = new Set<string>();
    private redeliveryReconnectPeerRequests = new Set<string>();
    private awaitingDeliveryAck: Map<string, { to: string; envelopeToSend: any; timer: ReturnType<typeof setTimeout>; type: SignalType }> = new Map();
    
    private ackedChunkTransfers: Map<string, number> = new Map();
    private sendQueues: Map<string, { running: boolean; highStreak: number; high: QueuedSend[]; low: QueuedSend[] }> = new Map();
    private totalSendTasks = 0;
    private activeSendTasks = 0;
    private sendPermitWaiters: Array<{
        generation: number;
        resolve: (release: (() => void) | null) => void;
    }> = [];
    private ackSpoolQueue: Array<{
        to: string;
        envelopeToSend: any;
        generation: number;
        deliveryGeneration: number;
    }> = [];
    private ackSpoolActive = 0;
    private ackSpoolQueuedIds = new Set<string>();
    private ackSpoolInFlightIds = new Set<string>();
    private redeliveryInFlight = new Set<string>();
    private deliveryAckPersistence: DeliveryAckPersistence | null = null;
    private durableAckEntries = new Map<string, DurableAckEntry>();
    private durableAckPersistenceTail: Promise<void> = Promise.resolve();
    private durableAckRetryTimers = new Map<string, ReturnType<typeof setTimeout>>();
    private durableAckRestore: Promise<void> = Promise.resolve();
    private durableAckStoreState: 'disabled' | 'loading' | 'ready' | 'failed' = 'disabled';
    private durableAckRestoreRetryTimer: ReturnType<typeof setTimeout> | null = null;
    private durableAckRestoreAttempts = 0;
    private recoveryClearPending = new Map<string, Set<string>>();
    private recoveryClearTimer: ReturnType<typeof setTimeout> | null = null;
    private recoveryClearTask: Promise<void> | null = null;
    private earlyDeliveryAcks = new Map<string, SignalType | null>();
    private durableAckReconcileTimer: ReturnType<typeof setTimeout> | null = null;
    private durableAckReconcileAttempts = 0;

    constructor() {
        window.addEventListener(EventType.USER_BLOCKED, this.userBlockedListener);
        window.addEventListener(
            EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT,
            this.keyTransparencySecurityIncidentListener
        );
    }

    private readonly keyTransparencySecurityIncidentListener = (): void => {
        this.resetForAccountTransition();
        void websocketClient.close({ killSession: true }).catch(() => { });
        void p2pTransport.shutdown().catch(() => { });
    };

    private readonly userBlockedListener = (event: Event): void => {
        if (!(event instanceof CustomEvent)) return;
        const detail = event.detail;
        if (!exactObjectKeys(detail, ['username']) || !isCanonicalUsername(detail.username)) return;
        this.registerRecipientBlock(detail.username);
    };

    private registerRecipientBlock(peer: string): void {
        if (!this.recipientPolicyEpochs.has(peer) && this.recipientPolicyEpochs.size >= MAX_BLOCK_LIST_SIZE) {
            this.recipientPolicyGeneration += 1;
            this.recipientPolicyEpochs.clear();
        }
        this.recipientPolicyEpochs.set(peer, (this.recipientPolicyEpochs.get(peer) || 0) + 1);
        this.cancelPeerTraffic(peer);
    }

    private captureSendPolicy(peer: string): SendPolicyContext {
        return {
            accountGeneration: this.accountGeneration,
            policyGeneration: this.recipientPolicyGeneration,
            recipientEpoch: this.recipientPolicyEpochs.get(peer) || 0,
        };
    }

    private recipientPolicyError(peer: string, context?: SendPolicyContext): string | null {
        if (context?.accountGeneration !== undefined && context.accountGeneration !== this.accountGeneration) {
            return 'account-transition';
        }
        if (
            context &&
            (
                context.policyGeneration !== this.recipientPolicyGeneration ||
                context.recipientEpoch !== (this.recipientPolicyEpochs.get(peer) || 0)
            )
        ) {
            return 'recipient-policy-changed';
        }
        if (!blockingSystem.isEnforcementReady()) return 'blocking-policy-unavailable';
        if (blockingSystem.isBlockedSync(peer)) return 'recipient-blocked';
        return null;
    }

    private cancelPeerTraffic(peer: string): void {
        const queue = this.sendQueues.get(peer);
        if (queue) {
            for (const task of queue.high) task.cancel('recipient-blocked');
            for (const task of queue.low) task.cancel('recipient-blocked');
            queue.high.length = 0;
            queue.low.length = 0;
            if (!queue.running) this.sendQueues.delete(peer);
        }

        const recoveryIds = new Set<string>();
        for (const [trackingKey, entry] of this.pendingRedelivery) {
            if (entry.to !== peer) continue;
            if (typeof entry.envelope?.messageId === 'string') recoveryIds.add(entry.envelope.messageId);
            this.pendingRedelivery.delete(trackingKey);
        }
        this.redeliveryNormalPeerRequests.delete(peer);
        this.redeliveryReconnectPeerRequests.delete(peer);

        const durableKeys = new Set<string>();
        for (const [trackingKey, entry] of this.awaitingDeliveryAck) {
            if (entry.to !== peer) continue;
            clearTimeout(entry.timer);
            recoveryIds.add(entry.envelopeToSend.messageId);
            this.awaitingDeliveryAck.delete(trackingKey);
            durableKeys.add(trackingKey);
        }
        for (const [trackingKey, entry] of this.durableAckEntries) {
            if (entry.to !== peer) continue;
            recoveryIds.add(entry.messageId);
            durableKeys.add(trackingKey);
        }

        this.ackSpoolQueue = this.ackSpoolQueue.filter((queued) => {
            if (queued.to !== peer) return true;
            const messageId = queued.envelopeToSend?.messageId;
            if (typeof messageId === 'string') {
                this.ackSpoolQueuedIds.delete(this.deliveryTrackingKey(peer, messageId));
                recoveryIds.add(messageId);
            }
            return false;
        });

        const prefix = `${peer}\0`;
        for (const key of Array.from(this.earlyDeliveryAcks.keys())) {
            if (key.startsWith(prefix)) this.earlyDeliveryAcks.delete(key);
        }
        for (const key of Array.from(this.ackedChunkTransfers.keys())) {
            if (key.startsWith(prefix)) this.ackedChunkTransfers.delete(key);
        }
        for (const messageId of recoveryIds) this.queueRecoveryClear(peer, messageId);
        void this.completeDurableAcks(durableKeys);

        if (this.pendingRedelivery.size === 0 && this.redeliveryFlusher !== null) {
            clearInterval(this.redeliveryFlusher);
            this.redeliveryFlusher = null;
        }
    }

    private deliveryTrackingKey(to: string, messageId: string): string {
        return `${to}\0${messageId}`;
    }

    private fileTransferIdFromChunkMessageId(messageId: string): string | null {
        const marker = ':chunk:';
        const markerAt = messageId.lastIndexOf(marker);
        if (markerAt <= 0) return null;
        const transferId = messageId.slice(0, markerAt);
        const chunkIndex = messageId.slice(markerAt + marker.length);
        return /^(0|[1-9][0-9]*)$/.test(chunkIndex) && sanitizeMessageId(transferId) === transferId
            ? transferId
            : null;
    }

    private rememberAckedChunkTransfer(peer: string, transferId: string): void {
        const key = this.deliveryTrackingKey(peer, transferId);
        if (!this.ackedChunkTransfers.has(key) && this.ackedChunkTransfers.size >= MAX_ACKED_CHUNK_TRANSFERS) {
            const oldest = this.ackedChunkTransfers.keys().next().value;
            if (oldest !== undefined) this.ackedChunkTransfers.delete(oldest);
        }
        this.ackedChunkTransfers.delete(key);
        this.ackedChunkTransfers.set(key, Date.now());
    }

    private rememberEarlyDeliveryAck(
        peer: string,
        trackingKey: string,
        expectedType: SignalType | null
    ): void {
        const peerPrefix = `${peer}\0`;
        let peerCount = 0;
        let oldestPeerKey: string | null = null;
        for (const key of this.earlyDeliveryAcks.keys()) {
            if (!key.startsWith(peerPrefix)) continue;
            peerCount += 1;
            if (oldestPeerKey === null) oldestPeerKey = key;
        }
        if (peerCount >= MAX_EARLY_ACKS_PER_PEER && oldestPeerKey) {
            this.earlyDeliveryAcks.delete(oldestPeerKey);
        } else if (this.earlyDeliveryAcks.size >= MAX_AWAITING_ACK) {
            return;
        }
        this.earlyDeliveryAcks.delete(trackingKey);
        this.earlyDeliveryAcks.set(trackingKey, expectedType);
    }

    noteEncryptionDenial(to: string, type: string, reason: string): void {
        this.lastEncryptionDenial = { to, type, reason, at: Date.now() };
    }

    // Register a provider that encrypts payloads
    setEncryptionProvider(provider: ((to: string, payload: any, type: SignalType) => Promise<any>) | null): void {
        this.encryptionProvider = provider;
    }

    // Register a sender that can sign and send P2P messages with route proofs
    setP2PSender(
        sender: ((to: string, payload: any, type: SignalType) => Promise<void>) | null,
        prepare: ((to: string) => Promise<void>) | null = null,
    ): void {
        this.p2pSender = sender;
        this.peerPreparer = sender ? prepare : null;
    }

    preparePeer(to: string): void {
        if (!isCanonicalUsername(to) || to === 'server' || this.recipientPolicyError(to)) return;
        try {
            void this.peerPreparer?.(to).catch(() => { });
        } catch { }
    }

    private clearDeliveryAckStateForPersistenceChange(): number {
        this.deliveryAckGeneration += 1;
        this.deliveryAckPersistence = null;
        this.durableAckStoreState = 'disabled';
        this.durableAckRestore = Promise.resolve();
        if (this.durableAckRestoreRetryTimer) clearTimeout(this.durableAckRestoreRetryTimer);
        this.durableAckRestoreRetryTimer = null;
        this.durableAckRestoreAttempts = 0;
        this.earlyDeliveryAcks.clear();

        if (this.recoveryClearTimer) clearTimeout(this.recoveryClearTimer);
        this.recoveryClearTimer = null;
        this.recoveryClearPending.clear();
        this.recoveryClearTask = null;

        for (const entry of this.awaitingDeliveryAck.values()) clearTimeout(entry.timer);
        this.awaitingDeliveryAck.clear();
        this.ackedChunkTransfers.clear();
        this.ackSpoolQueue = [];
        this.ackSpoolActive = 0;
        this.ackSpoolQueuedIds.clear();
        this.ackSpoolInFlightIds.clear();
        for (const timer of this.durableAckRetryTimers.values()) clearTimeout(timer);
        this.durableAckRetryTimers.clear();
        if (this.durableAckReconcileTimer) clearTimeout(this.durableAckReconcileTimer);
        this.durableAckReconcileTimer = null;
        this.durableAckReconcileAttempts = 0;
        this.durableAckEntries.clear();
        this.durableAckPersistenceTail = Promise.resolve();
        return this.deliveryAckGeneration;
    }

    setDeliveryAckPersistence(persistence: DeliveryAckPersistence | null): void {
        const deliveryGeneration = this.clearDeliveryAckStateForPersistenceChange();
        this.deliveryAckPersistence = persistence;
        if (!persistence) {
            return;
        }
        const generation = this.accountGeneration;
        this.startDurableAckRestore(persistence, generation, deliveryGeneration);
    }

    private startDurableAckRestore(
        persistence: DeliveryAckPersistence,
        generation: number,
        deliveryGeneration: number
    ): void {
        if (
            generation !== this.accountGeneration ||
            deliveryGeneration !== this.deliveryAckGeneration ||
            this.deliveryAckPersistence !== persistence
        ) return;
        if (this.durableAckRestoreRetryTimer) {
            clearTimeout(this.durableAckRestoreRetryTimer);
            this.durableAckRestoreRetryTimer = null;
        }
        this.durableAckStoreState = 'loading';
        this.durableAckRestore = this.restoreDurableAcks(
            persistence,
            generation,
            deliveryGeneration
        ).then(() => {
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration ||
                this.deliveryAckPersistence !== persistence
            ) return;
            this.durableAckRestoreAttempts = 0;
            this.durableAckStoreState = 'ready';
            for (const entry of this.durableAckEntries.values()) {
                this.enqueueAckSpool(entry.to, entry.envelopeToSend);
            }
        }).catch(() => {
            if (
                generation === this.accountGeneration &&
                deliveryGeneration === this.deliveryAckGeneration &&
                this.deliveryAckPersistence === persistence
            ) {
                this.durableAckStoreState = 'failed';
                this.earlyDeliveryAcks.clear();
                this.scheduleDurableAckRestoreRetry(persistence, generation, deliveryGeneration);
            }
        });
    }

    private scheduleDurableAckRestoreRetry(
        persistence: DeliveryAckPersistence,
        generation: number,
        deliveryGeneration: number
    ): void {
        if (
            this.durableAckRestoreRetryTimer ||
            generation !== this.accountGeneration ||
            deliveryGeneration !== this.deliveryAckGeneration ||
            this.deliveryAckPersistence !== persistence
        ) return;
        const delay = Math.min(
            DURABLE_ACK_RESTORE_RETRY_BASE_MS * (2 ** Math.min(this.durableAckRestoreAttempts, 6)),
            60_000
        );
        this.durableAckRestoreAttempts = Math.min(this.durableAckRestoreAttempts + 1, 16);
        this.durableAckRestoreRetryTimer = setTimeout(() => {
            this.durableAckRestoreRetryTimer = null;
            this.startDurableAckRestore(persistence, generation, deliveryGeneration);
        }, delay);
    }

    private validDurableAckEntry(value: unknown): value is DurableAckEntry {
        if (
            !exactObjectKeys(value, ['createdAt', 'envelopeToSend', 'messageId', 'to', 'type'])
        ) return false;
        const entry = value as DurableAckEntry;
        if (
            sanitizeMessageId(entry.messageId) !== entry.messageId ||
            !isCanonicalUsername(entry.to) ||
            !isAckTrackedSignalType(entry.type) ||
            !Number.isSafeInteger(entry.createdAt) || entry.createdAt <= 0
        ) return false;
        const envelope = entry.envelopeToSend;
        const isFileChunk = entry.type === SignalType.FILE_MESSAGE_CHUNK;
        if (isFileChunk
            ? !exactObjectKeys(envelope, ['type', 'messageId', 'fileTransferId', 'envelope', 'recipientKyberPublicBase64'])
            : !exactObjectKeys(envelope, ['type', 'messageId', 'envelope', 'recipientKyberPublicBase64'])) return false;
        return envelope.type === SignalType.SEALED_ENVELOPE &&
            envelope.messageId === entry.messageId &&
            sanitizeMessageId(envelope.messageId) === envelope.messageId &&
            (!isFileChunk || (
                sanitizeMessageId(envelope.fileTransferId) === envelope.fileTransferId &&
                this.fileTransferIdFromChunkMessageId(entry.messageId) === envelope.fileTransferId
            )) &&
            canonicalBase64Shape(envelope.recipientKyberPublicBase64, { exactBytes: PQ_KEM_PUBLIC_KEY_SIZE }) &&
            isHybridEnvelopeWireShape(envelope.envelope, 'libsignal-message');
    }

    private validOutboundEnvelope(envelope: unknown, applicationType: SignalType): boolean {
        const isFileChunk = applicationType === SignalType.FILE_MESSAGE_CHUNK;
        if (isFileChunk
            ? !exactObjectKeys(envelope, ['type', 'messageId', 'fileTransferId', 'envelope', 'recipientKyberPublicBase64'])
            : !exactObjectKeys(envelope, ['type', 'messageId', 'envelope', 'recipientKyberPublicBase64'])) return false;
        const candidate = envelope as Record<string, any>;
        if (
            candidate.type !== SignalType.SEALED_ENVELOPE ||
            sanitizeMessageId(candidate.messageId) !== candidate.messageId ||
            !canonicalBase64Shape(candidate.recipientKyberPublicBase64, { exactBytes: PQ_KEM_PUBLIC_KEY_SIZE }) ||
            !isHybridEnvelopeWireShape(candidate.envelope, 'libsignal-message')
        ) return false;
        if (
            isFileChunk &&
            (
                sanitizeMessageId(candidate.fileTransferId) !== candidate.fileTransferId ||
                this.fileTransferIdFromChunkMessageId(candidate.messageId) !== candidate.fileTransferId
            )
        ) return false;

        const timestamp = candidate.envelope.routing.timestamp;
        const now = Date.now();
        return timestamp >= now - HYBRID_ENVELOPE_MAX_AGE_MS - CERT_CLOCK_SKEW_MS &&
            timestamp <= now + CERT_CLOCK_SKEW_MS;
    }

    private durableAckEntryExpired(entry: DurableAckEntry, now: number = Date.now()): boolean {
        const routingTimestamp = entry.envelopeToSend?.envelope?.routing?.timestamp;
        const retentionMs = entry.type === SignalType.FILE_MESSAGE_CHUNK
            ? FILE_RETRANSMIT_RETENTION_MS
            : OUTBOUND_RETRY_MAX_AGE_MS;
        const oldestRoutingTimestamp = now - retentionMs - CERT_CLOCK_SKEW_MS;
        const oldestCreatedAt = now - retentionMs;
        const newestAllowed = now + CERT_CLOCK_SKEW_MS;
        return !Number.isSafeInteger(routingTimestamp) ||
            !Number.isSafeInteger(entry.createdAt) ||
            routingTimestamp <= oldestRoutingTimestamp ||
            routingTimestamp > newestAllowed ||
            entry.createdAt <= oldestCreatedAt ||
            entry.createdAt > now;
    }

    private async restoreDurableAcks(
        persistence: DeliveryAckPersistence,
        generation: number,
        deliveryGeneration: number
    ): Promise<void> {
        const policyGeneration = this.recipientPolicyGeneration;
        if (!blockingSystem.isEnforcementReady()) {
            throw new Error('Blocking policy unavailable during recovery restore');
        }
        const loaded = await persistence.load();
        if (
            generation !== this.accountGeneration ||
            deliveryGeneration !== this.deliveryAckGeneration ||
            this.deliveryAckPersistence !== persistence
        ) return;
        if (
            policyGeneration !== this.recipientPolicyGeneration ||
            !blockingSystem.isEnforcementReady()
        ) throw new Error('Blocking policy changed during recovery restore');
        if (!Array.isArray(loaded) || loaded.length > MAX_AWAITING_ACK) {
            throw new Error('Delivery acknowledgement journal is invalid');
        }
        let encodedBytes = 2;
        const seen = new Set<string>();
        const restored = new Map<string, DurableAckEntry>();
        let journalChanged = false;
        const now = Date.now();
        for (const candidate of loaded) {
            if (!this.validDurableAckEntry(candidate)) {
                throw new Error('Delivery acknowledgement journal is invalid');
            }
            const trackingKey = this.deliveryTrackingKey(candidate.to, candidate.messageId);
            if (seen.has(trackingKey)) {
                throw new Error('Delivery acknowledgement journal contains duplicates');
            }
            seen.add(trackingKey);
            encodedBytes += JSON.stringify(candidate).length + 1;
            if (encodedBytes > MAX_DURABLE_ACK_BYTES) {
                throw new Error('Delivery acknowledgement journal exceeds its byte budget');
            }
            // File transfer state is intentionally live-only. The source bytes,
            // receiver state, and NACK window do not survive an account/app
            // restart, so replaying a persisted chunk cannot resume the transfer.
            if (candidate.type === SignalType.FILE_MESSAGE_CHUNK) {
                journalChanged = true;
                this.queueRecoveryClear(candidate.to, candidate.messageId);
                continue;
            }
            if (this.durableAckEntryExpired(candidate, now)) {
                journalChanged = true;
                continue;
            }
            if (blockingSystem.isBlockedSync(candidate.to)) {
                journalChanged = true;
                this.queueRecoveryClear(candidate.to, candidate.messageId);
                continue;
            }
            if (this.earlyDeliveryAcks.has(trackingKey)) {
                const earlyType = this.earlyDeliveryAcks.get(trackingKey);
                this.earlyDeliveryAcks.delete(trackingKey);
                if (earlyType === null || earlyType === candidate.type) {
                    journalChanged = true;
                    continue;
                }
            }
            restored.set(trackingKey, candidate);
        }
        this.earlyDeliveryAcks.clear();
        this.durableAckEntries.clear();
        for (const [trackingKey, entry] of restored) {
            if (!blockingSystem.isBlockedSync(entry.to)) {
                this.durableAckEntries.set(trackingKey, entry);
            } else {
                journalChanged = true;
                this.queueRecoveryClear(entry.to, entry.messageId);
            }
        }
        if (journalChanged) {
            await persistence.save(Array.from(this.durableAckEntries.values()));
        }
    }

    private persistDurableAckSnapshot(): Promise<void> {
        const persistence = this.deliveryAckPersistence;
        const generation = this.accountGeneration;
        const deliveryGeneration = this.deliveryAckGeneration;
        if (!persistence || this.durableAckStoreState !== 'ready') {
            return Promise.reject(new Error('Delivery acknowledgement store unavailable'));
        }
        const write = this.durableAckPersistenceTail
            .catch(() => { })
            .then(async () => {
                if (
                    generation !== this.accountGeneration ||
                    deliveryGeneration !== this.deliveryAckGeneration ||
                    this.deliveryAckPersistence !== persistence
                ) {
                    throw new Error('Account transition');
                }
                
                const snapshot = Array.from(this.durableAckEntries.values());
                if (JSON.stringify(snapshot).length > MAX_DURABLE_ACK_BYTES) {
                    throw new Error('Delivery acknowledgement store exceeds byte budget');
                }
                await persistence.save(snapshot);
            });
        this.durableAckPersistenceTail = write.catch(() => { });
        return write;
    }

    private scheduleDurableAckReconcile(): void {
        if (
            this.durableAckReconcileTimer ||
            !this.deliveryAckPersistence ||
            this.durableAckStoreState !== 'ready'
        ) return;
        const generation = this.accountGeneration;
        const deliveryGeneration = this.deliveryAckGeneration;
        const persistence = this.deliveryAckPersistence;
        const delay = Math.min(1000 * (2 ** Math.min(this.durableAckReconcileAttempts, 6)), 60_000);
        this.durableAckReconcileTimer = setTimeout(() => {
            this.durableAckReconcileTimer = null;
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration ||
                persistence !== this.deliveryAckPersistence
            ) return;
            void this.persistDurableAckSnapshot().then(() => {
                if (
                    generation === this.accountGeneration &&
                    deliveryGeneration === this.deliveryAckGeneration &&
                    persistence === this.deliveryAckPersistence
                ) {
                    this.durableAckReconcileAttempts = 0;
                }
            }).catch(() => {
                if (
                    generation === this.accountGeneration &&
                    deliveryGeneration === this.deliveryAckGeneration &&
                    persistence === this.deliveryAckPersistence
                ) {
                    this.durableAckReconcileAttempts = Math.min(this.durableAckReconcileAttempts + 1, 16);
                    this.scheduleDurableAckReconcile();
                }
            });
        }, delay);
    }

    private queueRecoveryClear(peer: string, messageId: string): void {
        const persistence = this.deliveryAckPersistence;
        if (!persistence) return;
        let ids = this.recoveryClearPending.get(peer);
        if (!ids) {
            if (this.recoveryClearPending.size >= MAX_AWAITING_ACK) return;
            ids = new Set<string>();
            this.recoveryClearPending.set(peer, ids);
        }
        let total = 0;
        for (const pendingIds of this.recoveryClearPending.values()) total += pendingIds.size;
        if (!ids.has(messageId) && total >= MAX_AWAITING_ACK) return;
        ids.add(messageId);
        if (!this.recoveryClearTimer) {
            this.recoveryClearTimer = setTimeout(() => {
                this.recoveryClearTimer = null;
                this.flushRecoveryClears();
            }, 50);
        }
    }

    private flushRecoveryClears(): void {
        const persistence = this.deliveryAckPersistence;
        if (
            !persistence ||
            this.recoveryClearPending.size === 0 ||
            this.recoveryClearTask
        ) return;
        const clearRecovery = persistence.clearRecovery;
        const generation = this.accountGeneration;
        const deliveryGeneration = this.deliveryAckGeneration;
        const batches = new Map(Array.from(this.recoveryClearPending, ([peer, ids]) => [
            peer,
            Array.from(ids),
        ]));

        let task!: Promise<void>;
        task = (async () => {
            for (const [peer, ids] of batches) {
                if (
                    generation !== this.accountGeneration ||
                    deliveryGeneration !== this.deliveryAckGeneration ||
                    persistence !== this.deliveryAckPersistence
                ) return;
                await clearRecovery(peer, ids);
                if (
                    generation !== this.accountGeneration ||
                    deliveryGeneration !== this.deliveryAckGeneration ||
                    persistence !== this.deliveryAckPersistence
                ) return;
                const pending = this.recoveryClearPending.get(peer);
                if (!pending) continue;
                for (const id of ids) pending.delete(id);
                if (pending.size === 0) this.recoveryClearPending.delete(peer);
            }
        })();
        this.recoveryClearTask = task;
        let failed = false;
        void task.catch(() => { failed = true; }).finally(() => {
            if (this.recoveryClearTask !== task) return;
            this.recoveryClearTask = null;
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration ||
                persistence !== this.deliveryAckPersistence ||
                this.recoveryClearPending.size === 0
            ) return;
            if (!this.recoveryClearTimer) {
                this.recoveryClearTimer = setTimeout(() => {
                    this.recoveryClearTimer = null;
                    this.flushRecoveryClears();
                }, failed ? DURABLE_ACK_RETRY_MS : 50);
            }
        });
    }

    private static readonly PRIORITY_SEND_TYPES: ReadonlySet<SignalType> = new Set([
        SignalType.RECEIPT_BATCH, SignalType.TYPING_START, SignalType.TYPING_STOP,
        SignalType.FILE_TRANSPORT_ACK, SignalType.FILE_CHUNK_NACK, SignalType.FILE_TRANSFER_CANCEL,
        SignalType.SESSION_RESET_REQUEST, SignalType.CALL_SIGNAL
    ]);

    // Send signal to a peer
    async send(
        to: string,
        payload: any,
        type: SignalType
    ): Promise<SendResult> {
        const generation = this.accountGeneration;
        const canonicalRecipient = typeof to === 'string' ? to.trim().toLowerCase() : '';
        if (to !== canonicalRecipient || canonicalRecipient === 'server' || !AUTH_USERNAME_REGEX.test(canonicalRecipient)) {
            return { success: false, transport: 'server', error: 'invalid-recipient' };
        }
        const initialPolicyError = this.recipientPolicyError(canonicalRecipient);
        if (initialPolicyError) {
            return { success: false, transport: 'server', error: initialPolicyError };
        }
        const sendPolicy = this.captureSendPolicy(canonicalRecipient);
        const queuedAt = Date.now();
        if (this.totalSendTasks >= MAX_TOTAL_SEND_TASKS) {
            return { success: false, transport: 'server', error: 'global-send-queue-saturated' };
        }
        const key = String(to);
        let q = this.sendQueues.get(key);
        if (!q) { q = { running: false, highStreak: 0, high: [], low: [] }; this.sendQueues.set(key, q); }

        // refuse to grow the per peer queue without bound
        const isPriority = UnifiedSignalTransport.PRIORITY_SEND_TYPES.has(type);
        const depth = isPriority ? q.high.length : q.low.length;
        const cap = isPriority ? MAX_QUEUED_PRIORITY_SENDS : MAX_QUEUED_SENDS_PER_PEER;
        if (depth >= cap) {
            console.warn('[MSG-SEND] per-peer send queue saturated, applying backpressure', {
                type, depth, cap
            });
            return { success: false, transport: 'server', error: 'send-queue-saturated' };
        }

        this.preparePeer(to);
        this.totalSendTasks += 1;
        const result = new Promise<SendResult>((resolve) => {
            let settled = false;
            let taskReleased = false;
            const finish = (value: SendResult) => {
                if (settled) return;
                settled = true;
                resolve(value);
            };
            const releaseTask = () => {
                if (taskReleased) return;
                taskReleased = true;
                if (generation === this.accountGeneration) {
                    this.totalSendTasks = Math.max(0, this.totalSendTasks - 1);
                }
            };
            const task: QueuedSend = {
                run: async () => {
                    let releasePermit: (() => void) | null = null;
                    try {
                        if (
                            type === SignalType.CALL_SIGNAL &&
                            Date.now() - queuedAt >= CALL_SIGNAL_QUEUE_MAX_WAIT_MS
                        ) {
                            finish({
                                success: false,
                                transport: 'server',
                                error: 'call-signal-expired-in-send-lane'
                            });
                            return;
                        }
                        const queuedPolicyError = this.recipientPolicyError(canonicalRecipient, sendPolicy);
                        if (queuedPolicyError) {
                            finish({ success: false, transport: 'server', error: queuedPolicyError });
                            return;
                        }
                        releasePermit = await this.acquireSendPermit(generation);
                        if (
                            releasePermit &&
                            type === SignalType.CALL_SIGNAL &&
                            Date.now() - queuedAt >= CALL_SIGNAL_QUEUE_MAX_WAIT_MS
                        ) {
                            finish({
                                success: false,
                                transport: 'server',
                                error: 'call-signal-expired-awaiting-send-permit'
                            });
                            return;
                        }
                        const permittedPolicyError = this.recipientPolicyError(canonicalRecipient, sendPolicy);
                        if (!releasePermit || permittedPolicyError) {
                            finish({
                                success: false,
                                transport: 'server',
                                error: permittedPolicyError || 'account-transition'
                            });
                            return;
                        }
                        try {
                            finish(await this.performSend(to, payload, type, sendPolicy));
                        } catch (error: any) {
                            finish({ success: false, transport: 'server', error: error?.message || String(error) });
                        }
                    } finally {
                        releasePermit?.();
                        releaseTask();
                    }
                },
                cancel: (error = 'account-transition') => {
                    finish({ success: false, transport: 'server', error });
                    releaseTask();
                }
            };
            if (isPriority) q!.high.push(task);
            else q!.low.push(task);
        });
        this.drainSendQueue(key);
        return result;
    }

    private acquireSendPermit(generation: number): Promise<(() => void) | null> {
        if (generation !== this.accountGeneration) return Promise.resolve(null);
        if (this.activeSendTasks < MAX_CONCURRENT_SEND_TASKS) {
            this.activeSendTasks += 1;
            return Promise.resolve(this.createSendPermitRelease(generation));
        }
        return new Promise((resolve) => {
            this.sendPermitWaiters.push({ generation, resolve });
        });
    }

    private createSendPermitRelease(generation: number): () => void {
        let released = false;
        return () => {
            if (released) return;
            released = true;
            if (generation !== this.accountGeneration) return;
            this.activeSendTasks = Math.max(0, this.activeSendTasks - 1);
            while (this.sendPermitWaiters.length > 0) {
                const waiter = this.sendPermitWaiters.shift()!;
                if (waiter.generation !== this.accountGeneration) {
                    waiter.resolve(null);
                    continue;
                }
                this.activeSendTasks += 1;
                waiter.resolve(this.createSendPermitRelease(waiter.generation));
                break;
            }
        };
    }

    private drainSendQueue(key: string): void {
        const q = this.sendQueues.get(key);
        if (!q || q.running) return;
        let next: QueuedSend | undefined;
        if (q.high.length > 0 && (q.low.length === 0 || q.highStreak < MAX_PRIORITY_BURST)) {
            next = q.high.shift();
            q.highStreak += 1;
        } else {
            next = q.low.shift();
            q.highStreak = 0;
        }
        if (!next) { this.sendQueues.delete(key); return; }
        q.running = true;
        void next.run().finally(() => {
            q.running = false;
            this.drainSendQueue(key);
        });
    }

    private directP2PPayload(envelope: any, type: SignalType, payload: any): any {
        const fileTransferId = type === SignalType.FILE_MESSAGE_CHUNK
            ? envelope?.fileTransferId
            : type === SignalType.FILE_TRANSPORT_ACK
                ? this.fileTransferIdFromChunkMessageId(payload?.ackFor)
                : null;
        return {
            type: SignalType.SEALED_ENVELOPE,
            messageId: envelope?.messageId,
            ...(typeof fileTransferId === 'string'
                ? { fileTransferId }
                : {}),
            envelope: envelope?.envelope
        };
    }

    private async sealForServer(
        envelopeToSend: any,
        peer: string
    ): Promise<{ sealed: any; tag: string }> {
        if (!canonicalBase64Shape(envelopeToSend?.recipientKyberPublicBase64, { exactBytes: PQ_KEM_PUBLIC_KEY_SIZE })) {
            throw new Error('Invalid recipient ML-KEM routing key');
        }
        const client = getBlindRoutingClient();
        const recipientKyber = PostQuantumUtils.base64ToUint8Array(
            envelopeToSend.recipientKyberPublicBase64
        );
        try {
            const detectionKey = await resolvePeerDetectionKey(client.identity, peer);
            const context = detectionKey
                ? await nextOutboundTag(client.identity, peer, detectionKey)
                : null;
            if (!context) {
                throw new Error(`Spool tagging requires the detection key for ${peer}`);
            }
            const sealed = await client.createSealedEnvelope(
                recipientKyber,
                {
                    envelope: envelopeToSend.envelope,
                    messageId: envelopeToSend.messageId
                },
                {
                    forceLargeFrame: typeof envelopeToSend.fileTransferId === 'string',
                    forceStandardFrame: typeof envelopeToSend.fileTransferId !== 'string',
                    tag: context.tag,
                    probe: context.probe
                }
            );

            return { sealed, tag: sealed.tag };
        } finally {
            recipientKyber.fill(0);
        }
    }

    private async performSend(
        to: string,
        payload: any,
        type: SignalType,
        sendPolicy: SendPolicyContext
    ): Promise<SendResult> {
        const policyFailure = (): SendResult | null => {
            const error = this.recipientPolicyError(to, sendPolicy);
            return error ? { success: false, transport: 'server', error } : null;
        };
        const initialPolicyFailure = policyFailure();
        if (initialPolicyFailure) return initialPolicyFailure;
        const encryptionProvider = this.encryptionProvider;
        
        if (!encryptionProvider) {
            console.error('[MSG-SEND] no encryption provider set');
            return { success: false, transport: 'server', error: 'Encryption provider not set' };
        }

        const encryptedResult = await encryptionProvider(to, payload, type);
        const postEncryptionPolicyFailure = policyFailure();
        if (postEncryptionPolicyFailure) return postEncryptionPolicyFailure;
        if (!encryptedResult) {
            const denial = this.lastEncryptionDenial;
            const reason = denial &&
                denial.to === to &&
                denial.type === String(type) &&
                Date.now() - denial.at < ENCRYPTION_DENIAL_FRESH_MS
                ? denial.reason
                : 'unreported';
                
            const deferred = reason.startsWith('deferrable-signal-');
            const report = deferred ? console.warn : console.error;
            report('[MSG-SEND] encryption produced no envelope', { reason });
            return { success: false, transport: 'server', error: 'Encryption failed' };
        }

        const envelopeToSend = {
            type: SignalType.SEALED_ENVELOPE,
            messageId: encryptedResult.messageId,
            ...(type === SignalType.FILE_MESSAGE_CHUNK && typeof payload?.fileTransferId === 'string'
                ? { fileTransferId: payload.fileTransferId }
                : {}),
            envelope: encryptedResult.encryptedPayload,
            recipientKyberPublicBase64: encryptedResult.recipientKyberPublicBase64
        };

        if (!this.validOutboundEnvelope(envelopeToSend, type)) {
            console.error('[MSG-SEND] encryption provider returned an invalid envelope');
            return { success: false, transport: 'server', error: 'Invalid encrypted envelope' };
        }

        const preTransportPolicyFailure = policyFailure();
        if (preTransportPolicyFailure) return preTransportPolicyFailure;
        const p2pSender = this.p2pSender;
        if (p2pSender) {
            try {
                const preP2PPolicyFailure = policyFailure();
                if (preP2PPolicyFailure) return preP2PPolicyFailure;
                await p2pSender(to, this.directP2PPayload(envelopeToSend, type, payload), type);
                const postP2PPolicyFailure = policyFailure();
                if (postP2PPolicyFailure) return postP2PPolicyFailure;
                await this.trackDeliveryAck(to, { ...envelopeToSend }, type, sendPolicy);
                return { success: true, transport: 'p2p' };
            } catch (error) {
                const p2pPolicyFailure = policyFailure();
                if (p2pPolicyFailure) return p2pPolicyFailure;
                const errorMessage = error instanceof Error ? error.message : String(error);
                if (!/not ready|not connected|no active p2p connection/i.test(errorMessage)) {
                    console.warn('[MSG-SEND] P2P send failed, using sealed server route', { error: errorMessage });
                }
            }
        }

        let activeRequestId: string | null = null;
        try {
            const preServerPolicyFailure = policyFailure();
            if (preServerPolicyFailure) return preServerPolicyFailure;

            if (!canonicalBase64Shape(
                envelopeToSend.recipientKyberPublicBase64,
                { exactBytes: PQ_KEM_PUBLIC_KEY_SIZE }
            )) {
                console.warn('[UnifiedTransport] Cannot blind-route without recipient Kyber key');
                return { success: false, transport: 'server', error: 'valid recipientKyberPublicBase64 required' };
            }

            const { sealed: sealedEnvelope } = await this.sealForServer(envelopeToSend, to);
            const postSealPolicyFailure = policyFailure();
            if (postSealPolicyFailure) return postSealPolicyFailure;

            const requestId = crypto.randomUUID();
            activeRequestId = requestId;
            const ackPromise = this.awaitBlindRouteAck(requestId, BLIND_ROUTE_ACK_TIMEOUT_MS);
            const preServerWritePolicyFailure = policyFailure();
            if (preServerWritePolicyFailure) {
                this.cancelBlindRouteAck(requestId);
                activeRequestId = null;
                return preServerWritePolicyFailure;
            }

            const deliveryReady = await websocketClient.checkDeliveryReadyForSend();
            if (!deliveryReady) {
                this.cancelBlindRouteAck(requestId);
                activeRequestId = null;
                this.scheduleP2PRecoveryRedelivery(to, { ...envelopeToSend }, type);
                return { success: false, transport: 'server', error: 'delivery-not-activated' };
            }
            const serverTransmitted = await websocketClient.sendReliable(JSON.stringify({
                type: SignalType.BLIND_ROUTE,
                requestId,
                sealedEnvelope,
                ...(isLiveOnlySignalType(type)
                    ? { deliveryPolicy: LIVE_ONLY_DELIVERY_POLICY }
                    : {})
            }), { queueOnFailure: !isLiveOnlySignalType(type) });
            const postServerWritePolicyFailure = policyFailure();
            if (postServerWritePolicyFailure) {
                this.cancelBlindRouteAck(requestId);
                activeRequestId = null;
                return postServerWritePolicyFailure;
            }

            if (!serverTransmitted) {
                this.cancelBlindRouteAck(requestId);
                activeRequestId = null;
                this.scheduleP2PRecoveryRedelivery(to, { ...envelopeToSend }, type);
                return { success: false, transport: 'server', error: 'server send not confirmed (queued)' };
            }

            const ackResult = await ackPromise;
            activeRequestId = null;
            const postAckPolicyFailure = policyFailure();
            if (postAckPolicyFailure) return postAckPolicyFailure;
            if (!ackResult.acked) {
                this.scheduleP2PRecoveryRedelivery(to, { ...envelopeToSend }, type);
                return { success: false, transport: 'server', error: `blind-route not acked (${ackResult.error || 'timeout'})` };
            }
            if (!ackResult.success) {
                this.scheduleP2PRecoveryRedelivery(to, { ...envelopeToSend }, type);
                return { success: false, transport: 'server', error: `blind-route rejected (${ackResult.error || 'unknown'})` };
            }
            
            this.pendingRedelivery.delete(this.deliveryTrackingKey(to, envelopeToSend.messageId));
            if (this.pendingRedelivery.size === 0 && this.redeliveryFlusher !== null) {
                clearInterval(this.redeliveryFlusher);
                this.redeliveryFlusher = null;
            }
            return { success: true, transport: 'server' };
        } catch (serverErr: any) {
            if (activeRequestId) this.cancelBlindRouteAck(activeRequestId);
            const serverPolicyFailure = policyFailure();
            if (serverPolicyFailure) return serverPolicyFailure;
            console.error('[UnifiedTransport] Critical failure sending through server', {
                type,
                to,
                error: serverErr instanceof Error ? serverErr.message : String(serverErr)
            });
            
            this.scheduleP2PRecoveryRedelivery(to, { ...envelopeToSend }, type);
            return { success: false, transport: 'server', error: serverErr?.message || 'Server send failed' };
        }
    }

    private blindAckWaiters = new Map<string, (r: { acked: boolean; success?: boolean; error?: string }) => void>();
    private blindAckHandlerRegistered = false;
    private readonly blindAckHandler = (msg: any): void => {
        if (!exactObjectKeys(msg, ['type', 'requestId', 'success']) &&
            !exactObjectKeys(msg, ['type', 'requestId', 'success', 'error'])) return;
        if (
            msg.type !== SignalType.BLIND_ROUTE_ACK ||
            typeof msg.success !== 'boolean' ||
            ('error' in msg && (typeof msg.error !== 'string' || msg.error.length < 1 || msg.error.length > 200))
        ) return;
        const rid = msg?.requestId;
        if (
            typeof rid !== 'string' ||
            !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(rid)
        ) return;
        const waiter = this.blindAckWaiters.get(rid);
        if (waiter) {
            this.blindAckWaiters.delete(rid);
            waiter({
                acked: true,
                success: msg.success === true,
                error: typeof msg.error === 'string' ? msg.error.slice(0, 200) : undefined
            });
        }
    };

    private checkBlindAckHandler(): boolean {
        if (this.blindAckHandlerRegistered) return true;
        this.blindAckHandlerRegistered = true;
        try {
            websocketClient.registerMessageHandler(SignalType.BLIND_ROUTE_ACK, this.blindAckHandler);
            return true;
        } catch {
            this.blindAckHandlerRegistered = false;
            return false;
        }
    }

    private awaitBlindRouteAck(requestId: string, timeoutMs: number): Promise<{ acked: boolean; success?: boolean; error?: string }> {
        if (!this.checkBlindAckHandler()) throw new Error('Blind-route acknowledgement handler unavailable');
        if (this.blindAckWaiters.size >= MAX_BLIND_ACK_WAITERS || this.blindAckWaiters.has(requestId)) {
            throw new Error('Blind-route acknowledgement capacity reached');
        }
        return new Promise((resolve) => {
            const settle = (r: { acked: boolean; success?: boolean; error?: string }) => {
                clearTimeout(timeout);
                clearInterval(liveness);
                this.blindAckWaiters.delete(requestId);
                resolve(r);
            };
            const timeout = setTimeout(() => settle({ acked: false, error: 'timeout' }), timeoutMs);
            const liveness = setInterval(() => {
                if (!websocketClient.isConnectedToServer()) settle({ acked: false, error: 'disconnected' });
            }, BLIND_ROUTE_ACK_LIVENESS_POLL_MS);
            this.blindAckWaiters.set(requestId, settle);
        });
    }

    private cancelBlindRouteAck(requestId: string): void {
        const waiter = this.blindAckWaiters.get(requestId);
        if (waiter) {
            this.blindAckWaiters.delete(requestId);
            waiter({ acked: false, error: 'cancelled' });
        }
    }

    // Message types safe to retransmit over P2P as bounded delivery recovery
    private static readonly P2P_RECOVERY_REDELIVER_TYPES: ReadonlySet<SignalType> = new Set([
        SignalType.MESSAGE
    ]);

    // Queue a failed server route or an unacknowledged direct write for P2P recovery.
    private scheduleP2PRecoveryRedelivery(to: string, envelopeToSend: any, type: SignalType, opts?: { reconnectOnly?: boolean }): void {
        if (!this.p2pSender || !isCanonicalUsername(to) || to === 'server') return;
        if (this.recipientPolicyError(to)) return;
        if (!UnifiedSignalTransport.P2P_RECOVERY_REDELIVER_TYPES.has(type)) return;
        const messageId = envelopeToSend?.messageId;
        if (!messageId || typeof messageId !== 'string') return;
        const trackingKey = this.deliveryTrackingKey(to, messageId);
        if (this.pendingRedelivery.has(trackingKey)) return;

        if (this.pendingRedelivery.size >= REDELIVER_MAX_PENDING) {
            // Drop the oldest to bound memory.
            const oldest = this.pendingRedelivery.keys().next().value;
            if (oldest) this.pendingRedelivery.delete(oldest);
        }
        this.pendingRedelivery.set(trackingKey, {
            to,
            envelope: envelopeToSend,
            type,
            firstAt: Date.now(),
            generation: this.accountGeneration,
            reconnectOnly: !!opts?.reconnectOnly,
            attempts: 0,
            nextAttemptAt: 0
        });

        // Bind the connection ready listener
        if (!this.redeliveryPeerListenerBound) {
            this.redeliveryPeerListenerBound = true;
            window.addEventListener(EventType.P2P_PEER_CONNECTED, (evt: Event) => {
                if (!(evt instanceof CustomEvent)) return;
                const detail = evt.detail;
                if (!exactObjectKeys(detail, ['account', 'peer'])) return;
                if (detail.account !== p2pTransport.getLocalUsername()) return;
                const peer = detail.peer;
                if (isCanonicalUsername(peer)) {
                    void this.flushRedeliveries(peer, true);
                }
            });
        }

        if (this.redeliveryFlusher === null) {
            this.redeliveryFlusher = setInterval(() => { void this.flushRedeliveries(); }, REDELIVER_FLUSH_INTERVAL_MS);
        }

        if (!opts?.reconnectOnly) void this.flushRedeliveries(to);
    }

    private flushRedeliveries(onlyPeer?: string, fromReconnect = false): Promise<void> {
        if (this.pendingRedelivery.size === 0) {
            if (this.redeliveryFlusher !== null) { clearInterval(this.redeliveryFlusher); this.redeliveryFlusher = null; }
            return Promise.resolve();
        }

        if (fromReconnect) {
            if (!isCanonicalUsername(onlyPeer)) return Promise.resolve();
            this.redeliveryReconnectFlushRequested = true;
            this.redeliveryReconnectPeerRequests.add(onlyPeer);
        } else {
            this.redeliveryNormalFlushRequested = true;
            if (isCanonicalUsername(onlyPeer)) {
                this.redeliveryNormalPeerRequests.add(onlyPeer);
            } else {
                this.redeliveryNormalAllRequested = true;
                this.redeliveryNormalPeerRequests.clear();
            }
        }
        if (this.redeliveryFlushPromise) return this.redeliveryFlushPromise;

        const generation = this.accountGeneration;
        let flushPromise!: Promise<void>;
        flushPromise = (async () => {
            while (
                generation === this.accountGeneration &&
                (this.redeliveryNormalFlushRequested || this.redeliveryReconnectFlushRequested)
            ) {
                const allowNormal = this.redeliveryNormalFlushRequested;
                const allowReconnect = this.redeliveryReconnectFlushRequested;
                const normalAll = this.redeliveryNormalAllRequested;
                const normalPeers = new Set(this.redeliveryNormalPeerRequests);
                const reconnectPeers = new Set(this.redeliveryReconnectPeerRequests);
                this.redeliveryNormalFlushRequested = false;
                this.redeliveryReconnectFlushRequested = false;
                this.redeliveryNormalAllRequested = false;
                this.redeliveryNormalPeerRequests.clear();
                this.redeliveryReconnectPeerRequests.clear();
                await this.flushRedeliveryPass(
                    generation,
                    allowNormal,
                    allowReconnect,
                    normalAll,
                    normalPeers,
                    reconnectPeers
                );
            }
        })().finally(() => {
            if (this.redeliveryFlushPromise === flushPromise) {
                this.redeliveryFlushPromise = null;
            }
        });
        this.redeliveryFlushPromise = flushPromise;
        return flushPromise;
    }

    private async flushRedeliveryPass(
        generation: number,
        allowNormal: boolean,
        allowReconnect: boolean,
        normalAll: boolean,
        normalPeers: ReadonlySet<string>,
        reconnectPeers: ReadonlySet<string>
    ): Promise<void> {
        const now = Date.now();
        for (const [trackingKey, entry] of Array.from(this.pendingRedelivery.entries())) {
            if (generation !== this.accountGeneration) break;
            if (this.pendingRedelivery.get(trackingKey) !== entry) continue;
            if (this.recipientPolicyError(entry.to)) {
                this.pendingRedelivery.delete(trackingKey);
                continue;
            }
            if (entry.generation !== generation) {
                this.pendingRedelivery.delete(trackingKey);
                continue;
            }
            if (now - entry.firstAt >= REDELIVER_MAX_AGE_MS) {
                this.pendingRedelivery.delete(trackingKey);
                console.warn('[MSG-SEND] P2P re-delivery gave up (max age)');
                continue;
            }
            const normalRequested = allowNormal && (normalAll || normalPeers.has(entry.to));
            const reconnectRequested = allowReconnect && reconnectPeers.has(entry.to);
            if (entry.reconnectOnly ? !reconnectRequested : !(normalRequested || reconnectRequested)) continue;
            if ((entry.nextAttemptAt ?? 0) > now) continue;
            const sender = this.p2pSender;
            if (!sender) continue;
            const alias = p2pTransport.resolveUsernameAlias(entry.to);
            const connected = p2pTransport.isConnected(entry.to) || (!!alias && p2pTransport.isConnected(alias));
            if (!connected) continue;
            if (this.redeliveryInFlight.has(trackingKey)) continue;
            this.redeliveryInFlight.add(trackingKey);
            try {
                await sender(
                    entry.to,
                    this.directP2PPayload(entry.envelope, entry.type, undefined),
                    entry.type
                );
                if (
                    generation !== this.accountGeneration ||
                    entry.generation !== this.accountGeneration ||
                    this.pendingRedelivery.get(trackingKey) !== entry ||
                    this.recipientPolicyError(entry.to)
                ) continue;
                if (entry.type && isAckTrackedSignalType(entry.type)) {
                    await this.trackDeliveryAck(entry.to, { ...entry.envelope }, entry.type);
                }
                if (
                    entry.generation === this.accountGeneration &&
                    this.pendingRedelivery.get(trackingKey) === entry
                ) {
                    this.pendingRedelivery.delete(trackingKey);
                }
            } catch {
                if (
                    entry.generation === this.accountGeneration &&
                    this.pendingRedelivery.get(trackingKey) === entry
                ) {
                    const attempts = Math.min((entry.attempts ?? 0) + 1, 8);
                    entry.attempts = attempts;
                    entry.nextAttemptAt = Date.now() + Math.min(
                        REDELIVER_FLUSH_INTERVAL_MS * Math.pow(2, attempts - 1),
                        30_000
                    );
                }
            } finally {
                if (generation === this.accountGeneration) {
                    this.redeliveryInFlight.delete(trackingKey);
                }
            }
        }
        if (
            generation === this.accountGeneration &&
            this.pendingRedelivery.size === 0 &&
            this.redeliveryFlusher !== null
        ) {
            clearInterval(this.redeliveryFlusher); this.redeliveryFlusher = null;
        }
    }

    private async trackDeliveryAck(
        to: string,
        envelopeToSend: any,
        type: SignalType,
        sendPolicy?: SendPolicyContext
    ): Promise<void> {
        if (!isAckTrackedSignalType(type)) return;
        const initialPolicyError = this.recipientPolicyError(to, sendPolicy);
        if (initialPolicyError) throw new Error(initialPolicyError);
        const generation = this.accountGeneration;
        const deliveryGeneration = this.deliveryAckGeneration;
        const isLiveFileChunk = type === SignalType.FILE_MESSAGE_CHUNK;
        if (!isLiveFileChunk) await this.durableAckRestore;
        if (
            generation !== this.accountGeneration ||
            deliveryGeneration !== this.deliveryAckGeneration
        ) throw new Error('Account transition');
        const restoredPolicyError = this.recipientPolicyError(to, sendPolicy);
        if (restoredPolicyError) throw new Error(restoredPolicyError);
        if (!isLiveFileChunk && this.durableAckStoreState !== 'ready') {
            throw new Error('Delivery acknowledgement store unavailable');
        }
        const messageId = envelopeToSend?.messageId;
        if (!messageId || typeof messageId !== 'string') return;
        const trackingKey = this.deliveryTrackingKey(to, messageId);
        if (this.earlyDeliveryAcks.has(trackingKey)) {
            const earlyType = this.earlyDeliveryAcks.get(trackingKey);
            this.earlyDeliveryAcks.delete(trackingKey);
            if (earlyType === null || earlyType === type) {
                if (type === SignalType.FILE_MESSAGE_CHUNK) {
                    const transferId = typeof envelopeToSend?.fileTransferId === 'string'
                        ? envelopeToSend.fileTransferId
                        : null;
                    if (transferId && sanitizeMessageId(transferId) === transferId) {
                        this.rememberAckedChunkTransfer(to, transferId);
                    }
                }
                this.pendingRedelivery.delete(trackingKey);
                return;
            }
        }

        if (type === SignalType.FILE_MESSAGE_CHUNK) {
            const transferId = typeof envelopeToSend?.fileTransferId === 'string'
                ? envelopeToSend.fileTransferId
                : null;
            const transferTrackingKey = transferId
                ? this.deliveryTrackingKey(to, transferId)
                : null;
            const ackedAt = transferTrackingKey
                ? this.ackedChunkTransfers.get(transferTrackingKey)
                : undefined;
            if (ackedAt !== undefined) {
                if (Date.now() - ackedAt < FILE_RETRANSMIT_RETENTION_MS) return;
                this.ackedChunkTransfers.delete(transferTrackingKey!);
            }
        }

        if (!isLiveFileChunk) {
            this.scheduleP2PRecoveryRedelivery(to, { ...envelopeToSend }, type, { reconnectOnly: true });
        }

        if (this.awaitingDeliveryAck.has(trackingKey)) return;
        if (
            this.awaitingDeliveryAck.size >= MAX_AWAITING_ACK ||
            (!isLiveFileChunk &&
                !this.durableAckEntries.has(trackingKey) &&
                this.durableAckEntries.size >= MAX_AWAITING_ACK)
        ) {
            throw new Error('Delivery acknowledgement capacity reached');
        }
        const timer = setTimeout(() => {
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration
            ) return;
            const entry = this.awaitingDeliveryAck.get(trackingKey);
            if (!entry) return;
            this.awaitingDeliveryAck.delete(trackingKey);
            if (entry.type === SignalType.FILE_MESSAGE_CHUNK) {
                this.queueRecoveryClear(entry.to, entry.envelopeToSend.messageId);
                return;
            }
            this.enqueueAckSpool(entry.to, entry.envelopeToSend);
        }, DELIVERY_ACK_TIMEOUT_MS);
        const awaitingEntry = { to, envelopeToSend, timer, type };
        this.awaitingDeliveryAck.set(trackingKey, awaitingEntry);

        // File chunks use the transfer protocol's bounded in-memory retransmit
        // and NACK state. Persisting them here made abandoned transfers replay
        // after login for the general one-hour message retry window.
        if (isLiveFileChunk) return;

        const durableEntry = {
            messageId,
            to,
            envelopeToSend,
            type,
            createdAt: Date.now()
        };
        this.durableAckEntries.set(trackingKey, durableEntry);
        try {
            await this.persistDurableAckSnapshot();
        } catch (error) {
            clearTimeout(timer);
            if (this.awaitingDeliveryAck.get(trackingKey) === awaitingEntry) {
                this.awaitingDeliveryAck.delete(trackingKey);
            }
            if (this.durableAckEntries.get(trackingKey) === durableEntry) {
                this.durableAckEntries.delete(trackingKey);
            }
            this.scheduleDurableAckReconcile();
            throw error;
        }
    }

    private enqueueAckSpool(to: string, envelopeToSend: any): void {
        const messageId = envelopeToSend?.messageId;
        if (typeof messageId !== 'string' || !messageId || !isCanonicalUsername(to)) return;
        const trackingKey = this.deliveryTrackingKey(to, messageId);
        const policyError = this.recipientPolicyError(to);
        if (policyError) {
            if (policyError === 'recipient-blocked') void this.completeDurableAck(trackingKey);
            else this.scheduleDurableAckRetry(trackingKey);
            return;
        }
        const durableEntry = this.durableAckEntries.get(trackingKey);
        if (durableEntry && this.durableAckEntryExpired(durableEntry)) {
            void this.completeDurableAck(trackingKey);
            return;
        }
        if (this.ackSpoolQueuedIds.has(trackingKey) || this.ackSpoolInFlightIds.has(trackingKey)) return;
        if (this.ackSpoolQueue.length >= MAX_ACK_SPOOL_QUEUE) {
            this.scheduleDurableAckRetry(trackingKey);
            return;
        }
        this.ackSpoolQueue.push({
            to,
            envelopeToSend,
            generation: this.accountGeneration,
            deliveryGeneration: this.deliveryAckGeneration
        });
        this.ackSpoolQueuedIds.add(trackingKey);
        this.pumpAckSpool();
    }

    private pumpAckSpool(): void {
        while (this.ackSpoolActive < MAX_CONCURRENT_ACK_SPOOLS && this.ackSpoolQueue.length > 0) {
            const queued = this.ackSpoolQueue.shift();
            if (!queued) return;
            const messageId = queued.envelopeToSend?.messageId;
            const trackingKey = typeof messageId === 'string'
                ? this.deliveryTrackingKey(queued.to, messageId)
                : null;
            if (trackingKey) {
                this.ackSpoolQueuedIds.delete(trackingKey);
                this.ackSpoolInFlightIds.add(trackingKey);
            }
            this.ackSpoolActive++;
            void this.spoolPersistentToServer(
                queued.to,
                queued.envelopeToSend,
                queued.generation,
                queued.deliveryGeneration
            ).finally(() => {
                if (
                    queued.generation === this.accountGeneration &&
                    queued.deliveryGeneration === this.deliveryAckGeneration
                ) {
                    if (trackingKey) this.ackSpoolInFlightIds.delete(trackingKey);
                    this.ackSpoolActive = Math.max(0, this.ackSpoolActive - 1);
                    this.pumpAckSpool();
                }
            });
        }
    }

    private scheduleDurableAckRetry(trackingKey: string): void {
        if (this.durableAckRetryTimers.has(trackingKey) || !this.durableAckEntries.has(trackingKey)) return;
        const generation = this.accountGeneration;
        const deliveryGeneration = this.deliveryAckGeneration;
        const timer = setTimeout(() => {
            this.durableAckRetryTimers.delete(trackingKey);
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration
            ) return;
            const entry = this.durableAckEntries.get(trackingKey);
            if (!entry) return;
            if (this.durableAckEntryExpired(entry)) {
                void this.completeDurableAck(trackingKey);
            } else {
                this.enqueueAckSpool(entry.to, entry.envelopeToSend);
            }
        }, DURABLE_ACK_RETRY_MS);
        this.durableAckRetryTimers.set(trackingKey, timer);
    }

    private async completeDurableAcks(trackingKeys: Iterable<string>): Promise<void> {
        const generation = this.accountGeneration;
        const deliveryGeneration = this.deliveryAckGeneration;
        const persistence = this.deliveryAckPersistence;
        let removed = false;
        for (const trackingKey of new Set(trackingKeys)) {
            if (this.durableAckEntries.delete(trackingKey)) removed = true;
            const retryTimer = this.durableAckRetryTimers.get(trackingKey);
            if (retryTimer) clearTimeout(retryTimer);
            this.durableAckRetryTimers.delete(trackingKey);
        }
        if (!removed) return;
        try {
            await this.persistDurableAckSnapshot();
        } catch {
            if (
                generation === this.accountGeneration &&
                deliveryGeneration === this.deliveryAckGeneration &&
                persistence === this.deliveryAckPersistence
            ) {
                this.scheduleDurableAckReconcile();
            }
        }
    }

    private completeDurableAck(trackingKey: string): Promise<void> {
        return this.completeDurableAcks([trackingKey]);
    }

    markDelivered(messageId: string, from: string, expectedType?: SignalType): void {
        if (sanitizeMessageId(messageId) !== messageId || !isCanonicalUsername(from)) return;
        const trackingKey = this.deliveryTrackingKey(from, messageId);
        const entry = this.awaitingDeliveryAck.get(trackingKey);
        const pending = this.pendingRedelivery.get(trackingKey);
        const durable = this.durableAckEntries.get(trackingKey);
        const trackedType = entry?.type ?? durable?.type ?? pending?.type;
        if (expectedType && trackedType && trackedType !== expectedType) return;
        if (!entry && !pending && !durable) {
            if (expectedType === SignalType.FILE_MESSAGE_CHUNK) {
                const transferId = this.fileTransferIdFromChunkMessageId(messageId);
                const transferTrackingKey = transferId
                    ? this.deliveryTrackingKey(from, transferId)
                    : null;
                const ackedAt = transferTrackingKey
                    ? this.ackedChunkTransfers.get(transferTrackingKey)
                    : undefined;
                if (ackedAt !== undefined) {
                    if (Date.now() - ackedAt < FILE_RETRANSMIT_RETENTION_MS) {
                        this.queueRecoveryClear(from, messageId);
                        return;
                    }
                    this.ackedChunkTransfers.delete(transferTrackingKey!);
                }
            }
            
            this.queueRecoveryClear(from, messageId);
            this.rememberEarlyDeliveryAck(from, trackingKey, expectedType || null);
            return;
        }
        
        const trackedTo = entry?.to ?? pending?.to ?? durable?.to;
        if (trackedTo && trackedTo !== from) return;
        this.queueRecoveryClear(from, messageId);

        if (!entry && !durable && pending && this.redeliveryInFlight.has(trackingKey)) {
            this.rememberEarlyDeliveryAck(from, trackingKey, expectedType ?? pending.type ?? null);
            this.pendingRedelivery.delete(trackingKey);
            return;
        }

        if (trackedType === SignalType.FILE_MESSAGE_CHUNK || expectedType === SignalType.FILE_MESSAGE_CHUNK) {
            const transferId = (
                typeof entry?.envelopeToSend?.fileTransferId === 'string'
                    ? entry.envelopeToSend.fileTransferId
                    : typeof durable?.envelopeToSend?.fileTransferId === 'string'
                        ? durable.envelopeToSend.fileTransferId
                        : this.fileTransferIdFromChunkMessageId(messageId)
            );
            if (transferId && sanitizeMessageId(transferId) === transferId) {
                this.rememberAckedChunkTransfer(from, transferId);

                const completedKeys = new Set<string>();
                for (const [key, candidate] of this.awaitingDeliveryAck) {
                    if (
                        candidate.to === from &&
                        candidate.type === SignalType.FILE_MESSAGE_CHUNK &&
                        candidate.envelopeToSend?.fileTransferId === transferId
                    ) {
                        clearTimeout(candidate.timer);
                        this.awaitingDeliveryAck.delete(key);
                        completedKeys.add(key);
                    }
                }
                for (const [key, candidate] of this.pendingRedelivery) {
                    if (candidate.to === from && candidate.envelope?.fileTransferId === transferId) {
                        this.pendingRedelivery.delete(key);
                    }
                }
                for (const [key, candidate] of this.durableAckEntries) {
                    if (
                        candidate.to === from &&
                        candidate.type === SignalType.FILE_MESSAGE_CHUNK &&
                        candidate.envelopeToSend?.fileTransferId === transferId
                    ) completedKeys.add(key);
                }
                this.ackSpoolQueue = this.ackSpoolQueue.filter((queued) => {
                    const sameTransfer = queued.to === from && queued.envelopeToSend?.fileTransferId === transferId;
                    if (sameTransfer && typeof queued.envelopeToSend?.messageId === 'string') {
                        this.ackSpoolQueuedIds.delete(this.deliveryTrackingKey(from, queued.envelopeToSend.messageId));
                    }
                    return !sameTransfer;
                });
                void this.completeDurableAcks(completedKeys);
                return;
            }
        }

        if (entry) {
            try { clearTimeout(entry.timer); } catch { }
            this.awaitingDeliveryAck.delete(trackingKey);
        }
        this.pendingRedelivery.delete(trackingKey);
        void this.completeDurableAck(trackingKey);
    }

    private async spoolPersistentToServer(
        to: string,
        envelopeToSend: any,
        generation: number,
        deliveryGeneration: number
    ): Promise<void> {
        const messageId = typeof envelopeToSend?.messageId === 'string'
            ? envelopeToSend.messageId
            : '';
        const trackingKey = messageId ? this.deliveryTrackingKey(to, messageId) : '';
        try {
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration
            ) return;
            const durableEntry = trackingKey ? this.durableAckEntries.get(trackingKey) : undefined;
            
            if (trackingKey && !durableEntry) return;
            const initialPolicyError = this.recipientPolicyError(to);
            if (initialPolicyError) {
                if (initialPolicyError === 'recipient-blocked' && trackingKey) {
                    await this.completeDurableAck(trackingKey);
                } else if (trackingKey) {
                    this.scheduleDurableAckRetry(trackingKey);
                }
                return;
            }
            if (durableEntry && this.durableAckEntryExpired(durableEntry)) {
                await this.completeDurableAck(trackingKey);
                return;
            }
            if (!envelopeToSend?.recipientKyberPublicBase64) {
                if (trackingKey) this.scheduleDurableAckRetry(trackingKey);
                return;
            }
            const { sealed: sealedEnvelope } = await this.sealForServer(envelopeToSend, to);
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration
            ) return;
            
            let transmitted = false;
            for (let attempt = 0; attempt < SPOOL_MAX_ATTEMPTS && !transmitted; attempt++) {
                if (attempt > 0) await new Promise(r => setTimeout(r, SPOOL_RETRY_BASE_MS * attempt));
                if (
                    generation !== this.accountGeneration ||
                    deliveryGeneration !== this.deliveryAckGeneration
                ) return;
                const currentEntry = trackingKey ? this.durableAckEntries.get(trackingKey) : undefined;
                if (trackingKey && !currentEntry) return;
                const attemptPolicyError = this.recipientPolicyError(to);
                if (attemptPolicyError) {
                    if (attemptPolicyError === 'recipient-blocked' && trackingKey) {
                        await this.completeDurableAck(trackingKey);
                    } else if (trackingKey) {
                        this.scheduleDurableAckRetry(trackingKey);
                    }
                    return;
                }
                if (currentEntry && this.durableAckEntryExpired(currentEntry)) {
                    await this.completeDurableAck(trackingKey);
                    return;
                }
                const requestId = crypto.randomUUID();
                const ackPromise = this.awaitBlindRouteAck(requestId, BLIND_ROUTE_ACK_TIMEOUT_MS);
                let written = false;
                try {
                    const preWritePolicyError = this.recipientPolicyError(to);
                    if (preWritePolicyError) {
                        this.cancelBlindRouteAck(requestId);
                        if (preWritePolicyError === 'recipient-blocked' && trackingKey) {
                            await this.completeDurableAck(trackingKey);
                        } else if (trackingKey) {
                            this.scheduleDurableAckRetry(trackingKey);
                        }
                        return;
                    }
                    
                    if (!(await websocketClient.checkDeliveryReadyForSend())) {
                        this.cancelBlindRouteAck(requestId);
                        continue;
                    }
                    written = await websocketClient.sendReliable(JSON.stringify({
                        type: SignalType.BLIND_ROUTE,
                        requestId,
                        sealedEnvelope
                    }));
                } catch {
                    this.cancelBlindRouteAck(requestId);
                    continue;
                }
                if (
                    generation !== this.accountGeneration ||
                    deliveryGeneration !== this.deliveryAckGeneration
                ) {
                    this.cancelBlindRouteAck(requestId);
                    return;
                }
                if (!written) {
                    this.cancelBlindRouteAck(requestId);
                    continue;
                }
                const ack = await ackPromise;
                if (
                    generation !== this.accountGeneration ||
                    deliveryGeneration !== this.deliveryAckGeneration
                ) return;
                transmitted = ack.acked && ack.success === true;
            }
            if (transmitted) {
                if (trackingKey) await this.completeDurableAck(trackingKey);
            } else {
                if (trackingKey) this.scheduleDurableAckRetry(trackingKey);
            }
        } catch (e: any) {
            if (
                generation !== this.accountGeneration ||
                deliveryGeneration !== this.deliveryAckGeneration
            ) return;
            console.warn('[MSG-SEND] offline spool failed', {
                error: e instanceof Error ? e.message : String(e),
            });
            if (trackingKey) this.scheduleDurableAckRetry(trackingKey);
        }
    }

    resetForAccountTransition(): void {
        clearDetectionKeyCaches();
        this.accountGeneration += 1;
        this.recipientPolicyGeneration += 1;
        this.recipientPolicyEpochs.clear();
        this.deliveryAckGeneration += 1;
        this.encryptionProvider = null;
        this.p2pSender = null;
        this.peerPreparer = null;
        this.deliveryAckPersistence = null;
        this.durableAckStoreState = 'disabled';
        this.durableAckRestore = Promise.resolve();
        if (this.durableAckRestoreRetryTimer) clearTimeout(this.durableAckRestoreRetryTimer);
        this.durableAckRestoreRetryTimer = null;
        this.durableAckRestoreAttempts = 0;
        this.earlyDeliveryAcks.clear();
        if (this.recoveryClearTimer) clearTimeout(this.recoveryClearTimer);
        this.recoveryClearTimer = null;
        this.recoveryClearPending.clear();
        this.recoveryClearTask = null;

        this.pendingRedelivery.clear();
        this.redeliveryInFlight.clear();
        this.redeliveryNormalFlushRequested = false;
        this.redeliveryReconnectFlushRequested = false;
        this.redeliveryNormalAllRequested = false;
        this.redeliveryNormalPeerRequests.clear();
        this.redeliveryReconnectPeerRequests.clear();
        this.redeliveryFlushPromise = null;
        if (this.redeliveryFlusher !== null) {
            clearInterval(this.redeliveryFlusher);
            this.redeliveryFlusher = null;
        }

        for (const entry of this.awaitingDeliveryAck.values()) clearTimeout(entry.timer);
        this.awaitingDeliveryAck.clear();
        this.ackedChunkTransfers.clear();
        this.ackSpoolQueue = [];
        this.ackSpoolActive = 0;
        this.ackSpoolQueuedIds.clear();
        this.ackSpoolInFlightIds.clear();
        for (const timer of this.durableAckRetryTimers.values()) clearTimeout(timer);
        this.durableAckRetryTimers.clear();
        if (this.durableAckReconcileTimer) clearTimeout(this.durableAckReconcileTimer);
        this.durableAckReconcileTimer = null;
        this.durableAckReconcileAttempts = 0;
        this.durableAckEntries.clear();
        this.durableAckPersistenceTail = Promise.resolve();

        for (const queue of this.sendQueues.values()) {
            for (const task of queue.high) task.cancel();
            for (const task of queue.low) task.cancel();
            queue.high.length = 0;
            queue.low.length = 0;
        }
        this.sendQueues.clear();
        for (const waiter of this.sendPermitWaiters.splice(0)) waiter.resolve(null);
        this.totalSendTasks = 0;
        this.activeSendTasks = 0;

        for (const waiter of this.blindAckWaiters.values()) {
            waiter({ acked: false, error: 'account-transition' });
        }
        this.blindAckWaiters.clear();
        try {
            websocketClient.unregisterMessageHandler(SignalType.BLIND_ROUTE_ACK, this.blindAckHandler);
        } catch { }
        this.blindAckHandlerRegistered = false;
    }
}

export const unifiedSignalTransport = new UnifiedSignalTransport();
