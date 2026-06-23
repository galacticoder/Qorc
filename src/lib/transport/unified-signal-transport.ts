import { SignalType } from '../types/signal-types';
import websocketClient from '../websocket/websocket';
import { p2pTransport } from './p2p-transport';
import { getBlindRoutingClient } from './blind-routing-client';
import { PostQuantumUtils } from '../utils/pq-utils';
import { EventType } from '../types/event-types';
import {
    deriveMailboxMetadataId,
    deriveRendezvousRouteId,
    isRendezvousRouteId
} from './rendezvous-routing';

const INBOX_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/i;
const FORCE_DISCOVERY_REFRESH_COOLDOWN_MS = 10_000;
const REDELIVER_MAX_AGE_MS = 30 * 60 * 1000;
const REDELIVER_FLUSH_INTERVAL_MS = 3000;
const REDELIVER_MAX_PENDING = 400;
const DELIVERY_ACK_TIMEOUT_MS = 5000;
const MAX_AWAITING_ACK = 500;

const MAX_QUEUED_SENDS_PER_PEER = 100;
const MAX_QUEUED_PRIORITY_SENDS = 256;
const MAX_CONCURRENT_ACK_SPOOLS = 4;

// Unified Signal Transport
class UnifiedSignalTransport {
    private encryptionProvider: ((to: string, payload: any, type: SignalType, options?: { forceDiscoveryRefresh?: boolean }) => Promise<any>) | null = null;
    private p2pSender: ((to: string, payload: any, type: SignalType) => Promise<void>) | null = null;
    private forceRefreshCooldownUntil: Map<string, number> = new Map();
    private forceRefreshInFlight: Map<string, Promise<any | null>> = new Map();
    private pendingRedelivery: Map<string, { to: string; envelope: any; firstAt: number; reconnectOnly?: boolean }> = new Map();
    private redeliveryFlusher: ReturnType<typeof setInterval> | null = null;
    private redeliveryPeerListenerBound = false;
    private awaitingDeliveryAck: Map<string, { envelopeToSend: any; timer: ReturnType<typeof setTimeout> }> = new Map();
    private sendQueues: Map<string, { running: boolean; high: Array<() => Promise<void>>; low: Array<() => Promise<void>> }> = new Map();
    private ackSpoolQueue: any[] = [];
    private ackSpoolActive = 0;

    // Register a provider that encrypts payloads
    setEncryptionProvider(provider: (to: string, payload: any, type: SignalType, options?: { forceDiscoveryRefresh?: boolean }) => Promise<any>): void {
        this.encryptionProvider = provider;
    }

    // Register a sender that can sign and send P2P messages with route proofs
    setP2PSender(sender: (to: string, payload: any, type: SignalType) => Promise<void>): void {
        this.p2pSender = sender;
    }

    // latency critical types that jump ahead of queued text/files in per peer queue
    private static readonly PRIORITY_SEND_TYPES: ReadonlySet<SignalType> = new Set([
        SignalType.DELIVERY_RECEIPT, SignalType.READ_RECEIPT, SignalType.RECEIPT_BATCH,
        SignalType.DELIVERY_ACK, SignalType.TYPING_START, SignalType.TYPING_STOP
    ]);

    // Send signal to a peer
    async send(
        to: string,
        payload: any,
        type: SignalType,
        options?: { recipientInboxId?: string; destinationRouteId?: string; destinationMailboxLookupId?: string }
    ): Promise<{ success: boolean; transport: 'p2p' | 'server'; error?: string }> {
        if (to === 'SERVER') {
            return this.performSend(to, payload, type, options);
        }
        const key = String(to);
        let q = this.sendQueues.get(key);
        if (!q) { q = { running: false, high: [], low: [] }; this.sendQueues.set(key, q); }

        // refuse to grow the per peer queue without bound
        const isPriority = UnifiedSignalTransport.PRIORITY_SEND_TYPES.has(type);
        const depth = isPriority ? q.high.length : q.low.length;
        const cap = isPriority ? MAX_QUEUED_PRIORITY_SENDS : MAX_QUEUED_SENDS_PER_PEER;
        if (depth >= cap) {
            console.warn('[MSG-SEND] per-peer send queue saturated, applying backpressure', {
                to: key.slice(0, 24), type, depth, cap
            });
            return { success: false, transport: 'server', error: 'send-queue-saturated' };
        }

        const result = new Promise<{ success: boolean; transport: 'p2p' | 'server'; error?: string }>((resolve) => {
            const task = () => this.performSend(to, payload, type, options).then(
                resolve,
                (err) => resolve({ success: false, transport: 'server', error: err?.message || String(err) })
            );
            if (isPriority) q!.high.push(task);
            else q!.low.push(task);
        });
        this.drainSendQueue(key);
        return result;
    }

    private drainSendQueue(key: string): void {
        const q = this.sendQueues.get(key);
        if (!q || q.running) return;
        const next = q.high.shift() || q.low.shift();
        if (!next) { this.sendQueues.delete(key); return; }
        q.running = true;
        void next().finally(() => {
            q.running = false;
            this.drainSendQueue(key);
        });
    }

    private async performSend(
        to: string,
        payload: any,
        type: SignalType,
        options?: { recipientInboxId?: string; destinationRouteId?: string; destinationMailboxLookupId?: string }
    ): Promise<{ success: boolean; transport: 'p2p' | 'server'; error?: string }> {
        if (typeof window !== 'undefined' && to && to !== 'SERVER') {
            try {
                window.dispatchEvent(new CustomEvent('peer-interaction', { detail: { peer: to, outgoing: true, type } }));
            } catch { }
        }

        // Prefer direct P2P whenever possible
        const alias = p2pTransport.resolveUsernameAlias(to);
        const isP2PConnected = p2pTransport.isConnected(to) || (!!alias && p2pTransport.isConnected(alias));

        console.log('[MSG-SEND] UnifiedTransport.send', {
            to: String(to).slice(0, 24), type, isP2PConnected,
            alias: alias ? String(alias).slice(0, 16) : null, hasP2PSender: !!this.p2pSender
        });

        // Get encrypted envelope
        if (!this.encryptionProvider) {
            console.error('[MSG-SEND] no encryption provider set');
            return { success: false, transport: 'server', error: 'Encryption provider not set' };
        }

        let forceRefreshAttempted = false;
        let forceRefreshResult: any | null = null;
        const refreshDiscoveryMaterialOnce = async (reason: string): Promise<any | null> => {
            if (!this.encryptionProvider || to === 'SERVER') return null;
            if (forceRefreshAttempted) return forceRefreshResult;
            forceRefreshAttempted = true;
            const refreshKey = to.trim().toLowerCase();

            const existingInFlight = this.forceRefreshInFlight.get(refreshKey);
            if (existingInFlight) {
                forceRefreshResult = await existingInFlight.catch(() => null);
                return forceRefreshResult;
            }

            const refreshPromise = (async (): Promise<any | null> => {
                const now = Date.now();
                const cooldownUntil = this.forceRefreshCooldownUntil.get(refreshKey) || 0;
                if (now < cooldownUntil) {
                    return null;
                }

                console.warn('[UnifiedTransport] One-shot discovery refresh retry', { reason });
                const refreshed = await this.encryptionProvider(to, payload, type, { forceDiscoveryRefresh: true }).catch(() => null);

                if (!refreshed) {
                    this.forceRefreshCooldownUntil.set(refreshKey, Date.now() + FORCE_DISCOVERY_REFRESH_COOLDOWN_MS);
                    if (this.forceRefreshCooldownUntil.size > 512) {
                        const tsNow = Date.now();
                        for (const [peer, until] of this.forceRefreshCooldownUntil.entries()) {
                            if (until <= tsNow) this.forceRefreshCooldownUntil.delete(peer);
                        }
                    }
                } else {
                    this.forceRefreshCooldownUntil.delete(refreshKey);
                }
                return refreshed;
            })();

            this.forceRefreshInFlight.set(refreshKey, refreshPromise);
            try {
                forceRefreshResult = await refreshPromise;
                return forceRefreshResult;
            } finally {
                if (this.forceRefreshInFlight.get(refreshKey) === refreshPromise) {
                    this.forceRefreshInFlight.delete(refreshKey);
                }
            }
        };

        let encryptedResult = await this.encryptionProvider(to, payload, type, { forceDiscoveryRefresh: false });
        if (!encryptedResult && to !== 'SERVER') {
            const refreshed = await refreshDiscoveryMaterialOnce('initial-encryption-failure');
            if (refreshed) {
                encryptedResult = refreshed;
            }
        } else if (encryptedResult && to !== 'SERVER') {
            this.forceRefreshCooldownUntil.delete(to.trim().toLowerCase());
        }
        if (!encryptedResult) {
            console.error('[MSG-SEND] encryption failed (no routing material)', { to: String(to).slice(0, 24) });
            return { success: false, transport: 'server', error: 'Encryption failed' };
        }
        console.log('[MSG-SEND] encrypted OK', {
            to: String(to).slice(0, 24),
            hasInboxId: !!encryptedResult.recipientInboxId,
            hasKyber: !!encryptedResult.recipientKyberPublicBase64,
            recipientKyberFp: typeof encryptedResult.recipientKyberPublicBase64 === 'string' ? encryptedResult.recipientKyberPublicBase64.slice(0, 18) : undefined,
            messageId: encryptedResult.messageId
        });

        const envelopeToSend = {
            type: SignalType.SEALED_ENVELOPE,
            recipientInboxId: encryptedResult.recipientInboxId || options?.recipientInboxId,
            destinationRouteId: encryptedResult.destinationRouteId || options?.destinationRouteId,
            destinationMailboxLookupId: encryptedResult.destinationMailboxLookupId || options?.destinationMailboxLookupId,
            messageId: encryptedResult.messageId,
            envelope: encryptedResult.encryptedPayload,
            recipientKyberPublicBase64: encryptedResult.recipientKyberPublicBase64
        };

        const refreshEnvelopeForServerFallback = async (): Promise<boolean> => {
            if (!this.encryptionProvider || to === 'SERVER') return false;
            const refreshed = await refreshDiscoveryMaterialOnce('fallback-routing-material');
            if (!refreshed) return false;
            if (refreshed.encryptedPayload) {
                envelopeToSend.envelope = refreshed.encryptedPayload;
            }
            if (refreshed.messageId) {
                envelopeToSend.messageId = refreshed.messageId;
            }
            envelopeToSend.recipientInboxId =
                refreshed.recipientInboxId ||
                envelopeToSend.recipientInboxId ||
                options?.recipientInboxId;
            envelopeToSend.destinationRouteId =
                refreshed.destinationRouteId ||
                envelopeToSend.destinationRouteId ||
                options?.destinationRouteId;
            envelopeToSend.destinationMailboxLookupId =
                refreshed.destinationMailboxLookupId ||
                envelopeToSend.destinationMailboxLookupId ||
                options?.destinationMailboxLookupId;
            envelopeToSend.recipientKyberPublicBase64 =
                refreshed.recipientKyberPublicBase64 ||
                envelopeToSend.recipientKyberPublicBase64;
            return true;
        };

        let fallbackReason: 'p2p-not-connected' | 'p2p-send-failed' | 'server-target' = isP2PConnected ? 'p2p-send-failed' : 'p2p-not-connected';

        if (this.p2pSender && to !== 'SERVER') {
            try {
                if (isP2PConnected) {
                    // Connection is up await P2P send to completion
                    try {
                        console.log('[MSG-SEND] P2P attempt', { to: String(to).slice(0, 24), mode: 'await-connected' });
                        await this.p2pSender(to, envelopeToSend, SignalType.SEALED_ENVELOPE);
                        console.log('[MSG-SEND] ✓ sent via P2P', { to: String(to).slice(0, 24) });
                        this.trackDeliveryAck(to, { ...envelopeToSend }, type);
                        return { success: true, transport: 'p2p' };
                    } catch (p2pErr: any) {
                        console.warn('[MSG-SEND] P2P send failed (connected) -> server', { to: String(to).slice(0, 24), error: p2pErr?.message || String(p2pErr) });
                        fallbackReason = 'p2p-send-failed';
                    }
                } else {
                    if (!UnifiedSignalTransport.COLD_REDELIVER_TYPES.has(type)) {
                        fallbackReason = 'p2p-not-connected';
                    } else {
                        // Not connected yet
                        try {
                            console.log('[MSG-SEND] P2P attempt', { to: String(to).slice(0, 24), mode: 'quick-not-connected', timeoutMs: 3500 });
                            await Promise.race([
                                this.p2pSender(to, envelopeToSend, SignalType.SEALED_ENVELOPE),
                                new Promise<never>((_, reject) => setTimeout(() => reject(new Error('P2P send timeout')), 3500))
                            ]);
                            console.log('[MSG-SEND] sent via P2P', { to: String(to).slice(0, 24) });
                            return { success: true, transport: 'p2p' };
                        } catch (p2pErr: any) {
                            const errorMessage = p2pErr?.message || String(p2pErr);
                            const coldStartNotReady = /not ready|not connected|no active p2p connection/i.test(errorMessage);
                            if (coldStartNotReady) {
                                console.log('[MSG-SEND] P2P attempt failed', { to: String(to).slice(0, 24), error: errorMessage });
                            } else {
                                console.warn('[MSG-SEND] P2P attempt failed', { to: String(to).slice(0, 24), error: errorMessage });
                            }
                            fallbackReason = 'p2p-not-connected';
                        }
                    }
                }
            } catch {
                console.warn('[UnifiedTransport] P2P send failed, falling back to server');
            }
        }

        // Fallback to Server
        try {
            if (to === 'SERVER') {
                fallbackReason = 'server-target';
                websocketClient.send(JSON.stringify({ type, ...payload }));
                return { success: true, transport: 'server' };
            }

            // Only force refresh discovery material when routing metadata is missing
            if (
                fallbackReason === 'p2p-send-failed' &&
                (!envelopeToSend.recipientInboxId || !envelopeToSend.recipientKyberPublicBase64)
            ) {
                await refreshEnvelopeForServerFallback();
            }

            if (!envelopeToSend.recipientInboxId) {
                if (INBOX_ID_REGEX.test(to)) {
                    envelopeToSend.recipientInboxId = to;
                } else {
                    try {
                        const alias = p2pTransport.resolveUsernameAlias(to);
                        if (alias && INBOX_ID_REGEX.test(alias)) {
                            envelopeToSend.recipientInboxId = alias;
                        }
                    } catch { }
                }
            }

            if (!envelopeToSend.recipientInboxId) {
                await refreshEnvelopeForServerFallback();
            }

            if (!envelopeToSend.recipientInboxId) {
                console.warn('[UnifiedTransport] Cannot route message without recipient inbox material');
                return { success: false, transport: 'server', error: 'recipientInboxId required' };
            }

            if (!isRendezvousRouteId(envelopeToSend.destinationRouteId)) {
                envelopeToSend.destinationRouteId = deriveRendezvousRouteId(envelopeToSend.recipientInboxId);
            }
            if (!isRendezvousRouteId(envelopeToSend.destinationMailboxLookupId)) {
                envelopeToSend.destinationMailboxLookupId = deriveMailboxMetadataId(envelopeToSend.recipientInboxId);
            }

            if (!envelopeToSend.recipientKyberPublicBase64) {
                await refreshEnvelopeForServerFallback();
            }

            if (!envelopeToSend.recipientKyberPublicBase64) {
                console.warn('[UnifiedTransport] Cannot blind-route without recipient Kyber key');
                return { success: false, transport: 'server', error: 'recipientKyberPublicBase64 required' };
            }

            const blindClient = getBlindRoutingClient();
            let sealedEnvelope;
            try {
                const recipientKyber = PostQuantumUtils.base64ToUint8Array(envelopeToSend.recipientKyberPublicBase64);
                sealedEnvelope = await blindClient.createSealedEnvelope(
                    envelopeToSend.recipientInboxId,
                    recipientKyber,
                    { envelope: envelopeToSend.envelope, messageId: envelopeToSend.messageId }
                );
            } catch {
                const refreshed = await refreshEnvelopeForServerFallback();
                if (!refreshed || !envelopeToSend.recipientInboxId || !envelopeToSend.recipientKyberPublicBase64) {
                    throw new Error('Failed to refresh routing material for blind-route fallback');
                }
                const recipientKyber = PostQuantumUtils.base64ToUint8Array(envelopeToSend.recipientKyberPublicBase64);
                sealedEnvelope = await blindClient.createSealedEnvelope(
                    envelopeToSend.recipientInboxId,
                    recipientKyber,
                    { envelope: envelopeToSend.envelope, messageId: envelopeToSend.messageId }
                );
            }

            console.log('[MSG-SEND] -> server blind-route (P2P fallback)', {
                to: String(to).slice(0, 24), reason: fallbackReason,
                inboxId: String(envelopeToSend.recipientInboxId).slice(0, 16)
            });
            websocketClient.send(JSON.stringify({
                type: SignalType.BLIND_ROUTE,
                sealedEnvelope
            }));

            // first message of a fresh conversation sent here over server because P2P cold dial hasnt completed yet
            if (fallbackReason === 'p2p-not-connected') {
                this.scheduleColdStartP2PRedelivery(to, { ...envelopeToSend }, type);
            }

            return { success: true, transport: 'server' };
        } catch (serverErr: any) {
            console.error('[UnifiedTransport] Critical failure sending via server', {
                type,
                hasError: !!serverErr
            });
            
            this.scheduleColdStartP2PRedelivery(to, { ...envelopeToSend }, type);
            return { success: false, transport: 'server', error: serverErr?.message || 'Server send failed' };
        }
    }

    // Send a typing indicator
    async sendTyping(to: string, payload: any, isStart: boolean): Promise<void> {
        await this.send(to, payload, isStart ? SignalType.TYPING_START : SignalType.TYPING_STOP);
    }

    // Send a read receipt
    async sendReadReceipt(to: string, payload: any): Promise<void> {
        await this.send(to, payload, SignalType.READ_RECEIPT);
    }

    // message types that are safe to redeliver over P2P after cold start server fallback
    private static readonly COLD_REDELIVER_TYPES: ReadonlySet<SignalType> = new Set([
        SignalType.TEXT, SignalType.MESSAGE, SignalType.FILE, SignalType.FILE_MESSAGE
    ]);

    // Queue server fallbacked / failed persistent message for P2P redelivery
    private scheduleColdStartP2PRedelivery(to: string, envelopeToSend: any, type: SignalType, opts?: { reconnectOnly?: boolean }): void {
        if (!this.p2pSender || to === 'SERVER') return;
        if (!UnifiedSignalTransport.COLD_REDELIVER_TYPES.has(type)) return;
        const messageId = envelopeToSend?.messageId;
        if (!messageId || typeof messageId !== 'string') return;
        if (this.pendingRedelivery.has(messageId)) return;

        if (this.pendingRedelivery.size >= REDELIVER_MAX_PENDING) {
            // Drop the oldest to bound memory.
            const oldest = this.pendingRedelivery.keys().next().value;
            if (oldest) this.pendingRedelivery.delete(oldest);
        }
        this.pendingRedelivery.set(messageId, { to, envelope: envelopeToSend, firstAt: Date.now(), reconnectOnly: !!opts?.reconnectOnly });

        // Bind the connection ready listener
        if (!this.redeliveryPeerListenerBound && typeof window !== 'undefined') {
            this.redeliveryPeerListenerBound = true;
            window.addEventListener(EventType.P2P_PEER_CONNECTED, (evt: Event) => {
                const peer = (evt as CustomEvent)?.detail?.peer;
                void this.flushRedeliveries(typeof peer === 'string' ? peer : undefined, true);
            });
        }

        if (this.redeliveryFlusher === null && typeof window !== 'undefined') {
            this.redeliveryFlusher = setInterval(() => { void this.flushRedeliveries(); }, REDELIVER_FLUSH_INTERVAL_MS);
        }

        if (!opts?.reconnectOnly) void this.flushRedeliveries(to);
    }

    private async flushRedeliveries(onlyPeer?: string, fromReconnect = false): Promise<void> {
        if (this.pendingRedelivery.size === 0) {
            if (this.redeliveryFlusher !== null) { clearInterval(this.redeliveryFlusher); this.redeliveryFlusher = null; }
            return;
        }
        const now = Date.now();
        for (const [messageId, entry] of Array.from(this.pendingRedelivery.entries())) {
            if (now - entry.firstAt > REDELIVER_MAX_AGE_MS) {
                this.pendingRedelivery.delete(messageId);
                console.warn('[MSG-SEND] P2P re-delivery gave up (max age)', { to: String(entry.to).slice(0, 24) });
                continue;
            }
            if (entry.reconnectOnly && !fromReconnect) continue;
            if (onlyPeer && entry.to !== onlyPeer) continue;
            if (!this.p2pSender) continue;
            const alias = p2pTransport.resolveUsernameAlias(entry.to);
            const connected = p2pTransport.isConnected(entry.to) || (!!alias && p2pTransport.isConnected(alias));
            if (!connected) continue; // not ready yet; a later tick or the connect event will retry
            try {
                await this.p2pSender(entry.to, entry.envelope, SignalType.SEALED_ENVELOPE);
                this.pendingRedelivery.delete(messageId);
                console.log('[MSG-SEND] P2P re-delivery', { to: String(entry.to).slice(0, 24) });
            } catch {
            }
        }
        if (this.pendingRedelivery.size === 0 && this.redeliveryFlusher !== null) {
            clearInterval(this.redeliveryFlusher); this.redeliveryFlusher = null;
        }
    }

    // Track message sent over P2P awaiting a delivery receipt
    private trackDeliveryAck(to: string, envelopeToSend: any, type: SignalType): void {
        if (!UnifiedSignalTransport.COLD_REDELIVER_TYPES.has(type)) return;
        const messageId = envelopeToSend?.messageId;
        if (!messageId || typeof messageId !== 'string') return;

        this.scheduleColdStartP2PRedelivery(to, { ...envelopeToSend }, type, { reconnectOnly: true });

        if (this.awaitingDeliveryAck.has(messageId)) return;
        if (this.awaitingDeliveryAck.size >= MAX_AWAITING_ACK) {
            const oldest = this.awaitingDeliveryAck.keys().next().value;
            if (oldest) this.markDelivered(oldest);
        }
        const timer = setTimeout(() => {
            const entry = this.awaitingDeliveryAck.get(messageId);
            if (!entry) return;
            this.awaitingDeliveryAck.delete(messageId);
            this.enqueueAckSpool(entry.envelopeToSend);
        }, DELIVERY_ACK_TIMEOUT_MS);
        this.awaitingDeliveryAck.set(messageId, { envelopeToSend, timer });
    }

    private enqueueAckSpool(envelopeToSend: any): void {
        this.ackSpoolQueue.push(envelopeToSend);
        this.pumpAckSpool();
    }

    private pumpAckSpool(): void {
        while (this.ackSpoolActive < MAX_CONCURRENT_ACK_SPOOLS && this.ackSpoolQueue.length > 0) {
            const envelopeToSend = this.ackSpoolQueue.shift();
            this.ackSpoolActive++;
            void this.spoolPersistentToServer(envelopeToSend).finally(() => {
                this.ackSpoolActive--;
                this.pumpAckSpool();
            });
        }
    }

    markDelivered(messageId: string): void {
        if (!messageId) return;
        const entry = this.awaitingDeliveryAck.get(messageId);
        if (entry) {
            try { clearTimeout(entry.timer); } catch { }
            this.awaitingDeliveryAck.delete(messageId);
        }
        this.pendingRedelivery.delete(messageId);
    }

    private async spoolPersistentToServer(envelopeToSend: any): Promise<void> {
        try {
            if (!envelopeToSend?.recipientInboxId || !envelopeToSend?.recipientKyberPublicBase64) return;
            const blindClient = getBlindRoutingClient();
            const recipientKyber = PostQuantumUtils.base64ToUint8Array(envelopeToSend.recipientKyberPublicBase64);
            const sealedEnvelope = await blindClient.createSealedEnvelope(
                envelopeToSend.recipientInboxId,
                recipientKyber,
                { envelope: envelopeToSend.envelope, messageId: envelopeToSend.messageId }
            );
            websocketClient.send(JSON.stringify({ type: SignalType.BLIND_ROUTE, sealedEnvelope }));
            console.log('[MSG-SEND] unacked P2P msg spooled to server for offline catch-up', {
                messageId: String(envelopeToSend.messageId).slice(0, 12)
            });
        } catch (e: any) {
            console.warn('[MSG-SEND] offline spool failed', { error: e?.message || String(e) });
        }
    }

    clearRefreshCooldowns(): void {
        this.forceRefreshCooldownUntil.clear();
    }
}

export const unifiedSignalTransport = new UnifiedSignalTransport();
