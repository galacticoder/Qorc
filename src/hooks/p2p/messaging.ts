import { RefObject } from "react";
import { SecureP2PService } from "../../lib/transport/secure-p2p-service";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { SecurityAuditLogger } from "../../lib/cryptography/audit-logger";
import { EventType } from "../../lib/types/event-types";
import { SignalType } from "../../lib/types/signal-types";
import type {
  P2PMessage,
  P2PSendResult,
  EncryptedMessage,
  HybridKeys,
  RemoteHybridKeys,
  PeerCertificateBundle,
  RouteProofRecord,
  QueuedItem,
} from "../../lib/types/p2p-types";
import {
  createP2PError,
  buildRouteProof,
  verifyRouteProof,
  getChannelId,
  generateMessageId,
  generateRandomBase64
} from "../../lib/utils/p2p-utils";
import { P2P_ROUTE_PROOF_TTL_MS, MAX_MESSAGE_CONTENT_LENGTH, MAX_USERNAME_LENGTH, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_MESSAGES, MAX_P2P_INCOMING_QUEUE } from "../../lib/constants";
import { isPlainObject, hasPrototypePollutionKeys } from "../../lib/sanitizers";

// Shared refs required by the messaging helpers for queueing, rate limits, and event callbacks 
export interface MessagingRefs {
  p2pServiceRef: RefObject<SecureP2PService | null>;
  routeProofCacheRef: RefObject<Map<string, RouteProofRecord>>;
  channelSequenceRef: RefObject<Map<string, number>>;
  rateLimitRef: RefObject<Map<string, { windowStart: number; count: number }>>;
  outboundQueueRef: RefObject<Map<string, QueuedItem[]>>;
  flushTimersRef: RefObject<Map<string, ReturnType<typeof setTimeout>>>;
  messageCallbackRef: RefObject<((message: EncryptedMessage) => void) | null>;
  sentP2PReceiptsRef: RefObject<Map<string, number>>;
  processedReadReceiptsRef: RefObject<Set<string>>;
}

// Buffers outbound envelopes when a peer is temporarily unreachable
type SupportedP2PDataSignalType =
  | SignalType.CHAT
  | SignalType.TYPING
  | SignalType.TYPING_START
  | SignalType.TYPING_STOP
  | SignalType.REACTION
  | SignalType.FILE
  | SignalType.EDIT
  | SignalType.DELETE
  | SignalType.READ_RECEIPT
  | SignalType.DELIVERY_ACK
  | SignalType.SIGNAL
  | SignalType.CALL_SIGNAL;

const SUPPORTED_P2P_DATA_SIGNAL_TYPES: SupportedP2PDataSignalType[] = [
  SignalType.CHAT,
  SignalType.TYPING,
  SignalType.TYPING_START,
  SignalType.TYPING_STOP,
  SignalType.REACTION,
  SignalType.FILE,
  SignalType.EDIT,
  SignalType.DELETE,
  SignalType.READ_RECEIPT,
  SignalType.DELIVERY_ACK,
  SignalType.SIGNAL,
  SignalType.CALL_SIGNAL,
];

function isSupportedP2PDataType(type: P2PMessage['type']): type is SupportedP2PDataSignalType {
  return SUPPORTED_P2P_DATA_SIGNAL_TYPES.includes(type as SupportedP2PDataSignalType);
}

export function createEnqueueOutbound(refs: MessagingRefs) {
  return (to: string, envelope: any, type: SignalType.TEXT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE, ttlMs: number) => {
    const now = Date.now();
    const arr = refs.outboundQueueRef.current.get(to) || [];
    const pruned = arr.filter(it => (now - it.enqueuedAt) < it.ttlMs).slice(-MAX_P2P_INCOMING_QUEUE);
    pruned.push({ to, envelope, type, enqueuedAt: now, ttlMs });
    refs.outboundQueueRef.current.set(to, pruned);
  };
}

// Attempts to deliver any buffered outbound envelopes once a peer reconnects
export function createFlushPeerQueue(
  refs: MessagingRefs,
  flushPeerQueueRef: RefObject<(peer: string) => void>
) {
  const flushPeerQueue = (peer: string) => {
    const service = refs.p2pServiceRef.current;
    if (!service) return;
    const connectedPeers = service.getConnectedPeers();
    if (!connectedPeers.includes(peer)) return;
    const arr = refs.outboundQueueRef.current.get(peer) || [];
    if (arr.length === 0) return;
    const now = Date.now();
    const remaining: QueuedItem[] = [];
    for (const item of arr) {
      if (now - item.enqueuedAt >= item.ttlMs) {
        try { item.envelope = null; } catch { }
        continue;
      }
      try {
        service.sendMessage(peer, item.envelope, item.type === SignalType.TEXT ? SignalType.CHAT : item.type);
        try { item.envelope = null; } catch { }
      } catch {
        remaining.push(item);
      }
    }
    if (remaining.length > 0) {
      refs.outboundQueueRef.current.set(peer, remaining);
      const t = setTimeout(() => {
        refs.flushTimersRef.current.delete(peer);
        flushPeerQueueRef.current(peer);
      }, 1000);
      refs.flushTimersRef.current.set(peer, t);
    } else {
      refs.outboundQueueRef.current.delete(peer);
    }
  };
  return flushPeerQueue;
}

/**
 * Sends encrypted P2P payloads with per-peer rate limiting and peer key validation.
 */
export function createSendP2PMessage(
  refs: MessagingRefs,
  hybridKeys: HybridKeys | null,
  deriveConversationKey: (peer: string) => string | null,
  ensurePeerAuthenticated: (peer: string, envelope?: any) => Promise<boolean>,
  getPeerCertificate: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>,
  enqueueOutbound: (to: string, envelope: any, type: SignalType.TEXT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE, ttlMs: number) => void,
  connectToPeer: (peer: string) => Promise<void>,
  setLastError: (error: unknown) => void
) {
  return async (
    to: string,
    content: any,
    remoteHybridKeys?: RemoteHybridKeys,
    options?: {
      messageType?: SignalType.TEXT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE | SignalType.EDIT | SignalType.DELETE | SignalType.READ_RECEIPT | SignalType.DELIVERY_ACK | SignalType.SIGNAL;
      metadata?: any;
    }
  ): Promise<P2PSendResult> => {
    if (!refs.p2pServiceRef.current) {
      throw createP2PError('SERVICE_UNINITIALIZED');
    }
    if (!hybridKeys?.dilithium?.secretKey || !hybridKeys?.dilithium?.publicKeyBase64) {
      throw createP2PError('LOCAL_KEYS_MISSING');
    }

    if (!to || typeof to !== 'string' || to.length === 0 || to.length > MAX_USERNAME_LENGTH) {
      throw createP2PError('INVALID_RECIPIENT');
    }

    const isTyping = options?.messageType === SignalType.TYPING || options?.messageType === SignalType.TYPING_START || options?.messageType === SignalType.TYPING_STOP;
    const isReaction = options?.messageType === SignalType.REACTION;
    const isReceipt = options?.messageType === SignalType.READ_RECEIPT || options?.messageType === SignalType.DELIVERY_ACK;
    const isSignal = options?.messageType === SignalType.SIGNAL;
    const allowEmptyContent = isTyping || isReaction || isReceipt || isSignal || (options?.metadata?.targetMessageId && typeof options.metadata.targetMessageId === 'string');

    if (!allowEmptyContent && (!content || (typeof content !== 'string' && typeof content !== 'object') || (typeof content === 'string' && content.length === 0) || (typeof content === 'string' && content.length > MAX_MESSAGE_CONTENT_LENGTH))) {
      throw createP2PError('INVALID_CONTENT');
    }

    if (content.length > MAX_MESSAGE_CONTENT_LENGTH) {
      throw createP2PError('INVALID_CONTENT');
    }

    let effectiveRemoteKeys: RemoteHybridKeys | null = remoteHybridKeys ?? null;
    if (!effectiveRemoteKeys?.kyberPublicBase64 || !effectiveRemoteKeys?.dilithiumPublicBase64) {
      const peerCert = await getPeerCertificate(to);
      if (peerCert?.kyberPublicKey && peerCert?.dilithiumPublicKey) {
        effectiveRemoteKeys = {
          kyberPublicBase64: peerCert.kyberPublicKey,
          dilithiumPublicBase64: peerCert.dilithiumPublicKey,
          x25519PublicBase64: peerCert.x25519PublicKey,
        };
      }
    }
    if (!effectiveRemoteKeys?.kyberPublicBase64) {
      throw createP2PError('MISSING_REMOTE_KYBER_KEY');
    }
    if (!effectiveRemoteKeys.dilithiumPublicBase64) {
      throw createP2PError('MISSING_REMOTE_DILITHIUM_KEY');
    }

    if (!isTyping) {
      const now = Date.now();
      const bucket = refs.rateLimitRef.current.get(to) ?? { windowStart: now, count: 0 };
      if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      refs.rateLimitRef.current.set(to, bucket);
      if (bucket.count > RATE_LIMIT_MAX_MESSAGES) {
        throw createP2PError('RATE_LIMIT_EXCEEDED');
      }
    }

    const conversationKey = deriveConversationKey(to);
    if (!conversationKey) throw createP2PError('CONVERSATION_KEY_MISSING');

    await ensurePeerAuthenticated(to);

    const peerCert = await getPeerCertificate(to);
    if (!peerCert?.dilithiumPublicKey) {
      throw createP2PError('PEER_CERT_MISSING');
    }

    let routeProofRecord = refs.routeProofCacheRef.current.get(conversationKey);
    if (!routeProofRecord || routeProofRecord.expiresAt <= Date.now()) {
      const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, peerCert.dilithiumPublicKey);
      const sequence = (refs.channelSequenceRef.current.get(conversationKey) ?? 0) + 1;
      const routeProof = await buildRouteProof(
        hybridKeys.dilithium.secretKey,
        hybridKeys.dilithium.publicKeyBase64,
        peerCert.dilithiumPublicKey,
        channelId,
        sequence,
      );
      routeProofRecord = {
        proof: routeProof,
        expiresAt: Date.now() + P2P_ROUTE_PROOF_TTL_MS,
      };
      refs.routeProofCacheRef.current.set(conversationKey, routeProofRecord);
      refs.channelSequenceRef.current.set(conversationKey, sequence);
    }

    const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, peerCert.dilithiumPublicKey);
    const messageId = await generateMessageId(channelId, refs.channelSequenceRef.current.get(conversationKey) ?? 0);

    try {
      const messageObj = {
        id: messageId,
        content,
        timestamp: Date.now(),
        from: hybridKeys.dilithium.publicKeyBase64,
        to,
        routeProof: routeProofRecord.proof,
        messageType: options?.messageType || SignalType.TEXT,
        metadata: options?.metadata,
      };

      const encryptedEnvelope = await CryptoUtils.Hybrid.encryptForClient(messageObj, effectiveRemoteKeys, {
        to: peerCert.dilithiumPublicKey,
        from: hybridKeys.dilithium.publicKeyBase64,
        type: `p2p-${options?.messageType || SignalType.MESSAGE}`,
        senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
        senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
        timestamp: Date.now(),
        extras: {
          routeProof: routeProofRecord.proof,
          messageType: options?.messageType || SignalType.TEXT,
        },
      });

      let p2pType: SignalType.CHAT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE | SignalType.READ_RECEIPT | SignalType.DELIVERY_ACK | SignalType.SIGNAL = SignalType.CHAT;
      if (options?.messageType === SignalType.TYPING) p2pType = SignalType.TYPING;
      else if (options?.messageType === SignalType.TYPING_START) p2pType = SignalType.TYPING_START;
      else if (options?.messageType === SignalType.TYPING_STOP) p2pType = SignalType.TYPING_STOP;
      else if (options?.messageType === SignalType.REACTION) p2pType = SignalType.REACTION;
      else if (options?.messageType === SignalType.FILE) p2pType = SignalType.FILE;
      else if (options?.messageType === SignalType.READ_RECEIPT) p2pType = SignalType.READ_RECEIPT;
      else if (options?.messageType === SignalType.DELIVERY_ACK) p2pType = SignalType.DELIVERY_ACK;
      else if (options?.messageType === SignalType.SIGNAL) p2pType = SignalType.SIGNAL;

      const service = refs.p2pServiceRef.current;
      if (!service) {
        return { status: 'fatal_transport', messageId, errorCode: 'SERVICE_UNAVAILABLE' };
      }

      const connectedPeers = service.getConnectedPeers() ?? [];
      const serviceConnected = connectedPeers.includes(to);
      if (!serviceConnected) {
        const ttl = isTyping ? 5000 : p2pType === SignalType.REACTION ? 30000 : p2pType === SignalType.FILE ? 180000 : 120000;
        enqueueOutbound(to, encryptedEnvelope, p2pType as any, ttl);
        connectToPeer(to).catch(() => { });
        setLastError(createP2PError('PEER_NOT_CONNECTED'));
        return { status: 'queued_not_connected', messageId };
      }

      await service.sendMessage(to, encryptedEnvelope, p2pType);
      return { status: 'sent', messageId };
    } catch (_error) {
      try { SecurityAuditLogger.log('warn', 'p2p-send-error', { to, error: String((_error as any)?.message || _error) }); } catch { }
      const errorMsg = String((_error as any)?.message || _error);
      const errorCode = (_error as any)?.code as string | undefined;

      if (errorMsg.includes('no PQ session') || errorMsg.includes('without established PQ session')) {
        try {
          const p2pType: SignalType.CHAT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE =
            (options?.messageType === SignalType.TYPING || options?.messageType === SignalType.TYPING_START || options?.messageType === SignalType.TYPING_STOP) ? (options.messageType as any)
              : options?.messageType === SignalType.REACTION ? SignalType.REACTION
                : options?.messageType === SignalType.FILE ? SignalType.FILE
                  : SignalType.CHAT;
          const ttl = isTyping ? 5000 : p2pType === SignalType.REACTION ? 30000 : p2pType === SignalType.FILE ? 180000 : 120000;
          const messageObj = {
            id: messageId,
            content,
            timestamp: Date.now(),
            from: hybridKeys.dilithium.publicKeyBase64,
            to,
            routeProof: routeProofRecord.proof,
            messageType: options?.messageType || SignalType.TEXT,
            metadata: options?.metadata,
          };
          const encryptedEnvelope = await CryptoUtils.Hybrid.encryptForClient(messageObj, effectiveRemoteKeys, {
            to: peerCert.dilithiumPublicKey,
            from: hybridKeys.dilithium.publicKeyBase64,
            type: `p2p-${options?.messageType || SignalType.MESSAGE}`,
            senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
            senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
            timestamp: Date.now(),
            extras: {
              routeProof: routeProofRecord.proof,
              messageType: options?.messageType || SignalType.TEXT,
            },
          });
          enqueueOutbound(to, encryptedEnvelope, p2pType as any, ttl);
        } catch { }
        setLastError(_error);
        return {
          status: 'queued_no_session',
          messageId,
          errorCode,
          errorMessage: errorMsg,
        };
      }

      try {
        const p2pType: SignalType.CHAT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE =
          (options?.messageType === SignalType.TYPING || options?.messageType === SignalType.TYPING_START || options?.messageType === SignalType.TYPING_STOP) ? (options.messageType as any)
            : options?.messageType === SignalType.REACTION ? SignalType.REACTION
              : options?.messageType === SignalType.FILE ? SignalType.FILE
                : SignalType.CHAT;
        const ttl = isTyping ? 5000 : p2pType === SignalType.REACTION ? 30000 : p2pType === SignalType.FILE ? 180000 : 120000;
        const messageObj = {
          id: messageId,
          content,
          timestamp: Date.now(),
          from: hybridKeys.dilithium.publicKeyBase64,
          to,
          routeProof: routeProofRecord.proof,
          messageType: options?.messageType || SignalType.TEXT,
          metadata: options?.metadata,
        };
        const encryptedEnvelope = await CryptoUtils.Hybrid.encryptForClient(messageObj, effectiveRemoteKeys, {
          to: peerCert.dilithiumPublicKey,
          from: hybridKeys.dilithium.publicKeyBase64,
          type: `p2p-${options?.messageType || SignalType.MESSAGE}`,
          senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
          senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
          timestamp: Date.now(),
          extras: {
            routeProof: routeProofRecord.proof,
            messageType: options?.messageType || SignalType.TEXT,
          },
        });
        enqueueOutbound(to, encryptedEnvelope, (isTyping ? p2pType : (options?.messageType === SignalType.REACTION ? SignalType.REACTION : SignalType.CHAT)) as any, ttl);
      } catch { }
      setLastError(_error);
      return {
        status: 'fatal_transport',
        messageId,
        errorCode,
        errorMessage: errorMsg,
      };
    }
  };
}

// Processes inbound P2P signals/messages, handles decryption, acknowledgments, and surfaces chat/typing/reaction events to the rest of the app
export function createHandleIncomingP2PMessage(
  refs: MessagingRefs,
  username: string,
  hybridKeys: HybridKeys | null,
  deriveConversationKey: (peer: string) => string | null,
  ensurePeerAuthenticated: (peer: string, envelope?: any) => Promise<boolean>,
  getPeerCertificate: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>,
  invalidatePeerCert: (peer: string) => void,
  appendIncoming: (message: EncryptedMessage) => void
) {
  return async (message: P2PMessage) => {
    try {
      if (message.type === SignalType.CALL_SIGNAL) {
        try {
          const msg: EncryptedMessage = {
            id: generateRandomBase64(16),
            from: message.from,
            to: message.to,
            content: message.payload,
            timestamp: message.timestamp,
            encrypted: false,
            p2p: true,
            messageType: SignalType.CALL_SIGNAL
          };

          if (refs.messageCallbackRef.current) {
            refs.messageCallbackRef.current(msg);
          } else {
            appendIncoming(msg);
          }
        } catch (err) {
          console.error('[messaging] Error handling CALL_SIGNAL:', err);
        }
        return;
      }

      if (message.type === SignalType.SIGNAL) {
        try {
          const payload = message.payload;
          let parsed: any = null;

          if (payload && typeof payload === 'object' && payload.kind === EventType.CALL_SIGNAL) {
            parsed = payload;
          } else if (payload && typeof payload === 'string') {
            try {
              const temp = JSON.parse(payload);
              if (temp && typeof temp === 'object' && temp.kind === EventType.CALL_SIGNAL) {
                parsed = temp;
              }
            } catch { }
          }

          if (parsed && isPlainObject(parsed) && !hasPrototypePollutionKeys(parsed) && parsed.kind === EventType.CALL_SIGNAL) {
            const callSignal = parsed.signal;
            if (isPlainObject(callSignal) && !hasPrototypePollutionKeys(callSignal)) {
              try {
                window.dispatchEvent(new CustomEvent(EventType.CALL_SIGNAL, { detail: callSignal }));
              } catch { }
              return;
            }
          }
        } catch (err) {
          console.error('[P2P] Error processing raw call signal:', err);
        }
      }


      if (message.type === SignalType.TYPING || message.type === SignalType.TYPING_START || message.type === SignalType.TYPING_STOP) {
        try {
          let actionContent: string = message.type;
          let timestamp = message.timestamp;

          if (message.payload && typeof message.payload === 'object' && message.payload.type) {
            actionContent = message.payload.type;
            if (message.payload.timestamp) timestamp = message.payload.timestamp;
          }

          window.dispatchEvent(
            new CustomEvent(EventType.TYPING_INDICATOR, {
              detail: {
                transport: 'p2p',
                from: message.from,
                content: actionContent,
                timestamp: timestamp,
              },
            }),
          );
        } catch (err) {
          console.error('[messaging] Error processing typing indicator:', err);
        }
        return;
      }

      if (!isSupportedP2PDataType(message.type)) {
        return;
      }
      if (!hybridKeys?.dilithium?.secretKey || !hybridKeys?.dilithium?.publicKeyBase64) {
        throw createP2PError('LOCAL_KEYS_MISSING');
      }
      if (!hybridKeys?.kyber?.secretKey || !hybridKeys?.x25519?.private) {
        console.error('[P2P] Local decryption keys missing');
        throw createP2PError('LOCAL_DECRYPTION_KEYS_MISSING');
      }

      let peerCert = await getPeerCertificate(message.from);
      if (!peerCert) {
        peerCert = await getPeerCertificate(message.from, true);
        if (!peerCert) {
          console.error('[P2P] Peer certificate unavailable after fetch attempt for:', message.from);
          throw createP2PError('PEER_CERT_MISSING');
        }
      }

      const routeProof = message.routeProof || message.payload?.routing?.extras?.routeProof || message.payload?.metadata?.extras?.routeProof || message.payload?.metadata?.routeProof;
      const conversationKey = deriveConversationKey(message.from);
      const minSequence = 0;

      const validationChannelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, peerCert.dilithiumPublicKey);

      let validProof = await verifyRouteProof(
        routeProof,
        hybridKeys.dilithium.publicKeyBase64,
        peerCert.dilithiumPublicKey,
        validationChannelId,
        minSequence,
      );

      let freshPeerCert = peerCert;
      if (!validProof) {
        invalidatePeerCert(message.from);
        const newCert = await getPeerCertificate(message.from, true);
        if (newCert) {
          freshPeerCert = newCert;
          const newChannelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, newCert.dilithiumPublicKey);

          validProof = await verifyRouteProof(
            routeProof,
            hybridKeys.dilithium.publicKeyBase64,
            newCert.dilithiumPublicKey,
            newChannelId,
            minSequence,
          );
        }
      }

      if (!validProof) {
        throw createP2PError('ROUTE_PROOF_INVALID');
      }

      const authenticated = await ensurePeerAuthenticated(message.from, message.payload);
      if (!authenticated) {
        throw createP2PError('PEER_AUTH_FAILED');
      }

      const decryptedEnvelope = await CryptoUtils.Hybrid.decryptIncoming(
        message.payload,
        {
          kyberSecretKey: hybridKeys.kyber.secretKey,
          x25519SecretKey: hybridKeys.x25519.private,
          senderDilithiumPublicKey: freshPeerCert.dilithiumPublicKey,
        },
        { expectJsonPayload: true },
      );

      const decryptedMessage = decryptedEnvelope.payloadJson as any;
      const routeProofPayload = routeProof;
      const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, freshPeerCert.dilithiumPublicKey);
      const proofValid = await verifyRouteProof(
        routeProofPayload,
        hybridKeys.dilithium.publicKeyBase64,
        freshPeerCert.dilithiumPublicKey,
        channelId,
        0,
      );
      if (!proofValid) {
        throw createP2PError('PAYLOAD_ROUTE_PROOF_INVALID');
      }

      const currentSequence = refs.channelSequenceRef.current.get(conversationKey ?? '') ?? 0;
      const nextSequence = Math.max(currentSequence, routeProofPayload?.payload?.sequence ?? currentSequence) + 1;
      if (conversationKey) {
        refs.channelSequenceRef.current.set(conversationKey, nextSequence);
      }

      const messageSequence = routeProofPayload?.payload?.sequence ?? currentSequence;
      const messageId = await generateMessageId(channelId, messageSequence);

      let messageType: SignalType.TEXT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE | SignalType.EDIT | SignalType.DELETE | SignalType.READ_RECEIPT | SignalType.DELIVERY_ACK | SignalType.SIGNAL = SignalType.TEXT;
      if (message.type === SignalType.REACTION) messageType = SignalType.REACTION;
      else if (message.type === SignalType.FILE) messageType = SignalType.FILE;
      else if (message.type === SignalType.READ_RECEIPT) messageType = SignalType.READ_RECEIPT;
      else if (message.type === SignalType.DELIVERY_ACK) messageType = SignalType.DELIVERY_ACK;
      else if (message.type === SignalType.SIGNAL) messageType = SignalType.SIGNAL;
      else if ((message.type as string) === SignalType.EDIT) {
        messageType = SignalType.EDIT;
      } else if ((message.type as string) === SignalType.DELETE) {
        messageType = SignalType.DELETE;
      } else if (decryptedMessage.messageType) messageType = decryptedMessage.messageType;

      const encryptedMessage: EncryptedMessage = {
        id: decryptedMessage.id || messageId,
        from: message.from,
        to: message.to,
        content: decryptedMessage.content,
        timestamp: decryptedMessage.timestamp || message.timestamp,
        encrypted: true,
        p2p: true,
        transport: 'p2p',
        routeProof: routeProofPayload?.signature,
        messageType,
        metadata: decryptedMessage.metadata,
      };


      if (messageType === SignalType.READ_RECEIPT) {
        if (decryptedMessage?.messageId) {
          const id = String(decryptedMessage.messageId);
          if (refs.processedReadReceiptsRef.current.has(id)) return;
          refs.processedReadReceiptsRef.current.add(id);
          window.dispatchEvent(new CustomEvent(EventType.MESSAGE_READ, {
            detail: { messageId: id, from: message.from }
          }));
        }
        return;
      }

      if (messageType === SignalType.DELIVERY_ACK) {
        if (decryptedMessage?.messageId) {
          window.dispatchEvent(new CustomEvent(EventType.MESSAGE_DELIVERED, {
            detail: { messageId: decryptedMessage.messageId, from: message.from }
          }));
        }
        return;
      }

      if (messageType === SignalType.SIGNAL) {
        const payload = decryptedMessage;
        if (payload?.type === 'profile-picture-request' || payload?.type === 'profile-picture-response') {
          if (refs.messageCallbackRef.current) {
            refs.messageCallbackRef.current({
              id: 'signal-' + Date.now(),
              from: message.from,
              to: message.to,
              content: payload,
              timestamp: Date.now(),
              encrypted: true,
              p2p: true,
              transport: 'p2p',
              messageType: SignalType.SIGNAL,
            });
          }
          return;
        }
      }

      if (refs.messageCallbackRef.current) {
        refs.messageCallbackRef.current(encryptedMessage);
      } else {
        appendIncoming(encryptedMessage);
      }

      if (message.type === SignalType.CHAT || message.type === SignalType.FILE) {
        try {
          const ackPayload = {
            messageId: encryptedMessage.id,
            timestamp: Date.now(),
          };

          const encryptedAck = await CryptoUtils.Hybrid.encryptForClient(
            ackPayload,
            {
              kyberPublicBase64: freshPeerCert.kyberPublicKey,
              dilithiumPublicBase64: freshPeerCert.dilithiumPublicKey,
              x25519PublicBase64: freshPeerCert.x25519PublicKey,
            },
            {
              to: peerCert.dilithiumPublicKey,
              from: hybridKeys.dilithium.publicKeyBase64,
              type: SignalType.DELIVERY_ACK,
              senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
              senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
              timestamp: Date.now(),
            },
          );

          await refs.p2pServiceRef.current?.sendMessage(message.from, encryptedAck, SignalType.DELIVERY_ACK);
        } catch { }
      }
    } catch (_error) {
      console.error('[P2P-Messaging] handleIncomingP2PMessage - ERROR', { from: (message as any)?.from, type: (message as any)?.type, error: _error instanceof Error ? _error.message : String(_error) });
      try {
        SecurityAuditLogger.log(SignalType.ERROR, 'p2p-incoming-error', {
          from: (message as any)?.from || null,
          type: (message as any)?.type || null,
          error: _error instanceof Error ? _error.message : String(_error),
        });
      } catch { }
    }
  }
}
