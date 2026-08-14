import { RefObject } from "react";
import { AUTH_USERNAME_REGEX, PQ_SIG_PUBLIC_KEY_SIZE } from "../../lib/constants";
import { SignalType } from "../../lib/types/signal-types";
import type { P2PMessage } from "../../lib/types/p2p-types";
import { MAX_MESSAGE_FRAME_SIZE } from "../../lib/transport/secure-transport";

export interface MessagingRefs {
  handleEncryptedMessagePayloadRef: RefObject<((message: any) => Promise<boolean | void>) | null>;
  accountGenerationRef: RefObject<number>;
  inFlightRetriesRef: RefObject<{ generation: number; count: number; bytes: number }>;
}

const MAX_INFLIGHT_P2P_RETRIES = 32;
const MAX_INFLIGHT_P2P_RETRY_BYTES = 16 * 1024 * 1024;
const P2P_RETRY_DELAYS_MS = [250, 750, 1500];

// Forward sealed envelope P2P traffic into encrypted message handler
export function createHandleIncomingP2PMessage(refs: MessagingRefs) {
  return async (message: P2PMessage) => {
    const generation = refs.accountGenerationRef.current;
    if (message.type !== SignalType.SEALED_ENVELOPE) {
      console.warn('[MSG-RECV] createHandleIncomingP2PMessage DROP: not sealed', { type: message.type });
      return false;
    }

    const handler = refs.handleEncryptedMessagePayloadRef.current;
    if (!handler) {
      console.warn('[MSG-RECV] DROP: handleEncryptedMessagePayload not set');
      return false;
    }

    const verifiedSender = (message as any).__p2pVerifiedSender;
    const verifiedSenderKeys = verifiedSender && typeof verifiedSender === 'object' && !Array.isArray(verifiedSender)
      ? Object.keys(verifiedSender).sort().join(',')
      : '';
    if (
      verifiedSenderKeys !== 'dilithiumBase64,username' ||
      typeof verifiedSender.username !== 'string' ||
      !AUTH_USERNAME_REGEX.test(verifiedSender.username) ||
      verifiedSender.username !== message.from ||
      typeof verifiedSender.dilithiumBase64 !== 'string' ||
      verifiedSender.dilithiumBase64.length !== 4 * Math.ceil(PQ_SIG_PUBLIC_KEY_SIZE / 3)
    ) {
      console.warn('[MSG-RECV] DROP: P2P sender identity was not transport verified');
      return false;
    }
    if (!message.payload || typeof message.payload !== 'object' || Array.isArray(message.payload)) {
      return false;
    }

    const payload = {
      ...(message.payload as Record<string, unknown>),
      __transport: 'p2p',
      __p2pVerifiedSender: Object.freeze({
        username: verifiedSender.username,
        dilithiumBase64: verifiedSender.dilithiumBase64,
      }),
    };

    const accepted = await handler(payload);
    if (generation !== refs.accountGenerationRef.current) return false;
    if (accepted !== false) return true;

    const retryState = refs.inFlightRetriesRef.current;
    if (retryState.generation !== generation) {
      retryState.generation = generation;
      retryState.count = 0;
      retryState.bytes = 0;
    }
    const verifiedWireBytes = (message as any).__p2pVerifiedWireBytes;
    const retryBytes = Number.isSafeInteger(verifiedWireBytes) && verifiedWireBytes > 0
      ? Math.min(verifiedWireBytes, MAX_MESSAGE_FRAME_SIZE)
      : MAX_MESSAGE_FRAME_SIZE;
    if (
      retryState.count >= MAX_INFLIGHT_P2P_RETRIES ||
      retryState.bytes + retryBytes > MAX_INFLIGHT_P2P_RETRY_BYTES
    ) {
      console.warn('[MSG-RECV] P2P message dropped: inbound saturated and retry budget exhausted');
      return false;
    }
    retryState.count += 1;
    retryState.bytes += retryBytes;
    try {
      for (const delay of P2P_RETRY_DELAYS_MS) {
        await new Promise((r) => setTimeout(r, delay));
        if (generation !== refs.accountGenerationRef.current) return false;
        const retryHandler = refs.handleEncryptedMessagePayloadRef.current;
        if (!retryHandler) return false;
        const retryAccepted = await retryHandler(payload);
        if (retryAccepted !== false) return true;
      }
      console.warn('[MSG-RECV] P2P message dropped: still saturated after retries');
      return false;
    } finally {
      if (retryState.generation === generation) {
        retryState.count = Math.max(0, retryState.count - 1);
        retryState.bytes = Math.max(0, retryState.bytes - retryBytes);
      }
    }
  };
}
