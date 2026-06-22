import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import type { P2PMessage } from "../../lib/types/p2p-types";

export interface MessagingRefs {
  handleEncryptedMessagePayloadRef: RefObject<((message: any) => Promise<void>) | null>;
}

// Forward sealed-envelope P2P traffic into encrypted message handler
export function createHandleIncomingP2PMessage(refs: MessagingRefs) {
  return async (message: P2PMessage) => {
    if (message.type !== SignalType.SEALED_ENVELOPE) {
      console.warn('[MSG-RECV] createHandleIncomingP2PMessage DROP: not sealed', { type: message.type });
      return;
    }

    const handler = refs.handleEncryptedMessagePayloadRef.current;
    if (!handler) {
      console.warn('[MSG-RECV] DROP: handleEncryptedMessagePayload not set');
      return;
    }

    const payload = message.payload ?? message;
    if (payload && typeof payload === 'object') {
      (payload as any).__transport = 'p2p';
      // Carry the transport verified sender identity
      const verifiedSender = (message as any).__p2pVerifiedSender;
      if (verifiedSender && typeof verifiedSender === 'object') {
        (payload as any).__p2pVerifiedSender = verifiedSender;
      }
    }

    console.log('[MSG-RECV] -> handleEncryptedMessagePayload (libsignal decrypt)', {
      from: String((message as any)?.from).slice(0, 24),
      payloadKeys: payload && typeof payload === 'object' ? Object.keys(payload).slice(0, 10) : typeof payload
    });
    await handler(payload);
  };
}
