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
      return;
    }

    const handler = refs.handleEncryptedMessagePayloadRef.current;
    if (!handler) return;

    const payload = message.payload ?? message;
    if (payload && typeof payload === 'object') {
      (payload as any).__transport = 'p2p';
      if (!(payload as any).from && message.from) {
        (payload as any).from = message.from;
      }
      if (!(payload as any).to && message.to) {
        (payload as any).to = message.to;
      }
    }

    await handler(payload);
  };
}
