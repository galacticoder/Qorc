import { RefObject } from "react";
import { RECEIPT_RETENTION_MS } from "../../lib/constants";
import { SignalType } from "../../lib/types/signal-types";
import { unifiedSignalTransport } from "../../lib/transport/unified-signal-transport";

export interface ReceiptRefs {
  sentP2PReceiptsRef: RefObject<Map<string, number>>;
}

// Constructs read receipt sender
export function createSendP2PReadReceipt(
  refs: ReceiptRefs,
  isPeerConnected: (peer: string) => boolean
) {
  return async (messageId: string, recipient: string): Promise<void> => {
    if (!isPeerConnected(recipient)) return;

    try {
      const last = refs.sentP2PReceiptsRef.current.get(messageId);
      if (last && (Date.now() - last) < RECEIPT_RETENTION_MS) return;
    } catch { }

    try {
      const readReceiptPayload = {
        messageId,
        timestamp: Date.now(),
      };

      await unifiedSignalTransport.send(recipient, readReceiptPayload, SignalType.READ_RECEIPT);
      try { refs.sentP2PReceiptsRef.current.set(messageId, Date.now()); } catch { }
    } catch { }
  };
}
