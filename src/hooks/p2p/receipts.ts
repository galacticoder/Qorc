import { RefObject } from "react";
import { SecureP2PService } from "../../lib/transport/secure-p2p-service";
import type { HybridKeys, PeerCertificateBundle } from "../../lib/types/p2p-types";
import { RECEIPT_RETENTION_MS } from "../../lib/constants";
import { SignalType } from "../../lib/types/signal-types";

export interface ReceiptRefs {
  p2pServiceRef: RefObject<SecureP2PService | null>;
  sentP2PReceiptsRef: RefObject<Map<string, number>>;
}

// Constructs read receipt sender
export function createSendP2PReadReceipt(
  refs: ReceiptRefs,
  hybridKeys: HybridKeys | null,
  isPeerConnected: (peer: string) => boolean,
  getPeerCertificate: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>
) {
  return async (messageId: string, recipient: string): Promise<void> => {
    if (!refs.p2pServiceRef.current) return;
    if (!isPeerConnected(recipient)) return;
    if (!hybridKeys?.dilithium?.secretKey || !hybridKeys?.dilithium?.publicKeyBase64) return;

    try {
      const last = refs.sentP2PReceiptsRef.current.get(messageId);
      if (last && (Date.now() - last) < RECEIPT_RETENTION_MS) return;
    } catch { }

    try {
      const readReceiptPayload = {
        messageId,
        timestamp: Date.now(),
      };

      await refs.p2pServiceRef.current.sendMessage(recipient, readReceiptPayload, SignalType.READ_RECEIPT);
      try { refs.sentP2PReceiptsRef.current.set(messageId, Date.now()); } catch { }
    } catch { }
  };
}
