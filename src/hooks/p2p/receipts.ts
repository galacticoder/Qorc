import { RefObject } from "react";
import { WebRTCP2PService } from "../../lib/webrtc-p2p";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import type { HybridKeys, PeerCertificateBundle } from "../../lib/types/p2p-types";
import { RECEIPT_RETENTION_MS } from "../../lib/constants";
import { SignalType } from "../../lib/types/signal-types";

export interface ReceiptRefs {
  p2pServiceRef: RefObject<WebRTCP2PService | null>;
  sentP2PReceiptsRef: RefObject<Map<string, number>>;
}

// Constructs a read receipt sender that encrypts acknowledgements with the recipient's keys
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
      const peerCert = await getPeerCertificate(recipient);
      if (!peerCert) {
        return;
      }

      const readReceiptPayload = {
        messageId,
        timestamp: Date.now(),
      };

      const encryptedReceipt = await CryptoUtils.Hybrid.encryptForClient(
        readReceiptPayload,
        {
          kyberPublicBase64: peerCert.kyberPublicKey,
          dilithiumPublicBase64: peerCert.dilithiumPublicKey,
          x25519PublicBase64: peerCert.x25519PublicKey,
        },
        {
          to: peerCert.dilithiumPublicKey,
          from: hybridKeys.dilithium.publicKeyBase64,
          type: SignalType.READ_RECEIPT,
          senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
          senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
          timestamp: Date.now(),
        },
      );

      await refs.p2pServiceRef.current.sendMessage(recipient, encryptedReceipt, SignalType.READ_RECEIPT);
      try { refs.sentP2PReceiptsRef.current.set(messageId, Date.now()); } catch { }
    } catch { }
  };
}
