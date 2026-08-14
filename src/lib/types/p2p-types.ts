import { SignalType } from "./signal-types";
import { SecureConnection, SecureStream } from "../transport/secure-transport";
import type { HybridEnvelope } from "./crypto-types";
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export interface P2PMessage {
  type: SignalType.SEALED_ENVELOPE;
  from: string;
  to: string;
  timestamp: number;
  payload: {
    type: SignalType.SEALED_ENVELOPE;
    messageId: string;
    fileTransferId?: string;
    envelope: HybridEnvelope;
  };
  routeProof: {
    kind: typeof PROTOCOL_KEYS.ROUTE_PROOF_KIND;
    at: number;
    expiresAt: number;
    channelId: string;
    sequence: number;
  };
  signature: string;
}

export interface PeerSession {
  connection: SecureConnection;
  messageStream: SecureStream | null;
  lastSeen: number;
  state: 'connecting' | 'connected' | 'disconnected' | 'failed';
}

export interface P2PStatus {
  isInitialized: boolean;
  connectedPeers: string[];
}

export interface PeerCertificateBundle {
  username: string;
  dilithiumPublicKey: string;
  kyberPublicKey: string;
  x25519PublicKey: string;
  proof: string;
  issuedAt: number;
  expiresAt: number;
  signature: string;
}

export interface HybridKeys {
  native: true;
  dilithium: {
    publicKeyBase64: string;
  };
  kyber: {
    publicKey: Uint8Array;
  };
  x25519: {
    publicKey: Uint8Array;
  };
  signTranscript: (message: Uint8Array) => Promise<Uint8Array>;
  respondToHandshake: (
    kemCiphertext: Uint8Array,
    peerX25519Public: Uint8Array
  ) => Promise<{ pqSecret: Uint8Array; x25519Secret: Uint8Array }>;
}

export interface CertCacheEntry {
  cert: PeerCertificateBundle;
  expiresAt: number;
}
