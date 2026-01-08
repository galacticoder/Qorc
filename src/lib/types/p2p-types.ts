import { SignalType } from "./signal-types";
import { SecureConnection, SecureStream } from "../transport/secure-transport";

export interface P2PMessage {
  type:
  | SignalType.CHAT
  | SignalType.SIGNAL
  | 'heartbeat'
  | 'dummy'
  | SignalType.TYPING
  | SignalType.TYPING_START
  | SignalType.TYPING_STOP
  | SignalType.REACTION
  | SignalType.FILE
  | SignalType.DELIVERY_ACK
  | SignalType.READ_RECEIPT
  | SignalType.EDIT
  | SignalType.DELETE
  | SignalType.CALL_SIGNAL;
  from: string;
  to: string;
  timestamp: number;
  payload: any;
  routeProof?: any;
  signature?: string;
}

export interface PeerSession {
  connection: SecureConnection;
  messageStream: SecureStream | null;
  lastSeen: number;
  state: 'connecting' | 'connected' | 'disconnected' | 'failed';
}

export interface EncryptedMessage {
  id: string;
  from: string;
  to: string;
  content: any;
  timestamp: number;
  encrypted: boolean;
  p2p: boolean;
  transport?: 'p2p';
  routeProof?: string;
  messageType?: SignalType.TEXT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE | SignalType.EDIT | SignalType.DELETE | SignalType.SIGNAL | SignalType.READ_RECEIPT | SignalType.DELIVERY_ACK | SignalType.CALL_SIGNAL;
  metadata?: any;
}

export interface P2PStatus {
  isInitialized: boolean;
  connectedPeers: string[];
  signalingConnected: boolean;
  lastError: string | null;
}

export type P2PSendStatus =
  | 'sent'
  | 'queued_not_connected'
  | 'queued_no_session'
  | 'fatal_validation'
  | 'fatal_keys'
  | 'fatal_transport';

export interface P2PSendResult {
  status: P2PSendStatus;
  messageId?: string;
  errorCode?: string;
  errorMessage?: string;
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
  dilithium: {
    secretKey: Uint8Array;
    publicKeyBase64: string;
  };
  kyber?: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  };
  x25519?: {
    publicKey: Uint8Array;
    private: Uint8Array;
  };
}

export interface RemoteHybridKeys {
  dilithiumPublicBase64: string;
  kyberPublicBase64: string;
  x25519PublicBase64?: string;
}

export interface RouteProof {
  payload: {
    kind: string;
    nonce: string;
    at: number;
    expiresAt: number;
    from: string;
    to: string;
    channelId: string;
    sequence: number;
  };
  signature: string;
}

export interface RouteProofRecord {
  proof: RouteProof;
  expiresAt: number;
}

export interface CertCacheEntry {
  cert: PeerCertificateBundle;
  expiresAt: number;
}

export type QueuedItem = {
  to: string;
  envelope: any;
  type: SignalType.TEXT | SignalType.TYPING | SignalType.TYPING_START | SignalType.TYPING_STOP | SignalType.REACTION | SignalType.FILE | SignalType.READ_RECEIPT | SignalType.DELIVERY_ACK | SignalType.SIGNAL | SignalType.CALL_SIGNAL;
  enqueuedAt: number;
  ttlMs: number;
};
