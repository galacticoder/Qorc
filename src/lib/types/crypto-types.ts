/**
 * Crypto Type Definitions
 */

import { SignalType } from './signal-types';

export type NormalizedPayloadType = 'binary' | SignalType.TEXT | 'json';

export interface NormalizedPayload {
  bytes: Uint8Array;
  type: NormalizedPayloadType;
}

export interface RoutingHeader {
  to: string;
  from: string;
  type: string;
  timestamp: number;
  size: number;
}

export interface RoutingHeaderInput {
  to: string;
  from: string;
  type: string;
  timestamp: number;
}

export interface RoutingHeaderBuildInput extends RoutingHeaderInput {
  size: number;
}

export interface HybridOuterLayer {
  salt: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  mac: string;
}

export interface InnerEnvelope {
  version: string;
  salt: string;
  ephemeralX25519: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  mac: string;
  payloadType: NormalizedPayloadType;
  metadata?: {
    contentLength: number;
  };
}

export interface HybridEnvelope {
  version: string;
  routing: RoutingHeader;
  routingSignature: { algorithm: 'ML-DSA-87'; signature: string };
  algorithms: { outer: string; inner: string; aead: string; mac: string };
  kemCiphertext: string;
  outer: HybridOuterLayer;
}

export interface HybridRecipientKeys {
  kyberPublicBase64: string;
  x25519PublicBase64: string;
  dilithiumPublicBase64: string;
}

export interface ClientRoutingParams extends RoutingHeaderInput {
  senderDilithiumPublicKey: Uint8Array | string;
  signRoutingHeader: (canonicalHeader: Uint8Array) => Promise<string>;
}

export interface EnvelopeDecryptKeys {
  senderDilithiumPublicKey: Uint8Array | string;
}

export interface HybridDecryptionResult {
  routing: RoutingHeader;
  payload: Uint8Array;
  payloadText?: string;
  payloadJson?: unknown;
  senderDilithiumPublicKey: string;
}

export interface DecryptOptions {
  expectJsonPayload?: boolean;
}

export type WorkerRequestType =
  | 'kem.generateKeyPair'
  | 'kem.encapsulate'
  | 'kem.decapsulate'
  | 'sig.generateKeyPair'
  | 'sig.sign'
  | 'sig.verify'
  | 'pp.generateTokenBatch'
  | 'pp.unblindTokens'
  | 'opaque.startRegistration'
  | 'opaque.finishRegistration'
  | 'opaque.startLogin'
  | 'opaque.finishLogin'
  | 'argon2.hash'
  | 'argon2.verify'
  | 'aead.encrypt'
  | 'aead.decrypt';

export interface WorkerRequestMessage {
  id: string;
  type: WorkerRequestType;
  auth: string;
  params?: unknown;
  message?: Uint8Array;
  secretKey?: Uint8Array;
  publicKey?: Uint8Array;
  ciphertext?: Uint8Array;
  signature?: Uint8Array;
  count?: number;
  purpose?: string;
  tokenSecrets?: any[];
  signedBlindedTokens?: Uint8Array[];
  proof?: Uint8Array;
  serverPublicKey?: Uint8Array;
  passwordBytes?: Uint8Array;
  blindingFactor?: Uint8Array;
  serverResponse?: any;
  evaluatedElement?: Uint8Array;
  serverNonce?: Uint8Array;
  authChannelBinding?: Uint8Array;
  plaintext?: Uint8Array;
  key?: Uint8Array;
  additionalData?: Uint8Array;
  explicitNonce?: Uint8Array;
  tag?: Uint8Array;
  nonce?: Uint8Array;
}

export interface Argon2HashResult {
  hash: Uint8Array;
  encoded: string;
}
