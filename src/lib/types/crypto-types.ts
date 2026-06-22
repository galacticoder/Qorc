/**
 * Crypto Type Definitions
 */

import { SignalType } from './signal-types';

export type NormalizedPayloadType = 'binary' | SignalType.TEXT | 'json';

export interface NormalizedPayload {
  bytes: Uint8Array;
  type: NormalizedPayloadType;
  text?: string;
  json?: unknown;
}

export interface RoutingHeader {
  to: string;
  from: string;
  type: string;
  timestamp: number;
  size: number;
  extras?: Record<string, unknown>;
}

export interface RoutingHeaderInput {
  to: string;
  from: string;
  type: string;
  timestamp?: number;
  extras?: Record<string, unknown>;
}

export interface RoutingHeaderBuildInput extends RoutingHeaderInput {
  size: number;
}

export interface HybridEnvelopeMetadata {
  sender?: { dilithiumPublicKey?: string };
  recipient?: { dilithiumPublicKey?: string };
  context?: string;
  annotations?: Record<string, unknown>;
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
  metadata?: HybridEnvelopeMetadata;
}

export interface HybridRecipientKeys {
  kyberPublicBase64: string;
  x25519PublicBase64?: string;
  dilithiumPublicBase64?: string;
}

export interface ClientRoutingParams extends RoutingHeaderInput {
  senderDilithiumSecretKey: Uint8Array | string;
  senderDilithiumPublicKey?: Uint8Array | string;
  extras?: Record<string, unknown>;
  context?: string;
}

export interface HybridEncryptOptions {
  metadata?: HybridEnvelopeMetadata;
  includeSharedSecretInInner?: boolean;
  senderDilithiumSecretKey?: Uint8Array | string;
  senderDilithiumPublicKey?: Uint8Array | string;
}

export interface EnvelopeDecryptKeys {
  kyberSecretKey: Uint8Array | string;
  x25519SecretKey: Uint8Array | string;
  senderDilithiumPublicKey: Uint8Array | string;
}

export interface HybridDecryptionResult {
  routing: RoutingHeader;
  payload: Uint8Array;
  payloadText?: string;
  payloadJson?: unknown;
  metadata?: HybridEnvelopeMetadata;
  senderDilithiumPublicKey?: string;
}

export interface DecryptOptions {
  expectJsonPayload?: boolean;
}

export interface EncryptedMessagePayload {
  version: number;
  kemCiphertext: Uint8Array;
  aeadCiphertext: Uint8Array;
  aeadNonce: Uint8Array;
  aeadTag: Uint8Array;
  timestamp: number;
}

export type WorkerRequestType =
  | 'kem.generateKeyPair'
  | 'kem.destroyKey'
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
  | 'opaque.startOTLogin'
  | 'opaque.finishOTLogin'
  | 'argon2.hash'
  | 'argon2.verify'
  | 'aead.encrypt'
  | 'aead.decrypt';

export interface WorkerRequestMessage {
  id: string;
  type: WorkerRequestType;
  auth: string;
  keyId?: string;
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
  clientSecretKey?: Uint8Array;
  serverResponse?: any;
  shardSize?: number;
  myIndex?: number;
  myPrivKey?: Uint8Array;
  otRecords?: { ct: Uint8Array; masked: Uint8Array }[];
  evaluatedElement?: Uint8Array;
  serverNonce?: Uint8Array;
  plaintext?: Uint8Array;
  key?: Uint8Array;
  additionalData?: Uint8Array;
  explicitNonce?: Uint8Array;
  tag?: Uint8Array;
  nonce?: Uint8Array;
}

export interface SessionRecord {
  keys: unknown;
  created: number;
  lastUsed: number;
}

export interface KemKeyPairResult {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  keyId: string;
}

export interface Argon2HashResult {
  hash: Uint8Array;
  encoded: string;
}

export interface Argon2HashParams {
  pass: string;
  salt: Uint8Array;
  time: number;
  mem: number;
  parallelism: number;
  type: number;
  version: number;
  hashLen: number;
}

export interface Argon2VerifyParams {
  pass: string;
  encoded: string;
}
