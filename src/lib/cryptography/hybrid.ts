/**
 * Hybrid Encryption (ML-KEM + X25519 + Dilithium)
 */

import { blake3 as nobleBlake3 } from '@noble/hashes/blake3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { Base64, decodeCanonicalBase64 } from './base64';
import { PostQuantumKEM } from './kem';
import { PostQuantumHash } from './hash';
import { PostQuantumAEAD } from './aead';
import { PostQuantumRandom } from './random';
import { SecureMemory } from './secure-memory';
import { HashingService } from './hashing';
import {
  CERT_CLOCK_SKEW_MS,
  HYBRID_ENVELOPE_MAX_AGE_MS,
  HYBRID_ENVELOPE_MAX_OUTER_CIPHERTEXT_BYTES,
  HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES,
  PQ_AEAD_NONCE_SIZE,
  PQ_KEM_PUBLIC_KEY_SIZE,
  PQ_SIG_PUBLIC_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE
} from '../constants';
import type { DecryptOptions, RoutingHeader, NormalizedPayload, RoutingHeaderBuildInput, HybridEnvelope, HybridRecipientKeys, ClientRoutingParams, EnvelopeDecryptKeys, HybridDecryptionResult, InnerEnvelope } from '../types/crypto-types';
import { concatUint8Arrays } from '../utils/byte-utils';
import { computeX25519SharedSecret, generateX25519KeyPair } from '../utils/noise-utils';
import { SignalType } from '../types/signal-types';
import { account } from '../tauri-bindings';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { hasExactKeys, isPlainObject as isPlainRecord } from '../sanitizers';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const OUTER_SALT_BYTES = 32;
const OUTER_NONCE_BYTES = 12;
const OUTER_TAG_BYTES = 16;
const INNER_SALT_BYTES = 32;
const HYBRID_ROUTING_TYPES = new Set<string>(['libsignal-message', SignalType.FILE_MESSAGE_CHUNK]);
const HYBRID_ALGORITHMS = Object.freeze({
  outer: 'ML-KEM-1024',
  inner: 'X25519',
  aead: 'AES-256-GCM+XChaCha20-Poly1305',
  mac: 'BLAKE3-256'
});

type HybridPublicHeader = Pick<HybridEnvelope, 'version' | 'routing' | 'algorithms' | 'kemCiphertext'>;

function validateRoutingHeader(header: unknown, now = Date.now()): asserts header is RoutingHeader {
  if (!isPlainRecord(header) || !hasExactKeys(header, ['to', 'from', 'type', 'timestamp', 'size'])) {
    throw new Error('Invalid routing header shape');
  }
  if (!HYBRID_ROUTING_TYPES.has(header.type as string)) {
    throw new Error('Invalid routing type');
  }
  if (
    !Number.isSafeInteger(header.timestamp) ||
    (header.timestamp as number) > now + CERT_CLOCK_SKEW_MS ||
    (header.timestamp as number) < now - HYBRID_ENVELOPE_MAX_AGE_MS - CERT_CLOCK_SKEW_MS
  ) {
    throw new Error('Invalid routing timestamp');
  }
  if (
    !Number.isSafeInteger(header.size) ||
    (header.size as number) < 0 ||
    (header.size as number) > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES
  ) {
    throw new Error('Invalid routing payload size');
  }
  const toKey = decodeCanonicalBase64(header.to, 'routing recipient key', { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE });
  const fromKey = decodeCanonicalBase64(header.from, 'routing sender key', { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE });
  SecureMemory.zeroBuffer(toKey);
  SecureMemory.zeroBuffer(fromKey);
}

function canonicalizeRoutingHeader(header: RoutingHeader): string {
  const canonical: RoutingHeader = {
    to: header.to,
    from: header.from,
    type: header.type,
    timestamp: header.timestamp,
    size: header.size
  };
  return JSON.stringify(canonical);
}

function canonicalizePublicHeader(header: HybridPublicHeader): string {
  return JSON.stringify({
    version: header.version,
    routing: JSON.parse(canonicalizeRoutingHeader(header.routing)),
    algorithms: {
      outer: header.algorithms.outer,
      inner: header.algorithms.inner,
      aead: header.algorithms.aead,
      mac: header.algorithms.mac
    },
    kemCiphertext: header.kemCiphertext
  });
}

function computeRoutingDigest(header: HybridPublicHeader): Uint8Array {
  const bytes = textEncoder.encode(canonicalizePublicHeader(header));
  try {
    return nobleBlake3(bytes);
  } finally {
    SecureMemory.zeroBuffer(bytes);
  }
}

function checkUint8Array(input: Uint8Array | ArrayBuffer | string, label: string): Uint8Array {
  if (input instanceof Uint8Array) {
    const copy = new Uint8Array(input.length);
    copy.set(input);
    return copy;
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input.slice(0));
  }
  if (typeof input === 'string') {
    return Base64.base64ToUint8Array(input);
  }
  throw new Error(`${label} must be a Uint8Array or base64 string`);
}

function normalizePayload(payload: unknown): NormalizedPayload {
  if (payload instanceof Uint8Array) {
    if (payload.length > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) throw new Error('Hybrid payload is too large');
    return { bytes: SecureMemory.secureBufferCopy(payload), type: 'binary' };
  }
  if (payload instanceof ArrayBuffer) {
    if (payload.byteLength > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) throw new Error('Hybrid payload is too large');
    return { bytes: new Uint8Array(payload.slice(0)), type: 'binary' };
  }
  if (typeof payload === 'string') {
    const bytes = textEncoder.encode(payload);
    if (bytes.length > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) {
      SecureMemory.zeroBuffer(bytes);
      throw new Error('Hybrid payload is too large');
    }
    return { bytes, type: SignalType.TEXT };
  }
  const jsonSafe = payload ?? {};
  const text = JSON.stringify(jsonSafe);
  if (typeof text !== 'string') {
    throw new Error('Hybrid payload is not JSON serializable');
  }
  const bytes = textEncoder.encode(text);
  if (bytes.length > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) {
    SecureMemory.zeroBuffer(bytes);
    throw new Error('Hybrid payload is too large');
  }
  return { bytes, type: 'json' };
}

function buildRoutingHeader(input: RoutingHeaderBuildInput): RoutingHeader {
  if (!input.to || !input.from || !input.type) {
    throw new Error('Routing header requires to, from, and type');
  }
  if (!Number.isSafeInteger(input.size) || input.size < 0 || input.size > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) {
    throw new Error('Routing header size must be a non-negative finite number');
  }
  const header = {
    to: input.to,
    from: input.from,
    type: input.type,
    timestamp: input.timestamp,
    size: input.size
  };
  validateRoutingHeader(header);
  return header;
}

async function signPublicHeader(
  header: HybridPublicHeader,
  signer: (canonicalHeader: Uint8Array) => Promise<string>,
): Promise<string> {
  if (typeof signer !== 'function') throw new Error('Native routing signer is unavailable');
  const message = textEncoder.encode(canonicalizePublicHeader(header));
  try {
    const signatureBase64 = await signer(message);
    const signature = decodeCanonicalBase64(signatureBase64, 'routing signature', {
      exactBytes: PQ_SIG_SIGNATURE_SIZE,
    });
    signature.fill(0);
    return signatureBase64;
  } finally {
    SecureMemory.zeroBuffer(message);
  }
}

function deriveOuterKeys(sharedSecret: Uint8Array, salt: Uint8Array, routingDigest: Uint8Array) {
  const info = `${PROTOCOL_KEYS.HYBRID_OUTER_KDF_PREFIX}${Base64.arrayBufferToBase64(routingDigest)}`;
  const okm = PostQuantumHash.deriveKey(sharedSecret, salt, info, 64);
  const outerKey = new Uint8Array(32);
  const outerMacKey = new Uint8Array(32);
  outerKey.set(okm.subarray(0, 32));
  outerMacKey.set(okm.subarray(32, 64));
  SecureMemory.zeroBuffer(okm);
  return { outerKey, outerMacKey };
}

async function deriveInnerKeyMaterial(
  pqSharedSecret: Uint8Array,
  classicalSharedSecret: Uint8Array,
  salt: Uint8Array,
  routingDigest: Uint8Array
) {
  const info = `${PROTOCOL_KEYS.HYBRID_INNER_KDF_PREFIX}${Base64.arrayBufferToBase64(routingDigest)}`;
  const combined = new Uint8Array(pqSharedSecret.length + classicalSharedSecret.length);
  combined.set(pqSharedSecret, 0);
  combined.set(classicalSharedSecret, pqSharedSecret.length);
  let okm: Uint8Array | null = null;
  try {
    okm = PostQuantumHash.deriveKey(combined, salt, info, 64);
    const encKey = okm.slice(0, 32);
    const macKey = okm.slice(32, 64);
    return { encKey, macKey };
  } finally {
    if (okm) SecureMemory.zeroBuffer(okm);
    SecureMemory.zeroBuffer(combined);
  }
}

function computeClassicalSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return computeX25519SharedSecret(privateKey, publicKey);
}

async function createInnerLayer(
  payload: NormalizedPayload,
  recipientKeys: HybridRecipientKeys,
  routingDigest: Uint8Array,
  pqSharedSecret: Uint8Array
): Promise<InnerEnvelope> {
  if (!recipientKeys.x25519PublicBase64) {
    throw new Error('Recipient keys must include x25519PublicBase64 for inner layer derivation');
  }
  let recipientX25519: Uint8Array | null = null;
  let ephemeral: ReturnType<typeof generateX25519KeyPair> | null = null;
  let classicalShared: Uint8Array | null = null;
  let innerSalt: Uint8Array | null = null;
  let innerNonce: Uint8Array | null = null;
  let encKey: Uint8Array | null = null;
  let macKey: Uint8Array | null = null;
  let aad: Uint8Array | null = null;
  let ciphertext: Uint8Array | null = null;
  let tag: Uint8Array | null = null;
  let returnedNonce: Uint8Array | null = null;
  let mac: Uint8Array | null = null;
  let macInput: Uint8Array | null = null;
  try {
    recipientX25519 = decodeCanonicalBase64(
      recipientKeys.x25519PublicBase64,
      'recipient X25519 public key',
      { exactBytes: 32 }
    );
    ephemeral = generateX25519KeyPair();
    classicalShared = computeClassicalSharedSecret(ephemeral.secretKey, recipientX25519);
    innerSalt = PostQuantumRandom.randomBytes(INNER_SALT_BYTES);
    innerNonce = PostQuantumRandom.randomBytes(PQ_AEAD_NONCE_SIZE);
    ({ encKey, macKey } = await deriveInnerKeyMaterial(
      pqSharedSecret,
      classicalShared,
      innerSalt,
      routingDigest
    ));
    aad = textEncoder.encode(payload.type);
    const encrypted = await PostQuantumAEAD.encryptAsync(payload.bytes, encKey, aad, innerNonce);
    ciphertext = encrypted.ciphertext;
    tag = encrypted.tag;
    returnedNonce = encrypted.nonce;
    macInput = concatUint8Arrays(innerNonce, ciphertext, tag, routingDigest, ephemeral.publicKey, aad);
    mac = await HashingService.generateBlake3Mac(macInput, macKey);

    return {
      version: PROTOCOL_KEYS.INNER_ENVELOPE_PROTOCOL,
      salt: Base64.arrayBufferToBase64(innerSalt),
      ephemeralX25519: Base64.arrayBufferToBase64(ephemeral.publicKey),
      nonce: Base64.arrayBufferToBase64(innerNonce),
      ciphertext: Base64.arrayBufferToBase64(ciphertext),
      tag: Base64.arrayBufferToBase64(tag),
      mac: Base64.arrayBufferToBase64(mac),
      payloadType: payload.type,
      metadata: { contentLength: payload.bytes.length }
    };
  } finally {
    if (recipientX25519) SecureMemory.zeroBuffer(recipientX25519);
    if (ephemeral) {
      SecureMemory.zeroBuffer(ephemeral.secretKey);
      SecureMemory.zeroBuffer(ephemeral.publicKey);
    }
    if (classicalShared) SecureMemory.zeroBuffer(classicalShared);
    if (innerSalt) SecureMemory.zeroBuffer(innerSalt);
    if (innerNonce) SecureMemory.zeroBuffer(innerNonce);
    if (encKey) SecureMemory.zeroBuffer(encKey);
    if (macKey) SecureMemory.zeroBuffer(macKey);
    if (aad) SecureMemory.zeroBuffer(aad);
    if (ciphertext) SecureMemory.zeroBuffer(ciphertext);
    if (tag) SecureMemory.zeroBuffer(tag);
    if (returnedNonce) SecureMemory.zeroBuffer(returnedNonce);
    if (mac) SecureMemory.zeroBuffer(mac);
    if (macInput) SecureMemory.zeroBuffer(macInput);
  }
}

export class Hybrid {
  static async encryptForClient(
    payload: unknown,
    recipientKeys: HybridRecipientKeys,
    routingParams: ClientRoutingParams
  ): Promise<HybridEnvelope> {
    if (
      !recipientKeys?.kyberPublicBase64 ||
      !recipientKeys.x25519PublicBase64 ||
      !recipientKeys.dilithiumPublicBase64
    ) {
      throw new Error('Recipient ML-KEM, X25519, and ML-DSA public keys are required');
    }

    const normalizedPayload = normalizePayload(payload);
    if (normalizedPayload.bytes.length > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) {
      SecureMemory.zeroBuffer(normalizedPayload.bytes);
      throw new Error('Hybrid payload is too large');
    }

    let senderPublicKey: Uint8Array | null = null;
    let recipientSigningPublicKey: Uint8Array | null = null;
    let recipientKyber: Uint8Array | null = null;
    let kemCiphertext: Uint8Array | null = null;
    let pqSharedSecret: Uint8Array | null = null;
    let routingDigest: Uint8Array | null = null;
    let outerSalt: Uint8Array | null = null;
    let outerKey: Uint8Array | null = null;
    let outerMacKey: Uint8Array | null = null;
    let innerPayloadBytes: Uint8Array | null = null;
    let outerNonce: Uint8Array | null = null;
    let outerEncryptedWithTag: Uint8Array | null = null;
    let outerCiphertext: Uint8Array | null = null;
    let outerTag: Uint8Array | null = null;
    let outerMacInput: Uint8Array | null = null;
    let outerMac: Uint8Array | null = null;
    try {
      senderPublicKey = decodeCanonicalBase64(
        routingParams.senderDilithiumPublicKey,
        'sender ML-DSA public key',
        { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE }
      );
      if (routingParams.from !== Base64.arrayBufferToBase64(senderPublicKey)) {
        throw new Error('Routing sender does not match signing key');
      }
      recipientSigningPublicKey = decodeCanonicalBase64(
        recipientKeys.dilithiumPublicBase64,
        'recipient ML-DSA public key',
        { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE }
      );
      if (routingParams.to !== Base64.arrayBufferToBase64(recipientSigningPublicKey)) {
        throw new Error('Routing recipient does not match recipient certificate key');
      }

      const header = buildRoutingHeader({ ...routingParams, size: normalizedPayload.bytes.length });
      recipientKyber = decodeCanonicalBase64(
        recipientKeys.kyberPublicBase64,
        'recipient ML-KEM public key',
        { exactBytes: PQ_KEM_PUBLIC_KEY_SIZE }
      );
      const encapsulated = await PostQuantumKEM.encapsulate(recipientKyber);
      kemCiphertext = encapsulated.ciphertext;
      pqSharedSecret = encapsulated.sharedSecret;
      const publicHeader: HybridPublicHeader = {
        version: PROTOCOL_KEYS.HYBRID_ENVELOPE_PROTOCOL,
        routing: header,
        algorithms: { ...HYBRID_ALGORITHMS },
        kemCiphertext: Base64.arrayBufferToBase64(kemCiphertext)
      };
      routingDigest = computeRoutingDigest(publicHeader);
      const signatureBase64 = await signPublicHeader(publicHeader, routingParams.signRoutingHeader);
      const innerLayer = await createInnerLayer(normalizedPayload, recipientKeys, routingDigest, pqSharedSecret);

      outerSalt = PostQuantumRandom.randomBytes(OUTER_SALT_BYTES);
      ({ outerKey, outerMacKey } = deriveOuterKeys(pqSharedSecret, outerSalt, routingDigest));
      innerPayloadBytes = textEncoder.encode(JSON.stringify(innerLayer));
      if (innerPayloadBytes.length > HYBRID_ENVELOPE_MAX_OUTER_CIPHERTEXT_BYTES) {
        throw new Error('Hybrid inner envelope is too large');
      }
      outerNonce = PostQuantumRandom.randomBytes(OUTER_NONCE_BYTES);
      const outerCipher = gcm(outerKey, outerNonce, routingDigest);
      outerEncryptedWithTag = outerCipher.encrypt(innerPayloadBytes);

      outerCiphertext = outerEncryptedWithTag.slice(0, -OUTER_TAG_BYTES);
      outerTag = outerEncryptedWithTag.slice(-OUTER_TAG_BYTES);
      outerMacInput = concatUint8Arrays(outerNonce, outerCiphertext, outerTag, routingDigest);
      outerMac = await HashingService.generateBlake3Mac(outerMacInput, outerMacKey);

      const envelope: HybridEnvelope = {
        ...publicHeader,
        routingSignature: { algorithm: 'ML-DSA-87', signature: signatureBase64 },
        outer: {
          salt: Base64.arrayBufferToBase64(outerSalt),
          nonce: Base64.arrayBufferToBase64(outerNonce),
          ciphertext: Base64.arrayBufferToBase64(outerCiphertext),
          tag: Base64.arrayBufferToBase64(outerTag),
          mac: Base64.arrayBufferToBase64(outerMac)
        }
      };
      return envelope;
    } finally {
      if (senderPublicKey) SecureMemory.zeroBuffer(senderPublicKey);
      if (recipientSigningPublicKey) SecureMemory.zeroBuffer(recipientSigningPublicKey);
      if (recipientKyber) SecureMemory.zeroBuffer(recipientKyber);
      SecureMemory.zeroBuffer(normalizedPayload.bytes);
      if (kemCiphertext) SecureMemory.zeroBuffer(kemCiphertext);
      if (pqSharedSecret) SecureMemory.zeroBuffer(pqSharedSecret);
      if (routingDigest) SecureMemory.zeroBuffer(routingDigest);
      if (outerSalt) SecureMemory.zeroBuffer(outerSalt);
      if (outerKey) SecureMemory.zeroBuffer(outerKey);
      if (outerMacKey) SecureMemory.zeroBuffer(outerMacKey);
      if (innerPayloadBytes) SecureMemory.zeroBuffer(innerPayloadBytes);
      if (outerNonce) SecureMemory.zeroBuffer(outerNonce);
      if (outerEncryptedWithTag) SecureMemory.zeroBuffer(outerEncryptedWithTag);
      if (outerCiphertext) SecureMemory.zeroBuffer(outerCiphertext);
      if (outerTag) SecureMemory.zeroBuffer(outerTag);
      if (outerMacInput) SecureMemory.zeroBuffer(outerMacInput);
      if (outerMac) SecureMemory.zeroBuffer(outerMac);
    }
  }

  static async decryptIncoming(
    envelope: HybridEnvelope,
    ownKeys: EnvelopeDecryptKeys,
    options?: DecryptOptions
  ): Promise<HybridDecryptionResult> {
    let stage = 'sender-key-validation';
    const senderPublic = checkUint8Array(
      ownKeys?.senderDilithiumPublicKey,
      'senderDilithiumPublicKey',
    );
    try {
      const senderPublicBase64 = Base64.arrayBufferToBase64(senderPublic);
      stage = 'native-envelope-decryption';
      const native = await account.decryptHybrid(envelope, senderPublicBase64);
      stage = 'native-plaintext-decoding';
      const payload = Base64.base64ToUint8Array(native.payloadBase64);
      if (payload.length !== native.routing.size || payload.length > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES) {
        payload.fill(0);
        throw new Error('Native hybrid plaintext length mismatch');
      }
      let payloadText: string | undefined;
      let payloadJson: unknown | undefined;
      if (native.payloadType === SignalType.TEXT || native.payloadType === 'json' || options?.expectJsonPayload) {
        stage = 'native-plaintext-utf8';
        payloadText = textDecoder.decode(payload);
      }
      if (native.payloadType === 'json' || options?.expectJsonPayload) {
        stage = 'native-plaintext-json';
        payloadJson = JSON.parse(payloadText!);
      }
      return {
        routing: native.routing,
        payload,
        payloadText,
        payloadJson,
        senderDilithiumPublicKey: senderPublicBase64,
      };
    } catch {
      throw new Error(`${stage}: hybrid receive failed`);
    } finally {
      senderPublic.fill(0);
    }

  }
}
