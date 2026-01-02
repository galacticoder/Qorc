/**
 * Hybrid Encryption - Combines ML-KEM + X25519 + Dilithium
 */

import { blake3 as nobleBlake3 } from '@noble/hashes/blake3.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { Base64 } from './base64';
import { PostQuantumKEM } from './kem';
import { PostQuantumHash } from './hash';
import { PostQuantumAEAD } from './aead';
import { PostQuantumRandom } from './random';
import { SecureMemory } from './secure-memory';
import { HashingService } from './hashing';
import { DilithiumService } from './services';
import { HYBRID_ENVELOPE_VERSION, INNER_ENVELOPE_VERSION } from '../constants';
import type { DecryptOptions, RoutingHeader, NormalizedPayload, RoutingHeaderBuildInput, HybridEnvelope, HybridRecipientKeys, ClientRoutingParams, HybridEncryptOptions, EnvelopeDecryptKeys, HybridDecryptionResult, InnerEnvelope } from '../types/crypto-types';
import { concatUint8Arrays } from '../utils/shared-utils';
import { SignalType } from '../types/signal-types';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function canonicalizeExtras(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeExtras(item));
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    const normalized: Record<string, unknown> = {};
    for (const [key, val] of entries) {
      normalized[key] = canonicalizeExtras(val);
    }
    return normalized;
  }
  return value;
}

function canonicalizeRoutingHeader(header: RoutingHeader): string {
  const canonical: RoutingHeader = {
    to: header.to,
    from: header.from,
    type: header.type,
    timestamp: header.timestamp,
    size: header.size,
    ...(header.extras ? { extras: canonicalizeExtras(header.extras) as Record<string, unknown> } : {})
  };
  return JSON.stringify(canonical);
}

function computeRoutingDigest(header: RoutingHeader): Uint8Array {
  const canonical = canonicalizeRoutingHeader(header);
  return nobleBlake3(textEncoder.encode(canonical));
}

function ensureUint8Array(input: Uint8Array | ArrayBuffer | string, label: string): Uint8Array {
  if (input instanceof Uint8Array) {
    const copy = new Uint8Array(input.length);
    copy.set(input);
    return copy;
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (typeof input === 'string') {
    return Base64.base64ToUint8Array(input);
  }
  throw new Error(`${label} must be a Uint8Array or base64 string`);
}

function normalizePayload(payload: unknown): NormalizedPayload {
  if (payload instanceof Uint8Array) {
    return { bytes: SecureMemory.secureBufferCopy(payload), type: 'binary' };
  }
  if (payload instanceof ArrayBuffer) {
    return { bytes: new Uint8Array(payload), type: 'binary' };
  }
  if (typeof payload === 'string') {
    return { bytes: textEncoder.encode(payload), type: SignalType.TEXT, text: payload };
  }
  const jsonSafe = payload ?? {};
  const text = JSON.stringify(jsonSafe);
  return { bytes: textEncoder.encode(text), type: 'json', text, json: jsonSafe };
}

export function buildRoutingHeader(input: RoutingHeaderBuildInput): RoutingHeader {
  if (!input.to || !input.from || !input.type) {
    throw new Error('Routing header requires to, from, and type');
  }
  if (!Number.isFinite(input.size) || input.size < 0) {
    throw new Error('Routing header size must be a non-negative finite number');
  }
  const timestamp = input.timestamp ?? Date.now();
  return {
    to: input.to,
    from: input.from,
    type: input.type,
    timestamp,
    size: Math.floor(input.size),
    ...(input.extras ? { extras: canonicalizeExtras(input.extras) as Record<string, unknown> } : {})
  };
}

export async function signRoutingHeader(header: RoutingHeader, dilithiumSecretKey: Uint8Array | string): Promise<string> {
  const secretKey = ensureUint8Array(dilithiumSecretKey, 'dilithiumSecretKey');
  try {
    const message = textEncoder.encode(canonicalizeRoutingHeader(header));
    const signature = await DilithiumService.sign(secretKey, message);
    return Base64.arrayBufferToBase64(signature);
  } finally {
    SecureMemory.zeroBuffer(secretKey);
  }
}

export async function verifyRoutingHeader(
  header: RoutingHeader,
  signatureBase64: string,
  dilithiumPublicKey: Uint8Array | string
): Promise<boolean> {
  const signature = Base64.base64ToUint8Array(signatureBase64);
  const publicKey = ensureUint8Array(dilithiumPublicKey, 'dilithiumPublicKey');
  try {
    const message = textEncoder.encode(canonicalizeRoutingHeader(header));
    return await DilithiumService.verify(signature, message, publicKey);
  } finally {
    SecureMemory.zeroBuffer(publicKey);
  }
}

function deriveOuterKeys(sharedSecret: Uint8Array, salt: Uint8Array, routingDigest: Uint8Array) {
  const info = `outer-envelope:${Base64.arrayBufferToBase64(routingDigest)}`;
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
  const info = `inner-envelope:${Base64.arrayBufferToBase64(routingDigest)}`;
  const combined = new Uint8Array(pqSharedSecret.length + classicalSharedSecret.length);
  combined.set(pqSharedSecret, 0);
  combined.set(classicalSharedSecret, pqSharedSecret.length);
  const okm = PostQuantumHash.deriveKey(combined, salt, info, 64);
  const encKey = new Uint8Array(32);
  const macKey = new Uint8Array(32);
  encKey.set(okm.subarray(0, 32));
  macKey.set(okm.subarray(32, 64));
  SecureMemory.zeroBuffer(okm);
  SecureMemory.zeroBuffer(combined);
  return { encKey, macKey };
}

function clampX25519Scalar(sk: Uint8Array): Uint8Array {
  const out = new Uint8Array(sk);
  out[0] &= 248;
  out[31] &= 127;
  out[31] |= 64;
  return out;
}

function generateEphemeralX25519() {
  try {
    const raw = new Uint8Array(32);
    const g = (globalThis as any).crypto?.getRandomValues?.bind((globalThis as any).crypto);
    if (typeof g === 'function') {
      g(raw);
    } else {
      const rnd = PostQuantumRandom.randomBytes(32);
      raw.set(rnd);
    }
    const clamped = clampX25519Scalar(raw);
    const publicKey = x25519.getPublicKey(clamped);
    return { secretKey: clamped, publicKey: new Uint8Array(publicKey) };
  } catch {
    try {
      const ephemeralPrivate = x25519.utils.randomSecretKey();
      const publicKey = x25519.getPublicKey(ephemeralPrivate);
      return { secretKey: new Uint8Array(ephemeralPrivate), publicKey: new Uint8Array(publicKey) };
    } catch (e2) {
      throw new Error('Failed to generate X25519 ephemeral keypair: ' + (e2 as any)?.message);
    }
  }
}

function computeClassicalSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(privateKey, publicKey);
  return new Uint8Array(shared.slice(0, 32));
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
  const recipientX25519 = Base64.base64ToUint8Array(recipientKeys.x25519PublicBase64);
  const ephemeral = generateEphemeralX25519();
  const classicalShared = computeClassicalSharedSecret(ephemeral.secretKey, recipientX25519);

  const innerSalt = PostQuantumRandom.randomBytes(32);
  const innerNonce = PostQuantumRandom.randomBytes(36);
  const { encKey, macKey } = await deriveInnerKeyMaterial(pqSharedSecret, classicalShared, innerSalt, routingDigest);

  try {
    const aad = textEncoder.encode(payload.type);
    const { ciphertext, tag } = PostQuantumAEAD.encrypt(payload.bytes, encKey, aad, innerNonce);
    const macInput = concatUint8Arrays(innerNonce, ciphertext, tag, routingDigest, ephemeral.publicKey, aad);
    const mac = await HashingService.generateBlake3Mac(macInput, macKey);

    return {
      version: INNER_ENVELOPE_VERSION,
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
    SecureMemory.zeroBuffer(recipientX25519);
    SecureMemory.zeroBuffer(ephemeral.secretKey);
    SecureMemory.zeroBuffer(classicalShared);
    SecureMemory.zeroBuffer(encKey);
    SecureMemory.zeroBuffer(macKey);
  }
}

export class Hybrid {
  static async generateHybridKeyPair() {
    const kyberPair = PostQuantumKEM.generateKeyPair();
    const dilithiumPair = await DilithiumService.generateKeyPair();
    const x25519Pair = generateEphemeralX25519();
    return {
      kyber: {
        publicKeyBase64: Base64.arrayBufferToBase64(kyberPair.publicKey),
        secretKey: kyberPair.secretKey,
        version: 1024
      },
      dilithium: {
        publicKeyBase64: Base64.arrayBufferToBase64(dilithiumPair.publicKey),
        secretKey: dilithiumPair.secretKey
      },
      x25519: {
        publicKeyBase64: Base64.arrayBufferToBase64(x25519Pair.publicKey),
        private: x25519Pair.secretKey
      }
    };
  }

  static async encryptForClient(
    payload: unknown,
    recipientKeys: HybridRecipientKeys,
    routingParams: ClientRoutingParams,
    options?: HybridEncryptOptions
  ): Promise<HybridEnvelope> {
    if (!recipientKeys?.kyberPublicBase64) {
      throw new Error('Recipient Kyber public key is required');
    }

    const normalizedPayload = normalizePayload(payload);
    const header = buildRoutingHeader({ ...routingParams, size: normalizedPayload.bytes.length });
    const signatureBase64 = await signRoutingHeader(header, routingParams.senderDilithiumSecretKey);
    const routingDigest = computeRoutingDigest(header);

    const recipientKyber = Base64.base64ToUint8Array(recipientKeys.kyberPublicBase64);
    const { ciphertext: kemCiphertext, sharedSecret: pqSharedSecret } = PostQuantumKEM.encapsulate(recipientKyber);

    const innerLayer = await createInnerLayer(normalizedPayload, recipientKeys, routingDigest, pqSharedSecret);

    const outerSalt = PostQuantumRandom.randomBytes(32);
    const { outerKey, outerMacKey } = deriveOuterKeys(pqSharedSecret, outerSalt, routingDigest);
    try {
      const innerPayloadBytes = textEncoder.encode(JSON.stringify(innerLayer));
      const outerNonce = PostQuantumRandom.randomBytes(24);
      const outerIv = outerNonce.slice(0, 12);
      const outerCipher = gcm(outerKey, outerIv, routingDigest);
      const outerEncryptedWithTag = outerCipher.encrypt(innerPayloadBytes);

      const outerCiphertext = outerEncryptedWithTag.slice(0, -16);
      const outerTag = outerEncryptedWithTag.slice(-16);
      const outerMacInput = concatUint8Arrays(outerCiphertext, outerTag, routingDigest);
      const outerMac = await HashingService.generateBlake3Mac(outerMacInput, outerMacKey);

      const envelope: HybridEnvelope = {
        version: HYBRID_ENVELOPE_VERSION,
        routing: header,
        routingSignature: { algorithm: 'dilithium3', signature: signatureBase64 },
        algorithms: { outer: 'mlkem1024', inner: 'x25519', aead: 'aes-256-gcm', mac: 'blake3' },
        kemCiphertext: Base64.arrayBufferToBase64(kemCiphertext),
        outer: {
          salt: Base64.arrayBufferToBase64(outerSalt),
          nonce: Base64.arrayBufferToBase64(outerNonce),
          ciphertext: Base64.arrayBufferToBase64(outerCiphertext),
          tag: Base64.arrayBufferToBase64(outerTag),
          mac: Base64.arrayBufferToBase64(outerMac)
        },
        metadata: options?.metadata
      };

      if (routingParams.senderDilithiumPublicKey) {
        const senderKeyBytes =
          typeof routingParams.senderDilithiumPublicKey === 'string'
            ? Base64.base64ToUint8Array(routingParams.senderDilithiumPublicKey)
            : ensureUint8Array(routingParams.senderDilithiumPublicKey, 'senderDilithiumPublicKey');
        envelope.metadata = {
          ...envelope.metadata,
          sender: { ...(envelope.metadata?.sender ?? {}), dilithiumPublicKey: Base64.arrayBufferToBase64(senderKeyBytes) }
        };
      }

      if (options?.metadata?.context ?? routingParams.context) {
        envelope.metadata = { ...envelope.metadata, context: options?.metadata?.context ?? routingParams.context };
      }

      return envelope;
    } finally {
      SecureMemory.zeroBuffer(pqSharedSecret);
      SecureMemory.zeroBuffer(outerKey);
      SecureMemory.zeroBuffer(outerMacKey);
    }
  }

  static async encryptForServer(payload: unknown, serverKeys: HybridRecipientKeys, options?: HybridEncryptOptions) {
    const routing: ClientRoutingParams = {
      to: 'server',
      from: 'client',
      type: 'server',
      senderDilithiumSecretKey: options?.senderDilithiumSecretKey ?? '',
      senderDilithiumPublicKey: options?.senderDilithiumPublicKey,
      timestamp: Date.now()
    } as any;
    if (!routing.senderDilithiumSecretKey) {
      throw new Error('Sender Dilithium secret key required for server encryption');
    }
    return await this.encryptForClient(payload, serverKeys, routing, options);
  }

  static async decryptIncoming(
    envelope: HybridEnvelope,
    ownKeys: EnvelopeDecryptKeys,
    options?: DecryptOptions
  ): Promise<HybridDecryptionResult> {
    if (!envelope || envelope.version !== HYBRID_ENVELOPE_VERSION) {
      throw new Error('Unsupported envelope version');
    }

    if (!ownKeys?.senderDilithiumPublicKey) {
      throw new Error('EnvelopeDecryptKeys.senderDilithiumPublicKey is required for verification');
    }

    const senderPublicKey = ensureUint8Array(ownKeys.senderDilithiumPublicKey, 'senderDilithiumPublicKey');
    const header = envelope.routing;
    const routingDigest = computeRoutingDigest(header);

    const signatureValid = await verifyRoutingHeader(header, envelope.routingSignature.signature, senderPublicKey);
    if (!signatureValid) {
      throw new Error('Routing header signature verification failed');
    }

    const kyberSecret = ensureUint8Array(ownKeys.kyberSecretKey, 'kyberSecretKey');
    const kemCiphertext = Base64.base64ToUint8Array(envelope.kemCiphertext);
    const pqSharedSecret = PostQuantumKEM.decapsulate(kemCiphertext, kyberSecret);
    SecureMemory.zeroBuffer(kyberSecret);

    const outerSalt = Base64.base64ToUint8Array(envelope.outer.salt);
    const { outerKey, outerMacKey } = deriveOuterKeys(pqSharedSecret, outerSalt, routingDigest);

    try {
      const outerCiphertext = Base64.base64ToUint8Array(envelope.outer.ciphertext);
      const outerTag = Base64.base64ToUint8Array(envelope.outer.tag);
      const outerNonce = Base64.base64ToUint8Array(envelope.outer.nonce);
      const expectedMac = Base64.base64ToUint8Array(envelope.outer.mac);
      const outerMacInput = concatUint8Arrays(outerCiphertext, outerTag, routingDigest);
      const macValid = await HashingService.verifyBlake3Mac(outerMacInput, outerMacKey, expectedMac);
      if (!macValid) {
        throw new Error('Outer MAC verification failed');
      }

      const outerIv = outerNonce.slice(0, 12);
      const outerDecipher = gcm(outerKey, outerIv, routingDigest);
      const outerCiphertextWithTag = concatUint8Arrays(outerCiphertext, outerTag);
      const outerPlain = outerDecipher.decrypt(outerCiphertextWithTag);
      const innerLayer: InnerEnvelope = JSON.parse(textDecoder.decode(outerPlain));

      if (innerLayer.version !== INNER_ENVELOPE_VERSION) {
        throw new Error('Unsupported inner envelope version');
      }

      const innerSalt = Base64.base64ToUint8Array(innerLayer.salt);
      const innerNonce = Base64.base64ToUint8Array(innerLayer.nonce);
      const innerCiphertext = Base64.base64ToUint8Array(innerLayer.ciphertext);
      const innerTag = Base64.base64ToUint8Array(innerLayer.tag);
      const innerMac = Base64.base64ToUint8Array(innerLayer.mac);
      const ephemeralPublic = Base64.base64ToUint8Array(innerLayer.ephemeralX25519);

      const x25519Secret = ensureUint8Array(ownKeys.x25519SecretKey, 'x25519SecretKey');
      const classicalShared = computeClassicalSharedSecret(x25519Secret, ephemeralPublic);
      const { encKey, macKey } = await deriveInnerKeyMaterial(pqSharedSecret, classicalShared, innerSalt, routingDigest);

      try {
        const macInput = concatUint8Arrays(innerNonce, innerCiphertext, innerTag, routingDigest, ephemeralPublic, textEncoder.encode(innerLayer.payloadType));
        const innerMacValid = await HashingService.verifyBlake3Mac(macInput, macKey, innerMac);
        if (!innerMacValid) {
          throw new Error('Inner MAC verification failed');
        }

        const aad = textEncoder.encode(innerLayer.payloadType);
        const plaintextBytes = PostQuantumAEAD.decrypt(innerCiphertext, innerNonce, innerTag, encKey, aad);
        let payloadText: string | undefined;
        let payloadJson: unknown | undefined;
        if (innerLayer.payloadType === SignalType.TEXT || innerLayer.payloadType === 'json') {
          payloadText = textDecoder.decode(plaintextBytes);
          if (innerLayer.payloadType === 'json') {
            try {
              payloadJson = JSON.parse(payloadText);
            } catch {
              throw new Error('Invalid JSON payload format');
            }
          }
        }

        if (options?.expectJsonPayload) {
          if (!payloadText) {
            payloadText = textDecoder.decode(plaintextBytes);
          }
          if (payloadJson === undefined) {
            try {
              payloadJson = JSON.parse(payloadText);
            } catch {
              throw new Error('Expected JSON payload but parsing failed');
            }
          }
        }

        return {
          routing: header,
          payload: plaintextBytes,
          payloadText,
          payloadJson,
          metadata: envelope.metadata,
          senderDilithiumPublicKey: envelope.metadata?.sender?.dilithiumPublicKey
        };
      } finally {
        SecureMemory.zeroBuffer(x25519Secret);
        SecureMemory.zeroBuffer(classicalShared);
        SecureMemory.zeroBuffer(macKey);
      }
    } finally {
      SecureMemory.zeroBuffer(pqSharedSecret);
      SecureMemory.zeroBuffer(outerKey);
      SecureMemory.zeroBuffer(outerMacKey);
    }
  }
}
