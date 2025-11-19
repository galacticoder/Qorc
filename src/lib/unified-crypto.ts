import * as argon2 from "argon2-wasm";
import { blake3 as nobleBlake3 } from "@noble/hashes/blake3.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  KEM as PostQuantumKEM,
  Signature as PostQuantumSignature,
  Hash as PostQuantumHash,
  AEAD as PostQuantumAEAD,
  Random as PostQuantumRandom,
  PostQuantumWorker
} from "./post-quantum-crypto";
import { SecureMemory } from "./secure-memory";
import { gcm } from "@noble/ciphers/aes.js";

type NormalizedPayloadType = "binary" | "text" | "json";

interface NormalizedPayload {
  bytes: Uint8Array;
  type: NormalizedPayloadType;
  text?: string;
  json?: unknown;
}

const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

class CryptoConfig {
  static AES_KEY_SIZE = 256;
  static IV_LENGTH = 12;
  static AUTH_TAG_LENGTH = 16;
  static HKDF_HASH = "SHA-256";
  static HKDF_INFO = new TextEncoder().encode("endtoend-chat hybrid key v2");
  static X25519_DERIVE_BITS = 256;
}

class Base64 {
  static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    const chunkSize = 8192;
    if (bytes.length <= chunkSize) {
      return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
    }
    let binary = "";
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
      binary += String.fromCharCode.apply(null, Array.from(chunk));
    }
    return btoa(binary);
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    try {
      if (!base64 || typeof base64 !== "string") {
        throw new Error("Invalid base64 input: must be a non-empty string");
      }
      let normalized = base64.trim();
      normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
      normalized = normalized.replace(/\s+/g, "");

      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
        throw new Error("Invalid base64 format: contains invalid characters");
      }

      const padLen = normalized.length % 4;
      if (padLen === 1) {
        throw new Error("Invalid base64 length");
      } else if (padLen === 2) {
        normalized += "==";
      } else if (padLen === 3) {
        normalized += "=";
      }
      const binary = atob(normalized);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (error) {
      throw new Error(`Base64 decoding failed: ${(error as any)?.message ?? String(error)}`);
    }
  }

  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    return this.base64ToUint8Array(base64).buffer as ArrayBuffer;
  }

  static stringToArrayBuffer(str: string): ArrayBuffer {
    return textEncoder.encode(str).buffer;
  }
}

class DilithiumService {
  static async generateKeyPair() {
    return PostQuantumSignature.generateKeyPair();
  }

  static async sign(secretKey: Uint8Array, message: Uint8Array) {
    return PostQuantumSignature.sign(message, secretKey);
  }

  static async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
    return PostQuantumSignature.verify(signature, message, publicKey);
  }

  static serializePublicKey(publicKey: Uint8Array): string {
    return Base64.arrayBufferToBase64(publicKey);
  }

  static deserializePublicKey(base64: string): Uint8Array {
    return Base64.base64ToUint8Array(base64);
  }

  static serializeSecretKey(secretKey: Uint8Array): string {
    return Base64.arrayBufferToBase64(secretKey);
  }

  static deserializeSecretKey(base64: string): Uint8Array {
    return Base64.base64ToUint8Array(base64);
  }
}

// Convert Argon2 algorithm string to enum value
// Enforce Argon2id only
function mapArgon2Algorithm(algorithm: string | number): number {
  if (algorithm === 2 || algorithm === 'argon2id') return 2;
  throw new Error('Only Argon2id is supported for maximum security');
}

class HashingService {
  static parseArgon2Hash(encodedHash: string) {
    if (!encodedHash || typeof encodedHash !== "string") {
      throw new Error("Encoded hash must be a non-empty string");
    }
    if (encodedHash.length > 512) {
      throw new Error("Hash too long - potential DoS attack");
    }

    const parts = encodedHash.split("$");
    if (parts.length !== 6) {
      throw new Error("Invalid Argon2 encoded hash format - wrong number of parts");
    }

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;
    if (!algorithm || !["argon2i", "argon2d", "argon2id"].includes(algorithm)) {
      throw new Error("Invalid Argon2 algorithm type");
    }
    if (!versionPart || !versionPart.includes("=")) {
      throw new Error("Invalid version format");
    }

    const version = parseInt(versionPart.split("=")[1], 10);
    if (Number.isNaN(version) || version < 0x10 || version > 0x13) {
      throw new Error("Invalid Argon2 version");
    }

    if (!paramsPart) {
      throw new Error("Missing parameters");
    }

    const params: Record<string, number> = {};
    paramsPart.split(",").forEach((param) => {
      const equalIndex = param.indexOf("=");
      if (equalIndex === -1) {
        throw new Error("Invalid parameter format");
      }
      const key = param.substring(0, equalIndex);
      const value = param.substring(equalIndex + 1);
      if (!["m", "t", "p"].includes(key)) {
        throw new Error(`Invalid parameter key: ${key}`);
      }
      const numValue = Number(value);
      if (Number.isNaN(numValue) || numValue < 1 || numValue > 2 ** 30) {
        throw new Error(`Invalid parameter value for ${key}: ${value}`);
      }
      params[key] = numValue;
    });

    if (!params.m || !params.t || !params.p) {
      throw new Error("Missing required parameters (m, t, p)");
    }

    if (!saltB64 || !hashB64) {
      throw new Error("Missing salt or hash");
    }

    let hashBytes: Uint8Array;
    try {
      hashBytes = Uint8Array.from(atob(hashB64), (c) => c.charCodeAt(0));
    } catch {
      throw new Error("Invalid base64 encoding in hash");
    }
    if (hashBytes.length < 16 || hashBytes.length > 128) {
      throw new Error("Invalid hash length");
    }

    return {
      version,
      algorithm,
      salt: saltB64,
      memoryCost: params.m,
      timeCost: params.t,
      parallelism: params.p,
      hash: hashBytes
    };
  }

  static async hashDataUsingInfo(
    data: string,
    args: {
      version?: number;
      algorithm?: string;
      salt: string;
      memoryCost?: number;
      timeCost?: number;
      parallelism?: number;
    }
  ) {
    if (!args?.salt) throw new Error("Salt is required");

    const saltBuffer = Base64.base64ToUint8Array(args.salt);
    const algEnum = mapArgon2Algorithm(args.algorithm ?? "argon2id");

    const opts = {
      pass: data,
      salt: saltBuffer,
      time: args.timeCost ?? 3,
      mem: args.memoryCost ?? 65536,
      parallelism: args.parallelism ?? 1,
      type: algEnum,
      version: args.version ?? 0x13,
      hashLen: 32
    };

    const result = await PostQuantumWorker.argon2Hash(opts);
    return result.encoded;
  }

  static async hashData(data: string, timeoutMs: number = 30000) {
    if (!data || typeof data !== "string") {
      throw new Error("Invalid data for hashing - must be non-empty string");
    }
    if (data.length > 1_000_000) {
      throw new Error("Data too large for hashing (max 1MB)");
    }
    if (timeoutMs < 1000 || timeoutMs > 300000) {
      throw new Error("Invalid timeout value (must be 1-300 seconds)");
    }

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const opts = {
      pass: data,
      salt,
      time: 5,
      mem: 2 ** 17,
      parallelism: 4,
      type: 2,
      version: 0x13,
      hashLen: 32
    };

    return Promise.race([
      PostQuantumWorker.argon2Hash(opts).then((res) => {
        if (!res || !res.encoded) {
          throw new Error("Argon2 hash operation failed");
        }
        return res.encoded;
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Argon2 hash operation timed out")), timeoutMs)
      )
    ]);
  }

  static async verifyHash(encoded: string, data: string) {
    const verified = await PostQuantumWorker.argon2Verify({ pass: data, encoded });
    return verified;
  }

  static async generateBlake3Mac(message: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) {
      throw new Error("Message must be Uint8Array");
    }
    if (!(key instanceof Uint8Array)) {
      throw new Error("Key must be Uint8Array");
    }
    let normalizedKey = key;
    if (key.length !== 32) {
      normalizedKey = nobleBlake3(key, { dkLen: 32 });
    }
    const keyedHash = nobleBlake3.create({ key: normalizedKey });
    keyedHash.update(message);
    const mac = keyedHash.digest();
    if (normalizedKey !== key) {
      SecureMemory.zeroBuffer(normalizedKey);
    }
    return mac;
  }

  static async verifyBlake3Mac(message: Uint8Array, key: Uint8Array, expectedMac: Uint8Array): Promise<boolean> {
    const computedMac = await this.generateBlake3Mac(message, key);
    const isValid = SecureMemory.constantTimeCompare(computedMac, expectedMac);
    SecureMemory.zeroBuffer(computedMac);
    return isValid;
  }

  static async deriveKeyFromPassphrase(
    passphrase: string,
    options?: {
      salt?: string;
      time?: number;
      memoryCost?: number;
      parallelism?: number;
      algorithm?: number | string;
      version?: number;
      hashLen?: number;
    }
  ) {
    const saltBytes = options?.salt
      ? Base64.base64ToUint8Array(options.salt)
      : crypto.getRandomValues(new Uint8Array(16));

    const {
      time = 5,
      memoryCost = 2 ** 17,
      parallelism = 4,
      algorithm = 2,
      version = 0x13,
      hashLen = 32
    } = options || {};

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: mapArgon2Algorithm(algorithm),
      version,
      hashLen
    };

    const result = await PostQuantumWorker.argon2Hash(hashOptions);
    return result.hash;
  }
}

class KeyService {
  static async generateAESKey(): Promise<CryptoKey> {
    if (!subtle) {
      throw new Error("SubtleCrypto not available");
    }
    return await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }

  static async importAESKey(keyBytes: ArrayBuffer | Uint8Array, algorithm: string = "AES-GCM"): Promise<CryptoKey> {
    if (!subtle) {
      throw new Error("SubtleCrypto not available");
    }
    const rawKey = keyBytes instanceof Uint8Array ? keyBytes.buffer as ArrayBuffer : keyBytes;
    return await subtle.importKey("raw", rawKey, { name: algorithm, length: 256 }, true, ["encrypt", "decrypt"]);
  }

  static async exportAESKey(aesKey: CryptoKey): Promise<ArrayBuffer> {
    if (!subtle) {
      throw new Error("SubtleCrypto not available");
    }
    return await subtle.exportKey("raw", aesKey);
  }

  static async deriveAESKeyFromPassphrase(
    passphrase: string,
    options?: {
      saltBase64?: string;
      time?: number;
      memoryCost?: number;
      parallelism?: number;
      algorithm?: number | string;
      version?: number;
      hashLen?: number;
    }
  ) {
    if (!subtle) {
      throw new Error("SubtleCrypto not available");
    }
    const saltBytes = options?.saltBase64
      ? Base64.base64ToUint8Array(options.saltBase64)
      : crypto.getRandomValues(new Uint8Array(16));

    const {
      time = 5,
      memoryCost = 2 ** 17,
      parallelism = 4,
      algorithm = 2,
      version = 0x13,
      hashLen = 32
    } = options || {};

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: mapArgon2Algorithm(algorithm),
      version,
      hashLen
    };

    const result = await PostQuantumWorker.argon2Hash(hashOptions);
    const rawKeyBytes = result.hash;
    const aesKey = await this.importAESKey(rawKeyBytes);
    return {
      aesKey,
      encodedHash: result.encoded
    };
  }

  static async importRawAesKey(rawBytes: Uint8Array): Promise<CryptoKey> {
    return await this.importAESKey(rawBytes);
  }
}

class KyberService {
  static async generateKeyPair() {
    if (PostQuantumWorker.supportsWorkers()) {
      return await PostQuantumWorker.generateKemKeyPair();
    }
    return PostQuantumKEM.generateKeyPair();
  }

  static encapsulate(publicKey: Uint8Array) {
    const { ciphertext, sharedSecret } = PostQuantumKEM.encapsulate(publicKey);
    return {
      ciphertext,
      sharedSecret,
      version: 1024
    };
  }

  static decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array) {
    return PostQuantumKEM.decapsulate(ciphertext, secretKey);
  }
}

class KDF {
  static async argon2id(
    passphrase: string,
    options: {
      salt: Uint8Array;
      time: number;
      memoryCost: number;
      parallelism: number;
      hashLen: number;
    }
  ): Promise<Uint8Array> {
    const hashOptions = {
      pass: passphrase,
      salt: options.salt,
      time: options.time,
      mem: options.memoryCost,
      parallelism: options.parallelism,
      type: 2, // argon2id
      version: 0x13,
      hashLen: options.hashLen
    };

    const result = await PostQuantumWorker.argon2Hash(hashOptions);
    return result.hash;
  }

  static async blake3Hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, outLen: number): Promise<Uint8Array> {
    const prk = await HashingService.generateBlake3Mac(ikm, salt);
    const output = new Uint8Array(outLen);
    const hashLen = 32;
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    try {
      for (let i = 1; i <= n; i++) {
        const input = new Uint8Array(t.length + info.length + 1);
        input.set(t, 0);
        input.set(info, t.length);
        input[input.length - 1] = i;

        const newT = await HashingService.generateBlake3Mac(input, prk);

        // Securely zero old t before replacing
        if (t.length > 0) {
          SecureMemory.zeroBuffer(t as Uint8Array);
        }
        t = newT;

        const copyLen = Math.min(hashLen, outLen - outputOffset);
        output.set(t.subarray(0, copyLen), outputOffset);
        outputOffset += copyLen;
      }
    } finally {
      // Cleanup sensitive material
      SecureMemory.zeroBuffer(prk);
      if (t.length > 0) {
        SecureMemory.zeroBuffer(t);
      }
    }

    return output;
  }

  static async deriveAesCryptoKeyFromIkm(ikm: Uint8Array, salt: Uint8Array, context?: string) {
    if (!subtle) {
      throw new Error("SubtleCrypto not available");
    }
    const baseKey = await subtle.importKey("raw", ikm.buffer as ArrayBuffer, { name: "HKDF" }, false, ["deriveKey"]);
    const derivedKey = await subtle.deriveKey(
      { name: "HKDF", hash: CryptoConfig.HKDF_HASH, salt: salt.buffer as ArrayBuffer, info: context ? textEncoder.encode(context).buffer as ArrayBuffer : CryptoConfig.HKDF_INFO.buffer as ArrayBuffer },
      baseKey,
      { name: "AES-GCM", length: CryptoConfig.AES_KEY_SIZE },
      false,
      ["encrypt", "decrypt"]
    );
    return derivedKey;
  }

  static async deriveSessionKey(ikm: Uint8Array, salt: Uint8Array, sessionContext: string): Promise<Uint8Array> {
    const contextInfo = textEncoder.encode(`session-key-v2:${sessionContext}`);
    return await this.blake3Hkdf(ikm, salt, contextInfo, 32);
  }
}

export class AES {
  static async importAesKey(raw: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
    return await KeyService.importAESKey(raw);
  }

  static async encryptBinaryWithAES(data: Uint8Array, aesKey: CryptoKey, aad?: Uint8Array): Promise<{ iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array }> {
    const iv = crypto.getRandomValues(new Uint8Array(CryptoConfig.IV_LENGTH));
    const params: AesGcmParams = { name: 'AES-GCM', iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 } as AesGcmParams;
    if (aad && aad.byteLength) {
      (params as any).additionalData = aad;
    }
    const ciphertextWithTag = new Uint8Array(await subtle.encrypt(params, aesKey, data.buffer as ArrayBuffer));
    const authTag = ciphertextWithTag.slice(-CryptoConfig.AUTH_TAG_LENGTH);
    const encrypted = ciphertextWithTag.slice(0, -CryptoConfig.AUTH_TAG_LENGTH);
    return { iv, authTag, encrypted };
  }

  static async decryptBinaryWithAES(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, aesKey: CryptoKey, aad?: Uint8Array): Promise<Uint8Array> {
    const params: AesGcmParams = { name: 'AES-GCM', iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 } as AesGcmParams;
    if (aad && aad.byteLength) {
      (params as any).additionalData = aad;
    }
    const ciphertextWithTag = concatUint8Arrays(encrypted, authTag);
    const plaintext = new Uint8Array(await subtle.decrypt(params, aesKey, ciphertextWithTag.buffer as ArrayBuffer));
    return plaintext;
  }

  static async decryptWithAesGcmRaw(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, aesKey: CryptoKey, aad?: Uint8Array): Promise<string> {
    const plaintext = await this.decryptBinaryWithAES(iv, authTag, encrypted, aesKey, aad);
    return textDecoder.decode(plaintext);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
    const totalLength = 1 + 1 + iv.length + 1 + authTag.length + 4 + encrypted.length;
    const output = new Uint8Array(totalLength);
    let offset = 0;
    output[offset++] = 1;
    output[offset++] = iv.length;
    output.set(iv, offset);
    offset += iv.length;
    output[offset++] = authTag.length;
    output.set(authTag, offset);
    offset += authTag.length;
    output[offset++] = (encrypted.length >> 24) & 0xff;
    output[offset++] = (encrypted.length >> 16) & 0xff;
    output[offset++] = (encrypted.length >> 8) & 0xff;
    output[offset++] = encrypted.length & 0xff;
    output.set(encrypted, offset);
    return Base64.arrayBufferToBase64(output);
  }
}

class EncryptService {
  static async encryptWithAES(data: string, aesKey: CryptoKey): Promise<string> {
    const { iv, authTag, encrypted } = await AES.encryptBinaryWithAES(textEncoder.encode(data), aesKey);
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptBinaryWithAES(data: Uint8Array, aesKey: CryptoKey): Promise<{ iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array }> {
    return await AES.encryptBinaryWithAES(data, aesKey);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptAndFormatPayload(payload: any): Promise<string> {
    const { recipientHybridKeys, from, to, type, senderDilithiumSecretKey, ...rest } = payload ?? {};

    if (!recipientHybridKeys) {
      return JSON.stringify(payload ?? {});
    }

    if (!senderDilithiumSecretKey) {
      throw new Error("senderDilithiumSecretKey is required for hybrid encryption");
    }

    const envelope = await Hybrid.encryptForClient(rest, recipientHybridKeys, {
      from,
      to,
      type,
      senderDilithiumSecretKey
    });

    return JSON.stringify(envelope);
  }
}

class DecryptService {
  static deserializeEncryptedDataFromUint8Array(encryptedBytes: Uint8Array) {
    if (!encryptedBytes || encryptedBytes.length < 7) {
      throw new Error("Invalid encrypted data: insufficient length");
    }
    const combined = new Uint8Array(encryptedBytes);
    let off = 0;
    const version = combined[off++];
    if (version !== 1) throw new Error("Unsupported version");
    const ivLen = combined[off++];
    if (ivLen === undefined || ivLen === 0 || off + ivLen > combined.length) {
      throw new Error("Invalid IV length");
    }
    const iv = combined.slice(off, off + ivLen);
    off += ivLen;
    const tagLen = combined[off++];
    if (tagLen === undefined || tagLen === 0 || off + tagLen > combined.length) {
      throw new Error("Invalid auth tag length");
    }
    const authTag = combined.slice(off, off + tagLen);
    off += tagLen;
    if (off + 4 > combined.length) {
      throw new Error("Invalid encrypted data: missing length header");
    }
    const encLen = (combined[off] << 24) | (combined[off + 1] << 16) | (combined[off + 2] << 8) | combined[off + 3];
    off += 4;
    if (encLen === undefined || encLen === 0 || off + encLen > combined.length) {
      throw new Error("Invalid encrypted data length");
    }
    const encrypted = combined.slice(off, off + encLen);
    return { iv, authTag, encrypted };
  }

  static async decryptWithAESRaw(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, aesKey: CryptoKey): Promise<string> {
    return await AES.decryptWithAesGcmRaw(iv, authTag, encrypted, aesKey);
  }
}

const HYBRID_ENVELOPE_VERSION = "hybrid-envelope-v1";
const INNER_ENVELOPE_VERSION = "inner-envelope-v1";

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

interface RoutingHeaderBuildInput extends RoutingHeaderInput {
  size: number;
}

export interface HybridEnvelopeMetadata {
  sender?: { dilithiumPublicKey?: string };
  recipient?: { dilithiumPublicKey?: string };
  context?: string;
  annotations?: Record<string, unknown>;
}

interface HybridOuterLayer {
  salt: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  mac: string;
}

interface InnerEnvelope {
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
  routingSignature: { algorithm: "dilithium3"; signature: string };
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

interface DecryptOptions {
  expectJsonPayload?: boolean;
}

function canonicalizeExtras(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeExtras(item));
  }
  if (value && typeof value === "object") {
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
    // Create a defensive copy to prevent buffer sharing issues
    const copy = new Uint8Array(input.length);
    copy.set(input);
    return copy;
  }
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (typeof input === "string") {
    return Base64.base64ToUint8Array(input);
  }
  throw new Error(`${label} must be a Uint8Array or base64 string`);
}

function normalizePayload(payload: unknown): NormalizedPayload {
  if (payload instanceof Uint8Array) {
    return { bytes: SecureMemory.secureBufferCopy(payload), type: "binary" };
  }
  if (payload instanceof ArrayBuffer) {
    return { bytes: new Uint8Array(payload), type: "binary" };
  }
  if (typeof payload === "string") {
    return { bytes: textEncoder.encode(payload), type: "text", text: payload };
  }
  const jsonSafe = payload ?? {};
  const text = JSON.stringify(jsonSafe);
  return { bytes: textEncoder.encode(text), type: "json", text, json: jsonSafe };
}

function concatUint8Arrays(...arrays: Uint8Array[]): Uint8Array {
  if (arrays.length === 0) return new Uint8Array(0);
  if (arrays.length === 1) return new Uint8Array(arrays[0]);

  let totalLength = 0;
  for (let i = 0; i < arrays.length; i++) {
    totalLength += arrays[i].length;
  }

  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (let i = 0; i < arrays.length; i++) {
    out.set(arrays[i], offset);
    offset += arrays[i].length;
  }
  return out;
}

export function buildRoutingHeader(input: RoutingHeaderBuildInput): RoutingHeader {
  if (!input.to || !input.from || !input.type) {
    throw new Error("Routing header requires to, from, and type");
  }
  if (!Number.isFinite(input.size) || input.size < 0) {
    throw new Error("Routing header size must be a non-negative finite number");
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
  const secretKey = ensureUint8Array(dilithiumSecretKey, "dilithiumSecretKey");
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
  const publicKey = ensureUint8Array(dilithiumPublicKey, "dilithiumPublicKey");

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

  // Efficient key material split with proper copying
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
  // Use concatenation instead of XOR for better hybrid security (NIST SP 800-56C)
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
  } catch (_e) {
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
    throw new Error("Recipient keys must include x25519PublicBase64 for inner layer derivation");
  }
  const recipientX25519 = Base64.base64ToUint8Array(recipientKeys.x25519PublicBase64);
  const ephemeral = generateEphemeralX25519();
  const classicalShared = computeClassicalSharedSecret(ephemeral.secretKey, recipientX25519);

  // Derive inner keys using a dedicated salt and use a separate 36-byte nonce for AEAD
  const innerSalt = PostQuantumRandom.randomBytes(32);
  const innerNonce = PostQuantumRandom.randomBytes(36);
  const { encKey, macKey } = await deriveInnerKeyMaterial(pqSharedSecret, classicalShared, innerSalt, routingDigest);

  try {
    // Use payloadType as AAD to bind ciphertext to its context
    const aad = textEncoder.encode(payload.type);
    const { ciphertext, tag } = PostQuantumAEAD.encrypt(payload.bytes, encKey, aad, innerNonce);
    const macInput = concatUint8Arrays(innerNonce, ciphertext, tag, routingDigest, ephemeral.publicKey, aad);
    const mac = await HashingService.generateBlake3Mac(macInput, macKey);

    const envelope = {
      version: INNER_ENVELOPE_VERSION,
      salt: Base64.arrayBufferToBase64(innerSalt),
      ephemeralX25519: Base64.arrayBufferToBase64(ephemeral.publicKey),
      nonce: Base64.arrayBufferToBase64(innerNonce),
      ciphertext: Base64.arrayBufferToBase64(ciphertext),
      tag: Base64.arrayBufferToBase64(tag),
      mac: Base64.arrayBufferToBase64(mac),
      payloadType: payload.type,
      metadata: {
        contentLength: payload.bytes.length
      }
    };
    return envelope;
  } finally {
    // Secure cleanup of all sensitive material
    SecureMemory.zeroBuffer(recipientX25519);
    SecureMemory.zeroBuffer(ephemeral.secretKey);
    SecureMemory.zeroBuffer(classicalShared);
    SecureMemory.zeroBuffer(encKey);
    SecureMemory.zeroBuffer(macKey);
  }
}

class Hybrid {
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
      throw new Error("Recipient Kyber public key is required");
    }

    const normalizedPayload = normalizePayload(payload);

    const header = buildRoutingHeader({
      ...routingParams,
      size: normalizedPayload.bytes.length
    });
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

      // Extract ciphertext and GCM tag
      const outerCiphertext = outerEncryptedWithTag.slice(0, -16);
      const outerTag = outerEncryptedWithTag.slice(-16);

      const outerMacInput = concatUint8Arrays(outerCiphertext, outerTag, routingDigest);
      const outerMac = await HashingService.generateBlake3Mac(outerMacInput, outerMacKey);

      const envelope: HybridEnvelope = {
        version: HYBRID_ENVELOPE_VERSION,
        routing: header,
        routingSignature: { algorithm: "dilithium3", signature: signatureBase64 },
        algorithms: {
          outer: "mlkem1024",
          inner: "x25519",
          aead: "aes-256-gcm",
          mac: "blake3"
        },
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
            : ensureUint8Array(routingParams.senderDilithiumPublicKey, "senderDilithiumPublicKey");
        envelope.metadata = {
          ...envelope.metadata,
          sender: {
            ...(envelope.metadata?.sender ?? {}),
            dilithiumPublicKey: Base64.arrayBufferToBase64(senderKeyBytes)
          }
        };
      }

      if (options?.metadata?.context ?? routingParams.context) {
        envelope.metadata = {
          ...envelope.metadata,
          context: options?.metadata?.context ?? routingParams.context
        };
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
      to: "server",
      from: "client",
      type: "server",
      senderDilithiumSecretKey: options?.senderDilithiumSecretKey ?? "",
      timestamp: Date.now()
    } as any;
    if (!routing.senderDilithiumSecretKey) {
      throw new Error("Sender Dilithium secret key required for server encryption");
    }
    const result = await this.encryptForClient(payload, serverKeys, routing, options);
    return result;
  }

  static async decryptIncoming(
    envelope: HybridEnvelope,
    ownKeys: EnvelopeDecryptKeys,
    _options?: DecryptOptions
  ): Promise<HybridDecryptionResult> {
    if (!envelope || envelope.version !== HYBRID_ENVELOPE_VERSION) {
      throw new Error("Unsupported envelope version");
    }

    if (!ownKeys?.senderDilithiumPublicKey) {
      throw new Error("EnvelopeDecryptKeys.senderDilithiumPublicKey is required for verification");
    }

    const senderPublicKey = ensureUint8Array(ownKeys.senderDilithiumPublicKey, "senderDilithiumPublicKey");

    const header = envelope.routing;
    const routingDigest = computeRoutingDigest(header);

    const signatureValid = await verifyRoutingHeader(header, envelope.routingSignature.signature, senderPublicKey);
    if (!signatureValid) {
      throw new Error("Routing header signature verification failed");
    }

    const kyberSecret = ensureUint8Array(ownKeys.kyberSecretKey, "kyberSecretKey");
    const kemCiphertext = Base64.base64ToUint8Array(envelope.kemCiphertext);
    const pqSharedSecret = PostQuantumKEM.decapsulate(kemCiphertext, kyberSecret);

    // Secure cleanup of kyber secret after use
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
        throw new Error("Outer MAC verification failed");
      }

      // Use plain GCM for outer layer
      const outerIv = outerNonce.slice(0, 12);
      const outerDecipher = gcm(outerKey, outerIv, routingDigest);
      const outerCiphertextWithTag = concatUint8Arrays(outerCiphertext, outerTag);
      const outerPlain = outerDecipher.decrypt(outerCiphertextWithTag);
      const innerLayer: InnerEnvelope = JSON.parse(textDecoder.decode(outerPlain));

      if (innerLayer.version !== INNER_ENVELOPE_VERSION) {
        throw new Error("Unsupported inner envelope version");
      }

      const innerSalt = Base64.base64ToUint8Array(innerLayer.salt);
      const innerNonce = Base64.base64ToUint8Array(innerLayer.nonce);
      const innerCiphertext = Base64.base64ToUint8Array(innerLayer.ciphertext);
      const innerTag = Base64.base64ToUint8Array(innerLayer.tag);
      const innerMac = Base64.base64ToUint8Array(innerLayer.mac);
      const ephemeralPublic = Base64.base64ToUint8Array(innerLayer.ephemeralX25519);

      const x25519Secret = ensureUint8Array(ownKeys.x25519SecretKey, "x25519SecretKey");
      const classicalShared = computeClassicalSharedSecret(x25519Secret, ephemeralPublic);
      const { encKey, macKey } = await deriveInnerKeyMaterial(pqSharedSecret, classicalShared, innerSalt, routingDigest);

      try {
        const macInput = concatUint8Arrays(innerNonce, innerCiphertext, innerTag, routingDigest, ephemeralPublic, textEncoder.encode(innerLayer.payloadType));
        const innerMacValid = await HashingService.verifyBlake3Mac(macInput, macKey, innerMac);
        if (!innerMacValid) {
          throw new Error("Inner MAC verification failed");
        }

        const aad = textEncoder.encode(innerLayer.payloadType);
        const plaintextBytes = PostQuantumAEAD.decrypt(innerCiphertext, innerNonce, innerTag, encKey, aad);
        let payloadText: string | undefined;
        let payloadJson: unknown | undefined;
        if (innerLayer.payloadType === "text" || innerLayer.payloadType === "json") {
          payloadText = textDecoder.decode(plaintextBytes);
          if (innerLayer.payloadType === "json") {
            try {
              payloadJson = JSON.parse(payloadText);
            } catch (_error) {
              throw new Error("Invalid JSON payload format");
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

class PostQuantumHybridService {
  static async generateHybridKeyPair() {
    return Hybrid.generateHybridKeyPair();
  }

  static async exportPublicKeys(hybridKeyPair: any) {
    return {
      kyberPublicBase64: hybridKeyPair.kyber.publicKeyBase64,
      dilithiumPublicBase64: hybridKeyPair.dilithium.publicKeyBase64
    };
  }

  static async signMessage(message: Uint8Array, dilithiumSecretKey: Uint8Array) {
    return await DilithiumService.sign(dilithiumSecretKey, message);
  }

  static async verifySignature(signature: Uint8Array, message: Uint8Array, dilithiumPublicKey: Uint8Array) {
    return await DilithiumService.verify(signature, message, dilithiumPublicKey);
  }
}

export const CryptoUtils = {
  Config: CryptoConfig,
  Base64,
  Hash: HashingService,
  Keys: KeyService,
  Encrypt: EncryptService,
  Decrypt: DecryptService,
  Hybrid,
  Kyber: KyberService,
  Dilithium: DilithiumService,
  PostQuantum: PostQuantumHybridService,
  PostQuantumAEAD,
  AES,
  KDF,
  SecureMemory
};

