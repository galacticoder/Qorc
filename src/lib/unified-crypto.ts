import * as argon2 from "argon2-wasm";
import { MlKem768 } from "mlkem";

type Uint8ArrOrBuf = Uint8Array | ArrayBuffer;

const subtle = (globalThis as any).crypto?.subtle;

class CryptoConfig {
  static AES_KEY_SIZE = 256;
  static IV_LENGTH = 16;
  static AUTH_TAG_LENGTH = 16;
  static HKDF_HASH = "SHA-512";
  static HKDF_INFO = new TextEncoder().encode("endtoend-chat hybrid key v1");
  static X25519_DERIVE_BITS = 256;
}

class Base64 {
  static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    return this.base64ToUint8Array(base64).buffer;
  }

  static stringToArrayBuffer(str: string): ArrayBuffer {
    return new TextEncoder().encode(str).buffer;
  }
}

class HashingService {
  static parseArgon2Hash(encodedHash: string) {
    const parts = encodedHash.split("$");
    if (parts.length !== 6) throw new Error("Invalid Argon2 encoded hash format");

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;
    const version = parseInt(versionPart.split("=")[1], 10);

    const params: Record<string, number> = {};
    paramsPart.split(",").forEach((param) => {
      const [k, v] = param.split("=");
      if (k && v) params[k] = Number(v);
    });

    const hashBytes = Uint8Array.from(atob(hashB64), (c) => c.charCodeAt(0));
    return {
      version,
      algorithm,
      salt: saltB64,
      memoryCost: params.m,
      timeCost: params.t,
      parallelism: params.p,
      hash: hashBytes,
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
    const algMap: Record<string, number> = { argon2d: 0, argon2i: 1, argon2id: 2 };
    const algEnum = algMap[(args.algorithm ?? "argon2id").toLowerCase()] ?? 2;

    const opts = {
      pass: data,
      salt: saltBuffer,
      time: args.timeCost ?? 3,
      mem: args.memoryCost ?? 65536,
      parallelism: args.parallelism ?? 1,
      type: algEnum,
      version: args.version ?? 0x13,
      hashLen: 32,
    };

    const result = await argon2.hash(opts);
    return result.encoded;
  }

  static async hashData(data: string) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const opts = {
      pass: data,
      salt,
      time: 3,
      mem: 2 ** 16,
      parallelism: 1,
      type: 2,
      version: 0x13,
      hashLen: 32,
    };
    const res = await argon2.hash(opts);
    return res.encoded;
  }

  static async verifyHash(encoded: string, data: string) {
    const r = await argon2.verify({ pass: data, encoded });
    return r.verified;
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

    let { time = 5, memoryCost = 2 ** 17, parallelism = 2, algorithm = 2, version = 0x13, hashLen = 32 } = options || {};

    if (typeof algorithm === "string") {
      switch (algorithm.toLowerCase()) {
        case "argon2d":
          algorithm = 0;
          break;
        case "argon2i":
          algorithm = 1;
          break;
        case "argon2id":
          algorithm = 2;
          break;
        default:
          throw new Error(`Unknown Argon2 algorithm: ${algorithm}`);
      }
    }

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: algorithm,
      version,
      hashLen,
    };

    const result = await argon2.hash(hashOptions);
    return result.hash;
  }
}

class KeyService {
  static async generateAESKey(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async importAESKey(keyBytes: ArrayBuffer | Uint8Array): Promise<CryptoKey> {
    const rawKey = keyBytes instanceof Uint8Array ? keyBytes.buffer : keyBytes;
    return await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async exportAESKey(aesKey: CryptoKey): Promise<ArrayBuffer> {
    return await crypto.subtle.exportKey("raw", aesKey);
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
    const saltBytes = options?.saltBase64
      ? Base64.base64ToUint8Array(options.saltBase64)
      : crypto.getRandomValues(new Uint8Array(16));

    let { time = 5, memoryCost = 2 ** 17, parallelism = 2, algorithm = 2, version = 0x13, hashLen = 32 } = options || {};

    if (typeof algorithm === "string") {
      switch (algorithm.toLowerCase()) {
        case "argon2d":
          algorithm = 0;
          break;
        case "argon2i":
          algorithm = 1;
          break;
        case "argon2id":
          algorithm = 2;
          break;
        default:
          throw new Error(`Unknown Argon2 algorithm: ${algorithm}`);
      }
    }

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: algorithm,
      version,
      hashLen,
    };

    const result = await argon2.hash(hashOptions);
    const rawKeyBytes = result.hash;
    const aesKey = await this.importAESKey(rawKeyBytes);

    return {
      aesKey,
      encodedHash: result.encoded,
    };
  }
}

class X25519Service {
  private static nobleX: any | null = null;

  static async _loadNobleIfNeeded() {
    if (this.nobleX) return this.nobleX;
    try {
      const mod = await import("@noble/curves/ed25519");
      const x =
        (mod as any).x25519 ||
        (mod as any).x25519
      this.nobleX = x;
      return x;
    } catch (e) {
      try {
        const root = await import("@noble/curves");
        const x = (root as any).x25519;
        if (!x) throw e;
        this.nobleX = x;
        return x;
      } catch (err) {
        console.warn("Noble x25519 dynamic import failed:", err);
        throw new Error("No X25519 implementation available in this environment");
      }
    }
  }

  static supportsWebCryptoX25519(): boolean {
    try {
      if (!subtle || typeof subtle.generateKey !== "function") return false;

      return true;
    } catch {
      return false;
    }
  }

  static async generateKeyPair() {
    if (this.supportsWebCryptoX25519()) {
      try {
        const kp = await (subtle as SubtleCrypto).generateKey({ name: "X25519" } as any, true, [
          "deriveBits",
        ]);
        return kp as CryptoKeyPair;
      } catch (err) {
        console.warn("WebCrypto X25519 failed; falling back to noble", err);
      }
    }

    const x = await this._loadNobleIfNeeded();

    const priv = x.utils.randomPrivateKey();
    const pub = x.getPublicKey(priv);

    return {
      privateKeyBytes: priv,
      publicKeyBytes: pub,
    } as any;
  }

  static async generateKeyPairFromPrivateKey(privateKeyBytes: Uint8Array) {
    const x = await this._loadNobleIfNeeded();
    const publicKey = x.getPublicKey(privateKeyBytes);
    return {
      publicKeyBytes: publicKey,
      privateKeyBytes: privateKeyBytes,
    };
  }

  static async exportPublicRaw(keyLike: CryptoKey | { publicKeyBytes: Uint8Array }) {
    if ((keyLike as CryptoKey).type) {
      const raw = await (subtle as SubtleCrypto).exportKey("raw", keyLike as CryptoKey);
      return new Uint8Array(raw);
    } else {
      return (keyLike as any).publicKeyBytes as Uint8Array;
    }
  }

  static async importPublicRaw(raw: Uint8Array) {
    if (this.supportsWebCryptoX25519()) {
      try {
        const pub = await (subtle as SubtleCrypto).importKey("raw", raw, { name: "X25519" } as any, true, []);
        return pub as CryptoKey;
      } catch (err) {
        console.warn("WebCrypto importKey raw failed; using raw bytes", err);
      }
    }
    return raw;
  }

  static async deriveSharedSecret(privateKeyOrBytes: CryptoKey | Uint8Array, remotePublicRaw: Uint8Array) {
    if (this.supportsWebCryptoX25519() && (privateKeyOrBytes as CryptoKey).type) {
      const bits = await (subtle as SubtleCrypto).deriveBits(
        { name: "X25519", public: (await this.importPublicRaw(remotePublicRaw)) as any } as any,
        privateKeyOrBytes as CryptoKey,
        CryptoConfig.X25519_DERIVE_BITS
      );
      return new Uint8Array(bits);
    }

    const x = await this._loadNobleIfNeeded();
    const privBytes = (privateKeyOrBytes as any).privateKeyBytes ?? (privateKeyOrBytes as Uint8Array);
    const shared = x.getSharedSecret(privBytes, remotePublicRaw);
    return new Uint8Array(shared.slice(0, 32));
  }
}

class KyberService {
  static kyberInstance() {
    return new MlKem768()
  }

  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const ky = this.kyberInstance();
    const kp = await ky.generateKeyPair();
    if (Array.isArray(kp)) {
      const [pub, sec] = kp;
      return { publicKey: new Uint8Array(pub), secretKey: new Uint8Array(sec) };
    } else if ((kp as any).publicKey && (kp as any).secretKey) {
      return { publicKey: new Uint8Array((kp as any).publicKey), secretKey: new Uint8Array((kp as any).secretKey) };
    } else {
      throw new Error("Unexpected Kyber generateKeyPair result");
    }
  }

  static async generateKeyPairFromSeed(seed: Uint8Array): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const ky = this.kyberInstance();

    const kp = await ky.generateKeyPair();
    if (Array.isArray(kp)) {
      const [pub, sec] = kp;
      return { publicKey: new Uint8Array(pub), secretKey: new Uint8Array(sec) };
    } else if ((kp as any).publicKey && (kp as any).secretKey) {
      return { publicKey: new Uint8Array((kp as any).publicKey), secretKey: new Uint8Array((kp as any).secretKey) };
    } else {
      throw new Error("Unexpected Kyber generateKeyPair result");
    }
  }

  static async encapsulate(publicKey: Uint8Array) {
    const ky = this.kyberInstance();
    const out = await ky.encap(publicKey);
    if (Array.isArray(out)) {
      const [ciphertext, shared] = out;
      return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(shared) };
    } else if ((out as any).ciphertext && (out as any).sharedSecret) {
      return { ciphertext: new Uint8Array((out as any).ciphertext), sharedSecret: new Uint8Array((out as any).sharedSecret) };
    } else {
      throw new Error("Unexpected Kyber encap shape");
    }
  }

  static async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array) {
    const ky = this.kyberInstance();
    const shared = await ky.decap(ciphertext, secretKey);
    return new Uint8Array(shared);
  }
}

class KDF {
  static async deriveAesCryptoKeyFromIkm(ikm: Uint8Array, salt: Uint8Array) {
    const baseKey = await (subtle as SubtleCrypto).importKey("raw", ikm, { name: "HKDF" }, false, ["deriveKey"]);
    const derivedKey = await (subtle as SubtleCrypto).deriveKey(
      { name: "HKDF", hash: CryptoConfig.HKDF_HASH, salt: salt, info: CryptoConfig.HKDF_INFO },
      baseKey,
      { name: "AES-GCM", length: CryptoConfig.AES_KEY_SIZE },
      true,
      ["encrypt", "decrypt"]
    );
    return derivedKey;
  }
}

class AES {
  static async encryptWithAesGcmRaw(data: string | Uint8Array, cryptoKey: CryptoKey) {
    let dataBuf: Uint8Array;
    if (typeof data === "string") dataBuf = new TextEncoder().encode(data);
    else dataBuf = data instanceof Uint8Array ? data : new Uint8Array(data);

    const iv = crypto.getRandomValues(new Uint8Array(CryptoConfig.IV_LENGTH));
    const cipherBuf = await (subtle as SubtleCrypto).encrypt(
      { name: "AES-GCM", iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      dataBuf
    );
    const cipherArray = new Uint8Array(cipherBuf);
    const tagLen = CryptoConfig.AUTH_TAG_LENGTH;
    const encrypted = cipherArray.slice(0, -tagLen);
    const authTag = cipherArray.slice(-tagLen);
    return { iv, authTag, encrypted };
  }

  static async decryptWithAesGcmRaw(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, cryptoKey: CryptoKey) {
    const combined = new Uint8Array(encrypted.length + authTag.length);
    combined.set(encrypted, 0);
    combined.set(authTag, encrypted.length);
    const plainBuf = await (subtle as SubtleCrypto).decrypt(
      { name: "AES-GCM", iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      combined
    );
    return new TextDecoder().decode(plainBuf);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array) {
    const version = 1;
    const total = 1 + 1 + iv.length + 1 + authTag.length + 4 + encrypted.length;
    const out = new Uint8Array(total);
    let off = 0;
    out[off++] = version;
    out[off++] = iv.length;
    out.set(iv, off);
    off += iv.length;
    out[off++] = authTag.length;
    out.set(authTag, off);
    off += authTag.length;
    const encLen = encrypted.length;
    out[off++] = (encLen >>> 24) & 0xff;
    out[off++] = (encLen >>> 16) & 0xff;
    out[off++] = (encLen >>> 8) & 0xff;
    out[off++] = encLen & 0xff;
    out.set(encrypted, off);
    return Base64.arrayBufferToBase64(out);
  }

  static deserializeEncryptedData(serialized: string) {
    const combined = new Uint8Array(Base64.base64ToUint8Array(serialized));
    let off = 0;
    const version = combined[off++];
    if (version !== 1) throw new Error("Unsupported version");
    const ivLen = combined[off++];
    const iv = combined.slice(off, off + ivLen);
    off += ivLen;
    const tagLen = combined[off++];
    const authTag = combined.slice(off, off + tagLen);
    off += tagLen;
    const encLen = (combined[off] << 24) | (combined[off + 1] << 16) | (combined[off + 2] << 8) | combined[off + 3];
    off += 4;
    const encrypted = combined.slice(off, off + encLen);
    return { iv, authTag, encrypted };
  }
}

class EncryptService {
  static async encryptWithAES(data: string, aesKey: CryptoKey): Promise<string> {
    const { iv, authTag, encrypted } = await AES.encryptWithAesGcmRaw(data, aesKey);
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptBinaryWithAES(data: Uint8Array, aesKey: CryptoKey): Promise<{ iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array }> {
    return await AES.encryptWithAesGcmRaw(data, aesKey);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptAndFormatPayload(payload: any): Promise<string> {
    const { recipientHybridKeys, from, to, type, ...encryptedContent } = payload;

    if (!recipientHybridKeys) {
      return JSON.stringify(payload);
    }

    const encryptedPayload = await CryptoUtils.Hybrid.encryptHybridPayload(
      encryptedContent,
      recipientHybridKeys
    );

    return JSON.stringify({
      ...(from && { from }),
      ...(to && { to }),
      ...(type && { type }),
      ...encryptedPayload,
    });
  }
}

class DecryptService {
  static deserializeEncryptedDataFromUint8Array(encryptedBytes: Uint8Array): { iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array } {
    const combined = new Uint8Array(encryptedBytes);
    let off = 0;
    const version = combined[off++];
    if (version !== 1) throw new Error("Unsupported version");
    const ivLen = combined[off++];
    const iv = combined.slice(off, off + ivLen);
    off += ivLen;
    const tagLen = combined[off++];
    const authTag = combined.slice(off, off + tagLen);
    off += tagLen;
    const encLen = (combined[off] << 24) | (combined[off + 1] << 16) | (combined[off + 2] << 8) | combined[off + 3];
    off += 4;
    const encrypted = combined.slice(off, off + encLen);
    return { iv, authTag, encrypted };
  }

  static async decryptWithAESRaw(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, aesKey: CryptoKey): Promise<string> {
    return await AES.decryptWithAesGcmRaw(iv, authTag, encrypted, aesKey);
  }
}

class Hybrid {
  static async generateHybridKeyPair() {
    const xkp = await X25519Service.generateKeyPair();
    const kyberKP = await KyberService.generateKeyPair();

    let xPublicRaw: Uint8Array;
    if ((xkp as any).publicKey) {
      xPublicRaw = await X25519Service.exportPublicRaw((xkp as any).publicKey);
    } else if ((xkp as any).publicKeyBytes) {
      xPublicRaw = (xkp as any).publicKeyBytes as Uint8Array;
    } else {
      throw new Error("Unexpected xkp shape");
    }

    return {
      x25519: {
        private: (xkp as any).privateKey ?? (xkp as any).privateKeyBytes,
        publicKeyBase64: Base64.arrayBufferToBase64(xPublicRaw),
      },
      kyber: {
        publicKeyBase64: Base64.arrayBufferToBase64(kyberKP.publicKey),
        secretKey: kyberKP.secretKey,
      },
    };
  }

  static async generateHybridKeyPairFromSeed(seed: string) {
    const x = await X25519Service._loadNobleIfNeeded();

    const encoder = new TextEncoder();
    const seedBytes = encoder.encode(seed);
    const hash = await crypto.subtle.digest('SHA-256', seedBytes);
    const hashArray = new Uint8Array(hash);

    const x25519PrivateKey = x.utils.randomPrivateKey();
    for (let i = 0; i < 32; i++) {
      x25519PrivateKey[i] = hashArray[i];
    }

    x25519PrivateKey[0] &= 248;
    x25519PrivateKey[31] &= 127;
    x25519PrivateKey[31] |= 64;

    const x25519PublicKey = x.getPublicKey(x25519PrivateKey);

    const kyberSeed = hashArray.slice(32, 64);
    const kyberKP = await KyberService.generateKeyPairFromSeed(kyberSeed);

    return {
      x25519: {
        private: x25519PrivateKey,
        publicKeyBase64: Base64.arrayBufferToBase64(x25519PublicKey),
      },
      kyber: {
        publicKeyBase64: Base64.arrayBufferToBase64(kyberKP.publicKey),
        secretKey: kyberKP.secretKey,
      },
    };
  }

  static async encryptHybridPayload(payloadObj: any, recipientHybridPublic: { x25519PublicBase64: string; kyberPublicBase64: string; }) {
    if (!recipientHybridPublic?.x25519PublicBase64 || !recipientHybridPublic?.kyberPublicBase64) {
      throw new Error("recipient must include x25519PublicBase64 and kyberPublicBase64");
    }

    const eph = await X25519Service.generateKeyPair();
    let ephPubRaw: Uint8Array;
    if ((eph as any).publicKey) ephPubRaw = await X25519Service.exportPublicRaw((eph as any).publicKey);
    else ephPubRaw = (eph as any).publicKeyBytes as Uint8Array;

    const recipientKyberPub = Base64.base64ToUint8Array(recipientHybridPublic.kyberPublicBase64);
    const { ciphertext: kyberCiphertext, sharedSecret: kyberShared } = await KyberService.encapsulate(recipientKyberPub);

    const recipientXRaw = Base64.base64ToUint8Array(recipientHybridPublic.x25519PublicBase64);
    const xShared = await X25519Service.deriveSharedSecret((eph as any).privateKey ?? (eph as any).privateKeyBytes, recipientXRaw);

    const ikm = new Uint8Array(xShared.length + kyberShared.length);
    ikm.set(xShared, 0);
    ikm.set(kyberShared, xShared.length);

    const saltFull = await crypto.subtle.digest("SHA-512", (() => {
      const arr = new Uint8Array(ephPubRaw.length + kyberCiphertext.length);
      arr.set(ephPubRaw, 0);
      arr.set(kyberCiphertext, ephPubRaw.length);
      return arr;
    })());
    const salt = new Uint8Array(saltFull).slice(0, 32);

    const aesKey = await KDF.deriveAesCryptoKeyFromIkm(ikm, salt);

    const jsonStr = JSON.stringify(payloadObj);
    const { iv, authTag, encrypted } = await AES.encryptWithAesGcmRaw(jsonStr, aesKey);
    const serialized = AES.serializeEncryptedData(iv, authTag, encrypted);

    return {
      version: "hybrid-v1",
      ephemeralX25519Public: Base64.arrayBufferToBase64(ephPubRaw),
      kyberCiphertext: Base64.arrayBufferToBase64(kyberCiphertext),
      encryptedMessage: serialized,
    };
  }

  static async decryptHybridPayload(encryptedPayload: any, localHybridKeys: any) {
    if (!encryptedPayload || encryptedPayload.version !== "hybrid-v1") throw new Error("Invalid payload version");

    const { ephemeralX25519Public, kyberCiphertext, encryptedMessage } = encryptedPayload;
    if (!ephemeralX25519Public || !kyberCiphertext || !encryptedMessage) throw new Error("Missing fields");

    const ephPubRaw = Base64.base64ToUint8Array(ephemeralX25519Public);
    const kyCt = Base64.base64ToUint8Array(kyberCiphertext);

    const kyberSecret = localHybridKeys?.kyber?.secretKey as Uint8Array;
    if (!kyberSecret) throw new Error("localHybridKeys.kyber.secretKey required");
    const kyShared = await KyberService.decapsulate(kyCt, kyberSecret);

    const localXPrivate = localHybridKeys?.x25519?.private;
    if (!localXPrivate) throw new Error("localHybridKeys.x25519.private required");
    const xShared = await X25519Service.deriveSharedSecret(localXPrivate, ephPubRaw);

    const ikm = new Uint8Array(xShared.length + kyShared.length);
    ikm.set(xShared, 0);
    ikm.set(kyShared, xShared.length);

    const saltFull = await crypto.subtle.digest("SHA-512", (() => {
      const arr = new Uint8Array(ephPubRaw.length + kyCt.length);
      arr.set(ephPubRaw, 0);
      arr.set(kyCt, ephPubRaw.length);
      return arr;
    })());
    const salt = new Uint8Array(saltFull).slice(0, 32);

    const aesKey = await KDF.deriveAesCryptoKeyFromIkm(ikm, salt);

    const des = AES.deserializeEncryptedData(encryptedMessage);
    const decryptedJson = await AES.decryptWithAesGcmRaw(des.iv, des.authTag, des.encrypted, aesKey);

    return JSON.parse(decryptedJson);
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
  X25519: X25519Service,
  Kyber: KyberService,
  AES,
  KDF,
};
