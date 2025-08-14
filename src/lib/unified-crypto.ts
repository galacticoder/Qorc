import * as argon2 from "argon2-wasm";

class CryptoConfig {
  static RSA_KEY_SIZE = 4096;
  static AES_KEY_SIZE = 256;
  static IV_LENGTH = 16;
  static AUTH_TAG_LENGTH = 16;
  static HASH_ALGORITHM = 'SHA-512';
}

class Base64Utils {
  static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  static stringToArrayBuffer(str: string): ArrayBuffer {
    const encoder = new TextEncoder();
    return encoder.encode(str);
  }
}

class HashingService {
  static parseArgon2Hash(encodedHash: string) {
    const parts = encodedHash.split('$');
    if (parts.length !== 6) throw new Error('Invalid Argon2 encoded hash format');

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;

    const version = parseInt(versionPart.split('=')[1], 10);

    const params: { [key: string]: number } = {};
    paramsPart.split(',').forEach(param => {
      const [key, value] = param.split('=');
      if (key && value) params[key] = Number(value);
    });

    const saltBase64 = saltB64;
    const hashBytes = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0));

    return {
      version,
      algorithm,
      salt: saltBase64,
      memoryCost: params.m,
      timeCost: params.t,
      parallelism: params.p,
      hash: hashBytes,
    };
  }

  static async hashDataUsingInfo(data: string, args: {
    version?: number;
    algorithm?: string;
    salt: string;
    memoryCost?: number;
    timeCost?: number;
    parallelism?: number;
  }): Promise<string> {
    if (!args?.salt) {
      throw new Error("Salt is required");
    }

    console.log("Server hashing info received: ", args)

    const saltBufferRaw = CryptoUtils.Base64.base64ToArrayBuffer(args.salt);
    const saltBuffer = new Uint8Array(saltBufferRaw);

    console.log("Decoded salt buffer length:", saltBuffer.byteLength);
    if (saltBuffer.byteLength < 8) {
      throw new Error("Salt length is too short for Argon2 hashing.");
    }

    // map string alg to argon2 enum
    const algMap: Record<string, number> = {
      argon2d: 0,
      argon2i: 1,
      argon2id: 2,
    };

    const algEnum = algMap[(args.algorithm ?? 'argon2id').toLowerCase()] ?? 2;


    const hashOptions = {
      pass: data,
      salt: saltBuffer,
      time: args.timeCost ?? 3,
      mem: args.memoryCost ?? 65536,
      parallelism: args.parallelism ?? 1,
      type: algEnum,
      version: args.version ?? 0x13,
      hashLen: 32,
    };

    const result = await argon2.hash(hashOptions);
    return result.encoded;
  }

  static compareHashes(hash1: Buffer, hash2: Buffer): boolean {
    if (hash1.length !== hash2.length) return false;

    let diff = 0;
    for (let i = 0; i < hash1.length; i++) {
      diff |= hash1[i] ^ hash2[i];
    }
    return diff === 0;
  }


  static async hashData(data: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16)); //gen 16 byte salt

    const hashOptions = {
      pass: data,
      salt: salt,
      time: 3,
      mem: 2 ** 16,
      parallelism: 1,
      type: 2,
      version: 0x13,
      hashLen: 32,
    };

    const encodedHash = await argon2.hash(hashOptions);

    console.log("Argon2 hash created: ", encodedHash.encoded)
    return encodedHash.encoded;
  }

  static async verifyHash(hash: string, data: string): Promise<boolean> {
    const result = await argon2.verify({
      pass: data,
      encoded: hash,
    });
    return result.verified;
  }
}

class KeyService {
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

    const saltBytes = options?.saltBase64 //decode or gen salt
      ? Uint8Array.from(atob(options.saltBase64), c => c.charCodeAt(0))
      : crypto.getRandomValues(new Uint8Array(16));

    //merge options with defaults
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
    const aesKey = await KeyService.importAESKey(rawKeyBytes.buffer);

    return {
      aesKey,
      encodedHash: result.encoded, //for verification
    };
  }

  static async generateRSAKeyPair(): Promise<CryptoKeyPair> {
    return await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: CryptoConfig.RSA_KEY_SIZE,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: CryptoConfig.HASH_ALGORITHM,
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async generateAESKey(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: CryptoConfig.AES_KEY_SIZE,
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async exportPublicKeyToPEM(publicKey: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    const base64 = Base64Utils.arrayBufferToBase64(exported);
    const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
  }

  static async exportPrivateKeyToPEM(privateKey: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    const base64 = Base64Utils.arrayBufferToBase64(exported);
    const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
  }

  static async importPublicKeyFromPEM(pem: string): Promise<CryptoKey> {
    const pemContents = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '');
    const binaryDer = Base64Utils.base64ToArrayBuffer(pemContents);
    return await crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: CryptoConfig.HASH_ALGORITHM,
      },
      true,
      ["encrypt"]
    );
  }

  static async importPrivateKeyFromPEM(pem: string): Promise<CryptoKey> {
    const pemContents = pem
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s/g, '');
    const binaryDer = Base64Utils.base64ToArrayBuffer(pemContents);
    return await crypto.subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: CryptoConfig.HASH_ALGORITHM,
      },
      true,
      ["decrypt"]
    );
  }

  static async exportAESKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await crypto.subtle.exportKey("raw", key);
  }

  static async importAESKey(keyData: ArrayBuffer): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"]
    );
  }
}

class EncryptionService {
  static async encryptWithRSA(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> {
    return await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      data
    );
  }

  static async encryptBinaryWithAES(
    data: ArrayBuffer | Uint8Array,
    key: CryptoKey
  ): Promise<{
    iv: Uint8Array;
    authTag: Uint8Array;
    encrypted: Uint8Array;
  }> {
    const iv = crypto.getRandomValues(new Uint8Array(CryptoConfig.IV_LENGTH));
    const dataBuffer = data instanceof Uint8Array ? data.buffer : data;
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8,
      },
      key,
      dataBuffer
    );

    const resultArray = new Uint8Array(encryptedBuffer);
    const encrypted = resultArray.slice(0, -CryptoConfig.AUTH_TAG_LENGTH);
    const authTag = resultArray.slice(-CryptoConfig.AUTH_TAG_LENGTH);

    return { iv, authTag, encrypted };
  }

  static async encryptWithAES(data: string, key: CryptoKey): Promise<{
    iv: Uint8Array;
    authTag: Uint8Array;
    encrypted: Uint8Array;
  }> {
    const iv = crypto.getRandomValues(new Uint8Array(CryptoConfig.IV_LENGTH));
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const result = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8,
      },
      key,
      dataBuffer
    );

    const resultArray = new Uint8Array(result);
    const encrypted = resultArray.slice(0, -CryptoConfig.AUTH_TAG_LENGTH);
    const authTag = resultArray.slice(-CryptoConfig.AUTH_TAG_LENGTH);

    return {
      iv,
      authTag,
      encrypted,
    };
  }

  static serializeEncryptedData(
    iv: Uint8Array,
    authTag: Uint8Array,
    encrypted: Uint8Array
  ): string {
    const version = 1;
    const totalLength = 1 + 1 + iv.length + 1 + authTag.length + 4 + encrypted.length;
    const combined = new Uint8Array(totalLength);

    let offset = 0;

    combined[offset++] = version;

    combined[offset++] = iv.length;
    combined.set(iv, offset);
    offset += iv.length;

    combined[offset++] = authTag.length;
    combined.set(authTag, offset);
    offset += authTag.length;

    const encryptedLength = encrypted.length;
    combined[offset++] = (encryptedLength >>> 24) & 0xff;
    combined[offset++] = (encryptedLength >>> 16) & 0xff;
    combined[offset++] = (encryptedLength >>> 8) & 0xff;
    combined[offset++] = encryptedLength & 0xff;

    combined.set(encrypted, offset);

    return Base64Utils.arrayBufferToBase64(combined);
  }

  static async encryptAndFormatPayload(input: Record<string, any>) {
    const { recipientPEM, from, to, type, ...encryptedContent } = input;

    if (!recipientPEM) throw new Error("Missing recipientPEM");

    const recipientKey = await KeyService.importPublicKeyFromPEM(recipientPEM);
    const aesKey = await KeyService.generateAESKey();

    const { iv, authTag, encrypted } = await this.encryptWithAES(
      JSON.stringify(encryptedContent),
      aesKey
    );

    const encryptedMessage = this.serializeEncryptedData(iv, authTag, encrypted);
    const rawAes = await KeyService.exportAESKey(aesKey);
    const encryptedAes = await this.encryptWithRSA(rawAes, recipientKey);
    const encryptedAESKeyBase64 = Base64Utils.arrayBufferToBase64(encryptedAes);

    return {
      ...(from && { from }),
      ...(to && { to }),
      ...(type && { type }),
      encryptedAESKey: encryptedAESKeyBase64,
      encryptedMessage,
    };
  }
}

class DecryptionService {
  static async decryptWithRSA(encryptedData: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
    return await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedData
    );
  }

  static async decryptWithAES(
    encrypted: Uint8Array,
    iv: Uint8Array,
    authTag: Uint8Array,
    key: CryptoKey
  ): Promise<string> {
    const combined = new Uint8Array(encrypted.length + authTag.length);
    combined.set(encrypted);
    combined.set(authTag, encrypted.length);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8,
      },
      key,
      combined.buffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  static async decryptWithAESRaw(
    encrypted: Uint8Array,
    iv: Uint8Array,
    authTag: Uint8Array,
    key: CryptoKey
  ): Promise<ArrayBuffer> {
    const combined = new Uint8Array(encrypted.length + authTag.length);
    combined.set(encrypted);
    combined.set(authTag, encrypted.length);

    return await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8,
      },
      key,
      combined.buffer
    );
  }

  static deserializeEncryptedData(serialized: string): {
    iv: Uint8Array;
    authTag: Uint8Array;
    encrypted: Uint8Array;
  } {
    const combined = new Uint8Array(Base64Utils.base64ToArrayBuffer(serialized));
    let offset = 0;

    const version = combined[offset];
    if (version !== 1) {
      throw new Error(`Unsupported encryption version: ${version}`);
    }
    offset += 1;

    const ivLength = combined[offset];
    offset += 1;
    const iv = combined.slice(offset, offset + ivLength);
    offset += ivLength;

    const authTagLength = combined[offset];
    offset += 1;
    const authTag = combined.slice(offset, offset + authTagLength);
    offset += authTagLength;

    const encryptedLength =
      (combined[offset] << 24) |
      (combined[offset + 1] << 16) |
      (combined[offset + 2] << 8) |
      combined[offset + 3];
    offset += 4;

    const encrypted = combined.slice(offset, offset + encryptedLength);

    return { iv, authTag, encrypted };
  }

  static deserializeEncryptedDataFromUint8Array(
    combined: Uint8Array
  ): {
    iv: Uint8Array;
    authTag: Uint8Array;
    encrypted: Uint8Array;
  } {
    let offset = 0;

    const version = combined[offset];
    if (version !== 1) {
      throw new Error(`Unsupported encryption version: ${version}`);
    }
    offset += 1;

    const ivLength = combined[offset];
    offset += 1;
    const iv = combined.slice(offset, offset + ivLength);
    offset += ivLength;

    const authTagLength = combined[offset];
    offset += 1;
    const authTag = combined.slice(offset, offset + authTagLength);
    offset += authTagLength;

    const encryptedLength =
      (combined[offset] << 24) |
      (combined[offset + 1] << 16) |
      (combined[offset + 2] << 8) |
      combined[offset + 3];
    offset += 4;

    const encrypted = combined.slice(offset, offset + encryptedLength);

    return { iv, authTag, encrypted };
  }

  static async decryptAESKeyWithRSA(encryptedKey: ArrayBuffer, privateKey: CryptoKey): Promise<CryptoKey> {
    const keyData = await DecryptionService.decryptWithRSA(encryptedKey, privateKey);
    return await KeyService.importAESKey(keyData);
  }

  static async decryptMessage(encryptedData: string, aesKey: CryptoKey): Promise<string> {
    const { iv, authTag, encrypted } = this.deserializeEncryptedData(encryptedData);
    return await this.decryptWithAES(encrypted, iv, authTag, aesKey);
  }

  static async decryptAndFormatPayload(
    encryptedPayload: Record<string, any>,
    privateKey: CryptoKey | null
  ) {
    if (!privateKey) {
      throw new Error("Private key is required for decryption");
    }

    const { encryptedAESKey, encryptedMessage, ...restFields } = encryptedPayload;

    if (!encryptedAESKey || !encryptedMessage) {
      throw new Error("Invalid encrypted payload structure");
    }

    const encryptedAesKeyBuffer = Base64Utils.base64ToArrayBuffer(encryptedAESKey);
    const aesKey = await DecryptionService.decryptAESKeyWithRSA(encryptedAesKeyBuffer, privateKey);

    const decryptedJsonString = await this.decryptMessage(encryptedMessage, aesKey);

    const decryptedPayload = JSON.parse(decryptedJsonString);

    return {
      ...restFields,
      ...decryptedPayload,
    };
  }
}

export const CryptoUtils = {
  Config: CryptoConfig,
  Base64: Base64Utils,
  Hash: HashingService,
  Keys: KeyService,
  Encrypt: EncryptionService,
  Decrypt: DecryptionService,
};
