import { webcrypto } from 'crypto';
import argon2 from 'argon2';
import { MlKem768 } from 'mlkem';

const crypto = webcrypto;

class CryptoConfig {
  static AES_KEY_SIZE = 256;
  static IV_LENGTH = 16;
  static AUTH_TAG_LENGTH = 16;
  static HKDF_HASH = 'SHA-512';
  static HKDF_INFO = new TextEncoder().encode('endtoend-chat hybrid key v1');
  static X25519_DERIVE_BITS = 256;
}

class RandomGenerator {
  static generateSecureRandom(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }
}

class HashService {
  static stringToUint8Array(str) {
    return new TextEncoder().encode(str);
  }

  static arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Buffer.from(bytes).toString('base64');
  }

  static base64ToUint8Array(base64) {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }

  static async digestSHA512Bytes(...parts) {
    const totalLen = parts.reduce((s, p) => s + (p?.byteLength ?? 0), 0);
    const joined = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      const arr = p instanceof Uint8Array ? p : new Uint8Array(p);
      joined.set(arr, offset);
      offset += arr.length;
    }
    const hashBuf = await crypto.subtle.digest('SHA-512', joined);
    return new Uint8Array(hashBuf);
  }
}

class X25519Service {
  static async generateKeyPair() {
    return await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    );
  }

  static async exportPublicKeyRaw(publicKeyCryptoKey) {
    const raw = await crypto.subtle.exportKey('raw', publicKeyCryptoKey);
    return new Uint8Array(raw);
  }

  static async importPublicKeyRaw(rawPubBytes) {
    return await crypto.subtle.importKey(
      'raw',
      rawPubBytes,
      { name: 'X25519' },
      false,
      []
    );
  }

  static async deriveSharedSecretBits(privateKeyCryptoKey, remotePublicRaw) {
    const remotePubKey = await this.importPublicKeyRaw(remotePublicRaw);
    const bits = await crypto.subtle.deriveBits(
      { name: 'X25519', public: remotePubKey },
      privateKeyCryptoKey,
      CryptoConfig.X25519_DERIVE_BITS
    );
    return new Uint8Array(bits);
  }
}

class KyberService {
  static kyberInstance() {
    return new MlKem768();
  }

  static async generateKeyPair() {
    const kyber = this.kyberInstance();
    const result = await kyber.generateKeyPair();

    if (Array.isArray(result)) {
      const [publicKey, secretKey] = result;
      return {
        publicKey: new Uint8Array(publicKey),
        secretKey: new Uint8Array(secretKey)
      };
    }
  }

  static async encapsulate(publicKeyBytes) {
    const kyber = this.kyberInstance();
    const result = await kyber.encap(publicKeyBytes);

    const [ciphertext, sharedSecret] = result;
    return {
      ciphertext: new Uint8Array(ciphertext),
      sharedSecret: new Uint8Array(sharedSecret)
    };
  }

  static async decapsulate(ciphertextBytes, secretKeyBytes) {
    const kyber = this.kyberInstance();
    const shared = await kyber.decap(ciphertextBytes, secretKeyBytes);
    return new Uint8Array(shared);
  }
}

class KDFService {
  static async deriveAesKeyFromIkm(ikmUint8Array, saltUint8Array) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      ikmUint8Array,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const derived = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: CryptoConfig.HKDF_HASH,
        salt: saltUint8Array,
        info: CryptoConfig.HKDF_INFO,
      },
      baseKey,
      { name: 'AES-GCM', length: CryptoConfig.AES_KEY_SIZE },
      true,
      ['encrypt', 'decrypt']
    );

    return derived;
  }
}

class AESService {
  static async encryptWithAesGcmRaw(data, cryptoKey) {
    let dataBuf;
    if (typeof data === 'string') dataBuf = new TextEncoder().encode(data);
    else if (data instanceof ArrayBuffer) dataBuf = new Uint8Array(data);
    else if (data instanceof Uint8Array) dataBuf = data;
    else throw new Error('Unsupported data type for AES encrypt');

    const iv = RandomGenerator.generateSecureRandom(CryptoConfig.IV_LENGTH);

    const cipherBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      dataBuf
    );

    const cipherArray = new Uint8Array(cipherBuf);
    const tagLength = CryptoConfig.AUTH_TAG_LENGTH;
    const encrypted = cipherArray.slice(0, -tagLength);
    const authTag = cipherArray.slice(-tagLength);

    return { iv, authTag, encrypted };
  }

  static async decryptWithAesGcmRaw(iv, authTag, encrypted, cryptoKey) {
    const combined = new Uint8Array(encrypted.length + authTag.length);
    combined.set(encrypted, 0);
    combined.set(authTag, encrypted.length);

    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      combined
    );

    return new TextDecoder().decode(plainBuf);
  }

  static serializeEncryptedData(iv, authTag, encrypted) {
    const version = 1;
    const encryptedLength = encrypted.length;

    const result = new Uint8Array(
      1 +
      1 + iv.length +
      1 + authTag.length +
      4 +
      encrypted.length
    );

    let offset = 0;
    result[offset++] = version;

    result[offset++] = iv.length;
    result.set(iv, offset);
    offset += iv.length;

    result[offset++] = authTag.length;
    result.set(authTag, offset);
    offset += authTag.length;

    result[offset++] = (encryptedLength >> 24) & 0xff;
    result[offset++] = (encryptedLength >> 16) & 0xff;
    result[offset++] = (encryptedLength >> 8) & 0xff;
    result[offset++] = encryptedLength & 0xff;

    result.set(encrypted, offset);

    return Buffer.from(result).toString('base64');
  }

  static deserializeEncryptedData(base64Data) {
    const buffer = Buffer.from(base64Data, 'base64');
    let offset = 0;

    const version = buffer[offset++];
    if (version !== 1) throw new Error(`Unsupported version: ${version}`);

    const ivLength = buffer[offset++];
    const iv = new Uint8Array(buffer.slice(offset, offset + ivLength));
    offset += ivLength;

    const authTagLength = buffer[offset++];
    const authTag = new Uint8Array(buffer.slice(offset, offset + authTagLength));
    offset += authTagLength;

    const encryptedLength =
      (buffer[offset++] << 24) |
      (buffer[offset++] << 16) |
      (buffer[offset++] << 8) |
      buffer[offset++];

    const encrypted = new Uint8Array(buffer.slice(offset, offset + encryptedLength));
    return { iv, authTag, encrypted };
  }
}

class HybridService {
  static async generateHybridKeyPair() {
    const xkp = /** @type {CryptoKeyPair} */ (await X25519Service.generateKeyPair());
    const kyberKP = await KyberService.generateKeyPair();
    return {
      x25519: xkp,
      kyber: kyberKP
    };
  }

  static async exportX25519PublicBase64(publicKeyCryptoKey) {
    const raw = await X25519Service.exportPublicKeyRaw(publicKeyCryptoKey);
    return HashService.arrayBufferToBase64(raw);
  }

  static async exportKyberPublicBase64(kyberPublicUint8) {
    return HashService.arrayBufferToBase64(kyberPublicUint8);
  }

  static async importX25519PublicFromBase64(base64) {
    const raw = HashService.base64ToUint8Array(base64);
    return raw;
  }

  static async importKyberPublicFromBase64(base64) {
    return HashService.base64ToUint8Array(base64);
  }

  static async encryptHybridPayload(payloadObject, recipientHybridPublic) {
    if (!recipientHybridPublic?.x25519PublicBase64 || !recipientHybridPublic?.kyberPublicBase64) {
      throw new Error('recipientHybridPublic must include x25519PublicBase64 and kyberPublicBase64');
    }

    const eph = /** @type {CryptoKeyPair} */ (await X25519Service.generateKeyPair());
    const ephPubRaw = await X25519Service.exportPublicKeyRaw(eph.publicKey);

    const recipientKyberPub = HashService.base64ToUint8Array(recipientHybridPublic.kyberPublicBase64);
    const { ciphertext: kyberCiphertext, sharedSecret: kyberShared } = await KyberService.encapsulate(recipientKyberPub);

    const recipientX25519PubRaw = HashService.base64ToUint8Array(recipientHybridPublic.x25519PublicBase64);
    const x25519Shared = await X25519Service.deriveSharedSecretBits(eph.privateKey, recipientX25519PubRaw);

    const ikm = new Uint8Array(x25519Shared.length + kyberShared.length);
    ikm.set(x25519Shared, 0);
    ikm.set(kyberShared, x25519Shared.length);

    const saltFull = await HashService.digestSHA512Bytes(ephPubRaw, kyberCiphertext);
    const salt = saltFull.slice(0, 32);

    const aesCryptoKey = await KDFService.deriveAesKeyFromIkm(ikm, salt);

    const jsonStr = JSON.stringify(payloadObject);
    const { iv, authTag, encrypted } = await AESService.encryptWithAesGcmRaw(jsonStr, aesCryptoKey);

    const serializedMessage = AESService.serializeEncryptedData(iv, authTag, encrypted);

    return {
      version: 'hybrid-v1',
      ephemeralX25519Public: HashService.arrayBufferToBase64(ephPubRaw),
      kyberCiphertext: HashService.arrayBufferToBase64(kyberCiphertext),
      encryptedMessage: serializedMessage
    };
  }

  static async decryptHybridPayload(encryptedPayload, localHybridKeys) {
    if (!encryptedPayload || encryptedPayload.version !== 'hybrid-v1') {
      throw new Error('Unsupported payload version or invalid payload');
    }

    const { ephemeralX25519Public, kyberCiphertext, encryptedMessage } = encryptedPayload;

    if (!ephemeralX25519Public || !kyberCiphertext || !encryptedMessage) {
      throw new Error('Missing fields in hybrid payload');
    }

    const ephPubRaw = HashService.base64ToUint8Array(ephemeralX25519Public);
    const kyberCiphertextBytes = HashService.base64ToUint8Array(kyberCiphertext);

    const kyberSecret = localHybridKeys?.kyber?.secretKey;
    if (!kyberSecret) throw new Error('localHybridKeys.kyber.secretKey required to decrypt');

    const kyberShared = await KyberService.decapsulate(kyberCiphertextBytes, kyberSecret);

    const localXPrivate = localHybridKeys?.x25519?.privateKey;
    if (!localXPrivate) throw new Error('localHybridKeys.x25519.privateKey required to decrypt');

    const x25519Shared = await X25519Service.deriveSharedSecretBits(localXPrivate, ephPubRaw);

    const ikm = new Uint8Array(x25519Shared.length + kyberShared.length);
    ikm.set(x25519Shared, 0);
    ikm.set(kyberShared, x25519Shared.length);

    const saltFull = await HashService.digestSHA512Bytes(ephPubRaw, kyberCiphertextBytes);
    const salt = saltFull.slice(0, 32);

    const aesCryptoKey = await KDFService.deriveAesKeyFromIkm(ikm, salt);

    const decryptedJson = await (async () => {
      const deserialized = AESService.deserializeEncryptedData(encryptedMessage);
      return await AESService.decryptWithAesGcmRaw(deserialized.iv, deserialized.authTag, deserialized.encrypted, aesCryptoKey);
    })();

    return JSON.parse(decryptedJson);
  }
}

class HashingService {
  static async hashPassword(password) {
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
    });
  }

  static async verifyPassword(hash, inputPassword) {
    return await argon2.verify(hash, inputPassword);
  }

  static async parseArgon2Hash(encodedHash) {
    const parts = encodedHash.split('$');
    if (parts.length !== 6) {
      throw new Error('Invalid Argon2 encoded hash format');
    }

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;
    const version = parseInt(versionPart.split('=')[1], 10);

    const params = {};
    paramsPart.split(',').forEach(param => {
      const [key, value] = param.split('=');
      params[key] = Number(value);
    });

    const salt = Buffer.from(saltB64, 'base64');
    const hash = Buffer.from(hashB64, 'base64');

    return {
      algorithm,
      version,
      memoryCost: params.m,
      timeCost: params.t,
      parallelism: params.p,
      salt,
      hash
    };
  }
}

export const CryptoUtils = {
  Random: RandomGenerator,
  Hash: HashService,
  X25519: X25519Service,
  Kyber: KyberService,
  KDF: KDFService,
  AES: AESService,
  Hybrid: HybridService,
  Password: HashingService,
};
