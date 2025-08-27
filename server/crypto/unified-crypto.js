import { webcrypto } from 'crypto';
import argon2 from 'argon2';
import { MlKem768 } from 'mlkem';
import { blake3 } from '@noble/hashes/blake3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';

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

  // BLAKE3-based MAC for additional message authentication
  static async generateBlake3Mac(message, key) {
    const keyedHash = blake3.create({ key });
    keyedHash.update(message);
    return keyedHash.digest();
  }

  static async verifyBlake3Mac(message, key, expectedMac) {
    const computedMac = await this.generateBlake3Mac(message, key);
    if (computedMac.length !== expectedMac.length) return false;

    // Constant-time comparison to prevent timing attacks
    let result = 0;
    for (let i = 0; i < computedMac.length; i++) {
      result |= computedMac[i] ^ expectedMac[i];
    }
    return result === 0;
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

class ChaCha20Poly1305Service {
  /**
   * Encrypt data using ChaCha20-Poly1305
   */
  static encrypt(key, nonce, data, aad) {
    const cipher = chacha20poly1305(key, nonce, aad);
    return cipher.encrypt(data);
  }

  /**
   * Decrypt data using ChaCha20-Poly1305
   */
  static decrypt(key, nonce, ciphertext, aad) {
    const cipher = chacha20poly1305(key, nonce, aad);
    return cipher.decrypt(ciphertext);
  }

  /**
   * Generate a random 12-byte nonce for ChaCha20-Poly1305
   */
  static generateNonce() {
    return crypto.getRandomValues(new Uint8Array(12));
  }

  /**
   * Encrypt with automatic nonce generation and prepending
   */
  static encryptWithNonce(key, data, aad) {
    const nonce = this.generateNonce();
    const ciphertext = this.encrypt(key, nonce, data, aad);
    return { nonce, ciphertext };
  }

  /**
   * Decrypt with nonce extraction
   */
  static decryptWithNonce(key, nonce, ciphertext, aad) {
    return this.decrypt(key, nonce, ciphertext, aad);
  }
}

class XChaCha20Poly1305Service {
  /**
   * Encrypt data using XChaCha20-Poly1305 (extended nonce version)
   */
  static encrypt(key, nonce, data, aad) {
    const cipher = xchacha20poly1305(key, nonce, aad);
    return cipher.encrypt(data);
  }

  /**
   * Decrypt data using XChaCha20-Poly1305
   */
  static decrypt(key, nonce, ciphertext, aad) {
    const cipher = xchacha20poly1305(key, nonce, aad);
    return cipher.decrypt(ciphertext);
  }

  /**
   * Generate a random 24-byte nonce for XChaCha20-Poly1305
   */
  static generateNonce() {
    return crypto.getRandomValues(new Uint8Array(24));
  }

  /**
   * Encrypt with automatic nonce generation
   */
  static encryptWithNonce(key, data, aad) {
    const nonce = this.generateNonce();
    const ciphertext = this.encrypt(key, nonce, data, aad);
    return { nonce, ciphertext };
  }

  /**
   * Decrypt with nonce
   */
  static decryptWithNonce(key, nonce, ciphertext, aad) {
    return this.decrypt(key, nonce, ciphertext, aad);
  }
}

class DilithiumService {
  static async generateKeyPair() {
    const kp = await ml_dsa87.keygen(undefined);
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey)
    };
  }

  static async sign(secretKey, message) {
    const signature = await ml_dsa87.sign(secretKey, message);
    return new Uint8Array(signature);
  }

  static async verify(signature, message, publicKey) {
    return await ml_dsa87.verify(signature, message, publicKey);
  }
}

class KDFService {
  /**
   * BLAKE3-based HKDF implementation for enhanced security
   */
  static async blake3Hkdf(ikm, salt, info, outLen) {
    // HKDF-Extract: PRK = BLAKE3-MAC(salt, ikm)
    const prk = await HashService.generateBlake3Mac(ikm, salt);

    // HKDF-Expand: Generate output key material
    const output = new Uint8Array(outLen);
    const hashLen = 32; // BLAKE3 output length
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    for (let i = 1; i <= n; i++) {
      // T(i) = BLAKE3-MAC(PRK, T(i-1) || info || i)
      const input = new Uint8Array(t.length + info.length + 1);
      input.set(t, 0);
      input.set(info, t.length);
      input[input.length - 1] = i;

      t = await HashService.generateBlake3Mac(input, prk);

      const copyLen = Math.min(hashLen, outLen - outputOffset);
      output.set(t.slice(0, copyLen), outputOffset);
      outputOffset += copyLen;
    }

    return output;
  }

  /**
   * AES key derivation using BLAKE3-HKDF compatible with client
   */
  static async deriveAesKeyFromIkm(ikmUint8Array, saltUint8Array, context) {
    try {
      // Create context-bound info parameter to match client
      const contextInfo = context ?
        new TextEncoder().encode(`endtoend-chat hybrid key v2:${context}`) :
        CryptoConfig.HKDF_INFO;

      // Use BLAKE3-HKDF for key derivation
      const keyMaterial = await this.blake3Hkdf(ikmUint8Array, saltUint8Array, contextInfo, 32);

      // Validate key material
      if (!keyMaterial || keyMaterial.length !== 32) {
        throw new Error(`Invalid key material length: ${keyMaterial?.length}`);
      }

      // Import as AES key - fix for Node.js webcrypto compatibility
      const derived = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false, // Set to false to avoid potential issues
        ['encrypt', 'decrypt']
      );

      return derived;
    } catch (error) {
      console.error('[CRYPTO] AES key derivation failed:', error);
      throw new Error(`AES key derivation failed: ${error.message}`);
    }
  }

  /**
   * Enhanced session key derivation with BLAKE3 and context binding
   */
  static async deriveSessionKey(ikm, salt, sessionContext) {
    const contextInfo = new TextEncoder().encode(`session-key-v2:${sessionContext}`);
    return await this.blake3Hkdf(ikm, salt, contextInfo, 32);
  }

  /**
   * Legacy AES key derivation using standard HKDF for client compatibility
   */
  static async deriveAesKeyFromIkmLegacy(ikmUint8Array, saltUint8Array) {
    try {
      // Use standard WebCrypto HKDF like the client
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
          info: CryptoConfig.HKDF_INFO
        },
        baseKey,
        { name: 'AES-GCM', length: CryptoConfig.AES_KEY_SIZE },
        false,
        ['encrypt', 'decrypt']
      );

      return derived;
    } catch (error) {
      console.error('[CRYPTO] Legacy AES key derivation failed:', error);
      throw new Error(`Legacy AES key derivation failed: ${error.message}`);
    }
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
      { name: 'AES-GCM', iv: iv, tagLength: 128 },
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
    try {
      // Validate inputs
      if (!iv || iv.length !== 16) {
        throw new Error(`Invalid IV length: ${iv?.length}`);
      }
      if (!authTag || authTag.length !== 16) {
        throw new Error(`Invalid auth tag length: ${authTag?.length}`);
      }
      if (!encrypted || encrypted.length === 0) {
        throw new Error('No encrypted data provided');
      }
      if (!cryptoKey) {
        throw new Error('No crypto key provided');
      }

      const combined = new Uint8Array(encrypted.length + authTag.length);
      combined.set(encrypted, 0);
      combined.set(authTag, encrypted.length);

      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        cryptoKey,
        combined
      );

      return new TextDecoder().decode(plainBuf);
    } catch (error) {
      console.error('[CRYPTO] AES decryption failed:', {
        error: error.message,
        ivLength: iv?.length,
        authTagLength: authTag?.length,
        encryptedLength: encrypted?.length,
        hasKey: !!cryptoKey
      });
      throw new Error(`AES decryption failed: ${error.message}`);
    }
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

    // Generate BLAKE3 MAC for additional integrity
    const messageBytes = new TextEncoder().encode(jsonStr);
    const macKey = ikm.slice(0, 32); // BLAKE3 expects 32-byte key
    const blake3Mac = await HashService.generateBlake3Mac(messageBytes, macKey);
    const blake3MacBase64 = HashService.arrayBufferToBase64(blake3Mac);

    return {
      version: 'hybrid-v1',
      ephemeralX25519Public: HashService.arrayBufferToBase64(ephPubRaw),
      kyberCiphertext: HashService.arrayBufferToBase64(kyberCiphertext),
      encryptedMessage: serializedMessage,
      blake3Mac: blake3MacBase64
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

    const aesCryptoKey = await KDFService.deriveAesKeyFromIkm(ikm, salt, "message-encryption");

    const decryptedJson = await (async () => {
      const deserialized = AESService.deserializeEncryptedData(encryptedMessage);
      return await AESService.decryptWithAesGcmRaw(deserialized.iv, deserialized.authTag, deserialized.encrypted, aesCryptoKey);
    })();

    // Verify BLAKE3 MAC if present
    if (encryptedPayload.blake3Mac) {
      const messageBytes = new TextEncoder().encode(decryptedJson);
      const expectedMac = HashService.base64ToUint8Array(encryptedPayload.blake3Mac);
      const macKey = ikm.slice(0, 32); // BLAKE3 expects 32-byte key
      const isValid = await HashService.verifyBlake3Mac(messageBytes, macKey, expectedMac);
      if (!isValid) {
        throw new Error('BLAKE3 MAC verification failed - hybrid payload integrity compromised');
      }
    }

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

class PostQuantumHybridService {
  /**
   * Generate a complete hybrid key pair with X25519, Kyber768, and Dilithium3
   */
  static async generateHybridKeyPair() {
    const x25519Pair = await X25519Service.generateKeyPair();
    const kyberPair = await KyberService.generateKeyPair();
    const dilithiumPair = await DilithiumService.generateKeyPair();

    return {
      x25519: x25519Pair,
      kyber: kyberPair,
      dilithium: dilithiumPair
    };
  }

  /**
   * Export public keys for sharing
   */
  static async exportPublicKeys(hybridKeyPair) {
    return {
      x25519PublicBase64: await HybridService.exportX25519PublicBase64(hybridKeyPair.x25519.publicKey),
      kyberPublicBase64: HashService.arrayBufferToBase64(hybridKeyPair.kyber.publicKey),
      dilithiumPublicBase64: HashService.arrayBufferToBase64(hybridKeyPair.dilithium.publicKey)
    };
  }

  /**
   * Sign a message using Dilithium3 (post-quantum signature)
   */
  static async signMessage(message, dilithiumSecretKey) {
    return await DilithiumService.sign(dilithiumSecretKey, message);
  }

  /**
   * Verify a Dilithium3 signature
   */
  static async verifySignature(signature, message, dilithiumPublicKey) {
    return await DilithiumService.verify(signature, message, dilithiumPublicKey);
  }

  /**
   * Create a hybrid signature that includes both Ed25519 (for compatibility) and Dilithium3
   */
  static async createHybridSignature(message, ed25519PrivateKey, dilithiumSecretKey) {
    // Create Ed25519 signature (for backward compatibility)
    const ed25519Signature = ed25519PrivateKey.sign(message);

    // Create Dilithium3 signature (post-quantum)
    const dilithiumSignature = await DilithiumService.sign(dilithiumSecretKey, message);

    return {
      ed25519: HashService.arrayBufferToBase64(ed25519Signature),
      dilithium: HashService.arrayBufferToBase64(dilithiumSignature)
    };
  }

  /**
   * Verify a hybrid signature
   */
  static async verifyHybridSignature(hybridSignature, message, ed25519PublicKey, dilithiumPublicKey) {
    try {
      // Verify Ed25519 signature
      const ed25519Sig = HashService.base64ToUint8Array(hybridSignature.ed25519);
      const ed25519Valid = ed25519PublicKey.verify(message, ed25519Sig);

      // Verify Dilithium3 signature
      const dilithiumSig = HashService.base64ToUint8Array(hybridSignature.dilithium);
      const dilithiumValid = await DilithiumService.verify(dilithiumSig, message, dilithiumPublicKey);

      // Both signatures must be valid for maximum security
      return ed25519Valid && dilithiumValid;
    } catch (error) {
      console.error('Hybrid signature verification failed:', error);
      return false;
    }
  }
}

export const CryptoUtils = {
  Random: RandomGenerator,
  Hash: HashService,
  X25519: X25519Service,
  Kyber: KyberService,
  Dilithium: DilithiumService,
  ChaCha20Poly1305: ChaCha20Poly1305Service,
  XChaCha20Poly1305: XChaCha20Poly1305Service,
  KDF: KDFService,
  AES: AESService,
  Hybrid: HybridService,
  PostQuantum: PostQuantumHybridService,
  Password: HashingService,
};
