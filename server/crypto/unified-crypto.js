import { webcrypto } from 'crypto';
import argon2 from 'argon2';

const crypto = webcrypto;

class CryptoConfig {
  static RSA_KEY_SIZE = 4096;
  static AES_KEY_SIZE = 256;
  static IV_LENGTH = 16;
  static AUTH_TAG_LENGTH = 16;
  static HASH_ALGORITHM = 'SHA-512';
}

class RandomGenerator {
  static generateSecureRandom(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }
}

class HashService {
  static stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
  }

  static async hashData(data) {
    const dataBuffer = this.stringToArrayBuffer(data);
    const hashBuffer = await crypto.subtle.digest(
      CryptoConfig.HASH_ALGORITHM, 
      dataBuffer
    );
    return this.arrayBufferToBase64(hashBuffer);
  }

  static arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Buffer.from(bytes).toString('base64');
  }

  static base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

class KeyService {
  static async generateRSAKeyPair() {
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

  static async generateAESKey() {
    return await crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: CryptoConfig.AES_KEY_SIZE,
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async exportPublicKeyToPEM(publicKey) {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    const base64 = HashService.arrayBufferToBase64(exported);
    const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;
    return `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
  }

  static async importPublicKeyFromPEM(pem) {
    const pemContents = pem
      .replace(/-----BEGIN PUBLIC KEY-----/g, '')
      .replace(/-----END PUBLIC KEY-----/g, '')
      .replace(/\n/g, '')
      .replace(/\r/g, '')
      .trim();
    
    const binaryDer = HashService.base64ToArrayBuffer(pemContents);
    
    try {
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
    } catch (error) {
      console.error('Failed to import with SHA-512:', error);
      throw error;
    }
  }

  static async exportAESKey(key) {
    return await crypto.subtle.exportKey("raw", key);
  }

  static async importAESKey(keyData) {
    return await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async decryptAESKeyWithRSA(encryptedKey, privateKey) {
    const keyData = await DecryptionService.decryptWithRSA(encryptedKey, privateKey);
    return await this.importAESKey(keyData);
  }
}

class PasswordService {
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
}

class EncryptionService {
  static async encryptWithRSA(data, publicKey) {
    if (typeof publicKey === 'string' || Buffer.isBuffer(publicKey)) {
      publicKey = await KeyService.importPublicKeyFromPEM(publicKey.toString());
    }
    
    let buffer;
    if (typeof data === 'string') {
      buffer = new TextEncoder().encode(data);
    } else if (Buffer.isBuffer(data)) {
      buffer = new Uint8Array(data);
    } else if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
      buffer = data;
    } else {
      throw new Error('Unsupported data type for encryption');
    }
    
    try {
      return await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        buffer
      );
    } catch (error) {
      console.error('RSA encryption failed:', error);
      throw new Error('Failed to encrypt with RSA: ' + error.message);
    }
  }

  static async encryptWithAES(data, key) {
    const iv = RandomGenerator.generateSecureRandom(CryptoConfig.IV_LENGTH);
    let dataBuffer;
    
    if (typeof data === 'string') {
      dataBuffer = new TextEncoder().encode(data);
    } else if (Buffer.isBuffer(data)) {
      dataBuffer = new Uint8Array(data);
    } else if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
      dataBuffer = data;
    } else {
      throw new Error('Unsupported data type for encryption');
    }
    
    let cryptoKey;
    if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
      cryptoKey = await KeyService.importAESKey(key);
    } else {
      cryptoKey = key;
    }
    
    const result = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8
      },
      cryptoKey,
      dataBuffer
    );
    
    const resultArray = new Uint8Array(result);
    const encrypted = resultArray.slice(0, -CryptoConfig.AUTH_TAG_LENGTH);
    const authTag = resultArray.slice(-CryptoConfig.AUTH_TAG_LENGTH);
    
    return {
      iv,
      authTag,
      encrypted
    };
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

  static async encryptAndFormatPayload(input) {
    const { recipientPEM, from, to, type, ...encryptedContent } = input;

    console.log("Encrypted Content:", encryptedContent);

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
    const encryptedAESKeyBase64 = HashService.arrayBufferToBase64(encryptedAes);

    return {
      ...(from && { from }),
      ...(to && { to }),
      ...(type && { type }),
      encryptedAESKey: encryptedAESKeyBase64,
      encryptedMessage
    };
  }
}

class DecryptionService {
  static async decryptWithRSA(encryptedData, privateKey) {
    return await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedData
    );
  }

  static async decryptWithAES(encryptedData, key) {
    if (
      !encryptedData ||
      !encryptedData.iv ||
      !encryptedData.authTag ||
      !encryptedData.encrypted
    ) {
      throw new Error('Invalid encryptedData format for AES decryption');
    }

    const combined = new Uint8Array(
      encryptedData.encrypted.length + encryptedData.authTag.length
    );
    combined.set(encryptedData.encrypted);
    combined.set(encryptedData.authTag, encryptedData.encrypted.length);

    let cryptoKey;
    if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
      cryptoKey = await KeyService.importAESKey(key);
    } else {
      cryptoKey = key;
    }

    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: encryptedData.iv,
          tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8,
        },
        cryptoKey,
        combined
      );
      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error('AES decryption failed:', error);
      throw new Error('Failed to decrypt with AES: ' + error.message);
    }
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

  static async decryptAndFormatPayload(encryptedPayload, privateKey) {
    if (!privateKey) {
      throw new Error("Private key is required for decryption");
    }

    const {
      encryptedAESKey,
      encryptedMessage,
      ...restFields
    } = encryptedPayload;

    if (!encryptedAESKey || !encryptedMessage) {
      throw new Error("Invalid encrypted payload structure");
    }

    const encryptedAesKeyBuffer = HashService.base64ToArrayBuffer(encryptedAESKey);
    const aesKey = await KeyService.decryptAESKeyWithRSA(encryptedAesKeyBuffer, privateKey);
    const decryptedJsonString = await this.decryptMessage(encryptedMessage, aesKey);
    const decryptedPayload = JSON.parse(decryptedJsonString);

    return {
      ...restFields,
      ...decryptedPayload
    };
  }

  static async decryptMessage(encryptedMessageBase64, aesKey) {
    const encryptedData = this.deserializeEncryptedData(encryptedMessageBase64);
    return await this.decryptWithAES(encryptedData, aesKey);
  }
}

export const CryptoUtils = {
  Config: CryptoConfig,
  Random: RandomGenerator,
  Hash: HashService,
  Keys: KeyService,
  Password: PasswordService,
  Encrypt: EncryptionService,
  Decrypt: DecryptionService,
};