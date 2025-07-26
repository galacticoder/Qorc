import { webcrypto } from 'crypto';
const crypto = webcrypto;

export const CRYPTO_CONFIG = {
  RSA_KEY_SIZE: 4096,
  AES_KEY_SIZE: 256,
  IV_LENGTH: 16,      
  AUTH_TAG_LENGTH: 16,
  SALT_LENGTH: 32,
  PBKDF2_ITERATIONS: 200000,
  HASH_ALGORITHM: 'SHA-512'
};

export function generateSecureRandom(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Buffer.from(bytes).toString('base64');
}

export function base64ToArrayBuffer(base64) {
  const buffer = Buffer.from(base64, 'base64');
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

export async function generateRSAKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: CRYPTO_CONFIG.RSA_KEY_SIZE,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: CRYPTO_CONFIG.HASH_ALGORITHM,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportPublicKeyToPEM(publicKey) {
  const exported = await crypto.subtle.exportKey("spki", publicKey);
  const base64 = arrayBufferToBase64(exported);
  
  const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;
  
  return `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
}

export async function importPublicKeyFromPEM(pem) {
  const pemContents = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\s/g, '');
  
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  try {
    return await crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSA-OAEP",
        hash: CRYPTO_CONFIG.HASH_ALGORITHM,
      },
      true,
      ["encrypt"]
    );
  } catch (error) {
    console.error('Failed to import with SHA-512:', error);
  }
}

export async function generateAESKey() {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: CRYPTO_CONFIG.AES_KEY_SIZE,
    },
    true,
    ["encrypt", "decrypt"]
  );
}


export async function exportAESKey(key) {
  return await crypto.subtle.exportKey("raw", key);
}

export async function importAESKey(keyData) {
  return await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptWithRSA(data, publicKey) {
  if (typeof publicKey === 'string' || Buffer.isBuffer(publicKey)) {
    publicKey = await importPublicKeyFromPEM(publicKey.toString());
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

export async function encryptWithAES(data, key) {
  const iv = generateSecureRandom(CRYPTO_CONFIG.IV_LENGTH);
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
    cryptoKey = await importAESKey(key);
  } else {
    cryptoKey = key;
  }
  
  const result = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8
    },
    cryptoKey,
    dataBuffer
  );
  
  const resultArray = new Uint8Array(result);
  const encrypted = resultArray.slice(0, -CRYPTO_CONFIG.AUTH_TAG_LENGTH);
  const authTag = resultArray.slice(-CRYPTO_CONFIG.AUTH_TAG_LENGTH);
  
  return {
    iv,
    authTag,
    encrypted
  };
}


export function serializeEncryptedData(iv, authTag, encrypted) {
  const combined = new Uint8Array(1 + iv.length + 1 + authTag.length + encrypted.length);
  let offset = 0;
  
  combined[offset] = iv.length;
  offset += 1;
  
  combined.set(iv, offset);
  offset += iv.length;
  
  combined[offset] = authTag.length;
  offset += 1;
  
  combined.set(authTag, offset);
  offset += authTag.length;
  
  combined.set(encrypted, offset);
  
  return Buffer.from(combined).toString('base64');
}

export function deserializeEncryptedData(serialized) {
  const combined = Buffer.from(serialized, 'base64');

  const ivLength = combined[0];
  if (ivLength !== CRYPTO_CONFIG.IV_LENGTH) {
    throw new Error(`Expected IV length ${CRYPTO_CONFIG.IV_LENGTH}, got ${ivLength}`);
  }
  
  const iv = combined.slice(1, 1 + ivLength);
  
  const authTagLength = combined[1 + ivLength];
  if (authTagLength !== CRYPTO_CONFIG.AUTH_TAG_LENGTH) {
    throw new Error(`Expected auth tag length ${CRYPTO_CONFIG.AUTH_TAG_LENGTH}, got ${authTagLength}`);
  }
  
  const authTag = combined.slice(1 + ivLength + 1, 1 + ivLength + 1 + authTagLength);
  const encrypted = combined.slice(1 + ivLength + 1 + authTagLength);
  
  return { iv, authTag, encrypted };
}