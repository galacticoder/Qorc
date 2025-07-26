export const CRYPTO_CONFIG = {
  RSA_KEY_SIZE: 4096,
  AES_KEY_SIZE: 256,
  IV_LENGTH: 16,
  AUTH_TAG_LENGTH: 16,
  SALT_LENGTH: 32,
  PBKDF2_ITERATIONS: 200000,
  HASH_ALGORITHM: 'SHA-512'
};

function uint8ToBase64(u8Arr: Uint8Array): string {
  let CHUNK_SIZE = 0x8000; // 32k
  let index = 0;
  let result = '';
  let slice;
  while (index < u8Arr.length) {
    slice = u8Arr.subarray(index, Math.min(index + CHUNK_SIZE, u8Arr.length));
    result += String.fromCharCode.apply(null, slice as any);
    index += CHUNK_SIZE;
  }
  return btoa(result);
}


export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
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

export async function exportPublicKeyToPEM(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("spki", publicKey);
  const base64 = arrayBufferToBase64(exported);
  const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;

  return `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
}

export async function exportPrivateKeyToPEM(privateKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
  const base64 = arrayBufferToBase64(exported);
  const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;

  return `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
}

export async function importPublicKeyFromPEM(pem: string): Promise<CryptoKey> {
  const pemContents = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  
  const binaryDer = base64ToArrayBuffer(pemContents);
  
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
}

export async function importPrivateKeyFromPEM(pem: string): Promise<CryptoKey> {
  const pemContents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  return await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: CRYPTO_CONFIG.HASH_ALGORITHM,
    },
    true,
    ["decrypt"]
  );
}

export async function generateAESKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: CRYPTO_CONFIG.AES_KEY_SIZE,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptWithRSA(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    data
  );
}

export async function decryptWithRSA(encryptedData: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedData
  );
}

export async function encryptBinaryWithAES(
  data: ArrayBuffer | Uint8Array,
  key: CryptoKey
): Promise<{
  iv: Uint8Array;
  authTag: Uint8Array;
  encrypted: Uint8Array;
}> {
  const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.IV_LENGTH));

  const dataBuffer = data instanceof Uint8Array ? data.buffer : data;

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8,
    },
    key,
    dataBuffer
  );

  const resultArray = new Uint8Array(encryptedBuffer);

  const encrypted = resultArray.slice(0, -CRYPTO_CONFIG.AUTH_TAG_LENGTH);
  const authTag = resultArray.slice(-CRYPTO_CONFIG.AUTH_TAG_LENGTH);

  return { iv, authTag, encrypted };
}


export async function encryptWithAES(data: string, key: CryptoKey): Promise<{
  iv: Uint8Array;
  authTag: Uint8Array;
  encrypted: Uint8Array;
}> {
  const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.IV_LENGTH));
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  
  const result = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8
    },
    key,
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

export async function decryptWithAES(
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
      tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8
    },
    key,
    combined.buffer
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

export async function decryptWithAESRaw(
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
      tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8,
    },
    key,
    combined.buffer
  );
}


export function serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
  const version = 1;
  const totalLength = 1 + 1 + iv.length + 1 + authTag.length + 4 + encrypted.length;
  const combined = new Uint8Array(totalLength);
  
  let offset = 0;
  
  combined[offset] = version;
  offset += 1;
  
  combined[offset] = iv.length;
  offset += 1;
  combined.set(iv, offset);
  offset += iv.length;
  
  combined[offset] = authTag.length;
  offset += 1;
  combined.set(authTag, offset);
  offset += authTag.length;
  
  const encryptedLength = encrypted.length;
  combined[offset] = (encryptedLength >>> 24) & 0xFF;
  combined[offset + 1] = (encryptedLength >>> 16) & 0xFF;
  combined[offset + 2] = (encryptedLength >>> 8) & 0xFF;
  combined[offset + 3] = encryptedLength & 0xFF;
  offset += 4;
  
  combined.set(encrypted, offset);
  
  return arrayBufferToBase64(combined);
}

export function deserializeEncryptedDataFromUint8Array(
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


export function deserializeEncryptedData(serialized: string): {
  iv: Uint8Array;
  authTag: Uint8Array;
  encrypted: Uint8Array;
} {
  const combined = new Uint8Array(base64ToArrayBuffer(serialized));
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
  
  const encryptedLength = (combined[offset] << 24) | 
                         (combined[offset + 1] << 16) | 
                         (combined[offset + 2] << 8) | 
                         combined[offset + 3];
  offset += 4;
  
  const encrypted = combined.slice(offset, offset + encryptedLength);
  
  return { iv, authTag, encrypted };
}

export async function decryptMessage(encryptedData: string, aesKey: CryptoKey): Promise<string> {
  const { iv, authTag, encrypted } = deserializeEncryptedData(encryptedData);
  return await decryptWithAES(encrypted, iv, authTag, aesKey);
}

export async function importAESKey(keyData: ArrayBuffer): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportAESKey(key: CryptoKey): Promise<ArrayBuffer> {
  return await crypto.subtle.exportKey("raw", key);
}

export async function decryptAESKeyWithRSA(encryptedKey: ArrayBuffer, privateKey: CryptoKey): Promise<CryptoKey> {
  const keyData = await decryptWithRSA(encryptedKey, privateKey);
  return await importAESKey(keyData);
}