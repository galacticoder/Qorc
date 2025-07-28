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

export async function encryptAndFormatPayload(input) {
  const { recipientPEM, from, to, type, ...encryptedContent } = input;

  console.log("Encrypted Content:", encryptedContent);

  if (!recipientPEM) throw new Error("Missing recipientPEM");

  const recipientKey = await importPublicKeyFromPEM(recipientPEM);
  const aesKey = await generateAESKey();

  const { iv, authTag, encrypted } = await encryptWithAES(
    JSON.stringify(encryptedContent),
    aesKey
  );

  const encryptedMessage = serializeEncryptedData(iv, authTag, encrypted);
  const rawAes = await exportAESKey(aesKey);
  const encryptedAes = await encryptWithRSA(rawAes, recipientKey);
  const encryptedAESKeyBase64 = arrayBufferToBase64(encryptedAes);

  return {
    ...(from && { from }),
    ...(to && { to }),
    ...(type && { type }),
    encryptedAESKey: encryptedAESKeyBase64,
    encryptedMessage
  };
}

export async function decryptAndFormatPayload(encryptedPayload, privateKey) {
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

  const encryptedAesKeyBuffer = base64ToArrayBuffer(encryptedAESKey);
  const aesKey = await decryptAESKeyWithRSA(encryptedAesKeyBuffer, privateKey);
  const decryptedJsonString = await decryptMessage(encryptedMessage, aesKey);
  const decryptedPayload = JSON.parse(decryptedJsonString);

  return {
    ...restFields,
    ...decryptedPayload
  };
}


export function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Buffer.from(bytes).toString('base64');
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
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

export async function decryptAESKeyWithRSA(encryptedKey, privateKey) {
  const keyData = await decryptWithRSA(encryptedKey, privateKey);
  return await importAESKey(keyData);
}

export async function decryptMessage(encryptedMessageBase64, aesKey) {
  const encryptedData = deserializeEncryptedData(encryptedMessageBase64);
  return await decryptWithAES(encryptedData, aesKey);
}

export async function exportPublicKeyToPEM(publicKey) {
  const exported = await crypto.subtle.exportKey("spki", publicKey);
  const base64 = arrayBufferToBase64(exported);
  
  const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;
  
  return `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
}

export async function exportPrivateKeyToPEM(privateKey) {
  const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
  const base64 = arrayBufferToBase64(exported);
  const pem = base64.match(/.{1,64}/g)?.join('\n') || base64;

  return `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
}

export async function importPublicKeyFromPEM(pem) {
  const pemContents = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\n/g, '')
    .replace(/\r/g, '')
    .trim();
  
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
  const version = 1;
  const encryptedLength = encrypted.length;

  const result = new Uint8Array(
    1 + // version
    1 + iv.length +
    1 + authTag.length +
    4 + // encrypted length (4 bytes)
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

export async function decryptWithAESRaw(encryptedData, key) {
  const combined = new Uint8Array(encryptedData.encrypted.length + encryptedData.authTag.length);
  combined.set(encryptedData.encrypted);
  combined.set(encryptedData.authTag, encryptedData.encrypted.length);

  const cryptoKey = await importAESKey(key);
  return await crypto.subtle.decrypt({
    name: 'AES-GCM',
    iv: encryptedData.iv,
    tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8
  }, cryptoKey, combined);
}

export function deserializeEncryptedData(base64Data) {
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




export async function decryptWithRSA(encryptedData, privateKey) {
  return await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedData
  );
}


export async function decryptWithAES(encryptedData, key) {
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
    cryptoKey = await importAESKey(key);
  } else {
    cryptoKey = key;
  }

  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: encryptedData.iv,
        tagLength: CRYPTO_CONFIG.AUTH_TAG_LENGTH * 8,
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

export async function importPrivateKeyFromPEM(pem) {
  const pemContents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');

  const binaryDer = base64ToArrayBuffer(pemContents);

  try {
    return await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSA-OAEP',
        hash: CRYPTO_CONFIG.HASH_ALGORITHM,
      },
      true,
      ['decrypt']
    );
  } catch (error) {
    console.error('Failed to import private key:', error);
    throw error;
  }
}
