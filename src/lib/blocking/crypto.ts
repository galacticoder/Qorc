/**
 * Cryptographic Operations for Blocking System
 */

import { CryptoUtils } from '../utils/crypto-utils';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { bytesToHex } from '../utils/blocking-utils';
import { BlockedUser, EncryptedBlockList, KeyMaterial } from '../types/blocking-types';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const BLOCKLIST_CONTEXT = encoder.encode('block-list-v3');

export const encryptBlockList = async (
  blockList: BlockedUser[],
  key: KeyMaterial
): Promise<EncryptedBlockList> => {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  let derivedKey: Uint8Array;
  if (key?.passphrase) {
    derivedKey = await CryptoUtils.KDF.argon2id(key.passphrase, {
      salt,
      time: 4,
      memoryCost: 2 ** 18,
      parallelism: 2,
      hashLen: 32
    });
  } else if (key?.kyberSecret) {
    const label = new TextEncoder().encode('block-list-v3');
    const combined = new Uint8Array(label.length + salt.length);
    combined.set(label, 0);
    combined.set(salt, label.length);
    const mac = await (CryptoUtils as any).Hash.generateBlake3Mac(combined, key.kyberSecret);
    derivedKey = mac instanceof Uint8Array ? mac : new Uint8Array(mac as ArrayBuffer);
  } else {
    throw new Error('No key material provided for block list encryption');
  }

  const plaintext = encoder.encode(JSON.stringify(blockList));
  const nonce = crypto.getRandomValues(new Uint8Array(36));
  const { PostQuantumAEAD } = CryptoUtils;

  const { ciphertext, tag } = PostQuantumAEAD.encrypt(plaintext, derivedKey, BLOCKLIST_CONTEXT, nonce);

  const encryptedDataArray = new Uint8Array(nonce.length + ciphertext.length + tag.length);
  encryptedDataArray.set(nonce, 0);
  encryptedDataArray.set(ciphertext, nonce.length);
  encryptedDataArray.set(tag, nonce.length + ciphertext.length);

  return {
    version: 3,
    encryptedData: CryptoUtils.Base64.arrayBufferToBase64(encryptedDataArray),
    salt: CryptoUtils.Base64.arrayBufferToBase64(salt),
    lastUpdated: Date.now()
  };
};

export const decryptBlockList = async (
  encryptedBlockList: EncryptedBlockList,
  key: KeyMaterial
): Promise<BlockedUser[]> => {
  if ((!key?.passphrase || key.passphrase.length === 0) && !key?.kyberSecret) {
    throw new Error('Key material is required');
  }

  if (encryptedBlockList.version < 3) {
    throw new Error(`Unsupported block list version: ${encryptedBlockList.version}. v3 required.`);
  }

  const encryptedData = CryptoUtils.Base64.base64ToUint8Array(encryptedBlockList.encryptedData);
  const salt = CryptoUtils.Base64.base64ToUint8Array(encryptedBlockList.salt);

  if (encryptedData.length < 52) {
    throw new Error('Invalid encrypted data: too short');
  }

  let derivedKey: Uint8Array;
  if (key?.passphrase) {
    derivedKey = await CryptoUtils.KDF.argon2id(key.passphrase, {
      salt,
      time: 4,
      memoryCost: 2 ** 18,
      parallelism: 2,
      hashLen: 32
    });
  } else {
    const label = new TextEncoder().encode('block-list-v3');
    const combined = new Uint8Array(label.length + salt.length);
    combined.set(label, 0);
    combined.set(salt, label.length);
    const mac = await (CryptoUtils as any).Hash.generateBlake3Mac(combined, key.kyberSecret!);
    derivedKey = mac instanceof Uint8Array ? mac : new Uint8Array(mac as ArrayBuffer);
  }

  const { PostQuantumAEAD } = CryptoUtils;

  const nonce = encryptedData.slice(0, 36);
  const ciphertext = encryptedData.slice(36, -16);
  const tag = encryptedData.slice(-16);

  const plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, derivedKey, BLOCKLIST_CONTEXT);
  const decryptedText = decoder.decode(plaintext);
  const blockList = JSON.parse(decryptedText);

  if (!isPlainObject(blockList) && !Array.isArray(blockList)) {
    throw new Error('Invalid block list format');
  }
  if (hasPrototypePollutionKeys(blockList)) {
    throw new Error('Prototype pollution detected in block list');
  }

  if (!Array.isArray(blockList)) {
    throw new Error('Invalid block list format: expected array');
  }

  for (const user of blockList) {
    if (!isPlainObject(user)) {
      throw new Error('Invalid blocked user entry');
    }
    if (hasPrototypePollutionKeys(user)) {
      throw new Error('Prototype pollution detected in blocked user entry');
    }
    if (!user.username || typeof user.username !== 'string' ||
      !user.blockedAt || typeof user.blockedAt !== 'number') {
      throw new Error('Invalid blocked user entry format');
    }
  }

  return blockList;
};

export const computeBlockListHash = async (encrypted: EncryptedBlockList): Promise<string> => {
  try {
    const { blake3 } = await import('@noble/hashes/blake3.js');
    const input = new TextEncoder().encode(`${encrypted.salt}|${encrypted.encryptedData}|v${encrypted.version}|${encrypted.lastUpdated}`);
    const digest = blake3(input, { dkLen: 16 });
    return bytesToHex(digest);
  } catch {
    return '';
  }
};
