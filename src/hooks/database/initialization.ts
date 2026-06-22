import { SecureDB } from '../../lib/database/secureDB';
import { encryptedStorage, syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { database } from '../../lib/tauri-bindings';
import { CryptoUtils } from '../../lib/utils/crypto-utils';

// Validate CryptoKey structure
export const isValidCryptoKey = (key: unknown): key is CryptoKey => {
  return (
    key !== null &&
    typeof key === 'object' &&
    'type' in key &&
    'extractable' in key &&
    'algorithm' in key &&
    'usages' in key
  );
};

// Initialize SecureDB
export const initializeSecureDB = async (
  username: string,
  aesKey: CryptoKey
): Promise<SecureDB> => {
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);
  const keyB64 = CryptoUtils.Base64.arrayBufferToBase64(rawKey);
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      await database.init(username, keyB64);
      lastError = null;
      break;
    } catch (error) {
      lastError = error;
      const message = error instanceof Error ? error.message : String(error);
      if (!/disk I\/O|database is locked|busy|temporarily unavailable/i.test(message) || attempt === 3) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 150 * (attempt + 1)));
    }
  }
  if (lastError) {
    throw lastError;
  }

  const db = new SecureDB(username);
  await db.initializeWithKey(aesKey);
  return db;
};

// Initialize blocking system
export const initializeBlockingSystem = async (
  secureDB: SecureDB,
  passphrase: string | null,
  kyberSecret: Uint8Array | null
): Promise<void> => {
  try {
    blockingSystem.setSecureDB(secureDB);
  } catch { }

  try {
    if (passphrase) {
      await blockingSystem.getBlockedUsers(passphrase);
    } else if (kyberSecret) {
      await blockingSystem.getBlockedUsers({ kyberSecret });
    }
  } catch (err) {
    console.error('[initializeBlockingSystem] Failed to load block list:', err);
    const msg = (err as Error)?.message || String(err);
    if (/decrypt|BLAKE3|passphrase|corrupt/i.test(msg)) {
      await Promise.all([
        secureDB.clearStore('blockListData'),
        secureDB.clearStore('blockListMeta')
      ]);
      if (passphrase) {
        await blockingSystem.getBlockedUsers(passphrase).catch(() => { });
      }
    }
  }
};

// Store authenticated user metadata
export const storeAuthMetadata = async (
  secureDB: SecureDB,
  hashedUsername: string,
  originalUsername?: string | null
): Promise<void> => {
  try {
    await secureDB.store('auth_metadata', 'username', hashedUsername);
    if (originalUsername) {
      await secureDB.store('auth_metadata', 'original_username', originalUsername);
    }
  } catch (err) {
    console.error('[storeAuthMetadata] Failed:', err);
    throw err;
  }
};

// Initialize encrypted storage systems
export const initializeEncryptedStorage = async (secureDB: SecureDB): Promise<void> => {
  try {
    await encryptedStorage.initialize(secureDB);
    await syncEncryptedStorage.initialize();
  } catch (err) {
    console.error('[initializeEncryptedStorage] Failed to initialize encrypted storage:', err);
    const msg = (err as Error)?.message || String(err);
    if (/decrypt|BLAKE3|passphrase|corrupt/i.test(msg)) {
      await secureDB.clearStore('encrypted_storage');
      await encryptedStorage.initialize(secureDB);
      await syncEncryptedStorage.initialize();
    }
  }
};
