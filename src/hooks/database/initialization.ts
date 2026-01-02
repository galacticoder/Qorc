import { SecureDB } from '../../lib/secureDB';
import { encryptedStorage, syncEncryptedStorage } from '../../lib/encrypted-storage';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { EventType } from '../../lib/types/event-types';

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
  originalUsername: string | null
): Promise<void> => {
  try {
    await secureDB.store('auth_metadata', 'current_user', hashedUsername);
  } catch (err) {
    console.error('[storeAuthMetadata] Failed to store authenticated user:', err);
  }

  if (originalUsername) {
    try {
      await secureDB.storeUsernameMapping(hashedUsername, originalUsername);
      await secureDB.store('auth_metadata', 'original_username', originalUsername);
    } catch (err) {
      console.error('[storeAuthMetadata] Failed to pre-store username mapping:', err);
    }
  }

  // Restore existing mapping if available
  try {
    const existingOriginal = await secureDB.retrieve('auth_metadata', 'original_username');
    if (typeof existingOriginal === 'string' && existingOriginal) {
      try { await secureDB.storeUsernameMapping(hashedUsername, existingOriginal); } catch { }
      try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: hashedUsername, original: existingOriginal } })); } catch { }
    }
  } catch { }
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
