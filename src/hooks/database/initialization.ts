import { SecureDB } from '../../lib/database/secureDB';
import { encryptedStorage, syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { account, database } from '../../lib/tauri-bindings';
import { getCurrentLocalAccountScope } from '../../lib/security/local-account-scope';
import { STORAGE_KEYS, STORAGE_STORES } from '../../lib/database/storage-keys';

// Initialize SecureDB
export const initializeSecureDB = async (
  username: string,
): Promise<SecureDB> => {
  const accountScope = await getCurrentLocalAccountScope(username);
  if (!await account.isUnlocked(accountScope)) {
    throw new Error('Native account is locked');
  }

  const db = new SecureDB(username, accountScope);
  try {
    await db.initializeNative();
    return db;
  } catch (error) {
    db.dispose();
    await database.lock(accountScope).catch(() => false);
    throw error;
  }
};

// Initialize blocking system
export const initializeBlockingSystem = async (
  secureDB: SecureDB
): Promise<void> => {
  blockingSystem.setSecureDB(secureDB);
  await blockingSystem.getBlockedUsers();
};

// Store authenticated user metadata
export const storeAuthMetadata = async (
  secureDB: SecureDB,
  hashedUsername: string,
  originalUsername?: string | null
): Promise<void> => {
  await secureDB.store(STORAGE_STORES.AUTH_METADATA, STORAGE_KEYS.AUTH_USERNAME, hashedUsername);
  if (originalUsername) {
    await secureDB.store(STORAGE_STORES.AUTH_METADATA, STORAGE_KEYS.AUTH_ORIGINAL_USERNAME, originalUsername);
  }
};

// Initialize encrypted storage systems
export const initializeEncryptedStorage = async (secureDB: SecureDB): Promise<void> => {
  try {
    await encryptedStorage.initialize(secureDB);
    await syncEncryptedStorage.initialize();
  } catch (error) {
    syncEncryptedStorage.reset();
    throw error;
  }
};
