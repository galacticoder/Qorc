import { CryptoUtils } from '../crypto/unified-crypto.js';
import nodeCrypto from 'crypto';
import * as db from '../database/database.js';
import * as ServerConfig from '../config/config.js'

export const validateUsernameFormat = (username) => /^[a-zA-Z0-9_-]+$/.test(username);
export const validateUsernameLength = (username) => username.length >= 3 && username.length <= 16;
export const isUsernameAvailable = (username) => !db.userDatabase.has(username);
export const isServerFull = (clients) => clients.size >= ServerConfig.MAX_CLIENTS;

export const createPasswordHash = async (password) => {
  const salt = nodeCrypto.randomBytes(CryptoUtils.Config.SALT_LENGTH);
  const derivedKey = await CryptoUtils.Password.deriveKeyFromPassword(password, salt);
  const exportedKeyBuffer = await CryptoUtils.Keys.exportAESKey(derivedKey);
  return {
    hash: CryptoUtils.Hash.arrayBufferToBase64(exportedKeyBuffer),
    salt: CryptoUtils.Hash.arrayBufferToBase64(salt)
  };
};

export const verifyPassword = async (password, userData) => {
  const salt = CryptoUtils.Hash.base64ToArrayBuffer(userData.salt);
  const derivedKey = await CryptoUtils.Password.deriveKeyFromPassword(password, salt);
  const exportedKeyBuffer = await CryptoUtils.Keys.exportAESKey(derivedKey);
  return userData.passwordHash === CryptoUtils.Hash.arrayBufferToBase64(exportedKeyBuffer);
};