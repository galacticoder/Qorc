import promptSync from 'prompt-sync';
import * as db from '../database/database.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import * as ServerConfig from '../config/config.js';

const prompt = promptSync({ sigint: true });

export const validateUsernameFormat = (username) => {
  if (!username || typeof username !== 'string') return false;
  return /^[a-zA-Z0-9_-]+$/.test(username);
};

export const validateUsernameLength = (username) => {
  if (!username || typeof username !== 'string') return false;
  return username.length >= 3 && username.length <= 16;
};
export const isUsernameAvailable = (username) => !db.userDatabase.has(username);
export const isServerFull = (clients) => clients.size >= ServerConfig.MAX_CLIENTS;

export async function setServerPasswordOnInput() {
  const password = prompt.hide('Set server password (Input will not be visible): ').trim();
  const confirm = prompt.hide('Confirm password: ').trim();

  if (password !== confirm) {
    console.error('Passwords do not match. Exiting.');
    process.exit(1);
  }

  const serverPasswordHash = await CryptoUtils.Password.hashPassword(password);
  ServerConfig.setServerPassword(serverPasswordHash);
  console.log('Password set successfully.');
}
