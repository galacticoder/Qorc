import * as db from '../database/database.js';
import * as ServerConfig from '../config/config.js'

export const validateUsernameFormat = (username) => /^[a-zA-Z0-9_-]+$/.test(username);
export const validateUsernameLength = (username) => username.length >= 3 && username.length <= 16;
export const isUsernameAvailable = (username) => !db.userDatabase.has(username);
export const isServerFull = (clients) => clients.size >= ServerConfig.MAX_CLIENTS;