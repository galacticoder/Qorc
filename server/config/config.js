export const PORT = 8443;
export const MAX_CLIENTS = 100;
export const SERVER_ID = 'SecureChat-Server';
export let SERVER_PASSWORD = null;

export function setServerPassword(pw) {
  SERVER_PASSWORD = pw;
}