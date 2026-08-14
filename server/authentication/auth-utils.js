import * as ServerConfig from '../config/config.js';
import {
  AUTH_CONNECTION_CLOSED,
  AUTH_CONNECTION_CLOSED_MESSAGE
} from '../config/error-codes.js';

export function authConnectionClosedError() {
  return Object.assign(new Error(AUTH_CONNECTION_CLOSED_MESSAGE), {
    code: AUTH_CONNECTION_CLOSED
  });
}

export function throwIfAuthConnectionClosed(signal) {
  if (signal?.aborted) throw authConnectionClosedError();
}

export async function initializeServerPasswordGate() {
  try {
    const plaintextPassword = typeof process.env.SERVER_PASSWORD === 'string'
      ? process.env.SERVER_PASSWORD.trim()
      : '';

    if (plaintextPassword.length < 12 || plaintextPassword.length > 512) {
      throw new Error('SERVER_PASSWORD must contain between 12 and 512 characters');
    }

    const { ServerGatekeeper } = await import('./gatekeeper.js');
    await ServerGatekeeper.initializeExplicit(plaintextPassword);
    ServerConfig.setServerPasswordGateReady();
    delete process.env.SERVER_PASSWORD;
  } catch (error) {
    console.error('[SERVER] Failed to initialize server password gate');
    throw error;
  }
}
