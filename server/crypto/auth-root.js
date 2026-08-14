import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

let authRoot = null;

function getAuthRoot() {
  if (authRoot) return authRoot;

  const configured = process.env.AUTH_ROOT_SEED;
  if (typeof configured !== 'string' || !/^[0-9a-fA-F]{64}$/.test(configured)) {
    throw new Error('AUTH_ROOT_SEED must be exactly 32 bytes encoded as 64 hexadecimal characters');
  }
  authRoot = Buffer.from(configured, 'hex');
  delete process.env.AUTH_ROOT_SEED;
  return authRoot;
}

export function deriveAuthRootKey(purpose) {
  if (typeof purpose !== 'string' || !/^[a-z0-9:-]{3,80}$/.test(purpose)) {
    throw new Error('Invalid authentication root-key purpose');
  }

  return hkdf(
    blake3,
    getAuthRoot(),
    new Uint8Array(0),
    UTF8_ENCODER.encode(`${PROTOCOL_KEYS.AUTH_ROOT}:${purpose}`),
    32
  );
}

export function destroyAuthRootKey() {
  authRoot?.fill(0);
  authRoot = null;
}
