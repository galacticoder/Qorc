/**
 * Hashing Service - Argon2 and BLAKE3 operations
 */

import { blake3 as nobleBlake3 } from '@noble/hashes/blake3.js';
import { Base64 } from './base64';
import { PostQuantumWorker } from './worker-bridge';
import { SecureMemory } from './secure-memory';
import { mapArgon2Algorithm } from '../utils/crypto-utils';
import {
  ARGON2_DEFAULT_TIME,
  ARGON2_DEFAULT_MEM,
  ARGON2_DEFAULT_PARALLELISM,
  ARGON2_VERSION,
  ARGON2_HASH_LEN,
  HASH_DATA_MAX_SIZE,
  HASH_TIMEOUT_MIN_MS,
  HASH_TIMEOUT_MAX_MS,
  ARGON2_MAX_ENCODED_LENGTH
} from '../constants';

export class HashingService {
  static parseArgon2Hash(encodedHash: string) {
    if (!encodedHash || typeof encodedHash !== 'string') {
      throw new Error('Encoded hash must be a non-empty string');
    }
    if (encodedHash.length > ARGON2_MAX_ENCODED_LENGTH) {
      throw new Error('Hash too long - potential DoS attack');
    }

    const parts = encodedHash.split('$');
    if (parts.length !== 6) {
      throw new Error('Invalid Argon2 encoded hash format - wrong number of parts');
    }

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;
    if (!algorithm || !['argon2i', 'argon2d', 'argon2id'].includes(algorithm)) {
      throw new Error('Invalid Argon2 algorithm type');
    }
    if (!versionPart || !versionPart.includes('=')) {
      throw new Error('Invalid version format');
    }

    const version = parseInt(versionPart.split('=')[1], 10);
    if (Number.isNaN(version) || version < 0x10 || version > 0x13) {
      throw new Error('Invalid Argon2 version');
    }

    if (!paramsPart) {
      throw new Error('Missing parameters');
    }

    const params: Record<string, number> = {};
    paramsPart.split(',').forEach((param) => {
      const equalIndex = param.indexOf('=');
      if (equalIndex === -1) {
        throw new Error('Invalid parameter format');
      }
      const key = param.substring(0, equalIndex);
      const value = param.substring(equalIndex + 1);
      if (!['m', 't', 'p'].includes(key)) {
        throw new Error(`Invalid parameter key: ${key}`);
      }
      const numValue = Number(value);
      if (Number.isNaN(numValue) || numValue < 1 || numValue > 2 ** 30) {
        throw new Error(`Invalid parameter value for ${key}: ${value}`);
      }
      params[key] = numValue;
    });

    if (!params.m || !params.t || !params.p) {
      throw new Error('Missing required parameters (m, t, p)');
    }

    if (!saltB64 || !hashB64) {
      throw new Error('Missing salt or hash');
    }

    let hashBytes: Uint8Array;
    try {
      hashBytes = Uint8Array.from(atob(hashB64), (c) => c.charCodeAt(0));
    } catch {
      throw new Error('Invalid base64 encoding in hash');
    }
    if (hashBytes.length < 16 || hashBytes.length > 128) {
      throw new Error('Invalid hash length');
    }

    return {
      version,
      algorithm,
      salt: saltB64,
      memoryCost: params.m,
      timeCost: params.t,
      parallelism: params.p,
      hash: hashBytes
    };
  }

  static async hashDataUsingInfo(
    data: string,
    args: {
      version?: number;
      algorithm?: string;
      salt: string;
      memoryCost?: number;
      timeCost?: number;
      parallelism?: number;
    }
  ) {
    if (!args?.salt) throw new Error('Salt is required');

    const saltBuffer = Base64.base64ToUint8Array(args.salt);
    const algEnum = mapArgon2Algorithm(args.algorithm ?? 'argon2id');

    const opts = {
      pass: data,
      salt: saltBuffer,
      time: args.timeCost ?? 3,
      mem: args.memoryCost ?? 65536,
      parallelism: args.parallelism ?? 1,
      type: algEnum,
      version: args.version ?? ARGON2_VERSION,
      hashLen: ARGON2_HASH_LEN
    };

    const result = await PostQuantumWorker.argon2Hash(opts);
    return result.encoded;
  }

  static async hashData(data: string, timeoutMs: number = 30000) {
    if (!data || typeof data !== 'string') {
      throw new Error('Invalid data for hashing - must be non-empty string');
    }
    if (data.length > HASH_DATA_MAX_SIZE) {
      throw new Error(`Data too large for hashing (max ${HASH_DATA_MAX_SIZE / 1_000_000}MB)`);
    }
    if (timeoutMs < HASH_TIMEOUT_MIN_MS || timeoutMs > HASH_TIMEOUT_MAX_MS) {
      throw new Error(`Invalid timeout value (must be ${HASH_TIMEOUT_MIN_MS / 1000}-${HASH_TIMEOUT_MAX_MS / 1000} seconds)`);
    }

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const opts = {
      pass: data,
      salt,
      time: ARGON2_DEFAULT_TIME,
      mem: ARGON2_DEFAULT_MEM,
      parallelism: ARGON2_DEFAULT_PARALLELISM,
      type: 2,
      version: ARGON2_VERSION,
      hashLen: ARGON2_HASH_LEN
    };

    return Promise.race([
      PostQuantumWorker.argon2Hash(opts).then((res) => {
        if (!res || !res.encoded) {
          throw new Error('Argon2 hash operation failed');
        }
        return res.encoded;
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Argon2 hash operation timed out')), timeoutMs)
      )
    ]);
  }

  static async verifyHash(encoded: string, data: string) {
    const verified = await PostQuantumWorker.argon2Verify({ pass: data, encoded });
    return verified;
  }

  static async generateBlake3Mac(message: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be Uint8Array');
    }
    if (!(key instanceof Uint8Array)) {
      throw new Error('Key must be Uint8Array');
    }
    let normalizedKey = key;
    if (key.length !== 32) {
      normalizedKey = nobleBlake3(key, { dkLen: 32 });
    }
    const keyedHash = nobleBlake3.create({ key: normalizedKey });
    keyedHash.update(message);
    const mac = keyedHash.digest();
    if (normalizedKey !== key) {
      SecureMemory.zeroBuffer(normalizedKey);
    }
    return mac;
  }

  static async verifyBlake3Mac(message: Uint8Array, key: Uint8Array, expectedMac: Uint8Array): Promise<boolean> {
    const computedMac = await this.generateBlake3Mac(message, key);
    const isValid = SecureMemory.constantTimeCompare(computedMac, expectedMac);
    SecureMemory.zeroBuffer(computedMac);
    return isValid;
  }

  static async deriveKeyFromPassphrase(
    passphrase: string,
    options?: {
      salt?: string;
      time?: number;
      memoryCost?: number;
      parallelism?: number;
      algorithm?: number | string;
      version?: number;
      hashLen?: number;
    }
  ) {
    const saltBytes = options?.salt
      ? Base64.base64ToUint8Array(options.salt)
      : crypto.getRandomValues(new Uint8Array(16));

    const {
      time = ARGON2_DEFAULT_TIME,
      memoryCost = ARGON2_DEFAULT_MEM,
      parallelism = ARGON2_DEFAULT_PARALLELISM,
      algorithm = 2,
      version = ARGON2_VERSION,
      hashLen = ARGON2_HASH_LEN
    } = options || {};

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: mapArgon2Algorithm(algorithm),
      version,
      hashLen
    };

    const result = await PostQuantumWorker.argon2Hash(hashOptions);
    return result.hash;
  }
}

export { mapArgon2Algorithm };
