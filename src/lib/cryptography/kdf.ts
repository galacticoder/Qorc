/**
 * Key Derivation Functions
 */

import { HashingService } from './hashing';
import { PostQuantumWorker } from './worker-bridge';
import { SecureMemory } from './secure-memory';
import {
  CRYPTO_AES_KEY_SIZE,
  CRYPTO_HKDF_HASH,
  CRYPTO_HKDF_INFO,
  ARGON2_VERSION
} from '../constants';

const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
const textEncoder = new TextEncoder();
const HKDF_INFO_BYTES = textEncoder.encode(CRYPTO_HKDF_INFO);

export class KDF {
  static async argon2id(
    passphrase: string,
    options: {
      salt: Uint8Array;
      time: number;
      memoryCost: number;
      parallelism: number;
      hashLen: number;
    }
  ): Promise<Uint8Array> {
    const hashOptions = {
      pass: passphrase,
      salt: options.salt,
      time: options.time,
      mem: options.memoryCost,
      parallelism: options.parallelism,
      type: 2,
      version: ARGON2_VERSION,
      hashLen: options.hashLen
    };

    const result = await PostQuantumWorker.argon2Hash(hashOptions);
    return result.hash;
  }

  static async blake3Hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, outLen: number): Promise<Uint8Array> {
    const prk = await HashingService.generateBlake3Mac(ikm, salt);
    const output = new Uint8Array(outLen);
    const hashLen = 32;
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    try {
      for (let i = 1; i <= n; i++) {
        const input = new Uint8Array(t.length + info.length + 1);
        input.set(t, 0);
        input.set(info, t.length);
        input[input.length - 1] = i;

        const newT = new Uint8Array(await HashingService.generateBlake3Mac(input, prk));

        if (t.length > 0) {
          SecureMemory.zeroBuffer(t as Uint8Array);
        }
        t = newT;

        const copyLen = Math.min(hashLen, outLen - outputOffset);
        output.set(t.subarray(0, copyLen), outputOffset);
        outputOffset += copyLen;
      }
    } finally {
      SecureMemory.zeroBuffer(prk);
      if (t.length > 0) {
        SecureMemory.zeroBuffer(t);
      }
    }

    return output;
  }

  static async deriveAesCryptoKeyFromIkm(ikm: Uint8Array, salt: Uint8Array, context?: string) {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    const baseKey = await subtle.importKey('raw', ikm.buffer as ArrayBuffer, { name: 'HKDF' }, false, ['deriveKey']);
    const derivedKey = await subtle.deriveKey(
      {
        name: 'HKDF',
        hash: CRYPTO_HKDF_HASH,
        salt: salt.buffer as ArrayBuffer,
        info: context ? textEncoder.encode(context).buffer as ArrayBuffer : HKDF_INFO_BYTES.buffer as ArrayBuffer
      },
      baseKey,
      { name: 'AES-GCM', length: CRYPTO_AES_KEY_SIZE },
      false,
      ['encrypt', 'decrypt']
    );
    return derivedKey;
  }

  static async deriveSessionKey(ikm: Uint8Array, salt: Uint8Array, sessionContext: string): Promise<Uint8Array> {
    const contextInfo = textEncoder.encode(`session-key-v2:${sessionContext}`);
    return await this.blake3Hkdf(ikm, salt, contextInfo, 32);
  }
}
