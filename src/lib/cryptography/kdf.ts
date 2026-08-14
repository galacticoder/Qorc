/**
 * Key Derivation Functions
 */

import { HashingService } from './hashing';
import { SecureMemory } from './secure-memory';
import {
  CRYPTO_AES_KEY_SIZE,
  CRYPTO_HKDF_HASH,
} from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
const textEncoder = new TextEncoder();
const HKDF_INFO_BYTES = textEncoder.encode(PROTOCOL_KEYS.HYBRID_KEY_KDF);

export class KDF {
  static async blake3Hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, outLen: number): Promise<Uint8Array> {
    const hashLen = 32;
    if (
      !(ikm instanceof Uint8Array) ||
      !(salt instanceof Uint8Array) ||
      !(info instanceof Uint8Array) ||
      !Number.isSafeInteger(outLen) ||
      outLen < 1 ||
      outLen > 255 * hashLen
    ) {
      throw new Error('Invalid BLAKE3 HKDF parameters');
    }

    const n = Math.ceil(outLen / hashLen);
    let prk: Uint8Array | null = null;
    let output: Uint8Array | null = null;
    let t: Uint8Array = new Uint8Array(0);
    let outputOffset = 0;
    let succeeded = false;

    try {
      prk = await HashingService.generateBlake3Mac(ikm, salt);
      if (prk.length !== hashLen) throw new Error('Invalid BLAKE3 HKDF extract length');
      output = new Uint8Array(outLen);

      for (let i = 1; i <= n; i++) {
        const input = new Uint8Array(t.length + info.length + 1);
        input.set(t, 0);
        input.set(info, t.length);
        input[input.length - 1] = i;

        let newT: Uint8Array;
        try {
          newT = await HashingService.generateBlake3Mac(input, prk);
        } finally {
          SecureMemory.zeroBuffer(input);
        }
        if (newT.length !== hashLen) {
          SecureMemory.zeroBuffer(newT);
          throw new Error('Invalid BLAKE3 HKDF expand length');
        }

        if (t.length > 0) {
          SecureMemory.zeroBuffer(t);
        }
        t = newT;

        const copyLen = Math.min(hashLen, outLen - outputOffset);
        output.set(t.subarray(0, copyLen), outputOffset);
        outputOffset += copyLen;
      }
      succeeded = true;
      return output;
    } finally {
      if (prk) SecureMemory.zeroBuffer(prk);
      if (t.length > 0) {
        SecureMemory.zeroBuffer(t);
      }
      if (!succeeded && output) SecureMemory.zeroBuffer(output);
    }
  }

  static async deriveAesCryptoKeyFromIkm(ikm: Uint8Array, salt: Uint8Array, context?: string) {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    if (
      !(ikm instanceof Uint8Array) ||
      ikm.length === 0 ||
      !(salt instanceof Uint8Array) ||
      salt.length === 0 ||
      (context !== undefined && (typeof context !== 'string' || context.length > 1024))
    ) {
      throw new Error('Invalid WebCrypto HKDF parameters');
    }
    const ikmSnapshot = ikm.slice();
    const saltSnapshot = salt.slice();
    const infoSnapshot = context ? textEncoder.encode(context) : HKDF_INFO_BYTES.slice();
    try {
      const baseKey = await subtle.importKey('raw', ikmSnapshot, { name: 'HKDF' }, false, ['deriveKey']);
      return await subtle.deriveKey(
        {
          name: 'HKDF',
          hash: CRYPTO_HKDF_HASH,
          salt: saltSnapshot,
          info: infoSnapshot
        },
        baseKey,
        { name: 'AES-GCM', length: CRYPTO_AES_KEY_SIZE },
        false,
        ['encrypt', 'decrypt']
      );
    } finally {
      SecureMemory.zeroBuffer(ikmSnapshot);
      SecureMemory.zeroBuffer(saltSnapshot);
      SecureMemory.zeroBuffer(infoSnapshot);
    }
  }

  static async deriveSessionKey(ikm: Uint8Array, salt: Uint8Array, sessionContext: string): Promise<Uint8Array> {
    const contextInfo = textEncoder.encode(`${PROTOCOL_KEYS.SESSION_KEY_KDF_PREFIX}${sessionContext}`);
    try {
      return await this.blake3Hkdf(ikm, salt, contextInfo, 32);
    } finally {
      SecureMemory.zeroBuffer(contextInfo);
    }
  }
}
