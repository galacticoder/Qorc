import { CryptoUtils } from './unified-crypto.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { HASH_OUTPUT_BYTES, WIDE_HASH_OUTPUT_BYTES } from '../../shared/crypto-sizes.js';

export async function deriveQuantumAeadKey(rawSecret, context) {
  if (!(rawSecret instanceof Uint8Array) || rawSecret.length === 0) {
    throw new TypeError('AEAD secret must be a non-empty byte array');
  }
  if (typeof context !== 'string' || context.length === 0) {
    throw new TypeError('AEAD context must be a non-empty string');
  }

  const secret = new Uint8Array(rawSecret);
  const salt = CryptoUtils.Hash.shake256(secret, WIDE_HASH_OUTPUT_BYTES);
  const info = UTF8_ENCODER.encode(context);
  try {
    return await CryptoUtils.KDF.quantumHKDF(
      secret,
      salt,
      info,
      HASH_OUTPUT_BYTES
    );
  } finally {
    secret.fill(0);
    salt.fill(0);
    info.fill(0);
  }
}
