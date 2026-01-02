/**
 * CryptoUtils - Main crypto utilities export
 */

import { Base64 } from '../cryptography/base64';
import { HashingService } from '../cryptography/hashing';
import { KeyService } from '../cryptography/keys';
import { KDF } from '../cryptography/kdf';
import { AES } from '../cryptography/aes-gcm';
import { DilithiumService, KyberService, EncryptService, DecryptService, PostQuantumHybridService } from '../cryptography/services';
import { Hybrid } from '../cryptography/hybrid';
import { PostQuantumAEAD } from '../cryptography/aead';
import { SecureMemory } from '../cryptography/secure-memory';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  CRYPTO_AES_KEY_SIZE,
  CRYPTO_IV_LENGTH,
  CRYPTO_AUTH_TAG_LENGTH,
  CRYPTO_HKDF_HASH,
  CRYPTO_X25519_DERIVE_BITS,
  CRYPTO_HKDF_INFO
} from '../constants';

export const kyber = ml_kem1024;

class CryptoConfig {
  static AES_KEY_SIZE = CRYPTO_AES_KEY_SIZE;
  static IV_LENGTH = CRYPTO_IV_LENGTH;
  static AUTH_TAG_LENGTH = CRYPTO_AUTH_TAG_LENGTH;
  static HKDF_HASH = CRYPTO_HKDF_HASH;
  static HKDF_INFO = new TextEncoder().encode(CRYPTO_HKDF_INFO);
  static X25519_DERIVE_BITS = CRYPTO_X25519_DERIVE_BITS;
}

export const CryptoUtils = {
  Config: CryptoConfig,
  Base64,
  Hash: HashingService,
  Keys: KeyService,
  Encrypt: EncryptService,
  Decrypt: DecryptService,
  Hybrid,
  Kyber: KyberService,
  Dilithium: DilithiumService,
  PostQuantum: PostQuantumHybridService,
  PostQuantumAEAD,
  AES,
  KDF,
  SecureMemory
};

export {
  Base64,
  HashingService,
  KeyService,
  KDF,
  AES,
  DilithiumService,
  KyberService,
  EncryptService,
  DecryptService,
  PostQuantumHybridService,
  Hybrid,
  CryptoConfig
};

export function mapArgon2Algorithm(algorithm: string | number): number {
  if (algorithm === 2 || algorithm === 'argon2id') return 2;
  throw new Error('Only Argon2id is supported for maximum security');
}

export {
  buildRoutingHeader,
  signRoutingHeader,
  verifyRoutingHeader
} from '../cryptography/hybrid';
