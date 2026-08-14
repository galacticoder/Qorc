/**
 * Main crypto utilities export
 */

import { Base64 } from '../cryptography/base64';
import { HashingService } from '../cryptography/hashing';
import { KeyService } from '../cryptography/keys';
import { KDF } from '../cryptography/kdf';
import { AES } from '../cryptography/aes-gcm';
import { DilithiumService, KyberService, EncryptService, DecryptService } from '../cryptography/services';
import { Hybrid } from '../cryptography/hybrid';
import { PostQuantumAEAD } from '../cryptography/aead';
import { SecureMemory } from '../cryptography/secure-memory';
import {
  CRYPTO_AES_KEY_SIZE,
  CRYPTO_IV_LENGTH,
  CRYPTO_AUTH_TAG_LENGTH,
  CRYPTO_HKDF_HASH,
  CRYPTO_X25519_DERIVE_BITS
} from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

class CryptoConfig {
  static AES_KEY_SIZE = CRYPTO_AES_KEY_SIZE;
  static IV_LENGTH = CRYPTO_IV_LENGTH;
  static AUTH_TAG_LENGTH = CRYPTO_AUTH_TAG_LENGTH;
  static HKDF_HASH = CRYPTO_HKDF_HASH;
  static HKDF_INFO = new TextEncoder().encode(PROTOCOL_KEYS.HYBRID_KEY_KDF);
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
  PostQuantumAEAD,
  AES,
  KDF,
  SecureMemory
};
