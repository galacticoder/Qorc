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

export const CryptoUtils = {
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
