import type { HybridPublicKeys } from '../../lib/types/message-sending-types';
import { hasPrototypePollutionKeys, isPlainObject } from '../../lib/sanitizers';
import {
  isValidDilithiumPublicKeyBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64,
} from '../../lib/utils/messaging-validators';
import { ML_DSA_87_PUBLIC_KEY_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES, X25519_KEY_BYTES } from '../../../shared/crypto-sizes.js';

const expectedBase64Length = (bytes: number): number => 4 * Math.ceil(bytes / 3);

const hasExactHybridKeyShape = (keys: unknown): keys is Required<HybridPublicKeys> => (
  isPlainObject(keys) &&
  !hasPrototypePollutionKeys(keys) &&
  Object.keys(keys).sort().join(',') === 'dilithiumPublicBase64,kyberPublicBase64,x25519PublicBase64' &&
  typeof keys.kyberPublicBase64 === 'string' &&
  keys.kyberPublicBase64.length === expectedBase64Length(ML_KEM_1024_PUBLIC_KEY_BYTES) &&
  typeof keys.dilithiumPublicBase64 === 'string' &&
  keys.dilithiumPublicBase64.length === expectedBase64Length(ML_DSA_87_PUBLIC_KEY_BYTES) &&
  typeof keys.x25519PublicBase64 === 'string' &&
  keys.x25519PublicBase64.length === expectedBase64Length(X25519_KEY_BYTES)
);

export const validateHybridKeys = (keys: unknown): keys is Required<HybridPublicKeys> => (
  hasExactHybridKeyShape(keys) &&
  isValidKyberPublicKeyBase64(keys.kyberPublicBase64) &&
  isValidDilithiumPublicKeyBase64(keys.dilithiumPublicBase64) &&
  isValidX25519PublicKeyBase64(keys.x25519PublicBase64)
);
