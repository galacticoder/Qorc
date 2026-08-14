import { KYBER_PUBLIC_KEY_LENGTH, DILITHIUM_PUBLIC_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH } from '../../lib/constants';
import type { HybridPublicKeys } from '../../lib/types/message-sending-types';
import { hasPrototypePollutionKeys, isPlainObject } from '../../lib/sanitizers';
import {
  isValidDilithiumPublicKeyBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64,
} from '../../lib/utils/messaging-validators';

const expectedBase64Length = (bytes: number): number => 4 * Math.ceil(bytes / 3);

const hasExactHybridKeyShape = (keys: unknown): keys is Required<HybridPublicKeys> => (
  isPlainObject(keys) &&
  !hasPrototypePollutionKeys(keys) &&
  Object.keys(keys).sort().join(',') === 'dilithiumPublicBase64,kyberPublicBase64,x25519PublicBase64' &&
  typeof keys.kyberPublicBase64 === 'string' &&
  keys.kyberPublicBase64.length === expectedBase64Length(KYBER_PUBLIC_KEY_LENGTH) &&
  typeof keys.dilithiumPublicBase64 === 'string' &&
  keys.dilithiumPublicBase64.length === expectedBase64Length(DILITHIUM_PUBLIC_KEY_LENGTH) &&
  typeof keys.x25519PublicBase64 === 'string' &&
  keys.x25519PublicBase64.length === expectedBase64Length(X25519_PUBLIC_KEY_LENGTH)
);

export const validateHybridKeys = (keys: unknown): keys is Required<HybridPublicKeys> => (
  hasExactHybridKeyShape(keys) &&
  isValidKyberPublicKeyBase64(keys.kyberPublicBase64) &&
  isValidDilithiumPublicKeyBase64(keys.dilithiumPublicBase64) &&
  isValidX25519PublicKeyBase64(keys.x25519PublicBase64)
);
