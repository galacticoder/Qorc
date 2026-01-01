import { CryptoUtils } from '../../lib/unified-crypto';
import { KYBER_PUBLIC_KEY_LENGTH, DILITHIUM_PUBLIC_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH } from '../../lib/constants';
import type { HybridPublicKeys } from '../../lib/types/message-sending-types';

// Recipient key validator
export const recipientKeyValidator = () => {
  const cache = new Map<string, { valid: boolean; expiresAt: number }>();
  return (keys: HybridPublicKeys | undefined) => {
    if (!keys) return false;
    const compositeKey = `${keys.kyberPublicBase64}:${keys.dilithiumPublicBase64}:${keys.x25519PublicBase64 ?? ''}`;
    const cached = cache.get(compositeKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.valid;
    }
    let valid = true;
    try {
      const kyber = CryptoUtils.Base64.base64ToUint8Array(keys.kyberPublicBase64);
      const dilithium = CryptoUtils.Base64.base64ToUint8Array(keys.dilithiumPublicBase64);
      if (kyber.length !== KYBER_PUBLIC_KEY_LENGTH || dilithium.length !== DILITHIUM_PUBLIC_KEY_LENGTH) {
        valid = false;
      }
      if (keys.x25519PublicBase64) {
        const x25519 = CryptoUtils.Base64.base64ToUint8Array(keys.x25519PublicBase64);
        if (x25519.length !== X25519_PUBLIC_KEY_LENGTH) {
          valid = false;
        }
      }
    } catch {
      valid = false;
    }
    cache.set(compositeKey, {
      valid,
      expiresAt: Date.now() + 60_000,
    });
    return valid;
  };
};

// Validate hybrid keys structure
export const validateHybridKeys = (keys: any): boolean => {
  if (!keys || typeof keys !== 'object') return false;
  return (
    typeof keys.kyberPublicBase64 === 'string' &&
    keys.kyberPublicBase64.length > 0 &&
    typeof keys.dilithiumPublicBase64 === 'string' &&
    keys.dilithiumPublicBase64.length > 0
  );
};
