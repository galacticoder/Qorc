import {
  HYBRID_ENVELOPE_MAX_OUTER_CIPHERTEXT_BYTES,
  HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES,
  PQ_AEAD_MAC_SIZE,
  PQ_KEM_CIPHERTEXT_SIZE,
  PQ_SIG_PUBLIC_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE,
} from '../constants';
import { hasExactObjectKeys } from '../sanitizers';
import type { HybridEnvelope } from '../types/crypto-types';
import { canonicalBase64Shape } from '../../../shared/canonical-base64.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export { canonicalBase64Shape } from '../../../shared/canonical-base64.js';

export function isHybridEnvelopeWireShape(value: unknown): value is HybridEnvelope {
  if (!hasExactObjectKeys(value, ['version', 'routing', 'routingSignature', 'algorithms', 'kemCiphertext', 'outer'])) return false;
  if (value.version !== PROTOCOL_KEYS.HYBRID_ENVELOPE_VERSION) return false;
  if (!hasExactObjectKeys(value.routing, ['to', 'from', 'type', 'timestamp', 'size'])) return false;
  if (
    !canonicalBase64Shape(value.routing.to, { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE }) ||
    !canonicalBase64Shape(value.routing.from, { exactBytes: PQ_SIG_PUBLIC_KEY_SIZE }) ||
    value.routing.type !== 'libsignal-message' ||
    !Number.isSafeInteger(value.routing.timestamp) ||
    !Number.isSafeInteger(value.routing.size) ||
    value.routing.size < 0 ||
    value.routing.size > HYBRID_ENVELOPE_MAX_PLAINTEXT_BYTES
  ) return false;
  if (
    !hasExactObjectKeys(value.routingSignature, ['algorithm', 'signature']) ||
    value.routingSignature.algorithm !== 'ML-DSA-87' ||
    !canonicalBase64Shape(value.routingSignature.signature, { exactBytes: PQ_SIG_SIGNATURE_SIZE })
  ) return false;
  if (
    !hasExactObjectKeys(value.algorithms, ['outer', 'inner', 'aead', 'mac']) ||
    value.algorithms.outer !== 'ML-KEM-1024' ||
    value.algorithms.inner !== 'X25519' ||
    value.algorithms.aead !== 'AES-256-GCM+XChaCha20-Poly1305' ||
    value.algorithms.mac !== 'BLAKE3-256'
  ) return false;
  if (!canonicalBase64Shape(value.kemCiphertext, { exactBytes: PQ_KEM_CIPHERTEXT_SIZE })) return false;
  if (!hasExactObjectKeys(value.outer, ['salt', 'nonce', 'ciphertext', 'tag', 'mac'])) return false;
  return canonicalBase64Shape(value.outer.salt, { exactBytes: 32 }) &&
    canonicalBase64Shape(value.outer.nonce, { exactBytes: 12 }) &&
    canonicalBase64Shape(value.outer.ciphertext, { maxBytes: HYBRID_ENVELOPE_MAX_OUTER_CIPHERTEXT_BYTES }) &&
    canonicalBase64Shape(value.outer.tag, { exactBytes: 16 }) &&
    canonicalBase64Shape(value.outer.mac, { exactBytes: PQ_AEAD_MAC_SIZE });
}
