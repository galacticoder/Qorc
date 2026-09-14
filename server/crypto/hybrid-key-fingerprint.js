import { UTF8_ENCODER } from '../utils/encoding.js';
import { PostQuantumHash } from '../../shared/post-quantum-hash.js';

export function computeHybridPublicKeyFingerprint(keyPair) {
  const encoded = UTF8_ENCODER.encode(JSON.stringify({
    kyberPublicBase64: Buffer.from(keyPair.kyber.publicKey).toString('base64'),
    dilithiumPublicBase64: Buffer.from(keyPair.dilithium.publicKey).toString('base64'),
    x25519PublicBase64: Buffer.from(keyPair.x25519.publicKey).toString('base64')
  }));
  const digest = PostQuantumHash.blake3(encoded);
  try {
    return Buffer.from(digest).toString('hex');
  } finally {
    encoded.fill(0);
    digest.fill(0);
  }
}
