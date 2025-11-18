import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';

const encoder = new TextEncoder();

const PostQuantumHash = {
  blake3(data, options) {
    return blake3(data, options);
  },

  deriveKey(inputKey, salt, info, length = 32) {
    const infoBytes = typeof info === 'string' ? encoder.encode(info) : info || new Uint8Array(0);
    return hkdf(blake3, inputKey, salt, infoBytes, length);
  }
};

export { PostQuantumHash };
