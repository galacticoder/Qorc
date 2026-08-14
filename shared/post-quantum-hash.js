import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';

const encoder = new TextEncoder();

export class PostQuantumHash {
  static blake3(data, options) {
    return blake3(data, options);
  }

  static digestParts(parts, length = 32) {
    const hasher = blake3.create({ dkLen: length });
    for (const part of parts) hasher.update(part);
    return hasher.digest();
  }

  static transcript(domain, fields, length = 32) {
    const hasher = blake3.create({ dkLen: length });
    const lengthBytes = new Uint8Array(4);
    const lengthView = new DataView(lengthBytes.buffer);
    for (const value of [domain, ...fields]) {
      const encoded = encoder.encode(String(value ?? ''));
      try {
        if (encoded.length > 0xffffffff) throw new Error('Transcript field too large');
        lengthView.setUint32(0, encoded.length, false);
        hasher.update(lengthBytes);
        hasher.update(encoded);
      } finally {
        encoded.fill(0);
      }
    }
    lengthBytes.fill(0);
    return hasher.digest();
  }

  static deriveKey(inputKey, salt, info, length = 32) {
    const infoBytes = typeof info === 'string' ? encoder.encode(info) : info || new Uint8Array(0);
    return hkdf(blake3, inputKey, salt, infoBytes, length);
  }

  static domainKdf(domain, key, length) {
    const domainBytes = typeof domain === 'string' ? encoder.encode(domain) : domain;
    if (!(domainBytes instanceof Uint8Array) || !(key instanceof Uint8Array)) {
      throw new Error('Invalid domain KDF input');
    }
    const input = new Uint8Array(domainBytes.length + 1 + key.length);
    input.set(domainBytes, 0);
    input[domainBytes.length] = 0;
    input.set(key, domainBytes.length + 1);
    try {
      return blake3(input, { dkLen: length });
    } finally {
      input.fill(0);
    }
  }
}
