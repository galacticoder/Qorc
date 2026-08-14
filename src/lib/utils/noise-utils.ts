import { x25519 } from '@noble/curves/ed25519.js';
import type { X25519KeyPair } from '../types/noise-types';
import { PostQuantumRandom } from '../cryptography/random';

// Clamp X25519 scalar
export function clampX25519Scalar(sk: Uint8Array): Uint8Array {
    const out = new Uint8Array(sk);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    return out;
}

// Generate ephemeral X25519 keypair
export function generateX25519KeyPair(): X25519KeyPair {
    const raw = PostQuantumRandom.randomBytes(32);
    let secretKey: Uint8Array | null = null;
    try {
        secretKey = clampX25519Scalar(raw);
        const publicKey = x25519.getPublicKey(secretKey);
        const result = { secretKey, publicKey: new Uint8Array(publicKey) };
        secretKey = null;
        return result;
    } finally {
        raw.fill(0);
        secretKey?.fill(0);
    }
}

// Compute X25519 shared secret
export function computeX25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    if (privateKey.length !== 32 || publicKey.length !== 32) {
        throw new Error('X25519 keys must be 32 bytes');
    }
    const shared = x25519.getSharedSecret(privateKey, publicKey);
    const result = new Uint8Array(shared.slice(0, 32));
    if (result.every((byte) => byte === 0)) {
        result.fill(0);
        throw new Error('Invalid all-zero X25519 shared secret');
    }
    return result;
}
