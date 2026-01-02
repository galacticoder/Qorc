/**
 * Long-Term Encryption Module
 * Encrypts data using recipient's long-term Kyber public key so it can be 
 * decrypted on any device using their passphrase-derived secret key.
 */

import { PostQuantumKEM } from './kem';
import { PostQuantumAEAD } from './aead';
import { PostQuantumHash } from './hash';
import { PostQuantumRandom } from './random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PQ_KEM_PUBLIC_KEY_SIZE, PQ_KEM_SECRET_KEY_SIZE, LONG_TERM_ENVELOPE_VERSION, LONG_TERM_ENVELOPE_KDF_INFO } from '../constants';

const KDF_SALT = new TextEncoder().encode('long-term-encryption-v1');

export interface LongTermEnvelope {
    version: string;
    kemCiphertext: string;
    nonce: string;
    ciphertext: string;
    tag: string;
    timestamp: number;
    senderPublicKey?: string;
}

export interface LongTermDecryptResult {
    data: Uint8Array;
    text?: string;
    json?: unknown;
    timestamp: number;
}

// Encrypt data to a recipient's long-term Kyber public key
export async function encryptLongTerm(
    data: string | Uint8Array,
    recipientKyberPublicKey: string | Uint8Array,
    senderPublicKey?: string
): Promise<LongTermEnvelope> {
    const plaintextBytes = typeof data === 'string'
        ? new TextEncoder().encode(data)
        : data;

    const recipientKey = typeof recipientKyberPublicKey === 'string'
        ? PostQuantumUtils.base64ToUint8Array(recipientKyberPublicKey)
        : recipientKyberPublicKey;

    // Validate key length
    if (recipientKey.length !== PQ_KEM_PUBLIC_KEY_SIZE) {
        throw new Error(`Invalid Kyber public key length: ${recipientKey.length}, expected ${PQ_KEM_PUBLIC_KEY_SIZE}`);
    }

    // Kyber encapsulation
    const { ciphertext: kemCiphertext, sharedSecret } = PostQuantumKEM.encapsulate(recipientKey);

    let aeadKey: Uint8Array | null = null;
    try {
        aeadKey = PostQuantumHash.deriveKey(sharedSecret, KDF_SALT, LONG_TERM_ENVELOPE_KDF_INFO, 32);
        const nonce = PostQuantumRandom.randomBytes(36);
        const timestamp = Date.now();
        const aad = new TextEncoder().encode(`${LONG_TERM_ENVELOPE_VERSION}:${timestamp}`);
        const { ciphertext, tag } = PostQuantumAEAD.encrypt(plaintextBytes, aeadKey, aad, nonce);

        return {
            version: LONG_TERM_ENVELOPE_VERSION,
            kemCiphertext: PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
            nonce: PostQuantumUtils.uint8ArrayToBase64(nonce),
            ciphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext),
            tag: PostQuantumUtils.uint8ArrayToBase64(tag),
            timestamp,
            ...(senderPublicKey ? { senderPublicKey } : {})
        };
    } finally {
        if (aeadKey) PostQuantumUtils.clearMemory(aeadKey);
        PostQuantumUtils.clearMemory(sharedSecret);
    }
}

// Decrypt data using recipient's long-term Kyber secret key
export async function decryptLongTerm(
    envelope: LongTermEnvelope,
    recipientKyberSecretKey: string | Uint8Array
): Promise<LongTermDecryptResult> {
    if (envelope.version !== LONG_TERM_ENVELOPE_VERSION) {
        throw new Error(`Unsupported envelope version: ${envelope.version}`);
    }

    const secretKey = typeof recipientKyberSecretKey === 'string'
        ? PostQuantumUtils.base64ToUint8Array(recipientKyberSecretKey)
        : recipientKyberSecretKey;

    if (secretKey.length !== PQ_KEM_SECRET_KEY_SIZE) {
        throw new Error(`Invalid Kyber secret key length: ${secretKey.length}, expected ${PQ_KEM_SECRET_KEY_SIZE}`);
    }

    // Decode envelope fields
    const kemCiphertext = PostQuantumUtils.base64ToUint8Array(envelope.kemCiphertext);
    const nonce = PostQuantumUtils.base64ToUint8Array(envelope.nonce);
    const ciphertext = PostQuantumUtils.base64ToUint8Array(envelope.ciphertext);
    const tag = PostQuantumUtils.base64ToUint8Array(envelope.tag);

    // Decapsulate to get shared secret
    const sharedSecret = PostQuantumKEM.decapsulate(kemCiphertext, secretKey);

    let aeadKey: Uint8Array | null = null;
    try {
        // Derive same AEAD key
        aeadKey = PostQuantumHash.deriveKey(sharedSecret, KDF_SALT, LONG_TERM_ENVELOPE_KDF_INFO, 32);

        const aad = new TextEncoder().encode(`${LONG_TERM_ENVELOPE_VERSION}:${envelope.timestamp}`);

        const plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, aeadKey, aad);

        let text: string | undefined;
        let json: unknown;
        try {
            text = new TextDecoder().decode(plaintext);
            try {
                json = JSON.parse(text);
            } catch {
            }
        } catch {
        }

        return {
            data: plaintext,
            text,
            json,
            timestamp: envelope.timestamp
        };
    } finally {
        if (aeadKey) PostQuantumUtils.clearMemory(aeadKey);
        PostQuantumUtils.clearMemory(sharedSecret);
    }
}

// Encrypt JSON data for long-term storage
export async function encryptJsonLongTerm<T>(
    data: T,
    recipientKyberPublicKey: string | Uint8Array,
    senderPublicKey?: string
): Promise<LongTermEnvelope> {
    const jsonStr = JSON.stringify(data);
    return encryptLongTerm(jsonStr, recipientKyberPublicKey, senderPublicKey);
}

// Decrypt and parse JSON data from long-term storage
export async function decryptJsonLongTerm<T>(
    envelope: LongTermEnvelope,
    recipientKyberSecretKey: string | Uint8Array
): Promise<T> {
    const result = await decryptLongTerm(envelope, recipientKyberSecretKey);
    if (result.json === undefined) {
        throw new Error('Decrypted data is not valid JSON');
    }
    return result.json as T;
}

// Check if an object is a valid LongTermEnvelope
export function isLongTermEnvelope(obj: unknown): obj is LongTermEnvelope {
    if (!obj || typeof obj !== 'object') return false;
    const e = obj as Record<string, unknown>;
    return (
        e.version === LONG_TERM_ENVELOPE_VERSION &&
        typeof e.kemCiphertext === 'string' &&
        typeof e.nonce === 'string' &&
        typeof e.ciphertext === 'string' &&
        typeof e.tag === 'string' &&
        typeof e.timestamp === 'number'
    );
}
