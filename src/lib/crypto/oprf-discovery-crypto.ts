/**
 * OPRF-Based Discovery Cryptography
 */

import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumUtils } from '../utils/pq-utils';
import type { PeerCertificateBundle } from '../types/p2p-types';
import type { AvatarData } from '../types/avatar-types';

export interface OPRFBlindResult {
    blind: Uint8Array;
    blinded: Uint8Array;
}

export interface OPRFServerResponse {
    evaluated: string;
    proof: string;
    publicKey: string;
}

export interface OPRFDiscoveryMaterial {
    inboxId: string;
    publicKeys: {
        kyberPublicBase64: string;
        dilithiumPublicBase64: string;
        x25519PublicBase64: string;
    };
    fullBundle?: unknown;
    peerCertificate?: PeerCertificateBundle;
    avatar?: AvatarData | null;
}

const DISCOVERY_TOKEN_DOMAIN = 'discovery-token-v1';
const DISCOVERY_ENCRYPTION_DOMAIN = 'discovery-encryption-key-v1';
const DISCOVERY_BLOB_AAD = 'oprf-discovery-blob-v1';

export class OPRFDiscoveryClient {
    private serverPublicKey: Uint8Array | null = null;

    setServerPublicKey(publicKeyHex: string): void {
        this.serverPublicKey = hexToBytes(publicKeyHex);
    }

    getServerPublicKey(): string | null {
        return this.serverPublicKey ? bytesToHex(this.serverPublicKey) : null;
    }

    blindHandle(handle: string): OPRFBlindResult {
        const normalizedHandle = handle.toLowerCase().trim();
        const handleBytes = new TextEncoder().encode(normalizedHandle);

        const result = ristretto255_oprf.voprf.blind(handleBytes);

        return {
            blind: result.blind,
            blinded: result.blinded
        };
    }

    finalizeToken(
        handle: string,
        blindResult: OPRFBlindResult,
        serverResponse: OPRFServerResponse,
        epoch: number
    ): { token: string; encryptionKey: Uint8Array } {
        const normalizedHandle = handle.toLowerCase().trim();
        const handleBytes = new TextEncoder().encode(normalizedHandle);

        const evaluated = hexToBytes(serverResponse.evaluated);
        const proof = hexToBytes(serverResponse.proof);
        const publicKey = hexToBytes(serverResponse.publicKey);

        if (this.serverPublicKey && !constantTimeEqual(publicKey, this.serverPublicKey)) {
            throw new Error('Server public key mismatch - possible MITM attack');
        }

        const oprfOutput = ristretto255_oprf.voprf.finalize(
            handleBytes,
            blindResult.blind,
            evaluated,
            blindResult.blinded,
            publicKey,
            proof
        );

        const epochBytes = new Uint8Array(8);
        new DataView(epochBytes.buffer).setBigUint64(0, BigInt(epoch), false);

        const token = blake3(
            concatBytes(
                new TextEncoder().encode(DISCOVERY_TOKEN_DOMAIN),
                oprfOutput,
                epochBytes
            ),
            { dkLen: 32 }
        );

        const encryptionKey = blake3(
            concatBytes(
                new TextEncoder().encode(DISCOVERY_ENCRYPTION_DOMAIN),
                oprfOutput
            ),
            { dkLen: 32 }
        );

        return {
            token: bytesToHex(token),
            encryptionKey
        };
    }

    encryptDiscoveryBlob(
        material: OPRFDiscoveryMaterial,
        encryptionKey: Uint8Array
    ): string {
        const plaintext = new TextEncoder().encode(JSON.stringify(material));
        const nonce = crypto.getRandomValues(new Uint8Array(36));
        const aad = new TextEncoder().encode(DISCOVERY_BLOB_AAD);

        const { ciphertext, tag } = PostQuantumAEAD.encrypt(plaintext, encryptionKey, aad, nonce);

        const combined = new Uint8Array(nonce.length + tag.length + ciphertext.length);
        combined.set(nonce, 0);
        combined.set(tag, nonce.length);
        combined.set(ciphertext, nonce.length + tag.length);

        return PostQuantumUtils.uint8ArrayToBase64(combined);
    }

    decryptDiscoveryBlob(
        blobBase64: string,
        encryptionKey: Uint8Array
    ): OPRFDiscoveryMaterial | null {
        try {
            const data = PostQuantumUtils.base64ToUint8Array(blobBase64);

            const nonce = data.slice(0, 36);
            const tag = data.slice(36, 68);
            const ciphertext = data.slice(68);
            const aad = new TextEncoder().encode(DISCOVERY_BLOB_AAD);

            const plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, encryptionKey, aad);

            return JSON.parse(new TextDecoder().decode(plaintext));
        } catch (error) {
            console.error('[OPRF-DISCOVERY] Failed to decrypt blob:', error);
            return null;
        }
    }
}

function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error('Invalid hex string length');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

export const oprfDiscoveryClient = new OPRFDiscoveryClient();
