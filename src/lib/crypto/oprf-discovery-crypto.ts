/**
 * OPRF-Based Discovery Cryptography
 */

import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumUtils } from '../utils/pq-utils';
import type { PeerCertificateBundle } from '../types/p2p-types';
import type { AvatarRef } from './avatar-blob-crypto';
import type { CertifiedPeerBundleV3 } from '../types/identity-types';
import { SPOOL_DETECTION_KEY_BYTES } from '../../../shared/spool-tag-protocol.js';
import { DISCOVERY_BLOB_BASE64_CHARS } from '../constants';
import {
    bytesToHex,
    concatUint8Arrays,
    constantTimeBytesEqual,
    hexToBytes as decodeHex,
} from '../utils/byte-utils';
import { canonicalBase64Shape } from '../../../shared/canonical-base64.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export { DISCOVERY_BLOB_BASE64_CHARS } from '../constants';

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
    publicKeys: {
        kyberPublicBase64: string;
        dilithiumPublicBase64: string;
        x25519PublicBase64: string;
    };
    fullBundle?: unknown;
    peerCertificate?: PeerCertificateBundle;
    peerCertificateFingerprint?: string;
    certifiedPeerBundle?: CertifiedPeerBundleV3;
    identityRootFingerprint?: string;
    identityBundleFingerprint?: string;
    avatarRef?: AvatarRef | null;
}

export interface OPRFDiscoveryBlob {
    spoolDetectionKey?: string;
    fullBundle: unknown;
    certifiedPeerBundle: CertifiedPeerBundleV3;
    avatarRef?: AvatarRef;
    keyTransparencyTransition?: {
        signedUpdate: unknown;
        authorization: unknown;
    };
}

const DISCOVERY_BLOB_WIRE_BYTES = (DISCOVERY_BLOB_BASE64_CHARS / 4) * 3;
const DISCOVERY_BLOB_NONCE_BYTES = 36;
const DISCOVERY_BLOB_SELECTOR_BYTES = 24;
const DISCOVERY_BLOB_TAG_BYTES = 32;
const DISCOVERY_BLOB_AEAD_CIPHERTEXT_OVERHEAD_BYTES = 32;
const DISCOVERY_BLOB_PREFIX_BYTES = DISCOVERY_BLOB_NONCE_BYTES + DISCOVERY_BLOB_SELECTOR_BYTES;
const DISCOVERY_BLOB_PREFIX_BASE64_CHARS = (DISCOVERY_BLOB_PREFIX_BYTES / 3) * 4;
const DISCOVERY_BLOB_HEADER_BYTES = 4;
const DISCOVERY_BLOB_PLAINTEXT_BYTES = DISCOVERY_BLOB_WIRE_BYTES -
    DISCOVERY_BLOB_PREFIX_BYTES -
    DISCOVERY_BLOB_TAG_BYTES -
    DISCOVERY_BLOB_AEAD_CIPHERTEXT_OVERHEAD_BYTES;
const DISCOVERY_BLOB_REQUIRED_KEYS = ['certifiedPeerBundle', 'fullBundle'];
const DISCOVERY_BLOB_OPTIONAL_KEYS = [
    'avatarRef',
    'keyTransparencyTransition',
    'spoolDetectionKey',
];
const DISCOVERY_DETECTION_KEY_RE = new RegExp(`^[a-f0-9]{${SPOOL_DETECTION_KEY_BYTES * 2}}$`);
const strictTextDecoder = new TextDecoder('utf-8', { fatal: true });

function deriveDiscoveryBlobSelector(encryptionKey: Uint8Array, nonce: Uint8Array): Uint8Array {
    if (encryptionKey.length !== 32 || nonce.length !== DISCOVERY_BLOB_NONCE_BYTES) {
        throw new Error('Invalid discovery selector material');
    }
    const domain = new TextEncoder().encode(PROTOCOL_KEYS.DISCOVERY_BLOB_SELECTOR);
    const input = concatUint8Arrays(domain, nonce);
    try {
        return blake3(input, { key: encryptionKey, dkLen: DISCOVERY_BLOB_SELECTOR_BYTES });
    } finally {
        domain.fill(0);
        input.fill(0);
    }
}

export class OPRFDiscoveryClient {
    private serverPublicKey: Uint8Array | null = null;

    setServerPublicKey(publicKeyHex: string): void {
        const next = hexToBytes(publicKeyHex, 32);
        this.serverPublicKey?.fill(0);
        this.serverPublicKey = next;
    }

    getServerPublicKey(): string | null {
        return this.serverPublicKey ? bytesToHex(this.serverPublicKey) : null;
    }

    blindHandle(handle: string): OPRFBlindResult {
        const normalizedHandle = handle.toLowerCase().trim();
        if (!/^[a-f0-9]{64}$/.test(normalizedHandle)) {
            throw new Error('Invalid blinded discovery handle');
        }
        const handleBytes = new TextEncoder().encode(normalizedHandle);
        try {
            const result = ristretto255_oprf.voprf.blind(handleBytes);
            return {
                blind: result.blind,
                blinded: result.blinded
            };
        } finally {
            handleBytes.fill(0);
        }
    }

    finalizeToken(
        handle: string,
        blindResult: OPRFBlindResult,
        serverResponse: OPRFServerResponse,
        epoch: number
    ): { token: string; encryptionKey: Uint8Array } {
        const { oprfOutput, encryptionKey } = this.finalizeOprfOutput(
            handle,
            blindResult,
            serverResponse
        );
        let succeeded = false;
        try {
            const result = {
                token: this.deriveTokenForEpoch(oprfOutput, epoch),
                encryptionKey
            };
            succeeded = true;
            return result;
        } finally {
            oprfOutput.fill(0);
            if (!succeeded) encryptionKey.fill(0);
        }
    }

    finalizeTokenBatch(
        handle: string,
        blindResult: OPRFBlindResult,
        serverResponse: OPRFServerResponse,
        epochs: number[]
    ): { encryptionKey: Uint8Array; tokens: Array<{ epoch: number; token: string }> } {
        const uniqueEpochs = Array.from(new Set(
            (Array.isArray(epochs) ? epochs : [])
                .filter((value) => Number.isFinite(value))
                .map((value) => Math.trunc(value))
        ));
        if (uniqueEpochs.length === 0) {
            blindResult.blind.fill(0);
            blindResult.blinded.fill(0);
            throw new Error('Discovery token epoch batch is empty');
        }

        const { oprfOutput, encryptionKey } = this.finalizeOprfOutput(
            handle,
            blindResult,
            serverResponse
        );
        let succeeded = false;
        try {
            const tokens = uniqueEpochs.map((epoch) => ({
                epoch,
                token: this.deriveTokenForEpoch(oprfOutput, epoch)
            }));
            succeeded = true;
            return { encryptionKey, tokens };
        } finally {
            oprfOutput.fill(0);
            if (!succeeded) encryptionKey.fill(0);
        }
    }

    private finalizeOprfOutput(
        handle: string,
        blindResult: OPRFBlindResult,
        serverResponse: OPRFServerResponse
    ): { oprfOutput: Uint8Array; encryptionKey: Uint8Array } {
        const normalizedHandle = handle.toLowerCase().trim();
        const handleBytes = new TextEncoder().encode(normalizedHandle);

        let evaluated: Uint8Array | null = null;
        let proof: Uint8Array | null = null;
        let publicKey: Uint8Array | null = null;
        let keyInput: Uint8Array | null = null;
        let oprfOutput: Uint8Array | null = null;
        let encryptionKey: Uint8Array | null = null;
        let succeeded = false;
        try {
            evaluated = hexToBytes(serverResponse.evaluated, 32);
            proof = hexToBytes(serverResponse.proof, 64);
            publicKey = hexToBytes(serverResponse.publicKey, 32);
            if (!this.serverPublicKey || !constantTimeBytesEqual(publicKey, this.serverPublicKey)) {
                throw new Error('Server OPRF public key mismatch');
            }

            oprfOutput = ristretto255_oprf.voprf.finalize(
                handleBytes,
                blindResult.blind,
                evaluated,
                blindResult.blinded,
                publicKey,
                proof
            );

            keyInput = concatUint8Arrays(
                new TextEncoder().encode(PROTOCOL_KEYS.DISCOVERY_ENCRYPTION),
                oprfOutput
            );
            encryptionKey = blake3(keyInput, { dkLen: 32 });
            succeeded = true;
            return { oprfOutput, encryptionKey };
        } finally {
            handleBytes.fill(0);
            evaluated?.fill(0);
            proof?.fill(0);
            publicKey?.fill(0);
            blindResult.blind.fill(0);
            blindResult.blinded.fill(0);
            keyInput?.fill(0);
            if (!succeeded) {
                oprfOutput?.fill(0);
                encryptionKey?.fill(0);
            }
        }
    }

    private deriveTokenForEpoch(oprfOutput: Uint8Array, epoch: number): string {
        const epochBytes = new Uint8Array(8);
        new DataView(epochBytes.buffer).setBigUint64(0, BigInt(epoch), false);
        const tokenInput = concatUint8Arrays(
                new TextEncoder().encode(PROTOCOL_KEYS.DISCOVERY_TOKEN),
                oprfOutput,
                epochBytes
            );
        const token = blake3(tokenInput, { dkLen: 32 });
        try {
            return bytesToHex(token);
        } finally {
            epochBytes.fill(0);
            tokenInput.fill(0);
            token.fill(0);
        }
    }

    encryptDiscoveryBlob(
        material: OPRFDiscoveryBlob,
        encryptionKey: Uint8Array
    ): string {
        const content = new TextEncoder().encode(JSON.stringify(material));
        if (content.length + DISCOVERY_BLOB_HEADER_BYTES > DISCOVERY_BLOB_PLAINTEXT_BYTES) {
            content.fill(0);
            throw new Error('Discovery identity bundle exceeds fixed PURB capacity');
        }
        const plaintext = new Uint8Array(DISCOVERY_BLOB_PLAINTEXT_BYTES);
        new DataView(plaintext.buffer).setUint32(0, content.length, true);
        plaintext.set(content, DISCOVERY_BLOB_HEADER_BYTES);
        const padding = plaintext.subarray(DISCOVERY_BLOB_HEADER_BYTES + content.length);
        crypto.getRandomValues(padding);
        const nonce = crypto.getRandomValues(new Uint8Array(DISCOVERY_BLOB_NONCE_BYTES));
        const aad = new TextEncoder().encode(PROTOCOL_KEYS.DISCOVERY_BLOB_AAD);
        let selector: Uint8Array | null = null;
        let ciphertext: Uint8Array | null = null;
        let tag: Uint8Array | null = null;
        let combined: Uint8Array | null = null;
        try {
            selector = deriveDiscoveryBlobSelector(encryptionKey, nonce);
            ({ ciphertext, tag } = PostQuantumAEAD.encrypt(plaintext, encryptionKey, aad, nonce));
            combined = new Uint8Array(nonce.length + selector.length + tag.length + ciphertext.length);
            combined.set(nonce, 0);
            combined.set(selector, nonce.length);
            combined.set(tag, nonce.length + selector.length);
            combined.set(ciphertext, nonce.length + selector.length + tag.length);
            const encoded = PostQuantumUtils.uint8ArrayToBase64(combined);
            if (encoded.length !== DISCOVERY_BLOB_BASE64_CHARS || encoded.endsWith('=')) {
                throw new Error('Discovery PURB wire shape mismatch');
            }
            return encoded;
        } finally {
            content.fill(0);
            plaintext.fill(0);
            nonce.fill(0);
            aad.fill(0);
            selector?.fill(0);
            ciphertext?.fill(0);
            tag?.fill(0);
            combined?.fill(0);
        }
    }

    decryptDiscoveryBlob(
        blobBase64: string,
        encryptionKey: Uint8Array,
        stats?: { selectorMatches: number }
    ): OPRFDiscoveryBlob | null {
        let data: Uint8Array | null = null;
        let prefix: Uint8Array | null = null;
        let nonce: Uint8Array | null = null;
        let selector: Uint8Array | null = null;
        let expectedSelector: Uint8Array | null = null;
        let tag: Uint8Array | null = null;
        let ciphertext: Uint8Array | null = null;
        let aad: Uint8Array | null = null;
        let plaintext: Uint8Array | null = null;
        let content: Uint8Array | null = null;
        try {
            if (!canonicalBase64Shape(blobBase64, { exactBytes: DISCOVERY_BLOB_WIRE_BYTES })) {
                return null;
            }

            prefix = PostQuantumUtils.base64ToUint8Array(
                blobBase64.slice(0, DISCOVERY_BLOB_PREFIX_BASE64_CHARS)
            );
            if (prefix.length !== DISCOVERY_BLOB_PREFIX_BYTES) return null;
            nonce = prefix.slice(0, DISCOVERY_BLOB_NONCE_BYTES);
            selector = prefix.slice(DISCOVERY_BLOB_NONCE_BYTES);
            expectedSelector = deriveDiscoveryBlobSelector(encryptionKey, nonce);
            if (!constantTimeBytesEqual(selector, expectedSelector)) return null;
            if (stats) stats.selectorMatches += 1;

            data = PostQuantumUtils.base64ToUint8Array(blobBase64);
            if (data.length !== DISCOVERY_BLOB_WIRE_BYTES) return null;

            tag = data.slice(
                DISCOVERY_BLOB_PREFIX_BYTES,
                DISCOVERY_BLOB_PREFIX_BYTES + DISCOVERY_BLOB_TAG_BYTES
            );
            ciphertext = data.slice(DISCOVERY_BLOB_PREFIX_BYTES + DISCOVERY_BLOB_TAG_BYTES);
            aad = new TextEncoder().encode(PROTOCOL_KEYS.DISCOVERY_BLOB_AAD);
            plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, encryptionKey, aad);
            if (plaintext.length !== DISCOVERY_BLOB_PLAINTEXT_BYTES) return null;
            const contentLength = new DataView(
                plaintext.buffer,
                plaintext.byteOffset,
                DISCOVERY_BLOB_HEADER_BYTES
            ).getUint32(0, true);
            if (
                contentLength < 1 ||
                contentLength + DISCOVERY_BLOB_HEADER_BYTES > plaintext.length
            ) return null;
            content = plaintext.slice(
                DISCOVERY_BLOB_HEADER_BYTES,
                DISCOVERY_BLOB_HEADER_BYTES + contentLength
            );
            const parsed = JSON.parse(strictTextDecoder.decode(content), (key, value) =>
                key === '__proto__' || key === 'prototype' || key === 'constructor' ? undefined : value
            );
            if (
                !parsed ||
                typeof parsed !== 'object' ||
                Array.isArray(parsed) ||
                Object.getPrototypeOf(parsed) !== Object.prototype
            ) return null;
            
            const keys = Object.keys(parsed);
            if (
                !DISCOVERY_BLOB_REQUIRED_KEYS.every((key) => keys.includes(key)) ||
                keys.some((key) => (
                    !DISCOVERY_BLOB_REQUIRED_KEYS.includes(key) &&
                    !DISCOVERY_BLOB_OPTIONAL_KEYS.includes(key)
                ))
            ) return null;
            const detectionKey = (parsed as OPRFDiscoveryBlob).spoolDetectionKey;
            if (detectionKey !== undefined && !DISCOVERY_DETECTION_KEY_RE.test(detectionKey)) {
                return null;
            }
            const transition = (parsed as OPRFDiscoveryBlob).keyTransparencyTransition;
            if (transition !== undefined && (
                !transition ||
                typeof transition !== 'object' ||
                Array.isArray(transition) ||
                Object.keys(transition).sort().join(',') !== 'authorization,signedUpdate'
            )) return null;
            return parsed as OPRFDiscoveryBlob;
        } catch {
            return null;
        } finally {
            data?.fill(0);
            prefix?.fill(0);
            nonce?.fill(0);
            selector?.fill(0);
            expectedSelector?.fill(0);
            tag?.fill(0);
            ciphertext?.fill(0);
            aad?.fill(0);
            plaintext?.fill(0);
            content?.fill(0);
        }
    }
}

function hexToBytes(hex: string, expectedBytes: number): Uint8Array {
    const bytes = decodeHex(hex, { exactBytes: expectedBytes, allowUppercase: true });
    if (!bytes) throw new Error('Invalid hexadecimal value');
    return bytes;
}


export const oprfDiscoveryClient = new OPRFDiscoveryClient();
