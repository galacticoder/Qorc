/**
 * Device Credential Manager
 */

import { PostQuantumUtils } from '../utils/pq-utils';
import { auth } from '../tauri-bindings';

interface DeviceCredentials {
    publicKey: Uint8Array;
    keyHash: Uint8Array;
}

interface DeviceAttestation {
    devicePublicKey: string;
    signature: string;
    challenge: string;
}

// Device Credential Manager
class DeviceCredentialManager {
    private publicKey: Uint8Array | null = null;
    private keyHash: Uint8Array | null = null;

    // Get device credentials
    async getCredentials(): Promise<DeviceCredentials> {
        if (this.publicKey && this.keyHash) {
            return {
                publicKey: this.publicKey,
                keyHash: this.keyHash
            };
        }

        try {
            const result = await auth.getDeviceCredentials() as any;

            this.publicKey = PostQuantumUtils.base64ToUint8Array(result.public_key || result.publicKey);
            this.keyHash = PostQuantumUtils.base64ToUint8Array(result.key_hash || result.keyHash);

            if (this.publicKey.length !== 2592) {
                console.error('[DeviceCredential] Invalid ML-DSA-87 public key length:', this.publicKey.length);
                throw new Error(`Invalid ML-DSA-87 public key length: ${this.publicKey.length} (expected 2592)`);
            }

            return {
                publicKey: this.publicKey,
                keyHash: this.keyHash
            };
        } catch (e) {
            const errorMessage = e instanceof Error ? e.message : String(e);
            console.error('[DeviceCredential] Failed to get device credentials:', errorMessage);
            throw new Error(`Device credentials API not available: ${errorMessage}`);
        }
    }

    // Sign a challenge with device credentials
    async signChallenge(challenge: string): Promise<DeviceAttestation> {
        const credentials = await this.getCredentials();
        const result = await auth.signChallenge(challenge) as any;
        const signatureBase64 = typeof result === 'string' ? result : result?.signature;

        return {
            devicePublicKey: PostQuantumUtils.uint8ArrayToBase64(credentials.publicKey),
            signature: signatureBase64,
            challenge
        };
    }

    // Get device hash
    async getDeviceHash(): Promise<string> {
        const credentials = await this.getCredentials();
        return PostQuantumUtils.bytesToHex(credentials.keyHash);
    }
}

export const deviceCredentialManager = new DeviceCredentialManager();
export type { DeviceCredentials, DeviceAttestation };
