/**
 * Device Credential Manager
 */

import { PostQuantumUtils } from './utils/pq-utils';

interface DeviceCredentials {
    publicKey: Uint8Array;
    keyHash: Uint8Array;
}

interface DeviceAttestation {
    devicePublicKey: string;
    signature: string;
    challenge: string;
}

class DeviceCredentialManager {
    private publicKey: Uint8Array | null = null;
    private keyHash: Uint8Array | null = null;

    async getCredentials(): Promise<DeviceCredentials> {
        if (this.publicKey && this.keyHash) {
            return {
                publicKey: this.publicKey,
                keyHash: this.keyHash
            };
        }

        if (typeof window === 'undefined' || !(window as any).edgeApi?.deviceCredentials) {
            throw new Error('Device credentials API not available');
        }

        const result = await (window as any).edgeApi.deviceCredentials.getCredentials();

        this.publicKey = PostQuantumUtils.base64ToUint8Array(result.publicKey);
        this.keyHash = PostQuantumUtils.base64ToUint8Array(result.keyHash);

        if (this.publicKey.length !== 2592) {
            throw new Error('Invalid ML-DSA-87 public key length');
        }

        return {
            publicKey: this.publicKey,
            keyHash: this.keyHash
        };
    }

    async signChallenge(challenge: string): Promise<DeviceAttestation> {
        if (typeof window === 'undefined' || !(window as any).edgeApi?.deviceCredentials) {
            throw new Error('Device credentials API not available');
        }

        const credentials = await this.getCredentials();
        const signatureBase64 = await (window as any).edgeApi.deviceCredentials.signChallenge(challenge);

        return {
            devicePublicKey: PostQuantumUtils.uint8ArrayToBase64(credentials.publicKey),
            signature: signatureBase64,
            challenge
        };
    }

    async getDeviceHash(): Promise<string> {
        const credentials = await this.getCredentials();
        return PostQuantumUtils.bytesToHex(credentials.keyHash);
    }
}

export const deviceCredentialManager = new DeviceCredentialManager();
export type { DeviceCredentials, DeviceAttestation };
