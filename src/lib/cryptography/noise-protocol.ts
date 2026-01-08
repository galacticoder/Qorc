/**
 * Noise Session Protocol 
 */

import { PostQuantumKEM } from './kem';
import { PostQuantumHash } from './hash';
import { PostQuantumAEAD } from './aead';
import { PostQuantumRandom } from './random';
import { PostQuantumSignature } from './signature';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SecureMemory } from './secure-memory';
import {
    NOISE_PROTOCOL_VERSION,
    NOISE_SESSION_SALT,
    NOISE_KEY_ROTATION_INTERVAL_MS,
    NOISE_MAX_MESSAGES_PER_SESSION,
    NOISE_MAX_SESSION_AGE_MS,
    NOISE_REPLAY_WINDOW_SIZE
} from '../constants';
import type {
    PQKeyPair,
    X25519KeyPair,
    PeerKeys,
    OwnKeys,
    HandshakeMessage,
    SessionState,
    EncryptedFrame
} from '../types/noise-types';
import { generateX25519KeyPair, computeX25519SharedSecret } from '../utils/noise-utils';


const SESSION_SALT = new TextEncoder().encode(NOISE_SESSION_SALT);

// Noise Session
export class PQSession {
    private sessionId: string;
    private peerId: string;
    private role: 'initiator' | 'responder';

    // Session keys derived from shared secrets
    private sendKey: Uint8Array | null = null;
    private receiveKey: Uint8Array | null = null;

    // Sequence tracking
    private sendSequence: bigint = BigInt(0);
    private receiveWindow: Set<bigint> = new Set();
    private receiveHighWater: bigint = BigInt(0);

    // Lifecycle
    private state: 'pending' | 'handshaking' | 'established' | 'failed' = 'pending';
    private createdAt: number;
    private lastRotation: number;
    private messageCount: number = 0;

    // Keys
    private ownKeys: OwnKeys;
    private peerKeys: PeerKeys | null = null;

    // Handshake state
    private ephemeralKyberPair: PQKeyPair | null = null;
    private ephemeralX25519Pair: X25519KeyPair | null = null;
    private handshakePQSecret: Uint8Array | null = null;
    private handshakeX25519Secret: Uint8Array | null = null;

    private constructor(
        sessionId: string,
        peerId: string,
        role: 'initiator' | 'responder',
        ownKeys: OwnKeys
    ) {
        this.sessionId = sessionId;
        this.peerId = peerId;
        this.role = role;
        this.ownKeys = ownKeys;
        this.createdAt = Date.now();
        this.lastRotation = this.createdAt;
    }

    // Session Establishment
    static createInitiatorSession(
        peerId: string,
        ownKeys: OwnKeys,
        peerKeys: PeerKeys
    ): { session: PQSession; message: HandshakeMessage } {
        const sessionId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
        const session = new PQSession(sessionId, peerId, 'initiator', ownKeys);
        session.peerKeys = peerKeys;
        session.state = 'handshaking';

        session.ephemeralKyberPair = PostQuantumKEM.generateKeyPair();
        session.ephemeralX25519Pair = generateX25519KeyPair();

        const { ciphertext: kemCiphertext, sharedSecret: pqSecret } =
            PostQuantumKEM.encapsulate(peerKeys.kyberPublicKey);

        const x25519Secret = computeX25519SharedSecret(
            session.ephemeralX25519Pair.secretKey,
            peerKeys.x25519PublicKey
        );

        session.handshakePQSecret = pqSecret;
        session.handshakeX25519Secret = x25519Secret;

        const timestamp = Date.now();
        const messageData = session.buildSignatureInput(
            'init',
            sessionId,
            timestamp,
            session.ephemeralKyberPair.publicKey,
            kemCiphertext,
            session.ephemeralX25519Pair.publicKey
        );

        const signature = PostQuantumSignature.sign(messageData, ownKeys.dilithiumKeyPair.secretKey);

        const message: HandshakeMessage = {
            version: NOISE_PROTOCOL_VERSION,
            type: 'init',
            sessionId,
            timestamp,
            ephemeralKyberPublic: session.ephemeralKyberPair.publicKey,
            kemCiphertext,
            ephemeralX25519Public: session.ephemeralX25519Pair.publicKey,
            signature,
            signerPublicKey: ownKeys.dilithiumKeyPair.publicKey
        };

        return { session, message };
    }

    // Process initiator message and create response
    static processInitiatorMessage(
        peerId: string,
        ownKeys: OwnKeys,
        message: HandshakeMessage
    ): { session: PQSession; response: HandshakeMessage } {
        if (message.version !== NOISE_PROTOCOL_VERSION || message.type !== 'init') {
            throw new Error('Invalid handshake message');
        }

        const age = Date.now() - message.timestamp;
        if (age > 5 * 60 * 1000 || age < -60 * 1000) {
            throw new Error('Handshake message expired');
        }

        // Verify ML-DSA signature
        const signatureInput = PQSession.prototype.buildSignatureInput.call(
            { sessionId: message.sessionId } as any,
            'init',
            message.sessionId,
            message.timestamp,
            message.ephemeralKyberPublic,
            message.kemCiphertext,
            message.ephemeralX25519Public
        );

        const signatureValid = PostQuantumSignature.verify(
            message.signature,
            signatureInput,
            message.signerPublicKey
        );

        if (!signatureValid) {
            throw new Error('Invalid ML-DSA signature');
        }

        // Create session
        const session = new PQSession(message.sessionId, peerId, 'responder', ownKeys);
        session.peerKeys = {
            kyberPublicKey: message.ephemeralKyberPublic,
            dilithiumPublicKey: message.signerPublicKey,
            x25519PublicKey: message.ephemeralX25519Public
        };
        session.state = 'handshaking';

        // Decapsulate initiator KEM ciphertext
        const initiatorPQSecret = PostQuantumKEM.decapsulate(
            message.kemCiphertext,
            ownKeys.kyberKeyPair.secretKey
        );

        // Compute X25519 shared secret with initiator ephemeral key
        const initiatorX25519Secret = computeX25519SharedSecret(
            ownKeys.x25519KeyPair.secretKey,
            message.ephemeralX25519Public
        );

        // Generate own ephemeral keys
        const responderKyberPair = PostQuantumKEM.generateKeyPair();
        const responderX25519Pair = generateX25519KeyPair();

        // Encapsulate to initiator ephemeral KEM key
        const { ciphertext: responseCiphertext, sharedSecret: responderPQSecret } =
            PostQuantumKEM.encapsulate(message.ephemeralKyberPublic);

        // Compute X25519 with initiator ephemeral key
        const responderX25519Secret = computeX25519SharedSecret(
            responderX25519Pair.secretKey,
            message.ephemeralX25519Public
        );

        session.deriveSessionKeys(
            initiatorPQSecret,
            responderPQSecret,
            initiatorX25519Secret,
            responderX25519Secret,
            'responder'
        );

        SecureMemory.zeroBuffer(initiatorPQSecret);
        SecureMemory.zeroBuffer(responderPQSecret);
        SecureMemory.zeroBuffer(initiatorX25519Secret);
        SecureMemory.zeroBuffer(responderX25519Secret);

        session.state = 'established';

        const timestamp = Date.now();
        const responseData = session.buildSignatureInput(
            'response',
            message.sessionId,
            timestamp,
            responderKyberPair.publicKey,
            responseCiphertext,
            responderX25519Pair.publicKey
        );

        const responseSignature = PostQuantumSignature.sign(
            responseData,
            ownKeys.dilithiumKeyPair.secretKey
        );

        const response: HandshakeMessage = {
            version: NOISE_PROTOCOL_VERSION,
            type: 'response',
            sessionId: message.sessionId,
            timestamp,
            ephemeralKyberPublic: responderKyberPair.publicKey,
            kemCiphertext: responseCiphertext,
            ephemeralX25519Public: responderX25519Pair.publicKey,
            signature: responseSignature,
            signerPublicKey: ownKeys.dilithiumKeyPair.publicKey
        };

        SecureMemory.zeroBuffer(responderKyberPair.secretKey);
        SecureMemory.zeroBuffer(responderX25519Pair.secretKey);

        return { session, response };
    }

    // Complete initiator handshake with responder message
    completeHandshake(response: HandshakeMessage): void {
        if (this.role !== 'initiator' || this.state !== 'handshaking') {
            throw new Error('Invalid state for completing handshake');
        }

        if (response.version !== NOISE_PROTOCOL_VERSION || response.type !== 'response') {
            throw new Error('Invalid handshake response');
        }

        if (response.sessionId !== this.sessionId) {
            throw new Error('Session ID mismatch');
        }

        // Verify ML-DSA signature
        const signatureInput = this.buildSignatureInput(
            'response',
            this.sessionId,
            response.timestamp,
            response.ephemeralKyberPublic,
            response.kemCiphertext,
            response.ephemeralX25519Public
        );

        const signatureValid = PostQuantumSignature.verify(
            response.signature,
            signatureInput,
            response.signerPublicKey
        );

        if (!signatureValid) {
            throw new Error('Invalid response signature');
        }

        // Check handshake state
        if (!this.ephemeralKyberPair || !this.ephemeralX25519Pair ||
            !this.handshakePQSecret || !this.handshakeX25519Secret) {
            throw new Error('Missing handshake state');
        }

        // Decapsulate responder KEM ciphertext using own ephemeral key
        const responderPQSecret = PostQuantumKEM.decapsulate(
            response.kemCiphertext,
            this.ephemeralKyberPair.secretKey
        );

        // Compute X25519 with responder ephemeral key
        const responderX25519Secret = computeX25519SharedSecret(
            this.ephemeralX25519Pair.secretKey,
            response.ephemeralX25519Public
        );

        // Derive session keys from all secrets
        this.deriveSessionKeys(
            this.handshakePQSecret,
            responderPQSecret,
            this.handshakeX25519Secret,
            responderX25519Secret,
            'initiator'
        );

        if (this.peerKeys) {
            this.peerKeys.dilithiumPublicKey = response.signerPublicKey;
        }

        SecureMemory.zeroBuffer(this.handshakePQSecret);
        SecureMemory.zeroBuffer(this.handshakeX25519Secret);
        SecureMemory.zeroBuffer(this.ephemeralKyberPair.secretKey);
        SecureMemory.zeroBuffer(this.ephemeralX25519Pair.secretKey);
        SecureMemory.zeroBuffer(responderPQSecret);
        SecureMemory.zeroBuffer(responderX25519Secret);

        this.handshakePQSecret = null;
        this.handshakeX25519Secret = null;
        this.ephemeralKyberPair = null;
        this.ephemeralX25519Pair = null;

        this.state = 'established';
    }

    // Derive session keys from hybrid shared secrets
    private deriveSessionKeys(
        pqSecret1: Uint8Array,
        pqSecret2: Uint8Array,
        classicalSecret1: Uint8Array,
        classicalSecret2: Uint8Array,
        role: 'initiator' | 'responder'
    ): void {
        const totalLen = pqSecret1.length + pqSecret2.length +
            classicalSecret1.length + classicalSecret2.length +
            this.sessionId.length;
        const combined = new Uint8Array(totalLen);
        let offset = 0;

        combined.set(pqSecret1, offset); offset += pqSecret1.length;
        combined.set(pqSecret2, offset); offset += pqSecret2.length;
        combined.set(classicalSecret1, offset); offset += classicalSecret1.length;
        combined.set(classicalSecret2, offset); offset += classicalSecret2.length;
        combined.set(new TextEncoder().encode(this.sessionId), offset);

        const keyMaterial = PostQuantumHash.blake3(combined, { dkLen: 64 });

        // Split into send/receive based on role
        if (role === 'initiator') {
            this.sendKey = keyMaterial.slice(0, 32);
            this.receiveKey = keyMaterial.slice(32, 64);
        } else {
            this.receiveKey = keyMaterial.slice(0, 32);
            this.sendKey = keyMaterial.slice(32, 64);
        }

        SecureMemory.zeroBuffer(combined);
        SecureMemory.zeroBuffer(keyMaterial);
    }

    // Encrypt message
    encrypt(plaintext: Uint8Array, aad?: Uint8Array): EncryptedFrame {
        if (this.state !== 'established' || !this.sendKey) {
            throw new Error('Session not established');
        }

        this.checkKeyRotation();

        const sequence = this.sendSequence;
        this.sendSequence = this.sendSequence + BigInt(1);
        this.messageCount++;

        const effectiveAad = aad || new Uint8Array(0);
        const nonce = this.deriveNonce(sequence);

        const { ciphertext, tag } = PostQuantumAEAD.encrypt(
            plaintext,
            this.sendKey,
            effectiveAad,
            nonce
        );

        return { sequence, ciphertext, nonce, tag };
    }

    // Decrypt message
    decrypt(frame: EncryptedFrame, aad?: Uint8Array): Uint8Array {
        if (this.state !== 'established' || !this.receiveKey) {
            throw new Error('Session not established');
        }

        this.checkKeyRotation();

        if (!this.validateSequence(frame.sequence)) {
            throw new Error('Replay attack detected');
        }

        const effectiveAad = aad || new Uint8Array(0);
        const nonce = this.deriveNonce(frame.sequence);

        const plaintext = PostQuantumAEAD.decrypt(
            frame.ciphertext,
            nonce,
            frame.tag,
            this.receiveKey,
            effectiveAad
        );

        this.updateReplayWindow(frame.sequence);
        this.messageCount++;

        return plaintext;
    }

    private deriveNonce(sequence: bigint): Uint8Array {
        const nonce = new Uint8Array(36);
        const view = new DataView(nonce.buffer);
        view.setBigUint64(0, sequence, false);
        view.setBigUint64(12, sequence, false);
        return nonce;
    }

    // Check if key rotation is needed
    private checkKeyRotation(): void {
        const now = Date.now();
        const age = now - this.lastRotation;

        if (age >= NOISE_KEY_ROTATION_INTERVAL_MS || this.messageCount >= NOISE_MAX_MESSAGES_PER_SESSION) {
            this.rotateKeys();
        }
    }

    // Rotate session keys forward
    rotateKeys(): void {
        if (!this.sendKey || !this.receiveKey) {
            return;
        }

        // Derive new keys from current keys
        const newSendKey = PostQuantumHash.deriveKey(
            this.sendKey,
            SESSION_SALT,
            this.role === 'initiator' ? 'initiator-to-responder' : 'responder-to-initiator',
            32
        );

        const newReceiveKey = PostQuantumHash.deriveKey(
            this.receiveKey,
            SESSION_SALT,
            this.role === 'initiator' ? 'responder-to-initiator' : 'initiator-to-responder',
            32
        );

        SecureMemory.zeroBuffer(this.sendKey);
        SecureMemory.zeroBuffer(this.receiveKey);

        this.sendKey = newSendKey;
        this.receiveKey = newReceiveKey;
        this.lastRotation = Date.now();
        this.messageCount = 0;
    }

    // Validate sequence number
    private validateSequence(sequence: bigint): boolean {
        if (sequence <= this.receiveHighWater - NOISE_REPLAY_WINDOW_SIZE) {
            return false;
        }

        if (sequence <= this.receiveHighWater) {
            if (this.receiveWindow.has(sequence)) {
                return false;
            }
        }

        return true;
    }

    private updateReplayWindow(sequence: bigint): void {
        if (sequence > this.receiveHighWater) {
            const newLow = sequence - NOISE_REPLAY_WINDOW_SIZE;

            for (const s of Array.from(this.receiveWindow)) {
                if (s < newLow) { this.receiveWindow.delete(s); }
            }
            this.receiveHighWater = sequence;
        }
        this.receiveWindow.add(sequence);
    }

    // Handshake signature input
    private buildSignatureInput(
        type: string,
        sessionId: string,
        timestamp: number,
        ephemeralKyberKey: Uint8Array,
        kemCiphertext: Uint8Array,
        ephemeralX25519Key: Uint8Array
    ): Uint8Array {
        const header = new TextEncoder().encode(`${NOISE_PROTOCOL_VERSION}:${type}:${sessionId}:${timestamp}`);
        const result = new Uint8Array(
            header.length + ephemeralKyberKey.length + kemCiphertext.length + ephemeralX25519Key.length
        );
        let offset = 0;
        result.set(header, offset); offset += header.length;
        result.set(ephemeralKyberKey, offset); offset += ephemeralKyberKey.length;
        result.set(kemCiphertext, offset); offset += kemCiphertext.length;
        result.set(ephemeralX25519Key, offset);
        return result;
    }

    getPeerId(): string {
        return this.peerId;
    }

    isEstablished(): boolean {
        return this.state === 'established';
    }

    isValid(): boolean {
        if (this.state !== 'established') {
            return false;
        }

        const age = Date.now() - this.createdAt;
        return age <= NOISE_MAX_SESSION_AGE_MS;
    }

    getState(): SessionState {
        return {
            sendKey: this.sendKey ? new Uint8Array(this.sendKey) : new Uint8Array(0),
            receiveKey: this.receiveKey ? new Uint8Array(this.receiveKey) : new Uint8Array(0),
            sendNonce: this.sendSequence,
            receiveNonce: this.receiveHighWater,
            sessionId: this.sessionId,
            peerId: this.peerId,
            role: this.role,
            createdAt: this.createdAt,
            lastRotation: this.lastRotation,
            messageCount: this.messageCount
        };
    }

    // Destroy the session
    destroy(): void {
        if (this.sendKey) {
            SecureMemory.zeroBuffer(this.sendKey);
            this.sendKey = null;
        }

        if (this.receiveKey) {
            SecureMemory.zeroBuffer(this.receiveKey);
            this.receiveKey = null;
        }

        if (this.handshakePQSecret) {
            SecureMemory.zeroBuffer(this.handshakePQSecret);
            this.handshakePQSecret = null;
        }

        if (this.handshakeX25519Secret) {
            SecureMemory.zeroBuffer(this.handshakeX25519Secret);
            this.handshakeX25519Secret = null;
        }

        if (this.ephemeralKyberPair) {
            SecureMemory.zeroBuffer(this.ephemeralKyberPair.secretKey);
            this.ephemeralKyberPair = null;
        }

        if (this.ephemeralX25519Pair) {
            SecureMemory.zeroBuffer(this.ephemeralX25519Pair.secretKey);
            this.ephemeralX25519Pair = null;
        }

        this.receiveWindow.clear();
        this.state = 'failed';
    }
}
