/**
 * PQ Noise Session Wrapper
 */

import { PQSession } from '../cryptography/noise-protocol';
import { PeerKeys, OwnKeys, HandshakeMessage, EncryptedFrame } from '../types/noise-types';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SessionStatus, encodeFrame, decodeFrame } from './secure-transport';

// Noise session wrapper
export class PQNoiseSession {
    private session: PQSession;

    private constructor(session: PQSession) {
        this.session = session;
    }

    // Create initiator session
    static createInitiatorSession(
        peerId: string,
        ownKeys: OwnKeys,
        peerKeys: PeerKeys
    ): { session: PQNoiseSession; message: PQNoiseHandshakeMessage } {
        const { session, message } = PQSession.createInitiatorSession(peerId, ownKeys, peerKeys);

        return {
            session: new PQNoiseSession(session),
            message: serializeHandshake(message)
        };
    }

    // Process initiator message as responder
    static processInitiatorMessage(
        peerId: string,
        ownKeys: OwnKeys,
        message: PQNoiseHandshakeMessage
    ): { session: PQNoiseSession; response: PQNoiseHandshakeMessage } {
        const parsed = deserializeHandshake(message);
        const { session, response } = PQSession.processInitiatorMessage(peerId, ownKeys, parsed);

        return {
            session: new PQNoiseSession(session),
            response: serializeHandshake(response)
        };
    }

    // Complete initiator handshake
    completeHandshake(response: PQNoiseHandshakeMessage): void {
        const parsed = deserializeHandshake(response);
        this.session.completeHandshake(parsed);
    }

    // Encrypt message
    encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
        const frame = this.session.encrypt(plaintext, aad);
        return encodeFrame(frame.sequence, frame.ciphertext, frame.tag);
    }

    // Decrypt message
    decrypt(data: Uint8Array, aad?: Uint8Array): Uint8Array {
        const decoded = decodeFrame(data);
        const frame: EncryptedFrame = {
            sequence: decoded.sequence,
            ciphertext: decoded.ciphertext,
            nonce: new Uint8Array(36),
            tag: decoded.tag
        };
        return this.session.decrypt(frame, aad);
    }

    // Rotate keys
    rotateKeys(): void {
        this.session.rotateKeys();
    }

    // Get session status
    getStatus(): SessionStatus {
        const state = this.session.getState();
        return {
            established: this.session.isEstablished(),
            inProgress: !this.session.isEstablished() && this.session.isValid(),
            sendKey: state.sendKey.length > 0 ? state.sendKey : null,
            receiveKey: state.receiveKey.length > 0 ? state.receiveKey : null,
            role: state.role,
            lastRotation: state.lastRotation
        };
    }

    // Check if session is valid
    isValid(): boolean {
        return this.session.isValid();
    }

    // Check if session is established
    isEstablished(): boolean {
        return this.session.isEstablished();
    }

    // Destroy session
    destroy(): void {
        this.session.destroy();
    }
}

// Handshake Message Serialization
export interface PQNoiseHandshakeMessage {
    version: string;
    type: 'init' | 'response';
    sessionId: string;
    timestamp: number;
    ephemeralKyberPublic: string;
    kemCiphertext: string;
    ephemeralX25519Public: string;
    signature: string;
    signerPublicKey: string;
}

// Serialize handshake message
function serializeHandshake(msg: HandshakeMessage): PQNoiseHandshakeMessage {
    return {
        version: msg.version,
        type: msg.type,
        sessionId: msg.sessionId,
        timestamp: msg.timestamp,
        ephemeralKyberPublic: PostQuantumUtils.uint8ArrayToBase64(msg.ephemeralKyberPublic),
        kemCiphertext: PostQuantumUtils.uint8ArrayToBase64(msg.kemCiphertext),
        ephemeralX25519Public: PostQuantumUtils.uint8ArrayToBase64(msg.ephemeralX25519Public),
        signature: PostQuantumUtils.uint8ArrayToBase64(msg.signature),
        signerPublicKey: PostQuantumUtils.uint8ArrayToBase64(msg.signerPublicKey)
    };
}

// Deserialize handshake message
function deserializeHandshake(msg: PQNoiseHandshakeMessage | HandshakeMessage): HandshakeMessage {
    const toUint8 = (val: string | Uint8Array | undefined): Uint8Array => {
        if (!val) return new Uint8Array(0);
        if (val instanceof Uint8Array) return val;
        return PostQuantumUtils.base64ToUint8Array(val);
    };

    return {
        version: msg.version as 'hybrid-session-v1',
        type: msg.type,
        sessionId: msg.sessionId,
        timestamp: msg.timestamp,
        ephemeralKyberPublic: toUint8(msg.ephemeralKyberPublic),
        kemCiphertext: toUint8(msg.kemCiphertext),
        ephemeralX25519Public: toUint8(msg.ephemeralX25519Public),
        signature: toUint8(msg.signature),
        signerPublicKey: toUint8(msg.signerPublicKey)
    };
}