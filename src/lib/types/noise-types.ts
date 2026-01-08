// Noise Protocol Types

import { NOISE_PROTOCOL_VERSION } from "../constants";

// Key Pairs
export interface PQKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

export interface X25519KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

// Peer public keys
export interface PeerKeys {
    kyberPublicKey: Uint8Array;
    dilithiumPublicKey: Uint8Array;
    x25519PublicKey: Uint8Array;
}

// Own keypairs
export interface OwnKeys {
    kyberKeyPair: PQKeyPair;
    dilithiumKeyPair: PQKeyPair;
    x25519KeyPair: X25519KeyPair;
}

// Handshake Message
export interface HandshakeMessage {
    version: typeof NOISE_PROTOCOL_VERSION;
    type: 'init' | 'response';
    sessionId: string;
    timestamp: number;
    ephemeralKyberPublic: Uint8Array;
    kemCiphertext: Uint8Array;
    ephemeralX25519Public: Uint8Array;
    signature: Uint8Array;
    signerPublicKey: Uint8Array;
}

// Session State
export interface SessionState {
    sendKey: Uint8Array;
    receiveKey: Uint8Array;
    sendNonce: bigint;
    receiveNonce: bigint;
    sessionId: string;
    peerId: string;
    role: 'initiator' | 'responder';
    createdAt: number;
    lastRotation: number;
    messageCount: number;
}

// Encrypted Frame
export interface EncryptedFrame {
    sequence: bigint;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    tag: Uint8Array;
}