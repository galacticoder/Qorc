// Noise Protocol Types

import { PROTOCOL_KEYS } from "../config/protocol-keys";

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

export interface OwnKeys {
    kyberPublicKey: Uint8Array;
    dilithiumPublicKey: Uint8Array;
    x25519PublicKey: Uint8Array;
    signTranscript: (message: Uint8Array) => Promise<Uint8Array>;
    respondToHandshake: (
        kemCiphertext: Uint8Array,
        peerX25519Public: Uint8Array
    ) => Promise<{ pqSecret: Uint8Array; x25519Secret: Uint8Array }>;
}

// Handshake Message
export interface HandshakeMessage {
    version: typeof PROTOCOL_KEYS.NOISE_PROTOCOL;
    type: 'init' | 'response';
    from: string;
    to: string;
    sessionId: string;
    timestamp: number;
    ephemeralKyberPublic?: Uint8Array;
    kemCiphertext: Uint8Array;
    ephemeralX25519Public: Uint8Array;
    signature: Uint8Array;
    signerPublicKey: Uint8Array;
}

// Encrypted Frame
export interface EncryptedFrame {
    sequence: bigint;
    ciphertext: Uint8Array;
    tag: Uint8Array;
}
