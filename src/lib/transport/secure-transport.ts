// Transport Abstraction Layer

import { SignalType } from '../types/signal-types';

// Connection states
export type ConnectionState =
    | 'disconnected'    // No connection
    | 'connecting'      // Transport-level connection in progress
    | 'handshaking'     // PQ + Noise handshake in progress
    | 'connected'       // Fully established and encrypted
    | 'reconnecting'    // Temporarily disconnected, attempting recovery
    | 'failed';         // Unrecoverable error

// Stream types
export type StreamType =
    | SignalType.MESSAGE     // 'message'
    | SignalType.CALL_SIGNAL // 'call-signal'
    | SignalType.CHAT        // 'chat'
    | SignalType.SIGNAL      // 'signal'
    | 'call-audio'           // Real-time audio (may be lossy)
    | 'call-video'           // Real-time video (may be lossy)
    | 'call-screen'          // Screen sharing stream
    | 'file';                // Large file transfer

// Encrypted frame format
export interface EncryptedFrame {
    readonly length: number;       // Total frame length
    readonly sequence: bigint;     // Message sequence number for replay protection
    readonly ciphertext: Uint8Array;
    readonly tag: Uint8Array;      // 32-byte BLAKE3 MAC
}

// Peer identity
export interface PeerIdentity {
    readonly username: string;
    readonly kyberPublicKey: Uint8Array;      // ML-KEM-1024 public key (1568 bytes)
    readonly dilithiumPublicKey: Uint8Array;  // ML-DSA-87 public key (2592 bytes)
    readonly x25519PublicKey: Uint8Array;     // X25519 public key (32 bytes)
}

// Connection options
export interface ConnectOptions {
    readonly peerIdentity: PeerIdentity;
    readonly timeout?: number;              // Connection timeout in ms (default: 30000)
    readonly preferDirect?: boolean;        // Prefer direct connection over relay (default: true)
    readonly onStateChange?: (state: ConnectionState) => void;
}

// Stream options
export interface StreamOptions {
    readonly type: StreamType;
    readonly lossy?: boolean;               // Allow packet loss for real-time (default: false)
    readonly priority?: 'high' | 'normal' | 'low';  // Stream priority
    readonly maxRetransmits?: number;       // For partially reliable streams
}

// Bidirectional stream
export interface SecureStream {
    readonly id: string;
    readonly type: StreamType;
    readonly peerId: string;
    readonly lossy: boolean;

    // Write encrypted data
    write(data: Uint8Array): Promise<void>;

    // Write with backpressure
    writeWithBackpressure(data: Uint8Array): Promise<void>;

    // Read decrypted data
    read(): Promise<Uint8Array | null>;

    // Async iterator
    [Symbol.asyncIterator](): AsyncIterableIterator<Uint8Array>;

    // Close
    close(): Promise<void>;

    // Abort immediately
    abort(reason?: string): void;

    // Stream state
    readonly readable: boolean;
    readonly writable: boolean;
    readonly closed: boolean;
}

// Connection to a peer
export interface SecureConnection {
    readonly peerId: string;
    readonly peerIdentity: PeerIdentity;
    readonly state: ConnectionState;
    readonly transport: 'quic' | 'relay' | 'unknown';
    readonly connectedAt: number | null;
    readonly lastActivity: number;

    // Create a new stream
    createStream(options: StreamOptions): Promise<SecureStream>;

    // Get stream by type
    getStream(type: StreamType): SecureStream | null;

    // Close streams and disconnect
    close(reason?: string): Promise<void>;

    // Force session key rotation
    rotateSessionKeys(): Promise<void>;

    // Handler for incoming streams
    onStream(handler: (stream: SecureStream) => void): () => void;

    // Handler for state changes
    onStateChange(handler: (state: ConnectionState) => void): () => void;
}

// Transport Service
export interface SecureTransport {
    // Initialize transport
    initialize(options: TransportInitOptions): Promise<void>;

    // Connect to a peer
    connect(peerId: string, options: ConnectOptions): Promise<SecureConnection>;

    // Disconnect from a peer
    disconnect(peerId: string): Promise<void>;

    // Disconnect all peers and shut down
    shutdown(): Promise<void>;

    // Get connection to a peer
    getConnection(peerId: string): SecureConnection | null;

    // Check if connected to a peer
    isConnected(peerId: string): boolean;

    // Send a message to a peer
    sendMessage(
        peerId: string,
        message: unknown,
        type?: SignalType
    ): Promise<void>;

    // Register incoming message handler
    onMessage(handler: MessageHandler): () => void;

    // Register peer connection handler
    onPeerConnected(handler: (peerId: string) => void): () => void;

    // Register peer disconnection handler
    onPeerDisconnected(handler: (peerId: string, reason?: string) => void): () => void;
}

// Supporting Types
// Options for initializing the transport
export interface TransportInitOptions {
    readonly localUsername: string;
    readonly kyberKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    readonly dilithiumKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    readonly x25519KeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    readonly relayServerUrl?: string;
    readonly signalServerUrl?: string;
}

// Incoming message with metadata
export interface IncomingMessage {
    readonly from: string;
    readonly to: string;
    readonly type: SignalType;
    readonly payload: unknown;
    readonly timestamp: number;
    readonly sequence: bigint;
    readonly verified: boolean;
    readonly routeProof?: any;
    readonly signature?: string;
}

// Message handler function
export type MessageHandler = (message: IncomingMessage) => void | Promise<void>;

// Session status info
export interface SessionStatus {
    readonly established: boolean;
    readonly inProgress: boolean;
    readonly sendKey: Uint8Array | null;
    readonly receiveKey: Uint8Array | null;
    readonly role: 'initiator' | 'responder' | null;
    readonly lastRotation: number | null;
}

// Encode an encrypted frame
export function encodeFrame(
    sequence: bigint,
    ciphertext: Uint8Array,
    tag: Uint8Array
): Uint8Array {
    const totalLength = 4 + 8 + ciphertext.length + tag.length;
    const frame = new Uint8Array(totalLength);
    const view = new DataView(frame.buffer);

    // Length (4 bytes, big-endian)
    view.setUint32(0, totalLength, false);

    // Sequence (8 bytes, big-endian)
    view.setBigUint64(4, sequence, false);

    // Ciphertext
    frame.set(ciphertext, 12);

    // Tag
    frame.set(tag, 12 + ciphertext.length);

    return frame;
}

// Decode a frame
export function decodeFrame(frame: Uint8Array): EncryptedFrame {
    if (frame.length < 44) {
        throw new Error('Frame too short');
    }

    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

    const length = view.getUint32(0, false);
    if (length !== frame.length) {
        throw new Error(`Frame length mismatch: expected ${length}, got ${frame.length}`);
    }

    const sequence = view.getBigUint64(4, false);
    const ciphertext = frame.slice(12, frame.length - 32);
    const tag = frame.slice(frame.length - 32);

    return { length, sequence, ciphertext, tag };
}

// Frame constants
export const FRAME_HEADER_SIZE = 12;
export const FRAME_TAG_SIZE = 32;
export const FRAME_OVERHEAD = FRAME_HEADER_SIZE + FRAME_TAG_SIZE;

// Maximum frame sizes
export const MAX_MESSAGE_FRAME_SIZE = 16 * 1024 * 1024;
export const MAX_CALL_FRAME_SIZE = 64 * 1024;
export const MAX_SIGNAL_FRAME_SIZE = 4 * 1024;
