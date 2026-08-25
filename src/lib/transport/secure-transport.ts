// Transport Abstraction Layer

import { SignalType } from '../types/signal-types';
import { PQ_AEAD_CIPHERTEXT_OVERHEAD } from '../constants';

// Connection states
export type ConnectionState =
    | 'disconnected'
    | 'connecting'
    | 'handshaking'
    | 'connected'
    | 'failed';

// Stream types
export type StreamType =
    | SignalType.MESSAGE
    | 'call-audio'
    | 'call-video'
    | 'call-telemetry'
    | 'call-screen';

// Encrypted frame format
export interface EncryptedFrame {
    readonly length: number;
    readonly sequence: bigint;
    readonly ciphertext: Uint8Array;
    readonly tag: Uint8Array;
}

// Peer identity
export interface PeerIdentity {
    readonly username: string;
    readonly kyberPublicKey: Uint8Array;
    readonly dilithiumPublicKey: Uint8Array;
    readonly x25519PublicKey: Uint8Array;
    readonly endpointUrl?: string;
    readonly certificateExpiresAt: number;
    readonly certVerified: true;
}

// Connection options
export interface ConnectOptions {
    readonly timeout?: number;
    readonly onStateChange?: (state: ConnectionState) => void;
}

// Stream options
export interface StreamOptions {
    readonly type: StreamType;
    readonly id?: string;
    readonly lossy?: boolean;
}

export interface StreamWriteOptions {
    readonly deadline?: number;
    readonly priority?: 'normal' | 'realtime' | 'visual';
    readonly transferOwnership?: boolean;
}

export interface AudioLaneTelemetryEntry {
    readonly id: string;
    readonly rttMs: number | null;
    readonly degradedSamples: number;
    readonly role: 'active' | 'secondary' | 'standby';
}

export interface AudioLaneTelemetry {
    readonly ready: number;
    readonly target: number;
    readonly active: number;
    readonly endpointAvailable: boolean;
    readonly dialing: number;
    readonly attempts: number;
    readonly failures: number;
    readonly retryInMs: number | null;
    readonly lastFailure: 'offer-send' | 'dial-timeout' | 'dial-failed' | 'preamble-send' | 'binding-timeout' | 'binding-closed' | 'binding-pressure' | 'binding-read-invalid' | 'binding-frame-invalid' | 'rtt-degraded' | 'lane-closed' | null;
    readonly selectedLane: string | null;
    readonly visualLane?: string | null;
    readonly selectedPath?: 'primary' | 'lane';
    readonly primaryRttMs?: number | null;
    readonly rttCeilingMs?: number | null;
    readonly lanes: readonly AudioLaneTelemetryEntry[];
}

// Bidirectional stream
export interface SecureStream {
    readonly id: string;
    readonly type: StreamType;
    readonly peerId: string;
    readonly lossy: boolean;

    // Write encrypted data
    write(data: Uint8Array, options?: StreamWriteOptions): Promise<void>;

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
    readonly transport: 'p2p' | 'unknown';
    readonly connectedAt: number | null;
    readonly lastActivity: number;

    // Create a new stream
    createStream(options: StreamOptions): Promise<SecureStream>;

    // Get stream by type
    getStream(type: StreamType): SecureStream | null;

    // Get a specific stream announced by an authenticated higher-level protocol
    getStreamById(id: string): SecureStream | null;

    // Public, per-handshake binding used to domain-separate application replay state.
    getSessionBinding(): string | null;

    getAudioLaneTelemetry(): AudioLaneTelemetry | null;

    updatePrimaryPathRtt(rttMs: number): void;

    // Close streams and disconnect
    close(reason?: string): Promise<void>;

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

    // Register incoming message handler
    onMessage(handler: MessageHandler): () => void;

    // Register peer connection handler
    onPeerConnected(handler: (peerId: string) => void): () => void;

    // Register peer disconnection handler
    onPeerDisconnected(handler: (peerId: string, reason?: string) => void): () => void;
}

// Supporting Types
export interface TransportInitOptions {
    readonly localUsername: string;
    readonly kyberPublicKey: Uint8Array;
    readonly dilithiumPublicKey: Uint8Array;
    readonly x25519PublicKey: Uint8Array;
    readonly signTranscript: (message: Uint8Array) => Promise<Uint8Array>;
    readonly respondToHandshake: (
        kemCiphertext: Uint8Array,
        peerX25519Public: Uint8Array
    ) => Promise<{ pqSecret: Uint8Array; x25519Secret: Uint8Array }>;
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
    readonly wireBytes?: number;
}

// Message handler function
export type MessageHandler = (message: IncomingMessage) => void | Promise<void>;

// Session status info
// Encode an encrypted frame
export function encodeFrame(
    sequence: bigint,
    ciphertext: Uint8Array,
    tag: Uint8Array
): Uint8Array {
    if (sequence < 0n || sequence > 0xffffffffffffffffn) {
        throw new Error('Frame sequence outside uint64 range');
    }
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length <= PQ_AEAD_CIPHERTEXT_OVERHEAD ||
        ciphertext.length > MAX_MESSAGE_FRAME_SIZE - FRAME_OVERHEAD ||
        !(tag instanceof Uint8Array) || tag.length !== FRAME_TAG_SIZE) {
        throw new Error('Invalid encrypted frame material');
    }
    const totalLength = 4 + 8 + ciphertext.length + tag.length;
    const frame = new Uint8Array(totalLength);
    const view = new DataView(frame.buffer);

    // Length
    view.setUint32(0, totalLength, false);

    // Sequence
    view.setBigUint64(4, sequence, false);

    // Ciphertext
    frame.set(ciphertext, 12);

    // Tag
    frame.set(tag, 12 + ciphertext.length);

    return frame;
}

// Decode a frame
export function decodeFrame(frame: Uint8Array): EncryptedFrame {
    if (!(frame instanceof Uint8Array) || frame.length < NOISE_FRAME_OVERHEAD + 1 ||
        frame.length > MAX_MESSAGE_FRAME_SIZE) {
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
export const TRANSPORT_FRAME_HEADER_SIZE = 12;
export const FRAME_TAG_SIZE = 32;
export const FRAME_OVERHEAD = TRANSPORT_FRAME_HEADER_SIZE + FRAME_TAG_SIZE;
export const NOISE_FRAME_OVERHEAD = FRAME_OVERHEAD + PQ_AEAD_CIPHERTEXT_OVERHEAD;

// Maximum frame sizes
export const MAX_MESSAGE_FRAME_SIZE = 4 * 1024 * 1024;
export const MAX_CALL_FRAME_SIZE = 2 * 1024 * 1024;
