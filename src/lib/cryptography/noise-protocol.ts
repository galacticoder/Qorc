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
    NOISE_MAX_SESSION_AGE_MS,
    NOISE_REPLAY_WINDOW_SIZE,
    AUTH_USERNAME_REGEX,
    PQ_KEM_CIPHERTEXT_SIZE,
    PQ_KEM_PUBLIC_KEY_SIZE,
    PQ_SIG_PUBLIC_KEY_SIZE,
    PQ_SIG_SIGNATURE_SIZE,
    X25519_PUBLIC_KEY_LENGTH
} from '../constants';
import type {
    PQKeyPair,
    X25519KeyPair,
    PeerKeys,
    OwnKeys,
    HandshakeMessage,
    EncryptedFrame
} from '../types/noise-types';
import { generateX25519KeyPair, computeX25519SharedSecret } from '../utils/noise-utils';
import { wipeHandshakeBytes as clearHandshakeSnapshot } from './wipe';
import { constantTimeBytesEqual } from '../utils/byte-utils';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const MAX_SEQUENCE = 0xffffffffffffffffn;
const HANDSHAKE_FRESHNESS_MS = 5 * 60 * 1000;
const MAX_HANDSHAKE_REPLAY_ENTRIES = 4096;
const acceptedInitiatorHandshakes = new Map<string, number>();
let acceptedInitiatorHandshakeGeneration = 0;
const NOISE_REPLAY_WINDOW_SLOTS = Number(NOISE_REPLAY_WINDOW_SIZE);
const monotonicNow = (): number => globalThis.performance?.now?.() ?? Date.now();
const CALL_STREAM_CONTEXT_RE = /^call-(?:audio|video|telemetry|screen):[a-f0-9]{16,64}$/;
const CALL_STREAM_KEY_SALT = new TextEncoder().encode(PROTOCOL_KEYS.NOISE_CALL_STREAM_KEY_SALT);
const MAX_CALL_STREAM_KEYS = 128;

if (!Number.isSafeInteger(NOISE_REPLAY_WINDOW_SLOTS) || NOISE_REPLAY_WINDOW_SLOTS < 1) {
    throw new Error('Invalid Noise replay window');
}

const SESSION_SALT = new TextEncoder().encode(PROTOCOL_KEYS.NOISE_SESSION_SALT);

function consumeInitiatorHandshakeReplay(
    localPeerId: string,
    peerId: string,
    sessionId: string,
    now: number,
    generation: number
): void {
    if (generation !== acceptedInitiatorHandshakeGeneration) {
        throw new Error('P2P handshake crossed an account transition');
    }
    
    while (acceptedInitiatorHandshakes.size > 0) {
        const oldest = acceptedInitiatorHandshakes.entries().next().value as
            | [string, number]
            | undefined;
        if (!oldest || oldest[1] > now) break;
        acceptedInitiatorHandshakes.delete(oldest[0]);
    }
    const cacheKey = `${localPeerId}\0${peerId}\0${sessionId}`;
    if (acceptedInitiatorHandshakes.has(cacheKey)) {
        throw new Error('Replayed P2P handshake');
    }
    while (acceptedInitiatorHandshakes.size >= MAX_HANDSHAKE_REPLAY_ENTRIES) {
        const oldest = acceptedInitiatorHandshakes.keys().next().value;
        if (oldest === undefined) break;
        acceptedInitiatorHandshakes.delete(oldest);
    }
    const expiresAt = now + HANDSHAKE_FRESHNESS_MS;
    acceptedInitiatorHandshakes.set(cacheKey, expiresAt);
}

export function clearNoiseHandshakeReplayCache(): void {
    acceptedInitiatorHandshakeGeneration += 1;
    acceptedInitiatorHandshakes.clear();
}

function snapshotHandshake(message: HandshakeMessage): HandshakeMessage {
    return {
        version: message.version,
        type: message.type,
        from: message.from,
        to: message.to,
        sessionId: message.sessionId,
        timestamp: message.timestamp,
        ...(message.ephemeralKyberPublic ? { ephemeralKyberPublic: message.ephemeralKyberPublic.slice() } : {}),
        kemCiphertext: message.kemCiphertext.slice(),
        ephemeralX25519Public: message.ephemeralX25519Public.slice(),
        signature: message.signature.slice(),
        signerPublicKey: message.signerPublicKey.slice()
    };
}

// Noise Session
export class PQSession {
    private sessionId: string;
    private localPeerId: string;
    private peerId: string;
    private role: 'initiator' | 'responder';

    // Session keys derived from shared secrets
    private sendKey: Uint8Array | null = null;
    private receiveKey: Uint8Array | null = null;
    private sendCallStreamKeys = new Map<string, Uint8Array>();
    private receiveCallStreamKeys = new Map<string, Uint8Array>();

    // Sequence tracking
    private sendSequence: bigint = BigInt(0);
    private receiveWindow: Array<bigint | undefined> = new Array(NOISE_REPLAY_WINDOW_SLOTS);
    private receiveHighWater: bigint = BigInt(0);

    // Lifecycle
    private state: 'pending' | 'handshaking' | 'established' | 'failed' = 'pending';
    private createdAt: number;

    private peerKeys: PeerKeys | null = null;

    // Handshake state
    private ephemeralKyberPair: PQKeyPair | null = null;
    private ephemeralX25519Pair: X25519KeyPair | null = null;
    private handshakePQSecret: Uint8Array | null = null;
    private handshakeX25519Secret: Uint8Array | null = null;
    private initiatorHandshakeHash: Uint8Array | null = null;

    private constructor(sessionId: string, localPeerId: string, peerId: string, role: 'initiator' | 'responder') {
        this.sessionId = sessionId;
        this.localPeerId = localPeerId;
        this.peerId = peerId;
        this.role = role;
        this.createdAt = monotonicNow();
    }

    // Session Establishment
    static async createInitiatorSession(
        localPeerId: string,
        peerId: string,
        ownKeys: OwnKeys,
        peerKeys: PeerKeys
    ): Promise<{ session: PQSession; message: HandshakeMessage }> {
        PQSession.validatePeerIds(localPeerId, peerId);
        PQSession.validateOwnKeys(ownKeys);
        PQSession.validatePeerKeys(peerKeys);
        const sessionId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
        const session = new PQSession(sessionId, localPeerId, peerId, 'initiator');
        session.peerKeys = {
            kyberPublicKey: peerKeys.kyberPublicKey.slice(),
            dilithiumPublicKey: peerKeys.dilithiumPublicKey.slice(),
            x25519PublicKey: peerKeys.x25519PublicKey.slice()
        };
        session.state = 'handshaking';
        let messageData: Uint8Array | null = null;
        try {
            session.ephemeralKyberPair = await PostQuantumKEM.generateKeyPair();
            session.ephemeralX25519Pair = generateX25519KeyPair();

            const { ciphertext: kemCiphertext, sharedSecret: pqSecret } = await PostQuantumKEM.encapsulate(
                session.peerKeys.kyberPublicKey
            );

            const x25519Secret = computeX25519SharedSecret(
                session.ephemeralX25519Pair.secretKey,
                session.peerKeys.x25519PublicKey
            );

            session.handshakePQSecret = pqSecret;
            session.handshakeX25519Secret = x25519Secret;

            const timestamp = Date.now();
            messageData = session.buildSignatureInput(
                'init',
                localPeerId,
                peerId,
                sessionId,
                timestamp,
                session.ephemeralKyberPair.publicKey,
                kemCiphertext,
                session.ephemeralX25519Pair.publicKey
            );

            const signature = await ownKeys.signTranscript(messageData);
            if (!(signature instanceof Uint8Array) || signature.length !== PQ_SIG_SIGNATURE_SIZE) {
                throw new Error('Native P2P signer returned an invalid signature');
            }
            const message: HandshakeMessage = {
                version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
                type: 'init',
                from: localPeerId,
                to: peerId,
                sessionId,
                timestamp,
                ephemeralKyberPublic: session.ephemeralKyberPair.publicKey.slice(),
                kemCiphertext,
                ephemeralX25519Public: session.ephemeralX25519Pair.publicKey.slice(),
                signature,
                signerPublicKey: ownKeys.dilithiumPublicKey.slice()
            };
            session.initiatorHandshakeHash = session.hashHandshakeMessage(message);

            return { session, message };
        } catch (error) {
            session.destroy();
            throw error;
        } finally {
            if (messageData) SecureMemory.zeroBuffer(messageData);
        }
    }

    // Process initiator message and create response
    static async processInitiatorMessage(
        localPeerId: string,
        peerId: string,
        ownKeys: OwnKeys,
        message: HandshakeMessage,
        expectedSignerPublicKey: Uint8Array
    ): Promise<{ session: PQSession; response: HandshakeMessage }> {
        PQSession.validatePeerIds(localPeerId, peerId);
        PQSession.validateOwnKeys(ownKeys);
        PQSession.validateHandshakeMessage(message, 'init');
        if (
            !(expectedSignerPublicKey instanceof Uint8Array) ||
            expectedSignerPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE
        ) {
            throw new Error('Invalid expected handshake signer key');
        }
        const expectedSignerSnapshot = expectedSignerPublicKey.slice();
        let messageSnapshot: HandshakeMessage | null = null;
        try {
            messageSnapshot = snapshotHandshake(message);
            message = messageSnapshot;
            expectedSignerPublicKey = expectedSignerSnapshot;
            const replayGeneration = acceptedInitiatorHandshakeGeneration;
            if (message.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION || message.type !== 'init') {
                throw new Error('Invalid handshake message');
            }
            if (message.from !== peerId || message.to !== localPeerId) {
                throw new Error('Handshake routing identity mismatch');
            }
            if (!message.ephemeralKyberPublic) {
                throw new Error('Missing initiator ephemeral ML-KEM key');
            }
            const initiatorKyberPublic = message.ephemeralKyberPublic;

            const age = Date.now() - message.timestamp;
            if (age > HANDSHAKE_FRESHNESS_MS || age < -60 * 1000) {
                throw new Error('Handshake message expired');
            }

            if (!constantTimeBytesEqual(message.signerPublicKey, expectedSignerPublicKey)) {
                throw new Error('Handshake signer identity mismatch');
            }

            // Verify ML-DSA signature
            const signatureInput = PQSession.prototype.buildSignatureInput.call(
                { sessionId: message.sessionId } as any,
                'init',
                message.from,
                message.to,
                message.sessionId,
                message.timestamp,
                initiatorKyberPublic,
                message.kemCiphertext,
                message.ephemeralX25519Public
            );

            let signatureValid = false;
            try {
                signatureValid = await PostQuantumSignature.verify(
                    message.signature,
                    signatureInput,
                    message.signerPublicKey
                );
            } finally {
                SecureMemory.zeroBuffer(signatureInput);
            }

            if (!signatureValid) {
                throw new Error('Invalid ML-DSA signature');
            }
            consumeInitiatorHandshakeReplay(
                localPeerId,
                peerId,
                message.sessionId,
                Date.now(),
                replayGeneration
            );

            const session = new PQSession(message.sessionId, localPeerId, peerId, 'responder');
            let initiatorMessageHash: Uint8Array | null = null;
            let initiatorPQSecret: Uint8Array | null = null;
            let initiatorX25519Secret: Uint8Array | null = null;
            let responderPQSecret: Uint8Array | null = null;
            let responderX25519Secret: Uint8Array | null = null;
            let responderX25519Pair: X25519KeyPair | null = null;
            let responseData: Uint8Array | null = null;
            let succeeded = false;
            try {
                session.peerKeys = {
                    kyberPublicKey: initiatorKyberPublic.slice(),
                    dilithiumPublicKey: message.signerPublicKey.slice(),
                    x25519PublicKey: message.ephemeralX25519Public.slice()
                };
                session.state = 'handshaking';
                initiatorMessageHash = session.hashHandshakeMessage(message);

                const staticSecrets = await ownKeys.respondToHandshake(
                    message.kemCiphertext,
                    message.ephemeralX25519Public
                );
                initiatorPQSecret = staticSecrets.pqSecret;
                initiatorX25519Secret = staticSecrets.x25519Secret;
                if (
                    !(initiatorPQSecret instanceof Uint8Array) || initiatorPQSecret.length !== 32 ||
                    !(initiatorX25519Secret instanceof Uint8Array) || initiatorX25519Secret.length !== 32
                ) {
                    throw new Error('Native P2P handshake returned invalid session material');
                }
                responderX25519Pair = generateX25519KeyPair();

                const encapsulated = await PostQuantumKEM.encapsulate(initiatorKyberPublic);
                const responseCiphertext = encapsulated.ciphertext;
                responderPQSecret = encapsulated.sharedSecret;
                responderX25519Secret = computeX25519SharedSecret(
                    responderX25519Pair.secretKey,
                    message.ephemeralX25519Public
                );

                const timestamp = Date.now();
                responseData = session.buildSignatureInput(
                    'response',
                    localPeerId,
                    peerId,
                    message.sessionId,
                    timestamp,
                    new Uint8Array(0),
                    responseCiphertext,
                    responderX25519Pair.publicKey,
                    initiatorMessageHash
                );
                const responseSignature = await ownKeys.signTranscript(responseData);
                if (!(responseSignature instanceof Uint8Array) || responseSignature.length !== PQ_SIG_SIGNATURE_SIZE) {
                    throw new Error('Native P2P signer returned an invalid signature');
                }
                const response: HandshakeMessage = {
                    version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
                    type: 'response',
                    from: localPeerId,
                    to: peerId,
                    sessionId: message.sessionId,
                    timestamp,
                    kemCiphertext: responseCiphertext,
                    ephemeralX25519Public: responderX25519Pair.publicKey.slice(),
                    signature: responseSignature,
                    signerPublicKey: ownKeys.dilithiumPublicKey.slice()
                };
                const transcriptHash = session.buildHandshakeTranscript(
                    initiatorMessageHash,
                    response,
                    ownKeys.kyberPublicKey,
                    ownKeys.x25519PublicKey
                );
                try {
                    session.deriveSessionKeys(
                        initiatorPQSecret,
                        responderPQSecret,
                        initiatorX25519Secret,
                        responderX25519Secret,
                        transcriptHash,
                        'responder'
                    );
                } finally {
                    SecureMemory.zeroBuffer(transcriptHash);
                }
                session.state = 'established';
                succeeded = true;
                return { session, response };
            } finally {
                if (initiatorPQSecret) SecureMemory.zeroBuffer(initiatorPQSecret);
                if (initiatorX25519Secret) SecureMemory.zeroBuffer(initiatorX25519Secret);
                if (responderPQSecret) SecureMemory.zeroBuffer(responderPQSecret);
                if (responderX25519Secret) SecureMemory.zeroBuffer(responderX25519Secret);
                if (responderX25519Pair) SecureMemory.zeroBuffer(responderX25519Pair.secretKey);
                if (responseData) SecureMemory.zeroBuffer(responseData);
                if (initiatorMessageHash) SecureMemory.zeroBuffer(initiatorMessageHash);
                initiatorMessageHash = null;
                if (!succeeded) {
                    session.destroy();
                }
            }
        } finally {
            if (messageSnapshot) clearHandshakeSnapshot(messageSnapshot);
            SecureMemory.zeroBuffer(expectedSignerSnapshot);
        }
    }

    // Complete initiator handshake with responder message
    async completeHandshake(response: HandshakeMessage, expectedSignerPublicKey: Uint8Array): Promise<void> {
        PQSession.validateHandshakeMessage(response, 'response');
        if (
            !(expectedSignerPublicKey instanceof Uint8Array) ||
            expectedSignerPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE
        ) {
            throw new Error('Invalid expected handshake signer key');
        }
        if (this.role !== 'initiator' || this.state !== 'handshaking') {
            throw new Error('Invalid state for completing handshake');
        }
        const expectedSignerSnapshot = expectedSignerPublicKey.slice();
        let responseSnapshot: HandshakeMessage | null = null;
        try {
            responseSnapshot = snapshotHandshake(response);
            response = responseSnapshot;
            expectedSignerPublicKey = expectedSignerSnapshot;

            if (response.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION || response.type !== 'response') {
                throw new Error('Invalid handshake response');
            }

            if (response.sessionId !== this.sessionId) {
                throw new Error('Session ID mismatch');
            }
            if (response.from !== this.peerId || response.to !== this.localPeerId) {
                throw new Error('Handshake response routing identity mismatch');
            }
            const responseAge = Date.now() - response.timestamp;
            if (responseAge > HANDSHAKE_FRESHNESS_MS || responseAge < -60 * 1000) {
                throw new Error('Handshake response expired');
            }
            if (response.ephemeralKyberPublic?.length) {
                throw new Error('Unexpected responder ephemeral ML-KEM key');
            }

            if (!constantTimeBytesEqual(response.signerPublicKey, expectedSignerPublicKey)) {
                throw new Error('Handshake signer identity mismatch');
            }
            if (!this.initiatorHandshakeHash) {
                throw new Error('Missing initiator handshake transcript');
            }

            // Verify ML-DSA signature
            const signatureInput = this.buildSignatureInput(
                'response',
                response.from,
                response.to,
                this.sessionId,
                response.timestamp,
                new Uint8Array(0),
                response.kemCiphertext,
                response.ephemeralX25519Public,
                this.initiatorHandshakeHash
            );

            let signatureValid = false;
            try {
                signatureValid = await PostQuantumSignature.verify(
                    response.signature,
                    signatureInput,
                    response.signerPublicKey
                );
            } finally {
                SecureMemory.zeroBuffer(signatureInput);
            }

            if (!signatureValid) {
                throw new Error('Invalid response signature');
            }

            // Check handshake state
            if (
                !this.ephemeralKyberPair ||
                !this.ephemeralX25519Pair ||
                !this.handshakePQSecret ||
                !this.handshakeX25519Secret ||
                !this.initiatorHandshakeHash ||
                !this.peerKeys
            ) {
                throw new Error('Missing handshake state');
            }

            // Decapsulate responder KEM ciphertext using own ephemeral key
            let responderPQSecret: Uint8Array | null = null;
            let responderX25519Secret: Uint8Array | null = null;
            try {
                responderPQSecret = await PostQuantumKEM.decapsulate(
                    response.kemCiphertext,
                    this.ephemeralKyberPair.secretKey
                );

                responderX25519Secret = computeX25519SharedSecret(
                    this.ephemeralX25519Pair.secretKey,
                    response.ephemeralX25519Public
                );

                const transcriptHash = this.buildHandshakeTranscript(
                    this.initiatorHandshakeHash,
                    response,
                    this.peerKeys.kyberPublicKey,
                    this.peerKeys.x25519PublicKey
                );
                try {
                    this.deriveSessionKeys(
                        this.handshakePQSecret,
                        responderPQSecret,
                        this.handshakeX25519Secret,
                        responderX25519Secret,
                        transcriptHash,
                        'initiator'
                    );
                } finally {
                    SecureMemory.zeroBuffer(transcriptHash);
                }

                SecureMemory.zeroBuffer(this.handshakePQSecret);
                SecureMemory.zeroBuffer(this.handshakeX25519Secret);
                SecureMemory.zeroBuffer(this.ephemeralKyberPair.secretKey);
                SecureMemory.zeroBuffer(this.ephemeralX25519Pair.secretKey);

                this.handshakePQSecret = null;
                this.handshakeX25519Secret = null;
                this.ephemeralKyberPair = null;
                this.ephemeralX25519Pair = null;
                SecureMemory.zeroBuffer(this.initiatorHandshakeHash);
                this.initiatorHandshakeHash = null;

                this.state = 'established';
            } finally {
                if (responderPQSecret) SecureMemory.zeroBuffer(responderPQSecret);
                if (responderX25519Secret) SecureMemory.zeroBuffer(responderX25519Secret);
            }
        } finally {
            if (responseSnapshot) clearHandshakeSnapshot(responseSnapshot);
            SecureMemory.zeroBuffer(expectedSignerSnapshot);
        }
    }

    // Derive session keys from hybrid shared secrets
    private deriveSessionKeys(
        pqSecret1: Uint8Array,
        pqSecret2: Uint8Array,
        classicalSecret1: Uint8Array,
        classicalSecret2: Uint8Array,
        transcriptHash: Uint8Array,
        role: 'initiator' | 'responder'
    ): void {
        if (transcriptHash.length !== 32) throw new Error('Invalid Noise transcript hash');
        const totalLen = pqSecret1.length + pqSecret2.length + classicalSecret1.length + classicalSecret2.length;
        const combined = new Uint8Array(totalLen);
        let offset = 0;

        combined.set(pqSecret1, offset);
        offset += pqSecret1.length;
        combined.set(pqSecret2, offset);
        offset += pqSecret2.length;
        combined.set(classicalSecret1, offset);
        offset += classicalSecret1.length;
        combined.set(classicalSecret2, offset);
        offset += classicalSecret2.length;
        const saltInput = new Uint8Array(SESSION_SALT.length + transcriptHash.length);
        let transcriptSalt: Uint8Array | null = null;
        let keyMaterial: Uint8Array | null = null;
        try {
            saltInput.set(SESSION_SALT, 0);
            saltInput.set(transcriptHash, SESSION_SALT.length);
            transcriptSalt = PostQuantumHash.blake3(saltInput, { dkLen: 32 });
            keyMaterial = PostQuantumHash.deriveKey(
                combined,
                transcriptSalt,
                `${PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION}:directional-session-keys`,
                64
            );

            if (role === 'initiator') {
                this.sendKey = keyMaterial.slice(0, 32);
                this.receiveKey = keyMaterial.slice(32, 64);
            } else {
                this.receiveKey = keyMaterial.slice(0, 32);
                this.sendKey = keyMaterial.slice(32, 64);
            }
        } finally {
            SecureMemory.zeroBuffer(combined);
            SecureMemory.zeroBuffer(saltInput);
            if (transcriptSalt) SecureMemory.zeroBuffer(transcriptSalt);
            if (keyMaterial) SecureMemory.zeroBuffer(keyMaterial);
        }
    }

    private resolveCallStreamKey(
        baseKey: Uint8Array,
        cache: Map<string, Uint8Array>,
        context?: string
    ): Uint8Array {
        if (context === undefined) return baseKey;
        if (!CALL_STREAM_CONTEXT_RE.test(context)) {
            throw new Error('Invalid call stream key context');
        }
        const existing = cache.get(context);
        if (existing) return existing;
        if (cache.size >= MAX_CALL_STREAM_KEYS) {
            throw new Error('Call stream key context limit exceeded');
        }
        const derived = PostQuantumHash.deriveKey(
            baseKey,
            CALL_STREAM_KEY_SALT,
            `${PROTOCOL_KEYS.NOISE_CALL_STREAM_KEY_CONTEXT_PREFIX}${context}`,
            32
        );
        cache.set(context, derived);
        return derived;
    }

    releaseCallStreamContext(context: string): void {
        if (!CALL_STREAM_CONTEXT_RE.test(context)) return;
        const sendKey = this.sendCallStreamKeys.get(context);
        if (sendKey) {
            SecureMemory.zeroBuffer(sendKey);
            this.sendCallStreamKeys.delete(context);
        }
        const receiveKey = this.receiveCallStreamKeys.get(context);
        if (receiveKey) {
            SecureMemory.zeroBuffer(receiveKey);
            this.receiveCallStreamKeys.delete(context);
        }
    }

    // Encrypt message
    async encrypt(
        plaintext: Uint8Array,
        aad?: Uint8Array,
        callStreamContext?: string
    ): Promise<EncryptedFrame> {
        if (this.state !== 'established' || !this.sendKey) {
            throw new Error('Session not established');
        }
        if (monotonicNow() - this.createdAt > NOISE_MAX_SESSION_AGE_MS) {
            this.destroy();
            throw new Error('Session expired');
        }
        if (this.sendSequence > MAX_SEQUENCE) {
            this.destroy();
            throw new Error('Session sequence exhausted');
        }

        const encryptionKey = this.resolveCallStreamKey(
            this.sendKey,
            this.sendCallStreamKeys,
            callStreamContext
        );
        const sequence = this.sendSequence;
        this.sendSequence = this.sendSequence + BigInt(1);

        const effectiveAad = aad || new Uint8Array(0);
        const nonce = this.deriveNonce(sequence);
        let returnedNonce: Uint8Array | null = null;
        try {
            const encrypted = await PostQuantumAEAD.encryptAsync(plaintext, encryptionKey, effectiveAad, nonce);
            returnedNonce = encrypted.nonce;
            return { sequence, ciphertext: encrypted.ciphertext, tag: encrypted.tag };
        } finally {
            SecureMemory.zeroBuffer(nonce);
            if (returnedNonce) SecureMemory.zeroBuffer(returnedNonce);
        }
    }

    // Decrypt message
    async decrypt(
        frame: EncryptedFrame,
        aad?: Uint8Array,
        callStreamContext?: string
    ): Promise<Uint8Array> {
        if (this.state !== 'established' || !this.receiveKey) {
            throw new Error('Session not established');
        }
        if (monotonicNow() - this.createdAt > NOISE_MAX_SESSION_AGE_MS) {
            this.destroy();
            throw new Error('Session expired');
        }

        if (
            typeof frame?.sequence !== 'bigint' ||
            frame.sequence < 0n ||
            frame.sequence > MAX_SEQUENCE ||
            !(frame.ciphertext instanceof Uint8Array) ||
            frame.ciphertext.length === 0 ||
            !(frame.tag instanceof Uint8Array) ||
            frame.tag.length !== 32 ||
            !this.validateSequence(frame.sequence)
        ) {
            throw new Error('Replay attack detected');
        }

        const effectiveAad = aad || new Uint8Array(0);
        const nonce = this.deriveNonce(frame.sequence);
        const decryptionKey = this.resolveCallStreamKey(
            this.receiveKey,
            this.receiveCallStreamKeys,
            callStreamContext
        );
        try {
            const plaintext = await PostQuantumAEAD.decryptAsync(
                frame.ciphertext,
                nonce,
                frame.tag,
                decryptionKey,
                effectiveAad
            );

            this.updateReplayWindow(frame.sequence);
            return plaintext;
        } finally {
            SecureMemory.zeroBuffer(nonce);
        }
    }

    private deriveNonce(sequence: bigint): Uint8Array {
        if (sequence < 0n || sequence > MAX_SEQUENCE) {
            throw new Error('Noise sequence outside uint64 range');
        }
        const nonce = new Uint8Array(36);
        const view = new DataView(nonce.buffer);
        view.setBigUint64(0, sequence, false);
        view.setBigUint64(12, sequence, false);
        return nonce;
    }

    // Validate sequence number
    private validateSequence(sequence: bigint): boolean {
        if (sequence <= this.receiveHighWater - NOISE_REPLAY_WINDOW_SIZE) {
            return false;
        }
        const slot = Number(sequence % NOISE_REPLAY_WINDOW_SIZE);
        return this.receiveWindow[slot] !== sequence;
    }

    private updateReplayWindow(sequence: bigint): void {
        if (sequence > this.receiveHighWater) {
            this.receiveHighWater = sequence;
        }
        const slot = Number(sequence % NOISE_REPLAY_WINDOW_SIZE);
        this.receiveWindow[slot] = sequence;
    }

    // Handshake signature input
    private buildSignatureInput(
        type: string,
        from: string,
        to: string,
        sessionId: string,
        timestamp: number,
        ephemeralKyberKey: Uint8Array,
        kemCiphertext: Uint8Array,
        ephemeralX25519Key: Uint8Array,
        priorHandshakeHash?: Uint8Array
    ): Uint8Array {
        const prior = priorHandshakeHash || new Uint8Array(0);
        if (prior.length !== 0 && prior.length !== 32) throw new Error('Invalid prior handshake hash');
        const header = new TextEncoder().encode(
            `${PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION}:${type}:${from}:${to}:${sessionId}:${timestamp}`
        );
        const result = new Uint8Array(
            header.length + prior.length + ephemeralKyberKey.length + kemCiphertext.length + ephemeralX25519Key.length
        );
        let offset = 0;
        result.set(header, offset);
        offset += header.length;
        result.set(prior, offset);
        offset += prior.length;
        result.set(ephemeralKyberKey, offset);
        offset += ephemeralKyberKey.length;
        result.set(kemCiphertext, offset);
        offset += kemCiphertext.length;
        result.set(ephemeralX25519Key, offset);
        return result;
    }

    private hashHandshakeMessage(message: HandshakeMessage, priorHandshakeHash?: Uint8Array): Uint8Array {
        const signatureInput = this.buildSignatureInput(
            message.type,
            message.from,
            message.to,
            message.sessionId,
            message.timestamp,
            message.ephemeralKyberPublic || new Uint8Array(0),
            message.kemCiphertext,
            message.ephemeralX25519Public,
            priorHandshakeHash
        );
        const material = new Uint8Array(
            signatureInput.length + message.signerPublicKey.length + message.signature.length
        );
        material.set(signatureInput, 0);
        material.set(message.signerPublicKey, signatureInput.length);
        material.set(message.signature, signatureInput.length + message.signerPublicKey.length);
        try {
            return PostQuantumHash.blake3(material, { dkLen: 32 });
        } finally {
            SecureMemory.zeroBuffer(signatureInput);
            SecureMemory.zeroBuffer(material);
        }
    }

    private buildHandshakeTranscript(
        initiatorHash: Uint8Array,
        response: HandshakeMessage,
        responderStaticKyberPublicKey: Uint8Array,
        responderStaticX25519PublicKey: Uint8Array
    ): Uint8Array {
        if (
            initiatorHash.length !== 32 ||
            responderStaticKyberPublicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            responderStaticX25519PublicKey.length !== X25519_PUBLIC_KEY_LENGTH
        )
            throw new Error('Invalid Noise transcript context');
        const responseHash = this.hashHandshakeMessage(response, initiatorHash);
        const domain = new TextEncoder().encode(`${PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION}${PROTOCOL_KEYS.NOISE_COMPLETE_TRANSCRIPT_SUFFIX}`);
        const material = new Uint8Array(
            domain.length +
                initiatorHash.length +
                responseHash.length +
                responderStaticKyberPublicKey.length +
                responderStaticX25519PublicKey.length
        );
        let offset = 0;
        material.set(domain, offset);
        offset += domain.length;
        material.set(initiatorHash, offset);
        offset += initiatorHash.length;
        material.set(responseHash, offset);
        offset += responseHash.length;
        material.set(responderStaticKyberPublicKey, offset);
        offset += responderStaticKyberPublicKey.length;
        material.set(responderStaticX25519PublicKey, offset);
        try {
            return PostQuantumHash.blake3(material, { dkLen: 32 });
        } finally {
            SecureMemory.zeroBuffer(responseHash);
            SecureMemory.zeroBuffer(material);
        }
    }

    private static validateOwnKeys(keys: OwnKeys): void {
        if (
            !(keys?.kyberPublicKey instanceof Uint8Array) ||
            keys.kyberPublicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            !(keys.dilithiumPublicKey instanceof Uint8Array) ||
            keys.dilithiumPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            !(keys.x25519PublicKey instanceof Uint8Array) ||
            keys.x25519PublicKey.length !== X25519_PUBLIC_KEY_LENGTH ||
            typeof keys.signTranscript !== 'function' ||
            typeof keys.respondToHandshake !== 'function'
        )
            throw new Error('Invalid local Noise key material');
    }

    private static validatePeerIds(localPeerId: string, peerId: string): void {
        if (
            typeof localPeerId !== 'string' ||
            typeof peerId !== 'string' ||
            !AUTH_USERNAME_REGEX.test(localPeerId) ||
            !AUTH_USERNAME_REGEX.test(peerId) ||
            localPeerId === peerId
        ) {
            throw new Error('Invalid Noise routing identities');
        }
    }

    private static validatePeerKeys(keys: PeerKeys): void {
        if (
            !(keys?.kyberPublicKey instanceof Uint8Array) ||
            keys.kyberPublicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE ||
            !(keys.dilithiumPublicKey instanceof Uint8Array) ||
            keys.dilithiumPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            !(keys.x25519PublicKey instanceof Uint8Array) ||
            keys.x25519PublicKey.length !== X25519_PUBLIC_KEY_LENGTH
        )
            throw new Error('Invalid peer Noise key material');
    }

    private static validateHandshakeMessage(message: HandshakeMessage, expectedType: 'init' | 'response'): void {
        if (
            !message ||
            message.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION ||
            message.type !== expectedType ||
            typeof message.from !== 'string' ||
            !AUTH_USERNAME_REGEX.test(message.from) ||
            typeof message.to !== 'string' ||
            !AUTH_USERNAME_REGEX.test(message.to) ||
            typeof message.sessionId !== 'string' ||
            !/^[a-f0-9]{32}$/.test(message.sessionId) ||
            !Number.isSafeInteger(message.timestamp) ||
            !(message.kemCiphertext instanceof Uint8Array) ||
            message.kemCiphertext.length !== PQ_KEM_CIPHERTEXT_SIZE ||
            !(message.ephemeralX25519Public instanceof Uint8Array) ||
            message.ephemeralX25519Public.length !== X25519_PUBLIC_KEY_LENGTH ||
            !(message.signature instanceof Uint8Array) ||
            message.signature.length !== PQ_SIG_SIGNATURE_SIZE ||
            !(message.signerPublicKey instanceof Uint8Array) ||
            message.signerPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE ||
            (expectedType === 'init'
                ? !(message.ephemeralKyberPublic instanceof Uint8Array) ||
                  message.ephemeralKyberPublic.length !== PQ_KEM_PUBLIC_KEY_SIZE
                : message.ephemeralKyberPublic !== undefined)
        )
            throw new Error('Invalid Noise handshake key material');
    }

    isEstablished(): boolean {
        return this.state === 'established';
    }

    getBindingId(): string {
        if (this.state !== 'established') throw new Error('Session not established');
        return this.sessionId;
    }

    isValid(): boolean {
        if (this.state !== 'established') {
            return false;
        }

        const age = monotonicNow() - this.createdAt;
        return age <= NOISE_MAX_SESSION_AGE_MS;
    }

    // Destroy the session
    destroy(): void {
        for (const key of this.sendCallStreamKeys.values()) {
            SecureMemory.zeroBuffer(key);
        }
        this.sendCallStreamKeys.clear();
        for (const key of this.receiveCallStreamKeys.values()) {
            SecureMemory.zeroBuffer(key);
        }
        this.receiveCallStreamKeys.clear();
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

        if (this.initiatorHandshakeHash) {
            SecureMemory.zeroBuffer(this.initiatorHandshakeHash);
            this.initiatorHandshakeHash = null;
        }

        if (this.ephemeralKyberPair) {
            SecureMemory.zeroBuffer(this.ephemeralKyberPair.secretKey);
            this.ephemeralKyberPair = null;
        }

        if (this.ephemeralX25519Pair) {
            SecureMemory.zeroBuffer(this.ephemeralX25519Pair.secretKey);
            this.ephemeralX25519Pair = null;
        }

        if (this.peerKeys) {
            SecureMemory.zeroBuffer(this.peerKeys.kyberPublicKey);
            SecureMemory.zeroBuffer(this.peerKeys.dilithiumPublicKey);
            SecureMemory.zeroBuffer(this.peerKeys.x25519PublicKey);
            this.peerKeys = null;
        }

        this.receiveWindow.fill(undefined);
        this.sendSequence = 0n;
        this.receiveHighWater = 0n;
        this.state = 'failed';
    }
}
