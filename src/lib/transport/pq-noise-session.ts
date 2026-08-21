/**
 * PQ Noise Session Wrapper
 */

import { PQSession, clearNoiseHandshakeReplayCache } from '../cryptography/noise-protocol';
import { PeerKeys, OwnKeys, HandshakeMessage, EncryptedFrame } from '../types/noise-types';
import { PostQuantumUtils } from '../utils/pq-utils';
import { encodeFrame, decodeFrame, MAX_MESSAGE_FRAME_SIZE } from './secure-transport';
import {
    PQ_KEM_CIPHERTEXT_SIZE,
    PQ_KEM_PUBLIC_KEY_SIZE,
    PQ_SIG_PUBLIC_KEY_SIZE,
    PQ_SIG_SIGNATURE_SIZE,
    X25519_PUBLIC_KEY_LENGTH
} from '../constants';
import { wipeHandshakeBytes as clearHandshakeBytes } from '../cryptography/wipe';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const confirmationEncoder = new TextEncoder();
const MAX_PENDING_ENCRYPT_OPERATIONS = 128;
const MAX_PENDING_ENCRYPT_BYTES = 4 * MAX_MESSAGE_FRAME_SIZE;
const MAX_PENDING_REALTIME_ENCRYPT_OPERATIONS = 5;
const MAX_PENDING_VISUAL_ENCRYPT_OPERATIONS = 1;
const MAX_PENDING_DECRYPT_OPERATIONS = 128;
const MAX_PENDING_DECRYPT_BYTES = 4 * MAX_MESSAGE_FRAME_SIZE;

interface PendingEncryptInput {
    plaintext: Uint8Array;
    aad?: Uint8Array;
    callStreamContext?: string;
    byteLength: number;
    released: boolean;
    priority: 'normal' | 'realtime' | 'visual';
    resolve: (value: Uint8Array) => void;
    reject: (reason: unknown) => void;
}

interface PendingDecryptInput {
    data: Uint8Array;
    aad?: Uint8Array;
    callStreamContext?: string;
    byteLength: number;
    released: boolean;
}

export function clearP2PNoiseHandshakeReplayCache(): void {
    clearNoiseHandshakeReplayCache();
}

// Noise session wrapper
export class PQNoiseSession {
    private session: PQSession;
    private encryptQueue: PendingEncryptInput[] = [];
    private encryptProcessing = false;
    private decryptTail: Promise<void> = Promise.resolve();
    private pendingEncryptInputs = new Set<PendingEncryptInput>();
    private pendingEncryptBytes = 0;
    private pendingDecryptInputs = new Set<PendingDecryptInput>();
    private pendingDecryptBytes = 0;
    private retiredCallStreamContexts = new Set<string>();
    private destroyed = false;

    private constructor(session: PQSession) {
        this.session = session;
    }

    // Create initiator session
    static async createInitiatorSession(
        localPeerId: string,
        peerId: string,
        ownKeys: OwnKeys,
        peerKeys: PeerKeys
    ): Promise<{ session: PQNoiseSession; message: PQNoiseHandshakeMessage }> {
        const { session, message } = await PQSession.createInitiatorSession(localPeerId, peerId, ownKeys, peerKeys);
        const wrappedSession = new PQNoiseSession(session);
        try {
            return {
                session: wrappedSession,
                message: serializeHandshake(message)
            };
        } catch (error) {
            wrappedSession.destroy();
            throw error;
        } finally {
            clearHandshakeBytes(message);
        }
    }

    // Process initiator message as responder
    static async processInitiatorMessage(
        localPeerId: string,
        peerId: string,
        ownKeys: OwnKeys,
        message: PQNoiseHandshakeMessage,
        expectedSignerPublicKey: Uint8Array
    ): Promise<{ session: PQNoiseSession; response: PQNoiseHandshakeMessage }> {
        const parsed = deserializeHandshake(message);
        let wrappedSession: PQNoiseSession | null = null;
        let response: HandshakeMessage | null = null;
        try {
            const result = await PQSession.processInitiatorMessage(
                localPeerId,
                peerId,
                ownKeys,
                parsed,
                expectedSignerPublicKey
            );
            response = result.response;
            wrappedSession = new PQNoiseSession(result.session);
            return {
                session: wrappedSession,
                response: serializeHandshake(response)
            };
        } catch (error) {
            wrappedSession?.destroy();
            throw error;
        } finally {
            clearHandshakeBytes(parsed);
            if (response) clearHandshakeBytes(response);
        }
    }

    // Complete initiator handshake
    async completeHandshake(response: PQNoiseHandshakeMessage, expectedSignerPublicKey: Uint8Array): Promise<void> {
        let parsed: HandshakeMessage | null = null;
        try {
            parsed = deserializeHandshake(response);
            await this.session.completeHandshake(parsed, expectedSignerPublicKey);
        } catch (error) {
            this.destroy();
            throw error;
        } finally {
            if (parsed) clearHandshakeBytes(parsed);
        }
    }

    // Encrypt message
    async encrypt(
        plaintext: Uint8Array,
        aad?: Uint8Array,
        priority: 'normal' | 'realtime' | 'visual' = 'normal',
        callStreamContext?: string
    ): Promise<Uint8Array> {
        if (this.destroyed) throw new Error('P2P Noise session is destroyed');
        if (
            !(plaintext instanceof Uint8Array) ||
            (aad !== undefined && !(aad instanceof Uint8Array)) ||
            (callStreamContext !== undefined && typeof callStreamContext !== 'string')
        ) {
            throw new Error('Invalid P2P Noise encryption input');
        }
        const byteLength = plaintext.byteLength + (aad?.byteLength ?? 0);
        if (callStreamContext) this.retiredCallStreamContexts.delete(callStreamContext);
        if (priority === 'realtime') {
            const realtimePending = Array.from(this.pendingEncryptInputs)
                .filter(input => input.priority === 'realtime').length;
            if (realtimePending >= MAX_PENDING_REALTIME_ENCRYPT_OPERATIONS) {
                const oldestRealtime = this.encryptQueue.findIndex(input => input.priority === 'realtime');
                if (oldestRealtime >= 0) {
                    const [dropped] = this.encryptQueue.splice(oldestRealtime, 1);
                    dropped.reject(new Error('Realtime encryption superseded'));
                    this.releasePendingEncryptInput(dropped);
                } else {
                    throw new Error('P2P realtime encryption is busy');
                }
            }
            while (
                this.pendingEncryptInputs.size >= MAX_PENDING_ENCRYPT_OPERATIONS ||
                this.pendingEncryptBytes + byteLength > MAX_PENDING_ENCRYPT_BYTES
            ) {
                const oldestNormal = this.encryptQueue.findIndex(input => input.priority !== 'realtime');
                if (oldestNormal < 0) break;
                const [dropped] = this.encryptQueue.splice(oldestNormal, 1);
                dropped.reject(new Error('Lower-priority encryption superseded by realtime media'));
                this.releasePendingEncryptInput(dropped);
            }
        } else if (priority === 'visual') {
            const visualPending = Array.from(this.pendingEncryptInputs)
                .filter(input => input.priority === 'visual').length;
            if (visualPending >= MAX_PENDING_VISUAL_ENCRYPT_OPERATIONS) {
                const oldestVisual = this.encryptQueue.findIndex(input => input.priority === 'visual');
                if (oldestVisual >= 0) {
                    const [dropped] = this.encryptQueue.splice(oldestVisual, 1);
                    dropped.reject(new Error('Visual encryption superseded'));
                    this.releasePendingEncryptInput(dropped);
                } else {
                    throw new Error('P2P visual encryption is busy');
                }
            }
            while (
                this.pendingEncryptInputs.size >= MAX_PENDING_ENCRYPT_OPERATIONS ||
                this.pendingEncryptBytes + byteLength > MAX_PENDING_ENCRYPT_BYTES
            ) {
                const oldestNormal = this.encryptQueue.findIndex(input => input.priority === 'normal');
                if (oldestNormal < 0) break;
                const [dropped] = this.encryptQueue.splice(oldestNormal, 1);
                dropped.reject(new Error('Normal encryption superseded by visual media'));
                this.releasePendingEncryptInput(dropped);
            }
        }
        if (
            this.pendingEncryptInputs.size >= MAX_PENDING_ENCRYPT_OPERATIONS ||
            byteLength > MAX_PENDING_ENCRYPT_BYTES ||
            this.pendingEncryptBytes + byteLength > MAX_PENDING_ENCRYPT_BYTES
        ) {
            throw new Error('P2P Noise encryption queue is full');
        }
        return new Promise<Uint8Array>((resolve, reject) => {
            const input: PendingEncryptInput = {
                plaintext: plaintext.slice(),
                ...(aad ? { aad: aad.slice() } : {}),
                ...(callStreamContext ? { callStreamContext } : {}),
                byteLength,
                released: false,
                priority,
                resolve,
                reject,
            };
            this.pendingEncryptInputs.add(input);
            this.pendingEncryptBytes += byteLength;
            this.encryptQueue.push(input);
            void this.drainEncryptQueue();
        });
    }

    private async drainEncryptQueue(): Promise<void> {
        if (this.encryptProcessing) return;
        this.encryptProcessing = true;
        try {
            while (!this.destroyed && this.encryptQueue.length > 0) {
                const realtimeIndex = this.encryptQueue.findIndex(input => input.priority === 'realtime');
                const visualIndex = this.encryptQueue.findIndex(input => input.priority === 'visual');
                const index = realtimeIndex >= 0 ? realtimeIndex : visualIndex >= 0 ? visualIndex : 0;
                const input = this.encryptQueue.splice(index, 1)[0];
                try {
                    if (this.destroyed) throw new Error('P2P Noise session is destroyed');
                    const frame = await this.session.encrypt(
                        input.plaintext,
                        input.aad,
                        input.callStreamContext
                    );
                    try {
                        input.resolve(encodeFrame(frame.sequence, frame.ciphertext, frame.tag));
                    } finally {
                        frame.ciphertext.fill(0);
                        frame.tag.fill(0);
                    }
                } catch (error) {
                    input.reject(error);
                } finally {
                    this.releasePendingEncryptInput(input);
                }
            }
        } finally {
            this.encryptProcessing = false;
        }
    }

    private releasePendingEncryptInput(input: PendingEncryptInput): void {
        if (input.released) return;
        input.released = true;
        input.plaintext.fill(0);
        input.aad?.fill(0);
        this.pendingEncryptInputs.delete(input);
        this.pendingEncryptBytes = Math.max(0, this.pendingEncryptBytes - input.byteLength);
        if (input.callStreamContext) this.releaseRetiredCallStreamContext(input.callStreamContext);
    }

    // Decrypt message
    async decrypt(
        data: Uint8Array,
        aad?: Uint8Array,
        callStreamContext?: string
    ): Promise<Uint8Array> {
        if (this.destroyed) throw new Error('P2P Noise session is destroyed');
        if (
            !(data instanceof Uint8Array) ||
            (aad !== undefined && !(aad instanceof Uint8Array)) ||
            (callStreamContext !== undefined && typeof callStreamContext !== 'string')
        ) {
            throw new Error('Invalid P2P Noise decryption input');
        }
        const byteLength = data.byteLength + (aad?.byteLength ?? 0);
        if (callStreamContext) this.retiredCallStreamContexts.delete(callStreamContext);
        if (
            this.pendingDecryptInputs.size >= MAX_PENDING_DECRYPT_OPERATIONS ||
            byteLength > MAX_PENDING_DECRYPT_BYTES ||
            this.pendingDecryptBytes + byteLength > MAX_PENDING_DECRYPT_BYTES
        ) {
            throw new Error('P2P Noise decryption queue is full');
        }
        const input: PendingDecryptInput = {
            data: data.slice(),
            ...(aad ? { aad: aad.slice() } : {}),
            ...(callStreamContext ? { callStreamContext } : {}),
            byteLength,
            released: false
        };
        this.pendingDecryptInputs.add(input);
        this.pendingDecryptBytes += byteLength;

        const operation = this.decryptTail
            .catch(() => {})
            .then(async () => {
                if (this.destroyed) throw new Error('P2P Noise session is destroyed');
                const decoded = decodeFrame(input.data);
                const frame: EncryptedFrame = {
                    sequence: decoded.sequence,
                    ciphertext: decoded.ciphertext,
                    tag: decoded.tag
                };
                try {
                    return await this.session.decrypt(
                        frame,
                        input.aad,
                        input.callStreamContext
                    );
                } finally {
                    frame.ciphertext.fill(0);
                    frame.tag.fill(0);
                }
            });
        const trackedOperation = operation.finally(() => {
            this.releasePendingDecryptInput(input);
        });
        this.decryptTail = trackedOperation.then(
            () => {},
            () => {}
        );
        return trackedOperation;
    }

    private releasePendingDecryptInput(input: PendingDecryptInput): void {
        if (input.released) return;
        input.released = true;
        input.data.fill(0);
        input.aad?.fill(0);
        this.pendingDecryptInputs.delete(input);
        this.pendingDecryptBytes = Math.max(0, this.pendingDecryptBytes - input.byteLength);
        if (input.callStreamContext) this.releaseRetiredCallStreamContext(input.callStreamContext);
    }

    releaseCallStreamContext(context: string): void {
        if (this.destroyed || typeof context !== 'string' || context.length === 0) return;
        this.retiredCallStreamContexts.add(context);
        this.releaseRetiredCallStreamContext(context);
    }

    private releaseRetiredCallStreamContext(context: string): void {
        if (!this.retiredCallStreamContexts.has(context)) return;
        for (const input of this.pendingEncryptInputs) {
            if (input.callStreamContext === context) return;
        }
        for (const input of this.pendingDecryptInputs) {
            if (input.callStreamContext === context) return;
        }
        this.retiredCallStreamContexts.delete(context);
        this.session.releaseCallStreamContext(context);
    }

    async createKeyConfirmation(from: string, to: string): Promise<Uint8Array> {
        const sessionId = this.getBindingId();
        const aad = confirmationEncoder.encode(`${PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION}${PROTOCOL_KEYS.NOISE_CONFIRMATION_SEPARATOR}${sessionId}:${from}:${to}`);
        const plaintext = confirmationEncoder.encode(`${PROTOCOL_KEYS.NOISE_KEY_CONFIRMATION}:${sessionId}`);
        try {
            return await this.encrypt(plaintext, aad);
        } finally {
            plaintext.fill(0);
            aad.fill(0);
        }
    }

    async verifyKeyConfirmation(frame: Uint8Array, from: string, to: string): Promise<void> {
        const sessionId = this.getBindingId();
        const aad = confirmationEncoder.encode(`${PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION}${PROTOCOL_KEYS.NOISE_CONFIRMATION_SEPARATOR}${sessionId}:${from}:${to}`);
        const expected = confirmationEncoder.encode(`${PROTOCOL_KEYS.NOISE_KEY_CONFIRMATION}:${sessionId}`);
        let plaintext: Uint8Array | null = null;
        try {
            plaintext = await this.decrypt(frame, aad);
            if (!PostQuantumUtils.timingSafeEqual(plaintext, expected)) {
                throw new Error('Invalid P2P key confirmation');
            }
        } finally {
            plaintext?.fill(0);
            expected.fill(0);
            aad.fill(0);
        }
    }

    // Check if session is valid
    isValid(): boolean {
        return this.session.isValid();
    }

    // Check if session is established
    isEstablished(): boolean {
        return this.session.isEstablished();
    }

    getBindingId(): string {
        return this.session.getBindingId();
    }

    // Destroy session
    destroy(): void {
        if (this.destroyed) return;
        this.destroyed = true;
        for (const input of this.encryptQueue.splice(0)) {
            input.reject(new Error('P2P Noise session is destroyed'));
        }
        for (const input of Array.from(this.pendingEncryptInputs)) {
            this.releasePendingEncryptInput(input);
        }
        for (const input of Array.from(this.pendingDecryptInputs)) {
            this.releasePendingDecryptInput(input);
        }
        this.retiredCallStreamContexts.clear();
        this.session.destroy();
    }
}

// Handshake Message Serialization
export interface PQNoiseHandshakeMessage {
    version: string;
    type: 'init' | 'response';
    from: string;
    to: string;
    sessionId: string;
    timestamp: number;
    ephemeralKyberPublic?: string;
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
        from: msg.from,
        to: msg.to,
        sessionId: msg.sessionId,
        timestamp: msg.timestamp,
        ...(msg.ephemeralKyberPublic?.length
            ? {
                  ephemeralKyberPublic: PostQuantumUtils.uint8ArrayToBase64(msg.ephemeralKyberPublic)
              }
            : {}),
        kemCiphertext: PostQuantumUtils.uint8ArrayToBase64(msg.kemCiphertext),
        ephemeralX25519Public: PostQuantumUtils.uint8ArrayToBase64(msg.ephemeralX25519Public),
        signature: PostQuantumUtils.uint8ArrayToBase64(msg.signature),
        signerPublicKey: PostQuantumUtils.uint8ArrayToBase64(msg.signerPublicKey)
    };
}

// Deserialize handshake message
function deserializeHandshake(msg: PQNoiseHandshakeMessage | HandshakeMessage): HandshakeMessage {
    const toUint8 = (val: string | Uint8Array | undefined, expectedLength: number): Uint8Array => {
        if (!val) return new Uint8Array(0);
        if (val instanceof Uint8Array) {
            if (val.length !== expectedLength) throw new Error('Invalid Noise handshake byte length');
            return val.slice();
        }
        if (
            val.length !== 4 * Math.ceil(expectedLength / 3) ||
            !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(val)
        ) {
            throw new Error('Invalid Noise handshake encoding length');
        }
        const decoded = PostQuantumUtils.base64ToUint8Array(val);
        if (decoded.length !== expectedLength || PostQuantumUtils.uint8ArrayToBase64(decoded) !== val) {
            decoded.fill(0);
            throw new Error('Non-canonical Noise handshake encoding');
        }
        return decoded;
    };

    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
        throw new Error('Invalid Noise handshake object');
    }
    const prototype = Object.getPrototypeOf(msg);
    if (prototype !== Object.prototype && prototype !== null) {
        throw new Error('Invalid Noise handshake object');
    }
    if (msg.version !== PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION || (msg.type !== 'init' && msg.type !== 'response')) {
        throw new Error('Invalid Noise handshake header');
    }
    const expectedKeys = (
        msg.type === 'init'
            ? [
                  'version',
                  'type',
                  'from',
                  'to',
                  'sessionId',
                  'timestamp',
                  'ephemeralKyberPublic',
                  'kemCiphertext',
                  'ephemeralX25519Public',
                  'signature',
                  'signerPublicKey'
              ]
            : [
                  'version',
                  'type',
                  'from',
                  'to',
                  'sessionId',
                  'timestamp',
                  'kemCiphertext',
                  'ephemeralX25519Public',
                  'signature',
                  'signerPublicKey'
              ]
    ).sort();
    const actualKeys = Object.keys(msg).sort();
    if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
        throw new Error('Invalid Noise handshake shape');
    }
    if (typeof msg.from !== 'string' || typeof msg.to !== 'string') {
        throw new Error('Invalid Noise handshake routing identities');
    }
    if (typeof msg.sessionId !== 'string' || !/^[a-f0-9]{32}$/.test(msg.sessionId)) {
        throw new Error('Invalid Noise session ID');
    }
    if (!Number.isSafeInteger(msg.timestamp)) {
        throw new Error('Invalid Noise handshake timestamp');
    }

    let ephemeralKyberPublic: Uint8Array | null = null;
    let kemCiphertext: Uint8Array | null = null;
    let ephemeralX25519Public: Uint8Array | null = null;
    let signature: Uint8Array | null = null;
    let signerPublicKey: Uint8Array | null = null;
    try {
        if (msg.type === 'init') {
            ephemeralKyberPublic = toUint8(msg.ephemeralKyberPublic, PQ_KEM_PUBLIC_KEY_SIZE);
        }
        kemCiphertext = toUint8(msg.kemCiphertext, PQ_KEM_CIPHERTEXT_SIZE);
        ephemeralX25519Public = toUint8(msg.ephemeralX25519Public, X25519_PUBLIC_KEY_LENGTH);
        signature = toUint8(msg.signature, PQ_SIG_SIGNATURE_SIZE);
        signerPublicKey = toUint8(msg.signerPublicKey, PQ_SIG_PUBLIC_KEY_SIZE);
        if (
            (msg.type === 'init' && ephemeralKyberPublic?.length !== PQ_KEM_PUBLIC_KEY_SIZE) ||
            kemCiphertext.length !== PQ_KEM_CIPHERTEXT_SIZE ||
            ephemeralX25519Public.length !== X25519_PUBLIC_KEY_LENGTH ||
            signature.length !== PQ_SIG_SIGNATURE_SIZE ||
            signerPublicKey.length !== PQ_SIG_PUBLIC_KEY_SIZE
        ) {
            throw new Error('Invalid Noise handshake key material');
        }

        return {
            version: PROTOCOL_KEYS.NOISE_PROTOCOL_VERSION,
            type: msg.type,
            from: msg.from,
            to: msg.to,
            sessionId: msg.sessionId,
            timestamp: msg.timestamp,
            ...(msg.type === 'init' ? { ephemeralKyberPublic } : {}),
            kemCiphertext,
            ephemeralX25519Public,
            signature,
            signerPublicKey
        } as HandshakeMessage;
    } catch (error) {
        ephemeralKyberPublic?.fill(0);
        kemCiphertext?.fill(0);
        ephemeralX25519Public?.fill(0);
        signature?.fill(0);
        signerPublicKey?.fill(0);
        throw error;
    }
}
