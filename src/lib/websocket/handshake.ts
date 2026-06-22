/**
 * WebSocket PQ Handshake Manager
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { PostQuantumHash } from '../cryptography/hash';
import { PostQuantumKEM } from '../cryptography/kem';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumSignature } from '../cryptography/signature';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { generateX25519KeyPair, computeX25519SharedSecret } from '../utils/noise-utils';
import type { ServerKeyMaterial, SessionKeyMaterial, HandshakeCallbacks } from '../types/websocket-types';
import { MAX_HANDSHAKE_ATTEMPTS, SESSION_REKEY_INTERVAL_MS } from '../constants';

const WS_CLIENT_SIGNING_KEY_STORAGE_KEY = 'ws_client_signing_key_v1';
const WS_SIGNING_KEY_SELF_TEST_MESSAGE = new TextEncoder().encode('qor-ws-client-signing-key-self-test-v1');

export class WebSocketHandshake {
  private handshakeInFlight = false;
  private handshakePromise: Promise<void> | null = null;
  private handshakeAttempts = 0;
  private sessionRekeyTimer: ReturnType<typeof setTimeout> | null = null;
  private serverKeyMaterial?: ServerKeyMaterial;

  constructor(private callbacks: HandshakeCallbacks) { }

  private async isUsableSigningKeyPair(keyPair: { publicKey: Uint8Array; privateKey: Uint8Array }): Promise<boolean> {
    if (
      !(keyPair.publicKey instanceof Uint8Array) ||
      !(keyPair.privateKey instanceof Uint8Array) ||
      keyPair.publicKey.length !== PostQuantumSignature.sizes.publicKey ||
      keyPair.privateKey.length !== PostQuantumSignature.sizes.secretKey
    ) {
      return false;
    }

    try {
      const signature = await PostQuantumSignature.sign(WS_SIGNING_KEY_SELF_TEST_MESSAGE, keyPair.privateKey);
      return await PostQuantumSignature.verify(signature, WS_SIGNING_KEY_SELF_TEST_MESSAGE, keyPair.publicKey);
    } catch {
      return false;
    }
  }

  isInFlight(): boolean {
    return this.handshakeInFlight;
  }

  getPromise(): Promise<void> | null {
    return this.handshakePromise;
  }

  getServerKeyMaterial(): ServerKeyMaterial | undefined {
    return this.serverKeyMaterial;
  }

  setServerKeyMaterial(material: ServerKeyMaterial): void {
    this.serverKeyMaterial = material;
  }

  clearServerKeyMaterial(): void {
    this.serverKeyMaterial = undefined;
  }

  resetAttempts(): void {
    this.handshakeAttempts = 0;
  }

  cancelRekeyTimer(): void {
    if (this.sessionRekeyTimer) {
      clearTimeout(this.sessionRekeyTimer);
      this.sessionRekeyTimer = null;
    }
  }

  reset(): void {
    this.handshakeInFlight = false;
    this.handshakePromise = null;
    this.handshakeAttempts = 0;
    this.cancelRekeyTimer();
  }

  // Signing keys initialization
  async initializeSigningKeys(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array } | undefined> {
    try {
      try {
        const { encryptedStorage } = await import('../database/encrypted-storage');
        await encryptedStorage.removeItem(WS_CLIENT_SIGNING_KEY_STORAGE_KEY).catch(() => { });
      } catch { }

      const kp = await PostQuantumSignature.generateKeyPair();
      const signingKeyPair = { publicKey: kp.publicKey, privateKey: kp.secretKey };
      if (!await this.isUsableSigningKeyPair(signingKeyPair)) {
        throw new Error('Generated ML-DSA signing key failed self-test');
      }
      return signingKeyPair;
    } catch {
      return undefined;
    }
  }

  // Main handshake entry point
  async performHandshake(force: boolean): Promise<void> {
    if (!force && this.handshakeInFlight) {
      if (this.handshakePromise) {
        await this.handshakePromise;
      }
      return;
    }

    let serverMaterial = this.serverKeyMaterial;

    if (!serverMaterial) {
      const startTime = Date.now();
      const timeout = 5000;
      let lastRequestTime = 0;

      while (!this.serverKeyMaterial && (Date.now() - startTime) < timeout) {
        if (!await this.callbacks.isConnected()) {
          throw new Error('Connection lost while waiting for server keys');
        }

        const now = Date.now();
        if (now - lastRequestTime > 1500) {
          try {
            await this.callbacks.transmit(JSON.stringify({ type: 'request-server-public-key' }));
            lastRequestTime = Date.now();
          } catch (err) {
            console.error('[WebSocketHandshake] Failed to transmit request:', err);
          }
        }
        await new Promise(resolve => setTimeout(resolve, 250));
      }

      serverMaterial = this.serverKeyMaterial;
      if (!serverMaterial) {
        console.error('[WebSocketHandshake] Handshake timeout waiting for server keys');
        throw new Error('Server key material unavailable (timeout)');
      }
    }

    this.serverKeyMaterial = serverMaterial;

    if (this.handshakeInFlight) {
      if (this.handshakePromise) await this.handshakePromise;
      return;
    }

    this.handshakeInFlight = true;
    this.handshakePromise = this.executeHandshake(serverMaterial);

    try {
      await this.handshakePromise;
    } finally {
      this.handshakeInFlight = false;
    }
  }

  // Execute the handshake
  private async executeHandshake(serverMaterial: ServerKeyMaterial): Promise<void> {
    const sessionId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
    const handshakeNonce = PostQuantumRandom.randomBytes(32);
    const timestamp = this.callbacks.getTrustedNow?.() ?? Date.now();
    const { ciphertext: kemCiphertext, sharedSecret: pqSharedSecret } = await PostQuantumKEM.encapsulate(serverMaterial.kyberPublicKey);
    const signingKeyPair = await this.initializeSigningKeys();
    if (!signingKeyPair) {
      throw new Error('Client ML-DSA signing key unavailable');
    }

    if (!serverMaterial.dilithiumPublicKey) {
      throw new Error('Server Dilithium public key not available for authenticated PQ handshake');
    }
    if (!serverMaterial.x25519PublicKey) {
      throw new Error('Server X25519 public key not available for hybrid WS handshake');
    }

    const ephemeral = generateX25519KeyPair();
    const classicalShared = computeX25519SharedSecret(ephemeral.secretKey, serverMaterial.x25519PublicKey);

    let sendKey: Uint8Array | undefined;
    let recvKey: Uint8Array | undefined;
    try {
      const encoder = new TextEncoder();
      const baseInfo = `${serverMaterial.fingerprint}:${sessionId}`;
      const sendSalt = encoder.encode(`${baseInfo}:send-${timestamp}`);
      const recvSalt = encoder.encode(`${baseInfo}:recv-${timestamp}`);

      const combined = new Uint8Array(pqSharedSecret.length + classicalShared.length);
      combined.set(pqSharedSecret, 0);
      combined.set(classicalShared, pqSharedSecret.length);

      sendKey = PostQuantumHash.deriveKey(combined, sendSalt, 'ws-pq-hybrid-send', 32);
      recvKey = PostQuantumHash.deriveKey(combined, recvSalt, 'ws-pq-hybrid-recv', 32);

      combined.fill(0);
    } finally {
      PostQuantumUtils.clearMemory(pqSharedSecret);
      PostQuantumUtils.clearMemory(classicalShared);
      PostQuantumUtils.clearMemory(ephemeral.secretKey);
    }

    const pendingSession: SessionKeyMaterial = {
      sessionId,
      sendKey: sendKey!,
      recvKey: recvKey!,
      establishedAt: timestamp,
      fingerprint: serverMaterial.fingerprint,
      clientSigningPublicKey: signingKeyPair?.publicKey
    };

    const handshakeMessage = {
      type: SignalType.PQ_HANDSHAKE_INIT,
      payload: {
        version: 'pq-ws-1',
        algorithms: {
          kem: 'ML-KEM-1024',
          signature: 'ML-DSA-87',
          classicalKeyAgreement: 'X25519',
          kdf: 'BLAKE3-HKDF-SHA256-DOMAIN-SEPARATED',
          aead: 'QOR-PQ-AEAD'
        },
        sessionId,
        timestamp,
        clientNonce: PostQuantumUtils.uint8ArrayToBase64(handshakeNonce),
        kemCiphertext: PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
        clientX25519PublicKey: PostQuantumUtils.uint8ArrayToBase64(ephemeral.publicKey),
        clientSigningPublicKey: signingKeyPair
          ? PostQuantumUtils.uint8ArrayToBase64(signingKeyPair.publicKey)
          : undefined,
        fingerprint: serverMaterial.fingerprint,
        capabilities: {
          queueSize: this.callbacks.getQueueLength(),
          chunkingEnabled: false
        }
      }
    };

    const ackPromise = new Promise<void>((resolve, reject) => {
      const timeoutDuration = this.callbacks.getTorAdaptedTimeout(30000);
      let settled = false;

      const cleanup = () => {
        this.callbacks.unregisterMessageHandler(SignalType.PQ_HANDSHAKE_ACK);
        if (typeof window !== 'undefined') {
          window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handleAckEvent as EventListener);
          window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handleAckEvent as EventListener);
        }
      };

      const settleSuccess = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        cleanup();
        this.callbacks.onSessionEstablished(
          pendingSession,
          serverMaterial.dilithiumPublicKey,
          signingKeyPair
        );

        try {
          window.dispatchEvent(new CustomEvent(EventType.PQ_SESSION_ESTABLISHED, {
            detail: { timestamp: Date.now() }
          }));
        } catch { }

        resolve();
      };

      const timeout = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanup();
        SecurityAuditLogger.log(SignalType.ERROR, 'ws-handshake-ack-timeout', {
          timeoutMs: timeoutDuration
        });
        reject(new Error('Handshake acknowledgment timeout'));
      }, timeoutDuration);

      const getAckSessionId = (msg: any): string | undefined => {
        if (!msg || typeof msg !== 'object') return undefined;
        if (typeof msg.sessionId === 'string') return msg.sessionId;
        if (msg.payload && typeof msg.payload === 'object' && typeof msg.payload.sessionId === 'string') {
          return msg.payload.sessionId;
        }
        return undefined;
      };

      const handleAckMessage = (msg: any) => {
        const ackSessionId = getAckSessionId(msg);
        if (ackSessionId === sessionId) {
          settleSuccess();
          return;
        }
        SecurityAuditLogger.log('warn', 'ws-handshake-ack-session-mismatch', {
          hasReceivedSessionId: !!ackSessionId
        });
      };

      const handleAckEvent = (ev: Event) => {
        const detail = (ev as CustomEvent).detail;
        if (detail?.type !== SignalType.PQ_HANDSHAKE_ACK) return;
        handleAckMessage(detail);
      };

      this.callbacks.registerMessageHandler(SignalType.PQ_HANDSHAKE_ACK, handleAckMessage);
      if (typeof window !== 'undefined') {
        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handleAckEvent as EventListener);
        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handleAckEvent as EventListener);
      }
    });

    await this.callbacks.transmit(JSON.stringify(handshakeMessage));

    try {
      await ackPromise;
      this.handshakeAttempts = 0;
      this.scheduleRekey();
    } catch (error) {
      this.handshakeAttempts += 1;
      if (this.handshakeAttempts >= MAX_HANDSHAKE_ATTEMPTS) {
        SecurityAuditLogger.log(SignalType.ERROR, 'ws-handshake-max-attempts', {
          attempts: this.handshakeAttempts
        });
      }
      this.callbacks.onHandshakeError(error as Error);
      throw error;
    }
  }

  // Schedule rekey
  private scheduleRekey(): void {
    this.cancelRekeyTimer();

    this.sessionRekeyTimer = setTimeout(() => {
      void this.performHandshake(true).catch((error) => {
        this.callbacks.onHandshakeError(error as Error);
      });
    }, SESSION_REKEY_INTERVAL_MS);
  }

  // Compute server fingerprint
  computeServerFingerprint(keys: { kyber: string; dilithium: string; x25519: string }): string {
    const encoded = JSON.stringify({
      kyberPublicBase64: keys.kyber,
      dilithiumPublicBase64: keys.dilithium,
      x25519PublicBase64: keys.x25519
    });
    const digest = PostQuantumHash.blake3(new TextEncoder().encode(encoded));
    return PostQuantumUtils.bytesToHex(digest);
  }
}
