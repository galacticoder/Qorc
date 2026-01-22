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
import { session } from '../tauri-bindings';

export class WebSocketHandshake {
  private handshakeInFlight = false;
  private handshakePromise: Promise<void> | null = null;
  private handshakeAttempts = 0;
  private sessionRekeyTimer: ReturnType<typeof setTimeout> | null = null;
  private serverKeyMaterial?: ServerKeyMaterial;

  constructor(private callbacks: HandshakeCallbacks) { }

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
      const { encryptedStorage } = await import('../database/encrypted-storage');
      const stored = await encryptedStorage.getItem('ws_client_signing_key_v1');
      if (stored) {
        try {
          const parsed = typeof stored === 'string' ? JSON.parse(stored) : stored;
          if (parsed?.publicKey && parsed?.privateKey) {
            return {
              publicKey: PostQuantumUtils.base64ToUint8Array(parsed.publicKey),
              privateKey: PostQuantumUtils.base64ToUint8Array(parsed.privateKey)
            };
          }
        } catch { }
      }

      const kp = await PostQuantumSignature.generateKeyPair();
      const signingKeyPair = { publicKey: kp.publicKey, privateKey: kp.secretKey };
      try {
        const publicKey = PostQuantumUtils.asUint8Array(signingKeyPair.publicKey);
        const privateKey = PostQuantumUtils.asUint8Array(signingKeyPair.privateKey);
        await encryptedStorage.setItem('ws_client_signing_key_v1', JSON.stringify({
          publicKey: PostQuantumUtils.uint8ArrayToBase64(publicKey),
          privateKey: PostQuantumUtils.uint8ArrayToBase64(privateKey)
        }));
      } catch { }

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
      console.log('[WebSocketHandshake] Server material missing, waiting...');
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
            if (lastRequestTime === 0) {
              await new Promise(resolve => setTimeout(resolve, 200));
            }
            await this.callbacks.transmit(JSON.stringify({ type: 'request-server-public-key' }));
            lastRequestTime = Date.now();
          } catch (err) {
            console.error('[WebSocketHandshake] Failed to transmit request:', err);
          }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      serverMaterial = this.serverKeyMaterial;
      if (!serverMaterial) {
        console.error('[WebSocketHandshake] Handshake timeout waiting for server keys');
        throw new Error('Server key material unavailable (timeout)');
      }
    }

    this.serverKeyMaterial = serverMaterial;

    if (this.handshakeInFlight) {
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
    const timestamp = Date.now();
    const { ciphertext: kemCiphertext, sharedSecret: pqSharedSecret } = PostQuantumKEM.encapsulate(serverMaterial.kyberPublicKey);

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

      const combined = new Uint8Array(pqSharedSecret.length);
      for (let i = 0; i < pqSharedSecret.length; i++) {
        combined[i] = pqSharedSecret[i] ^ classicalShared[i % classicalShared.length];
      }

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
      fingerprint: serverMaterial.fingerprint
    };

    const handshakeMessage = {
      type: 'pq-handshake-init',
      payload: {
        version: 'pq-ws-1',
        sessionId,
        timestamp,
        clientNonce: PostQuantumUtils.uint8ArrayToBase64(handshakeNonce),
        kemCiphertext: PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
        clientX25519PublicKey: PostQuantumUtils.uint8ArrayToBase64(ephemeral.publicKey),
        fingerprint: serverMaterial.fingerprint,
        capabilities: {
          queueSize: this.callbacks.getQueueLength(),
          chunkingEnabled: false
        }
      }
    };

    const ackPromise = new Promise<void>((resolve, reject) => {
      const timeoutDuration = this.callbacks.getTorAdaptedTimeout(15000);
      const timeout = setTimeout(() => {
        this.callbacks.unregisterMessageHandler('pq-handshake-ack');
        SecurityAuditLogger.log(SignalType.ERROR, 'ws-handshake-ack-timeout', {
          sessionId: sessionId.slice(0, 16),
          timeoutMs: timeoutDuration
        });
        reject(new Error('Handshake acknowledgment timeout'));
      }, timeoutDuration);

      const handleAck = (msg: any) => {
        if (msg.sessionId === sessionId) {
          clearTimeout(timeout);
          this.callbacks.unregisterMessageHandler('pq-handshake-ack');
          this.callbacks.onSessionEstablished(pendingSession, serverMaterial.dilithiumPublicKey);

          try {
            window.dispatchEvent(new CustomEvent(EventType.PQ_SESSION_ESTABLISHED, {
              detail: { timestamp: Date.now(), sessionId: sessionId.slice(0, 16) }
            }));
          } catch { }

          // Store session keys for background mode
          try {
            const keysToStore = {
              session_id: pendingSession.sessionId,
              aes_key: PostQuantumUtils.uint8ArrayToBase64(pendingSession.sendKey),
              mac_key: PostQuantumUtils.uint8ArrayToBase64(pendingSession.recvKey),
              created_at: pendingSession.establishedAt
            };
            session.storePQKeys(keysToStore).catch(() => { });
          } catch { }

          resolve();
        } else {
          SecurityAuditLogger.log('warn', 'ws-handshake-ack-session-mismatch', {
            receivedSessionId: msg.sessionId?.slice(0, 16),
            expectedSessionId: sessionId.slice(0, 16)
          });
        }
      };

      this.callbacks.registerMessageHandler('pq-handshake-ack', handleAck);
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
