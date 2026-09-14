/**
 * WebSocket PQ Handshake Manager
 */

import { PostQuantumKEM } from '../cryptography/kem';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumSignature } from '../cryptography/signature';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { generateX25519KeyPair, computeX25519SharedSecret } from '../utils/noise-utils';
import type {
  HandshakeCallbacks,
  MessageHandler,
  ServerKeyMaterial,
  SessionKeyMaterial,
} from '../types/websocket-types';
import { SESSION_REKEY_INTERVAL_MS } from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { ML_KEM_1024_CIPHERTEXT_BYTES } from '../../../shared/crypto-sizes.js';
import { Base64 } from '../cryptography/base64';
import { PostQuantumHash } from '../../../shared/post-quantum-hash.js';

const SERVER_KEY_WAIT_BASE_TIMEOUT_MS = 45_000;
const SERVER_KEY_REQUEST_INTERVAL_MS = 5_000;
const HANDSHAKE_ACK_BASE_TIMEOUT_MS = 60_000;
const HANDSHAKE_CONFIRM_BASE_TIMEOUT_MS = 60_000;
const HANDSHAKE_PHASE_MAX_TIMEOUT_MS = 180_000;

interface HandshakeRequestPayload {
  version: string;
  algorithms: {
    kem: string;
    signature: string;
    classicalKeyAgreement: string;
    kdf: string;
    aead: string;
  };
  sessionId: string;
  timestamp: number;
  clientNonce: string;
  kemCiphertext: string;
  clientKemPublicKey: string;
  clientX25519PublicKey: string;
  fingerprint: string;
}

function buildHandshakeAckSignaturePayload(ack: Record<string, unknown>): string {
  return [
    PROTOCOL_KEYS.WS_PQ_HANDSHAKE_ACK,
    String(ack.version || ''),
    String(ack.sessionId || ''),
    String(ack.fingerprint || ''),
    String(ack.clientNonce || ''),
    String(ack.requestTimestamp || ''),
    String(ack.requestDigest || ''),
    String(ack.responseKemCiphertext || ''),
    String(ack.timestamp || '')
  ].join('|');
}

function computeHandshakeRequestDigest(payload: HandshakeRequestPayload): string {
  const algorithms = payload.algorithms;
  const encoded = new TextEncoder().encode([
    PROTOCOL_KEYS.WS_PQ_HANDSHAKE_REQUEST,
    String(payload.version || ''),
    String(algorithms.kem || ''),
    String(algorithms.signature || ''),
    String(algorithms.classicalKeyAgreement || ''),
    String(algorithms.kdf || ''),
    String(algorithms.aead || ''),
    String(payload.sessionId || ''),
    String(payload.timestamp || ''),
    String(payload.clientNonce || ''),
    String(payload.kemCiphertext || ''),
    String(payload.clientKemPublicKey || ''),
    String(payload.clientX25519PublicKey || ''),
    String(payload.fingerprint || '')
  ].join('|'));
  const digest = PostQuantumHash.blake3(encoded);
  try {
    return PostQuantumUtils.bytesToHex(digest);
  } finally {
    encoded.fill(0);
    digest.fill(0);
  }
}

export class WebSocketHandshake {
  private handshakeInFlight = false;
  private handshakePromise: Promise<void> | null = null;
  private sessionRekeyTimer: ReturnType<typeof setTimeout> | null = null;
  private serverKeyMaterial?: ServerKeyMaterial;
  private lifecycleGeneration = 0;
  private cancelActiveAckWait: ((error: Error) => void) | null = null;

  constructor(private callbacks: HandshakeCallbacks) { }

  private diagnostic(
    phase: string,
    details: Record<string, unknown> = {},
    level: 'info' | 'warn' | 'error' = 'info'
  ): void {
    this.callbacks.onDiagnostic(phase, details, level);
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

  cancelRekeyTimer(): void {
    if (this.sessionRekeyTimer) {
      clearTimeout(this.sessionRekeyTimer);
      this.sessionRekeyTimer = null;
    }
  }

  reset(): void {
    this.lifecycleGeneration += 1;
    const cancelAckWait = this.cancelActiveAckWait;
    this.cancelActiveAckWait = null;
    cancelAckWait?.(new Error('PQ handshake cancelled by connection reset'));
    this.handshakeInFlight = false;
    this.handshakePromise = null;
    this.cancelRekeyTimer();
  }

  // Main handshake entry point
  async performHandshake(force: boolean): Promise<void> {
    const handshakeStartedAt = Date.now();
    this.diagnostic('perform-requested', {
      force,
      hasServerKeyMaterial: !!this.serverKeyMaterial,
      alreadyInFlight: this.handshakeInFlight,
    });
    if (!force && this.handshakeInFlight) {
      if (this.handshakePromise) {
        this.diagnostic('join-existing');
        await this.handshakePromise;
      }
      return;
    }

    let serverMaterial = this.serverKeyMaterial;

    if (!serverMaterial) {
      const startTime = Date.now();
      const timeout = this.callbacks.getTorAdaptedTimeout(SERVER_KEY_WAIT_BASE_TIMEOUT_MS);
      let lastRequestTime = startTime;
      let requestCount = 0;
      this.diagnostic('server-key-wait-begin', { timeoutMs: timeout });

      while (!this.serverKeyMaterial && (Date.now() - startTime) < timeout) {
        if (!await this.callbacks.isConnected()) {
          this.diagnostic('server-key-wait-connection-lost', {
            waitMs: Date.now() - startTime,
            requestCount,
          }, 'error');
          throw new Error('Connection lost while waiting for server keys');
        }

        const now = Date.now();
        if (now - lastRequestTime > SERVER_KEY_REQUEST_INTERVAL_MS) {
          try {
            requestCount += 1;
            this.diagnostic('server-key-request-send', { requestCount });
            await this.callbacks.transmit(JSON.stringify({ type: 'request-server-public-key' }));
            lastRequestTime = Date.now();
          } catch (err) {
            this.diagnostic('server-key-request-failed', {
              requestCount,
              errorName: err instanceof Error ? err.name : 'UnknownError',
              errorMessage: err instanceof Error ? err.message : String(err),
            }, 'warn');
            console.error('[WebSocketHandshake] Failed to transmit request:', err);
          }
        }
        await new Promise(resolve => setTimeout(resolve, 250));
      }

      serverMaterial = this.serverKeyMaterial;
      if (!serverMaterial) {
        this.diagnostic('server-key-wait-timeout', {
          waitMs: Date.now() - startTime,
          requestCount,
        }, 'error');
        console.error('[WebSocketHandshake] Handshake timeout waiting for server keys');
        throw new Error('Server key material unavailable (timeout)');
      }
      this.diagnostic('server-key-ready', {
        waitMs: Date.now() - startTime,
        requestCount,
      });
    }

    this.serverKeyMaterial = serverMaterial;

    if (this.handshakeInFlight) {
      if (this.handshakePromise) {
        this.diagnostic('join-existing-after-key-wait');
        await this.handshakePromise;
      }
      return;
    }

    const generation = this.lifecycleGeneration;
    const handshakePromise = this.callbacks.runOnSecureSendLane(
      () => this.executeHandshake(serverMaterial, generation)
    );
    this.handshakeInFlight = true;
    this.handshakePromise = handshakePromise;

    try {
      await handshakePromise;
      this.diagnostic('perform-complete', {
        force,
        durationMs: Date.now() - handshakeStartedAt,
      });
    } catch (error) {
      this.diagnostic('perform-failed', {
        force,
        durationMs: Date.now() - handshakeStartedAt,
        errorName: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
      }, 'error');
      throw error;
    } finally {
      if (this.handshakePromise === handshakePromise) {
        this.handshakeInFlight = false;
        this.handshakePromise = null;
      }
    }
  }

  // Execute the handshake
  private async executeHandshake(serverMaterial: ServerKeyMaterial, generation: number): Promise<void> {
    const startedAt = Date.now();
    this.diagnostic('execute-begin', { lifecycleGeneration: generation });
    if (generation !== this.lifecycleGeneration) {
      throw new Error('PQ handshake cancelled by connection reset');
    }
    if (!serverMaterial.dilithiumPublicKey) {
      throw new Error('Server Dilithium public key not available for authenticated PQ handshake');
    }
    if (!serverMaterial.x25519PublicKey) {
      throw new Error('Server X25519 public key not available for hybrid WS handshake');
    }
    const sessionId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
    const handshakeNonce = PostQuantumRandom.randomBytes(32);
    const handshakeNonceBase64 = Base64.arrayBufferToBase64(handshakeNonce);
    const timestamp = this.callbacks.getTrustedNow();

    let baseHandshakeSecret: Uint8Array | null = null;
    let handshakePayload: HandshakeRequestPayload | null = null;
    let requestDigest = '';
    let handshakeBaseInfo = '';
    let kemCiphertext: Uint8Array | null = null;
    let pqSharedSecret: Uint8Array | null = null;
    let clientKemKeyPair: Awaited<ReturnType<typeof PostQuantumKEM.generateKeyPair>> | null = null;
    let ephemeral: ReturnType<typeof generateX25519KeyPair> | null = null;
    let classicalShared: Uint8Array | null = null;
    try {
      const encapsulated = await PostQuantumKEM.encapsulate(serverMaterial.kyberPublicKey);
      kemCiphertext = encapsulated.ciphertext;
      pqSharedSecret = encapsulated.sharedSecret;
      clientKemKeyPair = await PostQuantumKEM.generateKeyPair();
      ephemeral = generateX25519KeyPair();
      classicalShared = computeX25519SharedSecret(ephemeral.secretKey, serverMaterial.x25519PublicKey);
      this.diagnostic('request-crypto-ready', {
        durationMs: Date.now() - startedAt,
      });
      handshakePayload = {
        version: PROTOCOL_KEYS.WS_PQ_PROTOCOL,
        algorithms: {
          kem: 'ML-KEM-1024',
          signature: 'ML-DSA-87',
          classicalKeyAgreement: 'X25519',
          kdf: 'BLAKE3-HKDF-SHA256-DOMAIN-SEPARATED',
          aead: 'QORC-PQ-AEAD'
        },
        sessionId,
        timestamp,
        clientNonce: handshakeNonceBase64,
        kemCiphertext: Base64.arrayBufferToBase64(kemCiphertext),
        clientKemPublicKey: Base64.arrayBufferToBase64(clientKemKeyPair.publicKey),
        clientX25519PublicKey: Base64.arrayBufferToBase64(ephemeral.publicKey),
        fingerprint: serverMaterial.fingerprint
      };
      requestDigest = computeHandshakeRequestDigest(handshakePayload);

      const encoder = new TextEncoder();
      handshakeBaseInfo = `${PROTOCOL_KEYS.WS_PQ_PROTOCOL}:${serverMaterial.fingerprint}:${sessionId}:${handshakeNonceBase64}:${timestamp}:${requestDigest}`;
      const baseSalt = encoder.encode(`${handshakeBaseInfo}${PROTOCOL_KEYS.WS_PQ_BASE_SALT_SUFFIX}`);

      const combined = new Uint8Array(pqSharedSecret.length + classicalShared.length);
      try {
        combined.set(pqSharedSecret, 0);
        combined.set(classicalShared, pqSharedSecret.length);
        baseHandshakeSecret = PostQuantumHash.deriveKey(
          combined,
          baseSalt,
          PROTOCOL_KEYS.WS_PQ_TWO_WAY_EPHEMERAL_BASE,
          32
        );
      } finally {
        combined.fill(0);
        baseSalt.fill(0);
      }
    } catch (error) {
      baseHandshakeSecret?.fill(0);
      handshakeNonce.fill(0);
      throw error;
    } finally {
      if (kemCiphertext) PostQuantumUtils.clearMemory(kemCiphertext);
      if (pqSharedSecret) PostQuantumUtils.clearMemory(pqSharedSecret);
      if (classicalShared) PostQuantumUtils.clearMemory(classicalShared);
      if (ephemeral) {
        PostQuantumUtils.clearMemory(ephemeral.secretKey);
        PostQuantumUtils.clearMemory(ephemeral.publicKey);
      }
      clientKemKeyPair?.publicKey.fill(0);
    }
    if (!baseHandshakeSecret || !clientKemKeyPair || !handshakePayload || !requestDigest) {
      baseHandshakeSecret?.fill(0);
      clientKemKeyPair?.secretKey.fill(0);
      handshakeNonce.fill(0);
      throw new Error('PQ handshake key derivation failed');
    }
    const retainedBaseHandshakeSecret = baseHandshakeSecret;
    const retainedClientKemKeyPair = clientKemKeyPair;
    let pendingSession: SessionKeyMaterial | null = null;

    const handshakeMessage = {
      type: SignalType.PQ_HANDSHAKE_INIT,
      payload: handshakePayload
    };

    let cancelAckWait: ((error: Error) => void) | null = null;
    let sessionInstalled = false;
    const ackPromise = new Promise<void>((resolve, reject) => {
      const timeoutDuration = Math.min(
        this.callbacks.getTorAdaptedTimeout(HANDSHAKE_ACK_BASE_TIMEOUT_MS),
        HANDSHAKE_PHASE_MAX_TIMEOUT_MS,
      );
      let settled = false;
      let ackVerificationInFlight = false;
      let confirmationHandler: MessageHandler | null = null;
      let rejectConfirmation: ((error: Error) => void) | null = null;
      let timeout: ReturnType<typeof setTimeout>;

      const cleanup = () => {
        this.callbacks.unregisterMessageHandler(SignalType.PQ_HANDSHAKE_ACK);
        if (confirmationHandler) {
          this.callbacks.unregisterMessageHandler(
            SignalType.PQ_HANDSHAKE_CONFIRMED,
            confirmationHandler
          );
          confirmationHandler = null;
        }
        if (this.cancelActiveAckWait === settleFailure) {
          this.cancelActiveAckWait = null;
        }
        window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handleAckEvent as EventListener);
        window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handleAckEvent as EventListener);
      };

      const settleFailure = (error: Error) => {
        if (settled) return;
        settled = true;
        rejectConfirmation?.(error);
        rejectConfirmation = null;
        clearTimeout(timeout);
        cleanup();
        reject(error);
      };
      cancelAckWait = settleFailure;
      this.cancelActiveAckWait = settleFailure;

      const settleSuccess = (authenticatedServerTime: number) => {
        if (settled) return;
        if (generation !== this.lifecycleGeneration) {
          settleFailure(new Error('PQ handshake cancelled by connection reset'));
          return;
        }
        try {
          this.callbacks.onAuthenticatedServerTime(authenticatedServerTime);
        } catch (error) {
          settleFailure(error instanceof Error ? error : new Error('Failed to accept authenticated server time'));
          return;
        }

        settled = true;
        clearTimeout(timeout);
        cleanup();

        try {
          window.dispatchEvent(new CustomEvent(EventType.PQ_SESSION_ESTABLISHED, {
            detail: { timestamp: Date.now() }
          }));
        } catch { }

        resolve();
      };

      timeout = setTimeout(() => {
        settleFailure(new Error('Handshake acknowledgment timeout'));
      }, timeoutDuration);

      const verifyAck = async (msg: unknown) => {
        if (settled || ackVerificationInFlight) return;
        if (generation !== this.lifecycleGeneration) {
          settleFailure(new Error('PQ handshake cancelled by connection reset'));
          return;
        }
        ackVerificationInFlight = true;
        const acknowledgementReceivedAt = performance.now();
        this.diagnostic('ack-received', {
          durationMs: Date.now() - startedAt,
        });
        let signature: Uint8Array | null = null;
        let signatureMessage: Uint8Array | null = null;
        try {
          if (!msg || typeof msg !== 'object' || Array.isArray(msg) || Object.getPrototypeOf(msg) !== Object.prototype) {
            throw new Error('Invalid handshake acknowledgement');
          }
          const ack = msg as Record<string, unknown>;
          if (
            Object.keys(ack).sort().join(',') !== 'clientNonce,fingerprint,requestDigest,requestTimestamp,responseKemCiphertext,serverTime,sessionId,signature,timestamp,type,version' ||
            ack.type !== SignalType.PQ_HANDSHAKE_ACK ||
            ack.version !== PROTOCOL_KEYS.WS_PQ_PROTOCOL ||
            ack.sessionId !== sessionId ||
            ack.fingerprint !== serverMaterial.fingerprint ||
            ack.clientNonce !== handshakeNonceBase64 ||
            ack.requestTimestamp !== timestamp ||
            ack.requestDigest !== requestDigest ||
            typeof ack.responseKemCiphertext !== 'string' ||
            ack.responseKemCiphertext.length !== 4 * Math.ceil(ML_KEM_1024_CIPHERTEXT_BYTES / 3) ||
            !Number.isSafeInteger(ack.timestamp) ||
            ack.serverTime !== ack.timestamp ||
            typeof ack.signature !== 'string' ||
            ack.signature.length === 0 ||
            ack.signature.length > 7000 ||
            ack.signature.length % 4 !== 0 ||
            !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(ack.signature)
          ) {
            throw new Error('Invalid handshake acknowledgement');
          }

          signature = PostQuantumUtils.base64ToUint8Array(ack.signature);
          if (
            signature.length !== PostQuantumSignature.sizes.signature ||
            Base64.arrayBufferToBase64(signature) !== ack.signature
          ) {
            throw new Error('Invalid handshake acknowledgement signature');
          }
          signatureMessage = new TextEncoder().encode(buildHandshakeAckSignaturePayload(ack));
          const valid = await PostQuantumSignature.verify(
            signature,
            signatureMessage,
            serverMaterial.dilithiumPublicKey!
          );
          if (!valid) {
            throw new Error('Handshake acknowledgement signature verification failed');
          }
          if (settled || generation !== this.lifecycleGeneration) return;

          let responseKemCiphertext: Uint8Array | null = null;
          let responderSharedSecret: Uint8Array | null = null;
          let combinedSecret: Uint8Array | null = null;
          let sendSalt: Uint8Array | null = null;
          let recvSalt: Uint8Array | null = null;
          let sendKey: Uint8Array | null = null;
          let recvKey: Uint8Array | null = null;
          try {
            responseKemCiphertext = PostQuantumUtils.base64ToUint8Array(
              ack.responseKemCiphertext as string
            );
            if (
              responseKemCiphertext.length !== ML_KEM_1024_CIPHERTEXT_BYTES ||
              Base64.arrayBufferToBase64(responseKemCiphertext) !== ack.responseKemCiphertext
            ) {
              throw new Error('Invalid responder ML-KEM ciphertext');
            }
            responderSharedSecret = await PostQuantumKEM.decapsulate(
              responseKemCiphertext,
              retainedClientKemKeyPair.secretKey
            );
            if (settled || generation !== this.lifecycleGeneration) return;
            combinedSecret = new Uint8Array(
              retainedBaseHandshakeSecret.length + responderSharedSecret.length
            );
            combinedSecret.set(retainedBaseHandshakeSecret, 0);
            combinedSecret.set(responderSharedSecret, retainedBaseHandshakeSecret.length);
            const finalContext = `${handshakeBaseInfo}:${ack.responseKemCiphertext}${PROTOCOL_KEYS.WS_PQ_FINAL_SALT_SUFFIX}`;
            sendSalt = new TextEncoder().encode(`${finalContext}${PROTOCOL_KEYS.WS_PQ_CLIENT_SEND_SALT_SUFFIX}`);
            recvSalt = new TextEncoder().encode(`${finalContext}${PROTOCOL_KEYS.WS_PQ_CLIENT_RECV_SALT_SUFFIX}`);
            sendKey = PostQuantumHash.deriveKey(
              combinedSecret,
              sendSalt,
              PROTOCOL_KEYS.WS_PQ_CLIENT_SEND,
              32
            );
            recvKey = PostQuantumHash.deriveKey(
              combinedSecret,
              recvSalt,
              PROTOCOL_KEYS.WS_PQ_CLIENT_RECV,
              32
            );
            pendingSession = {
              sessionId,
              sendKey,
              recvKey,
              establishedAt: timestamp,
              fingerprint: serverMaterial.fingerprint
            };
            sendKey = null;
            recvKey = null;
            this.callbacks.onSessionEstablished(pendingSession);
            sessionInstalled = true;
            this.diagnostic('ack-verified-session-installed', {
              durationMs: Date.now() - startedAt,
            });
          } finally {
            responseKemCiphertext?.fill(0);
            responderSharedSecret?.fill(0);
            combinedSecret?.fill(0);
            sendSalt?.fill(0);
            recvSalt?.fill(0);
            sendKey?.fill(0);
            recvKey?.fill(0);
          }

          const confirmationPromise = new Promise<void>((confirmResolve, confirmReject) => {
            rejectConfirmation = confirmReject;
            confirmationHandler = (confirmation: unknown) => {
              if (
                !confirmation ||
                typeof confirmation !== 'object' ||
                Array.isArray(confirmation) ||
                Object.getPrototypeOf(confirmation) !== Object.prototype
              ) return;
              const value = confirmation as Record<string, unknown>;
              if (
                Object.keys(value).sort().join(',') !== 'requestDigest,sessionId,type,version' ||
                value.type !== SignalType.PQ_HANDSHAKE_CONFIRMED ||
                value.version !== PROTOCOL_KEYS.WS_PQ_PROTOCOL ||
                value.sessionId !== sessionId ||
                value.requestDigest !== requestDigest
              ) {
                confirmReject(new Error('Invalid encrypted handshake confirmation'));
                return;
              }
              confirmResolve();
            };
            this.callbacks.registerMessageHandler(
              SignalType.PQ_HANDSHAKE_CONFIRMED,
              confirmationHandler
            );
          });
          
          void confirmationPromise.catch(() => { });
          clearTimeout(timeout);
          const confirmationTimeoutMs = Math.min(
            this.callbacks.getTorAdaptedTimeout(HANDSHAKE_CONFIRM_BASE_TIMEOUT_MS),
            HANDSHAKE_PHASE_MAX_TIMEOUT_MS,
          );
          timeout = setTimeout(() => {
            settleFailure(new Error('Encrypted handshake confirmation timeout'));
          }, confirmationTimeoutMs);
          this.diagnostic('confirmation-wait-begin', { timeoutMs: confirmationTimeoutMs });
          await this.callbacks.transmitHandshake({
            type: SignalType.PQ_HANDSHAKE_CONFIRM,
            version: PROTOCOL_KEYS.WS_PQ_PROTOCOL,
            sessionId,
            requestDigest
          });
          this.diagnostic('confirmation-sent', {
            durationMs: Date.now() - startedAt,
          });
          await confirmationPromise;
          this.diagnostic('confirmation-received', {
            durationMs: Date.now() - startedAt,
          });
          rejectConfirmation = null;
          settleSuccess((ack.serverTime as number) + Math.floor(performance.now() - acknowledgementReceivedAt));
        } catch (error) {
          this.diagnostic('ack-processing-failed', {
            durationMs: Date.now() - startedAt,
            errorName: error instanceof Error ? error.name : 'UnknownError',
            errorMessage: error instanceof Error ? error.message : String(error),
          }, 'error');
          settleFailure(error instanceof Error ? error : new Error('Invalid handshake acknowledgement'));
        } finally {
          signature?.fill(0);
          signatureMessage?.fill(0);
          ackVerificationInFlight = false;
        }
      };

      const handleAckMessage = (msg: unknown) => {
        void verifyAck(msg);
      };

      const handleAckEvent = (ev: Event) => {
        const detail = (ev as CustomEvent).detail;
        if (detail?.type !== SignalType.PQ_HANDSHAKE_ACK) return;
        handleAckMessage(detail);
      };

      this.callbacks.registerMessageHandler(SignalType.PQ_HANDSHAKE_ACK, handleAckMessage);
      window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handleAckEvent as EventListener);
      window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handleAckEvent as EventListener);
    });
    void ackPromise.catch(() => { });

    try {
      if (generation !== this.lifecycleGeneration) {
        throw new Error('PQ handshake cancelled by connection reset');
      }
      this.diagnostic('request-send', {
        durationMs: Date.now() - startedAt,
      });
      await this.callbacks.transmitHandshake(handshakeMessage);
      this.diagnostic('request-sent', {
        durationMs: Date.now() - startedAt,
      });
      await ackPromise;
      if (generation !== this.lifecycleGeneration) {
        throw new Error('PQ handshake cancelled by connection reset');
      }
      this.scheduleRekey();
      this.diagnostic('execute-complete', {
        durationMs: Date.now() - startedAt,
      });
    } catch (error) {
      const handshakeError = error instanceof Error ? error : new Error('PQ handshake failed');
      this.diagnostic('execute-failed', {
        durationMs: Date.now() - startedAt,
        errorName: handshakeError.name,
        errorMessage: handshakeError.message,
      }, 'error');
      cancelAckWait?.(handshakeError);
      await ackPromise.catch(() => { });
      if (generation === this.lifecycleGeneration) {
        this.callbacks.onHandshakeError(handshakeError);
      }
      throw handshakeError;
    } finally {
      handshakeNonce.fill(0);
      retainedBaseHandshakeSecret.fill(0);
      retainedClientKemKeyPair.secretKey.fill(0);
      if (!sessionInstalled && pendingSession) {
        pendingSession.sendKey.fill(0);
        pendingSession.recvKey.fill(0);
      }
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
