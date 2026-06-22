/**
 * WebSocket Encryption/Decryption
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumSignature } from '../cryptography/signature';
import { SignalType } from '../types/signal-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { estimateBase64DecodedBytes } from '../utils/websocket-utils';
import type { ConnectionMetrics, EncryptionContext } from '../types/websocket-types';
import {
  MAX_MESSAGE_AAD_LENGTH,
  MAX_REPLAY_WINDOW_MS,
  MAX_NONCE_SEQUENCE_GAP,
  SESSION_FAILOVER_GRACE_PERIOD_MS,
  MAX_PQ_ENVELOPE_CIPHERTEXT_BYTES,
  MAX_PQ_ENVELOPE_NONCE_BYTES,
  MAX_PQ_ENVELOPE_TAG_BYTES,
  MAX_PQ_ENVELOPE_AAD_BYTES,
  WS_FIXED_MESSAGE_SIZE_BYTES,
  REPLAY_CACHE_LIMIT,
} from '../constants';

// WebSocket Encryption/Decryption
export class WebSocketEncryption {
  private seenMessageFingerprints: Map<string, number> = new Map();
  private sessionNonceCounter = 0;
  private expectedRemoteNonceCounter = 0;

  constructor(
    private context: EncryptionContext,
    private metrics: ConnectionMetrics,
    private getTrustedNow: () => number = () => Date.now()
  ) { }

  // Get current session nonce counter
  getSessionNonceCounter(): number {
    return this.sessionNonceCounter;
  }

  // Increment session nonce counter
  incrementSessionNonceCounter(): number {
    return ++this.sessionNonceCounter;
  }

  // Reset nonce counters
  resetCounters(): void {
    this.sessionNonceCounter = 0;
    this.expectedRemoteNonceCounter = 0;
  }

  // Clear replay cache
  clearReplayCache(): void {
    this.seenMessageFingerprints.clear();
  }

  // Validate nonce sequence to detect out of order or replayed messages
  validateNonceSequence(counter: number): boolean {
    if (counter <= this.expectedRemoteNonceCounter - MAX_NONCE_SEQUENCE_GAP) {
      this.metrics.securityEvents.replayAttempts += 1;
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-nonce-replay', {
        received: counter,
        expected: this.expectedRemoteNonceCounter,
        gap: this.expectedRemoteNonceCounter - counter
      });
      return false;
    }

    if (counter >= this.expectedRemoteNonceCounter) {
      this.expectedRemoteNonceCounter = counter + 1;
    }

    return true;
  }

  // Validate timestamp with skew tolerance
  validateTimestamp(timestamp: number): boolean {
    const now = this.getTrustedNow();
    const skew = Math.abs(now - timestamp);

    if (skew > MAX_REPLAY_WINDOW_MS) {
      this.metrics.securityEvents.replayAttempts += 1;
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-timestamp-invalid', {
        timestamp,
        now,
        skew,
        maxAllowed: MAX_REPLAY_WINDOW_MS
      });

      return false;
    }

    return true;
  }

  // Sign outgoing message for integrity verification
  private buildSignaturePayload(envelope: any): string {
    return [
      String(envelope?.version || ''),
      String(envelope?.sessionId || ''),
      String(envelope?.sessionFingerprint || ''),
      String(envelope?.messageId || ''),
      String(envelope?.timestamp || ''),
      String(envelope?.counter || ''),
      String(envelope?.aad || '')
    ].join('|');
  }

  async signMessage(envelope: any): Promise<string> {
    if (!this.context.signingKeyPair) {
      throw new Error('Client signing key unavailable');
    }
    const sessionSigningPublicKey = this.context.sessionKeyMaterial?.clientSigningPublicKey;
    if (
      sessionSigningPublicKey &&
      !PostQuantumUtils.timingSafeEqual(sessionSigningPublicKey, this.context.signingKeyPair.publicKey)
    ) {
      throw new Error('PQ session signing key binding mismatch');
    }

    try {
      const payload = this.buildSignaturePayload(envelope);
      const message = new TextEncoder().encode(payload);
      const signature = await PostQuantumSignature.sign(message, this.context.signingKeyPair.privateKey);
      return PostQuantumUtils.uint8ArrayToBase64(signature);
    } catch {
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-message-signing-failed', {});
      throw new Error('WebSocket message signing failed');
    }
  }

  // Verify incoming message signature
  async verifyMessageSignature(envelope: any): Promise<boolean> {
    if (!envelope.signature) {
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-signature-missing', {
        messageId: envelope.messageId
      });

      this.metrics.securityEvents.signatureFailures += 1;
      return false;
    }

    if (!this.context.serverSignatureKey) {
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-signature-key-unavailable', {
        messageId: envelope.messageId
      });
      this.metrics.securityEvents.signatureFailures += 1;
      return false;
    }

    try {
      const payload = this.buildSignaturePayload(envelope);
      const message = new TextEncoder().encode(payload);
      const signature = PostQuantumUtils.base64ToUint8Array(envelope.signature);
      const valid = await PostQuantumSignature.verify(signature, message, this.context.serverSignatureKey);

      if (!valid) {
        this.metrics.securityEvents.signatureFailures += 1;
        SecurityAuditLogger.log(SignalType.ERROR, 'ws-signature-invalid', {
          messageId: envelope.messageId
        });
      }

      return valid;
    } catch {
      this.metrics.securityEvents.signatureFailures += 1;
      return false;
    }
  }

  // Normalize payload for processing
  private normalizePayload(data: unknown): { type: string; body: any } {
    if (data && typeof data === 'object') {
      const body = this.sanitize(data);
      const type = typeof body.type === 'string' ? String(body.type) : 'generic';
      if (typeof body.type !== 'string') {
        body.type = type;
      }
      return { type, body };
    }

    if (typeof data === 'string') {
      try {
        const parsed = JSON.parse(data);
        if (parsed && typeof parsed === 'object') {
          const body = this.sanitize(parsed);
          const type = typeof body.type === 'string' ? String(body.type) : 'raw-string';
          if (typeof body.type !== 'string') {
            body.type = type;
          }
          return { type, body };
        }
      } catch {
      }
      return { type: 'raw-string', body: { type: 'raw-string', data } };
    }

    return { type: 'raw-scalar', body: { type: 'raw-scalar', data: String(data) } };
  }

  // Sanitize input for processing
  private sanitize(input: any): any {
    try {
      return JSON.parse(JSON.stringify(input));
    } catch {
      return { type: 'raw-string', data: String(input) };
    }
  }

  // Build AAD for encryption
  private buildEnvelopeAAD(type: string, messageId: string, timestamp: number, counter: number): Uint8Array {
    const encoder = new TextEncoder();
    const parts = `${type}|${messageId}|${timestamp}|${counter}`;
    const bytes = encoder.encode(parts);
    if (bytes.length <= MAX_MESSAGE_AAD_LENGTH) {
      return bytes;
    }
    return bytes.slice(0, MAX_MESSAGE_AAD_LENGTH);
  }

  // Prepare secure envelope for sending
  async prepareSecureEnvelope(data: unknown): Promise<string> {
    const session = this.context.sessionKeyMaterial;
    if (!session) {
      throw new Error('Post-quantum session not established');
    }

    const canonical = this.normalizePayload(data);
    const messageId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
    const timestamp = this.getTrustedNow();
    const counter = this.incrementSessionNonceCounter();

    if (typeof canonical.body.type !== 'string') {
      canonical.body.type = canonical.type;
    }

    const isSealedEnvelope = canonical.type === SignalType.SEALED_ENVELOPE;
    let payloadToEncrypt: any;

    if (isSealedEnvelope && canonical.body.envelope) {
      payloadToEncrypt = {
        type: canonical.type,
        envelope: canonical.body.envelope,
        messageId: canonical.body.messageId
      };
    } else {
      payloadToEncrypt = canonical.body;
    }

    const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadToEncrypt));
    const nonce = PostQuantumRandom.randomBytes(36);
    const aadBytes = this.buildEnvelopeAAD(canonical.type, messageId, timestamp, counter);

    const { ciphertext, tag } = await PostQuantumAEAD.encryptAsync(
      payloadBytes,
      session.sendKey,
      aadBytes,
      nonce
    );

    PostQuantumUtils.clearMemory(payloadBytes);

    const envelope = {
      type: SignalType.PQ_ENVELOPE,
      version: 'pq-ws-1',
      sessionId: session.sessionId,
      sessionFingerprint: session.fingerprint,
      messageId,
      counter,
      timestamp,
      nonce: PostQuantumUtils.uint8ArrayToBase64(nonce),
      ciphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext),
      tag: PostQuantumUtils.uint8ArrayToBase64(tag),
      aad: PostQuantumUtils.uint8ArrayToBase64(aadBytes)
    };

    (envelope as any).signature = await this.signMessage(envelope);

    if (!this.shouldPadEnvelope(canonical.type)) {
      return JSON.stringify(envelope);
    }

    return this.padEnvelopeToFixedSize(envelope);
  }

  private shouldPadEnvelope(type: string): boolean {
    const unpaddedControlTypes = new Set<string>([
      SignalType.PQ_HEARTBEAT_PING,
      SignalType.PQ_HEARTBEAT_PONG,
      SignalType.SERVER_ENTRY_REQUEST,
      SignalType.SERVER_ENTRY_CHALLENGE,
      SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
      SignalType.PRIVACY_PASS_REDEMPTION,
      SignalType.PRIVACY_PASS_ISSUANCE,
      SignalType.TOKEN_VALIDATION,
      SignalType.TOKEN_VALIDATION_RESPONSE,
      SignalType.AUTH_OT_REGISTER_REQUEST,
      SignalType.AUTH_OT_REGISTER_RESPONSE,
      SignalType.AUTH_OT_REGISTER_FINALIZE,
      SignalType.AUTH_OT_REQUEST,
      SignalType.AUTH_OT_RESPONSE,
      SignalType.AUTH_OT_FINALIZE,
      SignalType.AUTH_FULL_SUCCESS,
      SignalType.BLIND_SIGNATURE_REQUEST,
      SignalType.BLIND_SIGNATURE_RESPONSE,
      SignalType.ZK_REFRESH_CHALLENGE,
      SignalType.ZK_REFRESH_RESPONSE,
      SignalType.ZK_DEVICE_REGISTER,
      SignalType.ZK_DEVICE_REGISTER_RESPONSE,
      SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
      SignalType.OPRF_BLIND_EVALUATE,
      SignalType.OPRF_BLIND_EVALUATE_RESPONSE,
      SignalType.PUBLISH_DISCOVERY,
      SignalType.DISCOVERY_SNAPSHOT_REQUEST,
      SignalType.DISCOVERY_SNAPSHOT,
      SignalType.PIR_MANIFEST_REQUEST,
      SignalType.PIR_MANIFEST,
      SignalType.PIR_QUERY,
      SignalType.PIR_RESPONSE,
      SignalType.AUTH_ERROR,
      SignalType.ERROR,
      SignalType.OK,
      SignalType.CLAIM_INBOX,
      SignalType.CLAIM_INBOX_RESPONSE,
      SignalType.ROTATE_INBOX,
      SignalType.ROTATE_INBOX_RESPONSE
    ]);

    return !unpaddedControlTypes.has(type);
  }

  private padEnvelopeToFixedSize(envelope: Record<string, unknown>): string {
    const targetBytes = WS_FIXED_MESSAGE_SIZE_BYTES;
    const encoder = new TextEncoder();

    const base = { ...envelope, _pad: '' as string };
    const baseJson = JSON.stringify(base);
    const baseSize = encoder.encode(baseJson).length;

    if (baseSize > targetBytes) {
      SecurityAuditLogger.log('warn', 'ws-envelope-oversize', {
        baseSize,
        targetBytes
      });
      return JSON.stringify(envelope);
    }

    const padNeeded = targetBytes - baseSize;
    if (padNeeded === 0) {
      return baseJson;
    }

    const paddingBytes = PostQuantumRandom.randomBytes(Math.ceil(padNeeded * 0.75));
    const padding = PostQuantumUtils.uint8ArrayToBase64(paddingBytes).slice(0, padNeeded);
    (base as any)._pad = padding;

    const finalJson = JSON.stringify(base);
    const finalSize = encoder.encode(finalJson).length;
    if (finalSize !== targetBytes) {
      throw new Error(`Fixed size padding mismatch: ${finalSize} !== ${targetBytes}`);
    }

    return finalJson;
  }

  // Decrypt incoming envelope
  async decryptEnvelope(envelope: any): Promise<any | null> {
    const session = this.context.sessionKeyMaterial;
    if (!session?.recvKey) {
      SecurityAuditLogger.log('warn', 'ws-decrypt-no-session', {});
      return null;
    }

    if (!isPlainObject(envelope) || hasPrototypePollutionKeys(envelope)) {
      console.warn('[Encryption] decryptEnvelope: rejected - not plain object or prototype pollution');
      return null;
    }

    if (typeof envelope.sessionFingerprint !== 'string' || envelope.sessionFingerprint.length > 512) {
      console.warn('[Encryption] decryptEnvelope: rejected - bad sessionFingerprint');
      return null;
    }
    if (typeof envelope.sessionId !== 'string' || envelope.sessionId.length === 0 || envelope.sessionId.length > 128) {
      console.warn('[Encryption] decryptEnvelope: rejected - bad sessionId');
      return null;
    }
    if (typeof envelope.messageId !== 'string' || envelope.messageId.length === 0 || envelope.messageId.length > 512) {
      console.warn('[Encryption] decryptEnvelope: rejected - bad messageId');
      return null;
    }
    if (typeof envelope.timestamp !== 'number' || !Number.isFinite(envelope.timestamp)) {
      console.warn('[Encryption] decryptEnvelope: rejected - bad timestamp');
      return null;
    }
    if (typeof envelope.nonce !== 'string' || typeof envelope.ciphertext !== 'string' || typeof envelope.tag !== 'string') {
      console.warn('[Encryption] decryptEnvelope: rejected - missing nonce/ciphertext/tag');
      return null;
    }
    if (envelope.aad != null && typeof envelope.aad !== 'string') {
      return null;
    }

    const ciphertextBytes = estimateBase64DecodedBytes(envelope.ciphertext);
    if (ciphertextBytes <= 0 || ciphertextBytes > MAX_PQ_ENVELOPE_CIPHERTEXT_BYTES) {
      console.warn('[Encryption] decryptEnvelope: rejected - ciphertext size out of bounds', ciphertextBytes);
      return null;
    }
    const nonceBytes = estimateBase64DecodedBytes(envelope.nonce);
    if (nonceBytes <= 0 || nonceBytes > MAX_PQ_ENVELOPE_NONCE_BYTES) {
      return null;
    }
    const tagBytes = estimateBase64DecodedBytes(envelope.tag);
    if (tagBytes <= 0 || tagBytes > MAX_PQ_ENVELOPE_TAG_BYTES) {
      return null;
    }
    if (typeof envelope.aad === 'string') {
      const aadBytesEstimate = estimateBase64DecodedBytes(envelope.aad);
      if (aadBytesEstimate < 0 || aadBytesEstimate > MAX_PQ_ENVELOPE_AAD_BYTES) {
        return null;
      }
    }

    const currentFingerprint = session.fingerprint;
    const receivedFingerprint = envelope.sessionFingerprint;

    // Check for previous session grace period
    const now = this.getTrustedNow();
    const isWithinGracePeriod = this.context.previousSessionFingerprint &&
      this.context.sessionTransitionTime &&
      (now - this.context.sessionTransitionTime) < SESSION_FAILOVER_GRACE_PERIOD_MS;

    const previousSession = this.context.previousSessionKeyMaterial;
    const isCurrentSession = envelope.sessionId === session.sessionId;
    const isPreviousSession = !!previousSession &&
      envelope.sessionId === previousSession.sessionId &&
      this.context.sessionTransitionTime &&
      (now - this.context.sessionTransitionTime) < SESSION_FAILOVER_GRACE_PERIOD_MS;

    if (receivedFingerprint !== currentFingerprint) {
      if (!(isPreviousSession && receivedFingerprint === this.context.previousSessionFingerprint)) {
        this.metrics.securityEvents.fingerprintMismatches += 1;
        SecurityAuditLogger.log('warn', 'ws-decrypt-fingerprint-mismatch', {
          expectedPresent: !!currentFingerprint,
          receivedPresent: !!receivedFingerprint,
          hadPreviousSession: !!this.context.previousSessionFingerprint,
          gracePeriodExpired: !isWithinGracePeriod
        });

        return null;
      }
    }

    if (!isCurrentSession && !isPreviousSession) {
      console.warn('[Encryption] decryptEnvelope: rejected - unknown session');
      return null;
    }

    const messageId = typeof envelope.messageId === 'string' ? envelope.messageId : '';
    if (!messageId) {
      SecurityAuditLogger.log('warn', 'ws-decrypt-missing-message-id', {});
      return null;
    }

    if (!this.validateTimestamp(envelope.timestamp)) {
      return null;
    }

    const signatureValid = await this.verifyMessageSignature(envelope);
    if (!signatureValid) {
      console.warn('[Encryption] decryptEnvelope: rejected - signature verification failed');
      return null;
    }

    if (isCurrentSession && typeof envelope.counter === 'number' && !this.validateNonceSequence(envelope.counter)) {
      console.warn('[Encryption] decryptEnvelope: rejected - nonce sequence invalid');
      return null;
    }

    if (this.hasSeenMessage(messageId, envelope.timestamp)) {
      this.metrics.securityEvents.replayAttempts += 1;
      SecurityAuditLogger.log('warn', 'ws-decrypt-replay', { hasMessageId: !!messageId });
      return null;
    }

    try {
      const nonce = PostQuantumUtils.base64ToUint8Array(envelope.nonce);
      const ciphertext = PostQuantumUtils.base64ToUint8Array(envelope.ciphertext);
      const tag = PostQuantumUtils.base64ToUint8Array(envelope.tag);
      const aadBytes = typeof envelope.aad === 'string' ? PostQuantumUtils.base64ToUint8Array(envelope.aad) : new Uint8Array();

      const keyMaterial = isPreviousSession && previousSession ? previousSession : session;
      const decrypted = await PostQuantumAEAD.decryptAsync(
        ciphertext,
        nonce,
        tag,
        keyMaterial.recvKey,
        aadBytes
      );

      const decodedText = new TextDecoder().decode(decrypted);

      const canonical = JSON.parse(decodedText);
      const innerType = typeof canonical?.type === 'string' ? canonical.type : 'unknown';
      const expectedAad = this.buildEnvelopeAAD(innerType, envelope.messageId, envelope.timestamp, envelope.counter);
      if (!PostQuantumUtils.timingSafeEqual(aadBytes, expectedAad)) {
        SecurityAuditLogger.log(SignalType.ERROR, 'ws-decrypt-aad-mismatch', {
          messageId: envelope.messageId,
          expectedType: innerType
        });
        return null;
      }

      try {
        if (innerType === SignalType.ENCRYPTED_MESSAGE) {
          const env: any = (canonical as any)?.encryptedPayload || {};
          const hasChunk = typeof env?.chunkData === 'string' && env.chunkData.length > 0;
          void hasChunk;
        }
      } catch { }

      this.trackMessageFingerprint(messageId, envelope.timestamp ?? this.getTrustedNow());

      this.metrics.messagesReceived += 1;
      this.metrics.bytesReceived += ciphertext.length;

      if (canonical?.data && typeof canonical.data === 'object' && canonical.type) {
        return canonical.data;
      }

      return canonical;
    } catch (_error) {
      console.error('[Encryption] Decrypt execution failed:', _error);
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-decrypt-failed', {
        error: _error instanceof Error ? _error.message : String(_error)
      });
      return null;
    }
  }

  // Check if message has been seen before
  private hasSeenMessage(messageId: string, timestamp: number): boolean {
    const seenAt = this.seenMessageFingerprints.get(messageId);
    if (seenAt === undefined) {
      return false;
    }
    if (Math.abs(seenAt - timestamp) <= MAX_REPLAY_WINDOW_MS) {
      return true;
    }
    return false;
  }

  // Track message fingerprint for replay protection
  private trackMessageFingerprint(messageId: string, timestamp: number): void {
    this.seenMessageFingerprints.set(messageId, timestamp);
    this.pruneReplayCache();
  }

  // Prune replay cache
  pruneReplayCache(): void {
    if (this.seenMessageFingerprints.size === 0) {
      return;
    }

    const now = this.getTrustedNow();
    for (const [messageId, seenAt] of Array.from(this.seenMessageFingerprints.entries())) {
      if (now - seenAt > MAX_REPLAY_WINDOW_MS) {
        this.seenMessageFingerprints.delete(messageId);
      }
    }

    if (this.seenMessageFingerprints.size > REPLAY_CACHE_LIMIT) {
      const entries = Array.from(this.seenMessageFingerprints.entries()).sort((a, b) => a[1] - b[1]);
      while (this.seenMessageFingerprints.size > Math.floor(REPLAY_CACHE_LIMIT * 0.9) && entries.length > 0) {
        const [id] = entries.shift()!;
        this.seenMessageFingerprints.delete(id);
      }
    }
  }
}
