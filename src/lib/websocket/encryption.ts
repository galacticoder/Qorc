/**
 * WebSocket Encryption/Decryption
 */

import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SignalType } from '../types/signal-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import type { EncryptionContext } from '../types/websocket-types';
import { canonicalBase64Shape } from '../transport/envelope-shape';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import {
  MAX_MESSAGE_AAD_LENGTH,
  MAX_REPLAY_WINDOW_MS,
  MAX_PQ_ENVELOPE_CIPHERTEXT_BYTES,
  MAX_PQ_ENVELOPE_AAD_BYTES,
  PQ_AEAD_MAC_SIZE,
  PQ_AEAD_NONCE_SIZE,
  WS_FIXED_MESSAGE_SIZE_BYTES,
} from '../constants';

const UNPADDED_CONTROL_TYPES = new Set<string>([
  SignalType.PQ_HEARTBEAT_PING,
  SignalType.PQ_HEARTBEAT_PONG,
  SignalType.SECURE_CHUNK,
]);

const validServerEnvelopeShape = (envelope: unknown): envelope is Record<string, any> => {
  if (!isPlainObject(envelope) || hasPrototypePollutionKeys(envelope)) return false;
  const requiredKeys = [
    'aad', 'ciphertext', 'counter', 'messageId', 'nonce', 'sessionFingerprint',
    'sessionId', 'tag', 'timestamp', 'type', 'version'
  ];
  const actualShape = Object.keys(envelope).sort().join(',');
  if (
    actualShape !== requiredKeys.join(',') &&
    actualShape !== [...requiredKeys, '_pad'].sort().join(',')
  ) return false;
  if (
    envelope.type !== SignalType.PQ_ENVELOPE ||
    envelope.version !== PROTOCOL_KEYS.WS_PQ_PROTOCOL_VERSION ||
    typeof envelope.sessionId !== 'string' ||
    !/^[a-f0-9]{32}$/.test(envelope.sessionId) ||
    typeof envelope.sessionFingerprint !== 'string' ||
    !/^[a-f0-9]{64}$/.test(envelope.sessionFingerprint) ||
    typeof envelope.messageId !== 'string' ||
    !/^[A-Za-z0-9_-]{22}$/.test(envelope.messageId) ||
    typeof envelope.counter !== 'number' ||
    !Number.isSafeInteger(envelope.counter) ||
    envelope.counter <= 0 ||
    typeof envelope.timestamp !== 'number' ||
    !Number.isSafeInteger(envelope.timestamp)
  ) return false;
  if (
    Object.prototype.hasOwnProperty.call(envelope, '_pad') &&
    (typeof envelope._pad !== 'string' ||
      envelope._pad.length > WS_FIXED_MESSAGE_SIZE_BYTES ||
      !/^[A-Za-z0-9+/_-]*$/.test(envelope._pad))
  ) return false;

  return canonicalBase64Shape(envelope.ciphertext, {
    minBytes: 32,
    maxBytes: MAX_PQ_ENVELOPE_CIPHERTEXT_BYTES
  }) &&
    canonicalBase64Shape(envelope.nonce, { exactBytes: PQ_AEAD_NONCE_SIZE }) &&
    canonicalBase64Shape(envelope.tag, { exactBytes: PQ_AEAD_MAC_SIZE }) &&
    canonicalBase64Shape(envelope.aad, { maxBytes: MAX_PQ_ENVELOPE_AAD_BYTES });
};

const safeJsonPayloadShape = (root: unknown): boolean => {
  const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    nodes += 1;
    if (nodes > 20_000 || current.depth > 32) return false;
    if (!current.value || typeof current.value !== 'object') continue;
    if (!Array.isArray(current.value) && !isPlainObject(current.value)) return false;
    if (hasPrototypePollutionKeys(current.value)) return false;
    for (const [key, value] of Object.entries(current.value)) {
      if (key.length > 256) return false;
      stack.push({ value, depth: current.depth + 1 });
    }
  }
  return true;
};

// WebSocket Encryption/Decryption
export class WebSocketEncryption {
  private sessionNonceCounter = 0;
  private expectedRemoteNonceCounter = 0;

  constructor(
    private context: EncryptionContext,
    private getTrustedNow: () => number = () => Date.now()
  ) { }

  // Increment session nonce counter
  private incrementSessionNonceCounter(): number {
    return ++this.sessionNonceCounter;
  }

  // Reset nonce counters
  resetCounters(): void {
    this.sessionNonceCounter = 0;
    this.expectedRemoteNonceCounter = 0;
  }

  private isNonceSequenceFresh(counter: number): boolean {
    if (!Number.isSafeInteger(counter) || counter <= this.expectedRemoteNonceCounter) {
      return false;
    }

    return true;
  }

  private commitNonceSequence(counter: number): void {
    this.expectedRemoteNonceCounter = counter;
  }

  // Validate timestamp with skew tolerance
  validateTimestamp(timestamp: number): boolean {
    const now = this.getTrustedNow();
    const skew = Math.abs(now - timestamp);

    if (skew > MAX_REPLAY_WINDOW_MS) {
      return false;
    }

    return true;
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
  private buildEnvelopeAAD(messageId: string, timestamp: number, counter: number): Uint8Array {
    const encoder = new TextEncoder();
    const parts = `${PROTOCOL_KEYS.WS_PQ_AAD}|${messageId}|${timestamp}|${counter}`;
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
    const messageIdBytes = PostQuantumRandom.randomBytes(16);
    const messageId = PostQuantumUtils.bytesToHex(messageIdBytes);
    messageIdBytes.fill(0);
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

    let payloadBytes: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let aadBytes: Uint8Array | null = null;
    let ciphertext: Uint8Array | null = null;
    let tag: Uint8Array | null = null;
    try {
      payloadBytes = new TextEncoder().encode(JSON.stringify(payloadToEncrypt));
      nonce = PostQuantumRandom.randomBytes(PQ_AEAD_NONCE_SIZE);
      aadBytes = this.buildEnvelopeAAD(messageId, timestamp, counter);

      const encrypted = await PostQuantumAEAD.encryptAsync(
        payloadBytes,
        session.sendKey,
        aadBytes,
        nonce
      );
      ciphertext = encrypted.ciphertext;
      tag = encrypted.tag;

      const envelope = {
        type: SignalType.PQ_ENVELOPE,
        version: PROTOCOL_KEYS.WS_PQ_PROTOCOL_VERSION,
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

      if (this.shouldPadEnvelope(canonical.type)) {
        this.applyEnvelopeFixedPadding(envelope);
      }

      return JSON.stringify(envelope);
    } finally {
      payloadBytes?.fill(0);
      nonce?.fill(0);
      aadBytes?.fill(0);
      ciphertext?.fill(0);
      tag?.fill(0);
    }
  }

  private shouldPadEnvelope(type: string): boolean {
    return !UNPADDED_CONTROL_TYPES.has(type);
  }

  private applyEnvelopeFixedPadding(envelope: Record<string, unknown>): boolean {
    const targetBytes = WS_FIXED_MESSAGE_SIZE_BYTES;
    const encoder = new TextEncoder();
    if (!targetBytes || targetBytes <= 0) return false;

    const base = { ...envelope, _pad: '' as string };
    const baseJson = JSON.stringify(base);
    const baseSize = encoder.encode(baseJson).length;

    if (baseSize > targetBytes) {
      return false;
    }

    const padNeeded = targetBytes - baseSize;
    if (padNeeded === 0) {
      (envelope as any)._pad = '';
      return true;
    }

    const paddingBytes = PostQuantumRandom.randomBytes(Math.ceil(padNeeded * 0.75));
    const padding = PostQuantumUtils.uint8ArrayToBase64(paddingBytes).slice(0, padNeeded);
    paddingBytes.fill(0);
    (envelope as any)._pad = padding;

    const finalJson = JSON.stringify(envelope);
    const finalSize = encoder.encode(finalJson).length;
    if (finalSize !== targetBytes) {
      delete (envelope as any)._pad;
      throw new Error(`Fixed size padding mismatch: ${finalSize} !== ${targetBytes}`);
    }

    return true;
  }

  // Decrypt incoming envelope
  async decryptEnvelope(envelope: any): Promise<any | null> {
    const session = this.context.sessionKeyMaterial;
    if (!session?.recvKey) {
      return null;
    }

    if (!validServerEnvelopeShape(envelope)) {
      return null;
    }

    if (envelope.sessionFingerprint !== session.fingerprint) {
      return null;
    }

    if (envelope.sessionId !== session.sessionId) {
      console.warn('[Encryption] decryptEnvelope: rejected, unknown session');
      return null;
    }

    const messageId = typeof envelope.messageId === 'string' ? envelope.messageId : '';
    if (!messageId) {
      return null;
    }

    if (!this.validateTimestamp(envelope.timestamp)) {
      return null;
    }

    if (typeof envelope.counter !== 'number' || !this.isNonceSequenceFresh(envelope.counter)) {
      console.warn('[Encryption] decryptEnvelope: rejected - nonce sequence invalid');
      return null;
    }

    let nonce: Uint8Array | null = null;
    let ciphertext: Uint8Array | null = null;
    let tag: Uint8Array | null = null;
    let aadBytes: Uint8Array | null = null;
    let decrypted: Uint8Array | null = null;
    let expectedAad: Uint8Array | null = null;
    try {
      nonce = PostQuantumUtils.base64ToUint8Array(envelope.nonce);
      ciphertext = PostQuantumUtils.base64ToUint8Array(envelope.ciphertext);
      tag = PostQuantumUtils.base64ToUint8Array(envelope.tag);
      aadBytes = PostQuantumUtils.base64ToUint8Array(envelope.aad);

      decrypted = await PostQuantumAEAD.decryptAsync(
        ciphertext,
        nonce,
        tag,
        session.recvKey,
        aadBytes
      );

      const decodedText = new TextDecoder('utf-8', { fatal: true }).decode(decrypted);

      const canonical = JSON.parse(decodedText);
      if (
        !isPlainObject(canonical) ||
        !safeJsonPayloadShape(canonical) ||
        typeof canonical.type !== 'string' ||
        canonical.type.length === 0 ||
        canonical.type.length > 100
      ) return null;
      expectedAad = this.buildEnvelopeAAD(envelope.messageId, envelope.timestamp, envelope.counter);
      if (!PostQuantumUtils.timingSafeEqual(aadBytes, expectedAad)) {
        return null;
      }
      if (!this.hasValidPadding(envelope, canonical.type)) {
        return null;
      }

      this.commitNonceSequence(envelope.counter);

      return canonical;
    } catch {
      console.error('[Encryption] Encrypted envelope decryption failed');
      return null;
    } finally {
      nonce?.fill(0);
      ciphertext?.fill(0);
      tag?.fill(0);
      aadBytes?.fill(0);
      decrypted?.fill(0);
      expectedAad?.fill(0);
    }
  }

  private hasValidPadding(envelope: Record<string, unknown>, type: string): boolean {
    const hasPadding = Object.prototype.hasOwnProperty.call(envelope, '_pad');
    const shouldPad = this.shouldPadEnvelope(type);
    if (hasPadding) {
      return shouldPad && new TextEncoder().encode(JSON.stringify(envelope)).length === WS_FIXED_MESSAGE_SIZE_BYTES;
    }
    if (!shouldPad) return true;
    const paddedBase = { ...envelope, _pad: '' };
    return new TextEncoder().encode(JSON.stringify(paddedBase)).length > WS_FIXED_MESSAGE_SIZE_BYTES;
  }
}
