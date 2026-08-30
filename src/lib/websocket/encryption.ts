/**
 * Fixed-cell WebSocket encryption.
 *
 * Every post-handshake WebSocket frame is one authenticated 64 KiB binary
 * cell. Large logical messages are split before encryption and reassembled
 * only after every cell authenticates.
 */

import { PostQuantumAEAD } from '../cryptography/aead';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import type { EncryptionContext } from '../types/websocket-types';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import {
  MAX_REPLAY_WINDOW_MS,
  PQ_AEAD_CIPHERTEXT_OVERHEAD,
  PQ_AEAD_MAC_SIZE,
  PQ_AEAD_NONCE_SIZE,
  WS_FIXED_MESSAGE_SIZE_BYTES,
} from '../constants';

const CELL_MAGIC = new Uint8Array([0x51, 0x4f, 0x52, 0x43]);
const CELL_VERSION = 1;
const CELL_FLAGS = 0;
const CELL_SESSION_OFFSET = 8;
const CELL_FINGERPRINT_OFFSET = 24;
const CELL_MESSAGE_ID_OFFSET = 56;
const CELL_COUNTER_OFFSET = 72;
const CELL_TIMESTAMP_OFFSET = 80;
const CELL_CHUNK_INDEX_OFFSET = 88;
const CELL_CHUNK_COUNT_OFFSET = 92;
const CELL_TOTAL_LENGTH_OFFSET = 96;
const CELL_PLAINTEXT_LENGTH_OFFSET = 100;
const CELL_NONCE_OFFSET = 104;
const CELL_TAG_OFFSET = CELL_NONCE_OFFSET + PQ_AEAD_NONCE_SIZE;
const CELL_CIPHERTEXT_OFFSET = CELL_TAG_OFFSET + PQ_AEAD_MAC_SIZE;
const CELL_HEADER_BYTES = CELL_CIPHERTEXT_OFFSET;
const CELL_PLAINTEXT_BYTES = WS_FIXED_MESSAGE_SIZE_BYTES
  - CELL_HEADER_BYTES
  - PQ_AEAD_CIPHERTEXT_OVERHEAD;
const CELL_MAX_LOGICAL_BYTES = 24 * 1024 * 1024;
const CELL_MAX_CHUNKS = Math.ceil(CELL_MAX_LOGICAL_BYTES / CELL_PLAINTEXT_BYTES);
const CELL_MAX_CONCURRENT = 4;
const CELL_MAX_BUFFERED_BYTES = 32 * 1024 * 1024;
const CELL_REASSEMBLY_TIMEOUT_MS = 200_000;
const CELL_DOMAIN = new TextEncoder().encode(PROTOCOL_KEYS.WS_PQ_CELL_AAD);

export type CellDecryptResult =
  | { status: 'pending' }
  | { status: 'complete'; payload: Record<string, any> }
  | { status: 'invalid' };

interface CellReassembly {
  totalLength: number;
  chunkCount: number;
  parts: Array<Uint8Array | undefined>;
  received: number;
  receivedBytes: number;
  createdAt: number;
  timer: ReturnType<typeof setTimeout>;
}

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

function writeSafeU64(view: DataView, offset: number, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid fixed-cell integer');
  view.setUint32(offset, Math.floor(value / 0x1_0000_0000), false);
  view.setUint32(offset + 4, value >>> 0, false);
}

function readSafeU64(view: DataView, offset: number): number | null {
  const high = view.getUint32(offset, false);
  const low = view.getUint32(offset + 4, false);
  const value = high * 0x1_0000_0000 + low;
  return Number.isSafeInteger(value) ? value : null;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && PostQuantumUtils.timingSafeEqual(left, right);
}

function concatenate(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export class WebSocketEncryption {
  private sessionNonceCounter = 0;
  private expectedRemoteNonceCounter = 0;
  private cellReassemblies = new Map<string, CellReassembly>();
  private cellBufferedBytes = 0;

  constructor(
    private context: EncryptionContext,
    private getTrustedNow: () => number = () => Date.now()
  ) { }

  private incrementSessionNonceCounter(): number {
    if (this.sessionNonceCounter >= Number.MAX_SAFE_INTEGER) {
      throw new Error('Post-quantum session counter exhausted');
    }
    return ++this.sessionNonceCounter;
  }

  resetCounters(): void {
    this.sessionNonceCounter = 0;
    this.expectedRemoteNonceCounter = 0;
    this.clearCellReassemblies();
  }

  private isNonceSequenceFresh(counter: number): boolean {
    return Number.isSafeInteger(counter) && counter > this.expectedRemoteNonceCounter;
  }

  private commitNonceSequence(counter: number): void {
    this.expectedRemoteNonceCounter = counter;
  }

  validateTimestamp(timestamp: number): boolean {
    return Math.abs(this.getTrustedNow() - timestamp) <= MAX_REPLAY_WINDOW_MS;
  }

  private normalizePayload(data: unknown): { type: string; body: any } {
    if (data && typeof data === 'object') {
      const body = this.sanitize(data);
      const type = typeof body.type === 'string' ? String(body.type) : 'generic';
      if (typeof body.type !== 'string') body.type = type;
      return { type, body };
    }
    if (typeof data === 'string') {
      try {
        const parsed = JSON.parse(data);
        if (parsed && typeof parsed === 'object') {
          const body = this.sanitize(parsed);
          const type = typeof body.type === 'string' ? String(body.type) : 'raw-string';
          if (typeof body.type !== 'string') body.type = type;
          return { type, body };
        }
      } catch { }
      return { type: 'raw-string', body: { type: 'raw-string', data } };
    }
    return { type: 'raw-scalar', body: { type: 'raw-scalar', data: String(data) } };
  }

  private sanitize(input: any): any {
    try {
      return JSON.parse(JSON.stringify(input));
    } catch {
      return { type: 'raw-string', data: String(input) };
    }
  }

  async prepareSecureEnvelope(data: unknown): Promise<Uint8Array[]> {
    const session = this.context.sessionKeyMaterial;
    if (!session) throw new Error('Post-quantum session not established');

    const canonical = this.normalizePayload(data);
    if (typeof canonical.body.type !== 'string') canonical.body.type = canonical.type;
    const payloadBytes = new TextEncoder().encode(JSON.stringify(canonical.body));
    if (payloadBytes.length < 1 || payloadBytes.length > CELL_MAX_LOGICAL_BYTES) {
      payloadBytes.fill(0);
      throw new Error('Secure WebSocket payload exceeds fixed-cell limit');
    }

    const sessionId = PostQuantumUtils.hexToBytes(session.sessionId);
    const fingerprint = PostQuantumUtils.hexToBytes(session.fingerprint);
    const messageId = PostQuantumRandom.randomBytes(16);
    if (sessionId.length !== 16 || fingerprint.length !== 32) {
      payloadBytes.fill(0);
      sessionId.fill(0);
      fingerprint.fill(0);
      messageId.fill(0);
      throw new Error('Invalid post-quantum session identity');
    }

    const chunkCount = Math.ceil(payloadBytes.length / CELL_PLAINTEXT_BYTES);
    const timestamp = this.getTrustedNow();
    const cells: Uint8Array[] = [];
    try {
      for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
        const start = chunkIndex * CELL_PLAINTEXT_BYTES;
        const end = Math.min(payloadBytes.length, start + CELL_PLAINTEXT_BYTES);
        const plaintext = payloadBytes.subarray(start, end);
        const counter = this.incrementSessionNonceCounter();
        const nonce = PostQuantumRandom.randomBytes(PQ_AEAD_NONCE_SIZE);
        const cell = PostQuantumRandom.randomBytes(WS_FIXED_MESSAGE_SIZE_BYTES);
        const view = new DataView(cell.buffer, cell.byteOffset, cell.byteLength);
        let aad: Uint8Array | null = null;
        let ciphertext: Uint8Array | null = null;
        let tag: Uint8Array | null = null;
        try {
          cell.set(CELL_MAGIC, 0);
          view.setUint8(4, CELL_VERSION);
          view.setUint8(5, CELL_FLAGS);
          view.setUint16(6, CELL_HEADER_BYTES, false);
          cell.set(sessionId, CELL_SESSION_OFFSET);
          cell.set(fingerprint, CELL_FINGERPRINT_OFFSET);
          cell.set(messageId, CELL_MESSAGE_ID_OFFSET);
          writeSafeU64(view, CELL_COUNTER_OFFSET, counter);
          writeSafeU64(view, CELL_TIMESTAMP_OFFSET, timestamp);
          view.setUint32(CELL_CHUNK_INDEX_OFFSET, chunkIndex, false);
          view.setUint32(CELL_CHUNK_COUNT_OFFSET, chunkCount, false);
          view.setUint32(CELL_TOTAL_LENGTH_OFFSET, payloadBytes.length, false);
          view.setUint32(CELL_PLAINTEXT_LENGTH_OFFSET, plaintext.length, false);
          cell.set(nonce, CELL_NONCE_OFFSET);

          const ciphertextEnd = CELL_CIPHERTEXT_OFFSET
            + plaintext.length
            + PQ_AEAD_CIPHERTEXT_OVERHEAD;
          aad = concatenate(
            CELL_DOMAIN,
            cell.subarray(0, CELL_TAG_OFFSET),
            cell.subarray(ciphertextEnd)
          );
          const encrypted = await PostQuantumAEAD.encryptAsync(
            plaintext,
            session.sendKey,
            aad,
            nonce
          );
          ciphertext = encrypted.ciphertext;
          tag = encrypted.tag;
          if (
            ciphertext.length !== plaintext.length + PQ_AEAD_CIPHERTEXT_OVERHEAD ||
            tag.length !== PQ_AEAD_MAC_SIZE ||
            CELL_CIPHERTEXT_OFFSET + ciphertext.length > cell.length
          ) throw new Error('Fixed-cell encryption length mismatch');
          cell.set(tag, CELL_TAG_OFFSET);
          cell.set(ciphertext, CELL_CIPHERTEXT_OFFSET);
          cells.push(cell);
        } catch (error) {
          cell.fill(0);
          throw error;
        } finally {
          nonce.fill(0);
          aad?.fill(0);
          ciphertext?.fill(0);
          tag?.fill(0);
        }
      }
      return cells;
    } catch (error) {
      for (const cell of cells) cell.fill(0);
      throw error;
    } finally {
      payloadBytes.fill(0);
      sessionId.fill(0);
      fingerprint.fill(0);
      messageId.fill(0);
    }
  }

  async decryptCell(cell: Uint8Array): Promise<CellDecryptResult> {
    const session = this.context.sessionKeyMaterial;
    if (!session?.recvKey || !(cell instanceof Uint8Array) || cell.length !== WS_FIXED_MESSAGE_SIZE_BYTES) {
      return { status: 'invalid' };
    }

    const view = new DataView(cell.buffer, cell.byteOffset, cell.byteLength);
    if (
      !bytesEqual(cell.subarray(0, CELL_MAGIC.length), CELL_MAGIC) ||
      view.getUint8(4) !== CELL_VERSION ||
      view.getUint8(5) !== CELL_FLAGS ||
      view.getUint16(6, false) !== CELL_HEADER_BYTES
    ) return { status: 'invalid' };

    const sessionId = PostQuantumUtils.hexToBytes(session.sessionId);
    const fingerprint = PostQuantumUtils.hexToBytes(session.fingerprint);
    try {
      if (
        sessionId.length !== 16 ||
        fingerprint.length !== 32 ||
        !bytesEqual(cell.subarray(CELL_SESSION_OFFSET, CELL_FINGERPRINT_OFFSET), sessionId) ||
        !bytesEqual(cell.subarray(CELL_FINGERPRINT_OFFSET, CELL_MESSAGE_ID_OFFSET), fingerprint)
      ) return { status: 'invalid' };
    } finally {
      sessionId.fill(0);
      fingerprint.fill(0);
    }

    const counter = readSafeU64(view, CELL_COUNTER_OFFSET);
    const timestamp = readSafeU64(view, CELL_TIMESTAMP_OFFSET);
    const chunkIndex = view.getUint32(CELL_CHUNK_INDEX_OFFSET, false);
    const chunkCount = view.getUint32(CELL_CHUNK_COUNT_OFFSET, false);
    const totalLength = view.getUint32(CELL_TOTAL_LENGTH_OFFSET, false);
    const plaintextLength = view.getUint32(CELL_PLAINTEXT_LENGTH_OFFSET, false);
    if (
      counter === null || timestamp === null ||
      !this.isNonceSequenceFresh(counter) || !this.validateTimestamp(timestamp) ||
      totalLength < 1 || totalLength > CELL_MAX_LOGICAL_BYTES ||
      chunkCount < 1 || chunkCount > CELL_MAX_CHUNKS ||
      chunkCount !== Math.ceil(totalLength / CELL_PLAINTEXT_BYTES) ||
      chunkIndex >= chunkCount
    ) return { status: 'invalid' };

    const expectedPlaintextLength = chunkIndex + 1 === chunkCount
      ? totalLength - chunkIndex * CELL_PLAINTEXT_BYTES
      : CELL_PLAINTEXT_BYTES;
    if (plaintextLength !== expectedPlaintextLength) return { status: 'invalid' };
    const ciphertextLength = plaintextLength + PQ_AEAD_CIPHERTEXT_OVERHEAD;
    if (CELL_CIPHERTEXT_OFFSET + ciphertextLength > cell.length) return { status: 'invalid' };

    const nonce = cell.slice(CELL_NONCE_OFFSET, CELL_TAG_OFFSET);
    const tag = cell.slice(CELL_TAG_OFFSET, CELL_CIPHERTEXT_OFFSET);
    const ciphertext = cell.slice(
      CELL_CIPHERTEXT_OFFSET,
      CELL_CIPHERTEXT_OFFSET + ciphertextLength
    );
    const aad = concatenate(
      CELL_DOMAIN,
      cell.subarray(0, CELL_TAG_OFFSET),
      cell.subarray(CELL_CIPHERTEXT_OFFSET + ciphertextLength)
    );
    let plaintext: Uint8Array | null = null;
    try {
      plaintext = await PostQuantumAEAD.decryptAsync(
        ciphertext,
        nonce,
        tag,
        session.recvKey,
        aad
      );
      if (plaintext.length !== plaintextLength) return { status: 'invalid' };
      this.commitNonceSequence(counter);
      return this.ingestCellPlaintext(
        cell.subarray(CELL_MESSAGE_ID_OFFSET, CELL_COUNTER_OFFSET),
        chunkIndex,
        chunkCount,
        totalLength,
        plaintext
      );
    } catch {
      return { status: 'invalid' };
    } finally {
      nonce.fill(0);
      tag.fill(0);
      ciphertext.fill(0);
      aad.fill(0);
      plaintext?.fill(0);
    }
  }

  private ingestCellPlaintext(
    messageIdBytes: Uint8Array,
    chunkIndex: number,
    chunkCount: number,
    totalLength: number,
    plaintext: Uint8Array
  ): CellDecryptResult {
    if (chunkCount === 1) return this.decodeLogicalPayload(plaintext);

    const messageId = PostQuantumUtils.bytesToHex(messageIdBytes);
    let assembly = this.cellReassemblies.get(messageId);
    if (!assembly) {
      while (
        this.cellReassemblies.size >= CELL_MAX_CONCURRENT ||
        this.cellBufferedBytes + totalLength > CELL_MAX_BUFFERED_BYTES
      ) {
        const oldest = Array.from(this.cellReassemblies.entries())
          .sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
        if (!oldest) return { status: 'invalid' };
        this.discardCellReassembly(oldest[0]);
      }
      const timer = setTimeout(
        () => this.discardCellReassembly(messageId),
        CELL_REASSEMBLY_TIMEOUT_MS
      );
      assembly = {
        totalLength,
        chunkCount,
        parts: new Array(chunkCount),
        received: 0,
        receivedBytes: 0,
        createdAt: Date.now(),
        timer,
      };
      this.cellReassemblies.set(messageId, assembly);
      this.cellBufferedBytes += totalLength;
    } else if (assembly.totalLength !== totalLength || assembly.chunkCount !== chunkCount) {
      this.discardCellReassembly(messageId);
      return { status: 'invalid' };
    }

    if (assembly.parts[chunkIndex] !== undefined) {
      this.discardCellReassembly(messageId);
      return { status: 'invalid' };
    }
    assembly.parts[chunkIndex] = plaintext.slice();
    assembly.received += 1;
    assembly.receivedBytes += plaintext.length;
    if (assembly.received < assembly.chunkCount) return { status: 'pending' };

    const complete = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of assembly.parts) {
      if (!part || offset + part.length > complete.length) {
        complete.fill(0);
        this.discardCellReassembly(messageId);
        return { status: 'invalid' };
      }
      complete.set(part, offset);
      offset += part.length;
    }
    this.discardCellReassembly(messageId);
    if (offset !== complete.length || assembly.receivedBytes !== complete.length) {
      complete.fill(0);
      return { status: 'invalid' };
    }
    try {
      return this.decodeLogicalPayload(complete);
    } finally {
      complete.fill(0);
    }
  }

  private decodeLogicalPayload(bytes: Uint8Array): CellDecryptResult {
    try {
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      const payload = JSON.parse(decoded);
      if (
        !isPlainObject(payload) ||
        hasPrototypePollutionKeys(payload) ||
        !safeJsonPayloadShape(payload) ||
        typeof payload.type !== 'string' ||
        payload.type.length < 1 ||
        payload.type.length > 100
      ) return { status: 'invalid' };
      return { status: 'complete', payload };
    } catch {
      return { status: 'invalid' };
    }
  }

  private discardCellReassembly(messageId: string): void {
    const assembly = this.cellReassemblies.get(messageId);
    if (!assembly) return;
    clearTimeout(assembly.timer);
    for (const part of assembly.parts) part?.fill(0);
    this.cellReassemblies.delete(messageId);
    this.cellBufferedBytes = Math.max(0, this.cellBufferedBytes - assembly.totalLength);
  }

  private clearCellReassemblies(): void {
    for (const messageId of Array.from(this.cellReassemblies.keys())) {
      this.discardCellReassembly(messageId);
    }
  }
}

export const WS_BINARY_CELL_PLAINTEXT_BYTES = CELL_PLAINTEXT_BYTES;
export const WS_BINARY_CELL_BYTES = WS_FIXED_MESSAGE_SIZE_BYTES;
