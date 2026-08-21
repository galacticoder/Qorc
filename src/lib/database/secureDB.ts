import { SQLiteKV } from './sqlite-kv';
import { blake3 } from '@noble/hashes/blake3.js';
import { hasValidMessageControlState } from '../messages/message-controls';
import type { Message } from '../../components/chat/messaging/types';
import { validateFileData, mergeReceipts } from '../utils/database-utils';
import { isCanonicalAuthUsername as isCanonicalUsername, sanitizeMessageId } from '../sanitizers';
import { normalizeKnownUsers } from './known-users';
import { bytesToHex } from '../utils/byte-utils';
import { EphemeralConfig,
   EphemeralData,
   StoredMessage,
   StoredUser,
   ConversationMetadata
  } from '../types/database-types';
import {
   SECURE_DB_MAX_VALUE_SIZE,
   SECURE_DB_MAX_FILE_SIZE,
   SECURE_DB_MIN_CLEANUP_INTERVAL,
   SECURE_DB_MAX_EPHEMERAL_BATCH,
   HYBRID_ENVELOPE_MAX_AGE_MS,
  MAX_KNOWN_PEERS,
  CONVERSATION_SEGMENT_SIZE,
  MAX_CONVERSATION_STORED_MESSAGES,
 } from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEYS, STORAGE_PREFIXES, STORAGE_STORES } from './storage-keys';

const MAX_CONVERSATION_INPUT_MESSAGES = MAX_CONVERSATION_STORED_MESSAGES + 500;
const MAX_CONVERSATION_BATCH_WRITES = 511;
const MAX_EPHEMERAL_LIST_ITEMS = 500;
const MAX_DATE_TIMESTAMP = 8_640_000_000_000_000;
const MAX_TIMER_DELAY_MS = 2_147_483_647;
const CONVERSATION_METADATA_KEYS = new Set([
  'firstSegment',
  'isPinned',
  'lastMessage',
  'lastReadTimestamp',
  'lastSegment',
  'peerUsername',
  'pinnedAt',
]);

const MAX_SEGMENT_INDEX = 2 ** 40;
const SEGMENT_INDEX_DIGITS = 13;

function isValidTimestamp(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= MAX_DATE_TIMESTAMP
  );
}

interface PreparedConversationWrite {
  peer: string;
  grantsIncomingCallPermission: boolean;
  segments: Array<{ index: number; encrypted: Uint8Array; signature: string }>;
  deletedSegments: number[];
  firstSegment: number;
  lastSegment: number;
  last: StoredMessage;
  evictedFileIds: string[];
}

const MAX_CONVERSATION_MUTATION_DELETIONS = 2_048;

function isFileMessage(message: StoredMessage): boolean {
  return (
    message.type === 'file' ||
    message.type === 'file-message' ||
    typeof message.filename === 'string'
  );
}

export class SecureDB {
  private static readonly encoder = new TextEncoder();
  private static readonly decoder = new TextDecoder('utf-8', { fatal: true });

  private username: string;
  private accountScope: string;
  private nativeReady = false;
  private ephemeralConfig: EphemeralConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private lastCleanup = 0;
  private disposed = false;
  private lifecycleGeneration = 0;
  private cleanupRunning = false;
  private kvViewPromise: Promise<SQLiteKV> | null = null;

  constructor(username: string, accountScope: string, ephemeralConfig?: Partial<EphemeralConfig>) {
    if (!isCanonicalUsername(username)) throw new Error('Invalid username');
    if (!/^[a-f0-9]{64}$/.test(accountScope)) throw new Error('Invalid database account scope');
    this.username = username;
    this.accountScope = accountScope;
    const config: EphemeralConfig = {
      enabled: true,
      defaultTTL: 24 * 60 * 60 * 1000,
      maxTTL: HYBRID_ENVELOPE_MAX_AGE_MS,
      cleanupInterval: 60 * 60 * 1000,
      ...ephemeralConfig
    };
    if (
      typeof config.enabled !== 'boolean' ||
      !Number.isSafeInteger(config.defaultTTL) || config.defaultTTL <= 0 ||
      !Number.isSafeInteger(config.maxTTL) || config.maxTTL < config.defaultTTL ||
      config.maxTTL > MAX_DATE_TIMESTAMP ||
      !Number.isSafeInteger(config.cleanupInterval) ||
      config.cleanupInterval < SECURE_DB_MIN_CLEANUP_INTERVAL ||
      config.cleanupInterval > MAX_TIMER_DELAY_MS
    ) {
      throw new Error('Invalid ephemeral database configuration');
    }
    this.ephemeralConfig = config;
  }

  private assertCurrentLifecycle(generation: number): void {
    if (
      this.disposed ||
      generation !== this.lifecycleGeneration ||
      !this.nativeReady
    ) {
      throw new Error('Secure database lifecycle changed');
    }
  }

  private async kv() {
    const generation = this.lifecycleGeneration;
    this.assertCurrentLifecycle(generation);
    let pending = this.kvViewPromise;
    if (!pending) {
      pending = SQLiteKV.forUser(
        this.accountScope,
        () => this.assertCurrentLifecycle(generation),
      );
      this.kvViewPromise = pending;
    }
    try {
      const view = await pending;
      this.assertCurrentLifecycle(generation);
      return view;
    } catch (error) {
      if (this.kvViewPromise === pending) this.kvViewPromise = null;
      throw error;
    }
  }

  // Initialize database
  async initializeNative(): Promise<void> {
    try {
      if (this.disposed) throw new Error('Secure database has been disposed');
      if (this.nativeReady) return;
      this.nativeReady = true;
      if (this.ephemeralConfig.enabled) this.startEphemeralCleanup();
    } catch (_error) {
      if (this.cleanupInterval) { clearInterval(this.cleanupInterval); this.cleanupInterval = null; }
      throw _error;
    }
  }

  isInitialized(): boolean {
    return !this.disposed && this.nativeReady;
  }

  getAccountScope(): string {
    return this.accountScope;
  }

  dispose(): void {
    if (this.disposed) return;
    this.lifecycleGeneration += 1;
    this.disposed = true;
    if (this.cleanupInterval !== null) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.nativeReady = false;
    this.kvViewPromise = null;
    this.lastCleanup = 0;
    this.convSig.clear();
  }

  private storageAad(
    store: string,
    key: string,
    domain = PROTOCOL_KEYS.SECURE_DB_AEAD,
  ): Uint8Array {
    const storeBytes = SecureDB.encoder.encode(store);
    const keyBytes = SecureDB.encoder.encode(key);
    try {
      if (
        !store || !key ||
        storeBytes.length > 256 || keyBytes.length > 256 ||
        /[\u0000-\u001f\u007f-\u009f]/.test(store) ||
        /[\u0000-\u001f\u007f-\u009f]/.test(key)
      ) {
        throw new Error('Invalid secure database selector');
      }
      return SecureDB.encoder.encode(JSON.stringify([
        domain,
        this.username,
        store,
        key,
      ]));
    } finally {
      storeBytes.fill(0);
      keyBytes.fill(0);
    }
  }

  private async encryptBytes(
    dataBuffer: Uint8Array,
    store: string,
    storageKey: string,
    aadDomain = PROTOCOL_KEYS.SECURE_DB_AEAD,
  ): Promise<Uint8Array> {
    const generation = this.lifecycleGeneration;
    this.assertCurrentLifecycle(generation);
    if (dataBuffer.length === 0 || dataBuffer.length > SECURE_DB_MAX_VALUE_SIZE) {
      throw new Error(`Data too large: ${dataBuffer.length} bytes`);
    }
    this.storageAad(store, storageKey, aadDomain).fill(0);
    const prepared = dataBuffer.slice();
    this.assertCurrentLifecycle(generation);
    return prepared;
  }

  // Encrypt JSON data for one exact storage row
  private async encryptData(data: unknown, store: string, storageKey: string): Promise<Uint8Array> {
    let dataBuffer: Uint8Array | null = null;
    try {
      const serialized = JSON.stringify(data);
      if (serialized === undefined) throw new Error('Data is not JSON serializable');
      dataBuffer = SecureDB.encoder.encode(serialized);
      return await this.encryptBytes(dataBuffer, store, storageKey);
    } finally {
      dataBuffer?.fill(0);
    }
  }

  private async decryptBytes(
    encryptedData: Uint8Array,
    store: string,
    storageKey: string,
    aadDomain = PROTOCOL_KEYS.SECURE_DB_AEAD,
  ): Promise<Uint8Array> {
    const generation = this.lifecycleGeneration;
    this.assertCurrentLifecycle(generation);
    if (encryptedData.length === 0 || encryptedData.length > SECURE_DB_MAX_VALUE_SIZE) {
      throw new Error('Native database value size is invalid');
    }
    this.storageAad(store, storageKey, aadDomain).fill(0);
    const plaintext = encryptedData.slice();
    this.assertCurrentLifecycle(generation);
    return plaintext;
  }

  // Decrypt JSON data only in the row for which it was authenticated
  private async decryptData(
    encryptedData: Uint8Array,
    store: string,
    storageKey: string,
  ): Promise<unknown> {
    const generation = this.lifecycleGeneration;
    let decrypted: Uint8Array | null = null;
    try {
      decrypted = await this.decryptBytes(encryptedData, store, storageKey);
      this.assertCurrentLifecycle(generation);
      const parsed = JSON.parse(SecureDB.decoder.decode(decrypted));
      this.assertCurrentLifecycle(generation);
      return parsed;
    } catch {
      throw new Error('Failed to decrypt data');
    } finally {
      decrypted?.fill(0);
    }
  }

  private messageOpChain: Promise<unknown> = Promise.resolve();
  private ephemeralOpChain: Promise<unknown> = Promise.resolve();

  private withMessageLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.messageOpChain.then(fn, fn);
    this.messageOpChain = run.then(() => undefined, () => undefined);
    return run;
  }

  private withEphemeralLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.ephemeralOpChain.then(fn, fn);
    this.ephemeralOpChain = run.then(() => undefined, () => undefined);
    return run;
  }

  private convSig = new Map<string, string>();

  private static segmentKey(peer: string, index: number): string {
    if (!Number.isSafeInteger(index) || index < 0 || index >= MAX_SEGMENT_INDEX) {
      throw new Error('Invalid conversation segment index');
    }
    return `${peer}:${String(index).padStart(SEGMENT_INDEX_DIGITS, '0')}`;
  }

  private static parseSegmentKey(key: string): { peer: string; index: number } | null {
    const separator = key.indexOf(':');
    if (separator <= 0) return null;
    const peer = key.slice(0, separator);
    const rawIndex = key.slice(separator + 1);
    if (rawIndex.length !== SEGMENT_INDEX_DIGITS || !/^[0-9]+$/.test(rawIndex)) return null;
    if (!isCanonicalUsername(peer)) return null;
    const index = Number(rawIndex);
    if (!Number.isSafeInteger(index) || index < 0 || index >= MAX_SEGMENT_INDEX) return null;
    return { peer, index };
  }

  // The conversation partner for a message from this accounts perspective
  private peerOf(msg: StoredMessage, currentUser: string): string | null {
    const sender = typeof msg?.sender === 'string' ? msg.sender : '';
    const recipient = typeof msg?.recipient === 'string' ? msg.recipient : '';
    if (
      !isCanonicalUsername(sender) ||
      !isCanonicalUsername(recipient) ||
      sender === recipient
    ) return null;
    if (sender === currentUser) return recipient;
    if (recipient === currentUser) return sender;
    return null;
  }

  private normalizeConversationMessage(message: StoredMessage, expectedPeer: string): StoredMessage {
    if (!message || typeof message !== 'object') throw new Error('Invalid stored message');
    const id = typeof message.id === 'string' ? message.id : '';
    if (sanitizeMessageId(id) !== id) {
      throw new Error('Invalid stored message ID');
    }
    if (this.peerOf(message, this.username) !== expectedPeer) {
      throw new Error('Stored message does not belong to its conversation');
    }
    const rawTimestamp = (message as { timestamp?: unknown }).timestamp;
    const timestamp = rawTimestamp instanceof Date ? rawTimestamp.getTime() : rawTimestamp;
    if (!isValidTimestamp(timestamp)) {
      throw new Error('Invalid stored message timestamp');
    }
    if (
      message.wireMessageId !== undefined &&
      sanitizeMessageId(message.wireMessageId) !== message.wireMessageId
    ) {
      throw new Error('Invalid stored wire message ID');
    }
    if (
      message.secureContentId !== undefined &&
      sanitizeMessageId(message.secureContentId) !== message.secureContentId
    ) {
      throw new Error('Invalid stored secure content ID');
    }
    if (message.replyTo !== undefined) {
      if (
        !message.replyTo ||
        typeof message.replyTo !== 'object' ||
        sanitizeMessageId(message.replyTo.id) !== message.replyTo.id ||
        (message.replyTo.secureContentId !== undefined &&
          sanitizeMessageId(message.replyTo.secureContentId) !== message.replyTo.secureContentId)
      ) {
        throw new Error('Invalid stored reply identifiers');
      }
    }
    if (
      message.isDeliberateUserAction !== undefined &&
      (
        message.isDeliberateUserAction !== true ||
        message.sender !== this.username ||
        message.recipient !== expectedPeer ||
        message.isSystemMessage === true ||
        (message.type !== 'text' && !isFileMessage(message))
      )
    ) {
      throw new Error('Invalid deliberate-contact message provenance');
    }
    const isPrivateText = !message.isSystemMessage && !message.isDeleted && !isFileMessage(message);
    if (
      isPrivateText &&
      (message.content !== '' || !message.secureContentId)
    ) {
      throw new Error('Private message content must remain native-only');
    }
    if (message.replyTo?.content !== undefined && message.replyTo.content !== '') {
      throw new Error('Private reply content must remain native-only');
    }
    if (!hasValidMessageControlState(message as unknown as Message)) {
      throw new Error('Invalid stored message control state');
    }
    return { ...message, timestamp };
  }

  private conversationSignature(messages: StoredMessage[]): string {
    const bytes = SecureDB.encoder.encode(JSON.stringify(messages));
    const digest = blake3(bytes, { dkLen: 32 });
    try {
      return bytesToHex(digest);
    } finally {
      bytes.fill(0);
      digest.fill(0);
    }
  }

  private assertUniqueMessageSelectors(messages: StoredMessage[]): void {
    const owners = new Map<string, string>();
    for (const message of messages) {
      const localId = message.id!;
      const selectors = message.wireMessageId && message.wireMessageId !== localId
        ? [localId, message.wireMessageId]
        : [localId];
      for (const selector of selectors) {
        const owner = owners.get(selector);
        if (owner && owner !== localId) {
          throw new Error('Conversation contains colliding message identifiers');
        }
        owners.set(selector, localId);
      }
    }
  }

  // Validate ownership, dedupe by ID, sort ascending, and cap history
  private prepareConversation(
    msgs: StoredMessage[],
    peer: string,
    activePeer?: string,
  ): { messages: StoredMessage[]; droppedSegments: number } {
    if (!isCanonicalUsername(peer) || peer === this.username) {
      throw new Error('Invalid conversation peer');
    }
    if (!Array.isArray(msgs) || msgs.length > MAX_CONVERSATION_INPUT_MESSAGES) {
      throw new Error('Conversation input limit exceeded');
    }
    if (activePeer !== undefined && (!isCanonicalUsername(activePeer) || activePeer === this.username)) {
      throw new Error('Invalid active conversation peer');
    }
    const dedup = new Map<string, StoredMessage>();
    for (const message of msgs) {
      const normalized = this.normalizeConversationMessage(message, peer);
      dedup.set(normalized.id!, normalized);
    }
    const unique = Array.from(dedup.values());
    this.assertUniqueMessageSelectors(unique);
    const sorted = unique
      .sort((a, b) => (a.timestamp as number) - (b.timestamp as number));
      
    if (sorted.length <= MAX_CONVERSATION_STORED_MESSAGES) {
      return { messages: sorted, droppedSegments: 0 };
    }
    
    const excess = sorted.length - MAX_CONVERSATION_STORED_MESSAGES;
    const droppedSegments = Math.ceil(excess / CONVERSATION_SEGMENT_SIZE);
    return {
      messages: sorted.slice(droppedSegments * CONVERSATION_SEGMENT_SIZE),
      droppedSegments,
    };
  }

  // Inclusive segment range for a conversation, or null when it has none stored.
  private async conversationLayout(
    peer: string,
  ): Promise<{ firstSegment: number; lastSegment: number } | null> {
    const metadata = await this.loadConversationMetadataUnlocked();
    const entry = metadata?.find((candidate) => candidate.peerUsername === peer);
    if (!entry) return null;
    return { firstSegment: entry.firstSegment, lastSegment: entry.lastSegment };
  }

  // Decrypt one segment
  private async readSegment(peer: string, index: number): Promise<StoredMessage[] | null> {
    const storageKey = SecureDB.segmentKey(peer, index);
    const encrypted = await (await this.kv()).getBinary(STORAGE_STORES.MESSAGE_CONVERSATIONS, storageKey);
    if (!encrypted) {
      this.convSig.delete(storageKey);
      return null;
    }
    try {
      const data = await this.decryptData(encrypted, STORAGE_STORES.MESSAGE_CONVERSATIONS, storageKey);
      if (!Array.isArray(data) || data.length === 0 || data.length > CONVERSATION_SEGMENT_SIZE) {
        throw new Error('Stored conversation segment has an invalid shape');
      }
      const arr = data.map((message) =>
        this.normalizeConversationMessage(message as StoredMessage, peer));
      for (let i = 1; i < arr.length; i += 1) {
        if ((arr[i - 1].timestamp as number) > (arr[i].timestamp as number)) {
          throw new Error('Stored conversation segment is not in canonical order');
        }
      }
      this.convSig.set(storageKey, this.conversationSignature(arr));
      return arr;
    } finally {
      encrypted.fill(0);
    }
  }

  private async loadConversationTail(peer: string, needed: number): Promise<StoredMessage[]> {
    if (!isCanonicalUsername(peer) || peer === this.username) {
      throw new Error('Invalid conversation peer');
    }
    const layout = await this.conversationLayout(peer);
    if (!layout || needed <= 0) return [];
    const collected: StoredMessage[][] = [];
    let total = 0;
    for (let index = layout.lastSegment; index >= layout.firstSegment && total < needed; index -= 1) {
      const segment = await this.readSegment(peer, index);
      if (!segment) continue;
      collected.push(segment);
      total += segment.length;
    }
    collected.reverse();
    const flat = collected.flat();
    const arr = flat.length > needed ? flat.slice(flat.length - needed) : flat;
    this.assertUniqueMessageSelectors(arr);
    return arr;
  }

  private async loadConversation(peer: string): Promise<StoredMessage[]> {
    if (!isCanonicalUsername(peer) || peer === this.username) {
      throw new Error('Invalid conversation peer');
    }
    const layout = await this.conversationLayout(peer);
    if (!layout) return [];
    const segments: StoredMessage[][] = [];
    for (let index = layout.firstSegment; index <= layout.lastSegment; index += 1) {
      const segment = await this.readSegment(peer, index);
      if (segment) segments.push(segment);
    }
    const arr = segments.flat();
    if (arr.length > MAX_CONVERSATION_STORED_MESSAGES) {
      throw new Error('Stored conversation has an invalid shape');
    }
    const ids = new Set(arr.map((message) => message.id));
    if (ids.size !== arr.length) throw new Error('Stored conversation has duplicate message IDs');
    this.assertUniqueMessageSelectors(arr);
    return arr;
  }

  private static chunkConversation(messages: StoredMessage[]): StoredMessage[][] {
    const chunks: StoredMessage[][] = [];
    for (let offset = 0; offset < messages.length; offset += CONVERSATION_SEGMENT_SIZE) {
      chunks.push(messages.slice(offset, offset + CONVERSATION_SEGMENT_SIZE));
    }
    return chunks;
  }

  private async prepareConversationWrite(
    peer: string,
    msgs: StoredMessage[],
    activePeer?: string,
  ): Promise<PreparedConversationWrite | null> {
    const { messages: prepared, droppedSegments } = this.prepareConversation(msgs, peer, activePeer);
    if (prepared.length === 0) throw new Error('Cannot persist an empty conversation');

    const previous = await this.conversationLayout(peer);
    const firstSegment = (previous?.firstSegment ?? 0) + droppedSegments;
    const chunks = SecureDB.chunkConversation(prepared);
    const lastSegment = firstSegment + chunks.length - 1;
    if (lastSegment >= MAX_SEGMENT_INDEX) {
      throw new Error('Conversation segment index exhausted');
    }

    const segments: Array<{ index: number; encrypted: Uint8Array; signature: string }> = [];
    for (let position = 0; position < chunks.length; position += 1) {
      const index = firstSegment + position;
      const storageKey = SecureDB.segmentKey(peer, index);
      const signature = this.conversationSignature(chunks[position]);
      if (this.convSig.get(storageKey) === signature) continue;
      segments.push({
        index,
        encrypted: await this.encryptData(chunks[position], STORAGE_STORES.MESSAGE_CONVERSATIONS, storageKey),
        signature,
      });
    }

    const deletedSegments: number[] = [];
    if (previous) {
      for (let index = previous.firstSegment; index < firstSegment; index += 1) {
        deletedSegments.push(index);
      }
      for (let index = lastSegment + 1; index <= previous.lastSegment; index += 1) {
        deletedSegments.push(index);
      }
    }

    if (segments.length === 0 && deletedSegments.length === 0 &&
      previous?.firstSegment === firstSegment && previous?.lastSegment === lastSegment) {
      return null;
    }

    const retainedIds = new Set(prepared.map((message) => message.id!));
    const evictedFileIds = Array.from(new Set(
      msgs
        .filter((message) => isFileMessage(message) && !retainedIds.has(message.id!))
        .map((message) => message.id!)
    ));
    return {
      peer,
      grantsIncomingCallPermission: prepared.some((message) => (
        message.sender === this.username &&
        message.recipient === peer &&
        message.isSystemMessage !== true &&
        (message.type === 'text' || isFileMessage(message)) &&
        message.isDeliberateUserAction === true
      )),
      segments,
      deletedSegments,
      firstSegment,
      lastSegment,
      last: prepared[prepared.length - 1],
      evictedFileIds,
    };
  }

  private async persistConversationWrites(
    writes: PreparedConversationWrite[],
    additionalWrites: Array<{ store: string; key: string; value: Uint8Array }> = [],
  ): Promise<void> {
    if (writes.length === 0) return;
    const relationshipPeers = writes
      .filter(({ grantsIncomingCallPermission }) => grantsIncomingCallPermission)
      .map(({ peer }) => peer);
    if (
      writes.length > MAX_CONVERSATION_BATCH_WRITES ||
      writes.length + relationshipPeers.length + additionalWrites.length + 1 > 512
    ) {
      throw new Error('Conversation write batch limit exceeded');
    }
    if (new Set(writes.map(({ peer }) => peer)).size !== writes.length) {
      throw new Error('Duplicate conversation write');
    }
    const additionalTargets = new Set(additionalWrites.map(({ store, key }) => `${store}\0${key}`));
    if (additionalTargets.size !== additionalWrites.length) {
      throw new Error('Duplicate additional conversation write');
    }
    if (relationshipPeers.some((peer) => (
      additionalTargets.has(`${STORAGE_KEYS.DELIBERATE_CALL_ADMISSION}\0${peer}`)
    ))) {
      throw new Error('Conversation relationship marker collision');
    }
    const evictedFileIds = Array.from(new Set(writes.flatMap(({ evictedFileIds: ids }) => ids)));
    if (
      evictedFileIds.length > MAX_CONVERSATION_MUTATION_DELETIONS ||
      evictedFileIds.some((fileId) => additionalTargets.has(`files\0${fileId}`))
    ) {
      throw new Error('Conversation file cleanup limit exceeded');
    }

    let encryptedMetadata: Uint8Array | null = null;
    const encryptedRelationshipMarkers: Array<{ peer: string; value: Uint8Array }> = [];
    try {
      for (const peer of relationshipPeers) {
        encryptedRelationshipMarkers.push({
          peer,
          value: await this.encryptData(true, STORAGE_KEYS.DELIBERATE_CALL_ADMISSION, peer),
        });
      }
      let metadata = await this.loadConversationMetadataUnlocked();
      if (metadata === null) {
        const existingPeers = await (await this.kv()).keysForStore(STORAGE_STORES.MESSAGE_CONVERSATIONS);
        if (existingPeers.length !== 0) {
          throw new Error('Conversation metadata is missing for existing rows');
        }
        metadata = [];
      }
      const nextMetadata = metadata.map((entry) => ({ ...entry }));

      for (const write of writes) {
        const index = nextMetadata.findIndex((entry) => entry.peerUsername === write.peer);
        if (index === -1) {
          nextMetadata.push({
            peerUsername: write.peer,
            lastMessage: write.last,
            lastReadTimestamp: 0,
            firstSegment: write.firstSegment,
            lastSegment: write.lastSegment,
          });
        } else {
          nextMetadata[index] = {
            ...nextMetadata[index],
            lastMessage: write.last,
            firstSegment: write.firstSegment,
            lastSegment: write.lastSegment,
          };
        }
      }

      const validatedMetadata = this.validateConversationMetadata(nextMetadata);
      encryptedMetadata = await this.encryptData(validatedMetadata, STORAGE_STORES.DATA, STORAGE_KEYS.CONVERSATIONS_METADATA);
      
      await (await this.kv()).mutate(
        [
          ...writes.flatMap(({ peer, segments }) => segments.map(({ index, encrypted }) => ({
            store: STORAGE_STORES.MESSAGE_CONVERSATIONS,
            key: SecureDB.segmentKey(peer, index),
            value: encrypted,
          }))),
          ...additionalWrites,
          ...encryptedRelationshipMarkers.map(({ peer, value }) => ({
            store: STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
            key: peer,
            value,
          })),
          { store: STORAGE_STORES.DATA, key: STORAGE_KEYS.CONVERSATIONS_METADATA, value: encryptedMetadata },
        ],
        [
          ...writes.flatMap(({ peer, deletedSegments }) => deletedSegments.map((index) => ({
            store: STORAGE_STORES.MESSAGE_CONVERSATIONS,
            key: SecureDB.segmentKey(peer, index),
          }))),
          ...evictedFileIds.map((key) => ({ store: STORAGE_STORES.FILES, key })),
        ],
      );
      for (const { peer, segments, deletedSegments } of writes) {
        for (const { index, signature } of segments) {
          this.convSig.set(SecureDB.segmentKey(peer, index), signature);
        }
        for (const index of deletedSegments) {
          this.convSig.delete(SecureDB.segmentKey(peer, index));
        }
      }
    } finally {
      encryptedMetadata?.fill(0);
      for (const { value } of encryptedRelationshipMarkers) value.fill(0);
      for (const { segments } of writes) {
        for (const { encrypted } of segments) encrypted.fill(0);
      }
    }
  }

  // Store a message
  async storeMessage(message: StoredMessage): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    await this.withMessageLock(async () => {
      const peer = this.peerOf(message, this.username);
      if (!peer) throw new Error('Message conversation is required');
      const existing = await this.loadConversation(peer);
      const write = await this.prepareConversationWrite(peer, [...existing, message]);
      if (write) await this.persistConversationWrites([write]);
    });
  }

  async storeOutgoingMessageWithRetryState(
    message: StoredMessage,
    retryState: unknown,
  ): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    await this.withMessageLock(async () => {
      const peer = this.peerOf(message, this.username);
      if (!peer) throw new Error('Message conversation is required');
      const existing = await this.loadConversation(peer);
      if (existing.some((candidate) => (
        candidate.id === message.id ||
        candidate.wireMessageId === message.id ||
        (message.wireMessageId !== undefined && (
          candidate.id === message.wireMessageId ||
          candidate.wireMessageId === message.wireMessageId
        ))
      ))) {
        throw new Error('Outgoing message identifier already exists');
      }

      const write = await this.prepareConversationWrite(peer, [...existing, message], peer);
      if (!write) throw new Error('Outgoing message produced no conversation write');

      let encryptedRetryState: Uint8Array | null = null;
      try {
        encryptedRetryState = await this.encryptData(retryState, STORAGE_STORES.PENDING_RETRY, STORAGE_KEYS.PENDING_RETRY_ALL);
        await this.persistConversationWrites([write], [{
          store: STORAGE_STORES.PENDING_RETRY,
          key: STORAGE_KEYS.PENDING_RETRY_ALL,
          value: encryptedRetryState,
        }]);
      } finally {
        encryptedRetryState?.fill(0);
      }
    });
  }

  async storeMessageIfAbsent(message: StoredMessage, activeConversationPeer?: string): Promise<{
    stored: boolean;
    existing: StoredMessage | null;
  }> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    const messageId = typeof message?.id === 'string' ? message.id : '';
    if (sanitizeMessageId(messageId) !== messageId) throw new Error('Message ID is required');

    return this.withMessageLock(async () => {
      const peer = this.peerOf(message, this.username);
      if (!peer) throw new Error('Message conversation is required');
      const existing = await this.loadConversation(peer);
      const incomingSelectors = new Set([
        messageId,
        ...(typeof message.wireMessageId === 'string' ? [message.wireMessageId] : []),
      ]);
      const collision = existing.find(candidate => (
        incomingSelectors.has(candidate?.id) ||
        (typeof candidate?.wireMessageId === 'string' && incomingSelectors.has(candidate.wireMessageId))
      )) || null;
      if (collision) return { stored: false, existing: collision };

      const write = await this.prepareConversationWrite(
        peer,
        [...existing, message],
        activeConversationPeer,
      );
      if (write) await this.persistConversationWrites([write]);
      return { stored: true, existing: null };
    });
  }

  async updateConversationMessage(
    peerUsername: string,
    messageId: string,
    mutator: (message: StoredMessage) => StoredMessage | null | Promise<StoredMessage | null>,
    options?: { grantIncomingCallPermission?: boolean },
  ): Promise<StoredMessage | null> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    if (
      !isCanonicalUsername(peerUsername) || peerUsername === this.username ||
      sanitizeMessageId(messageId) !== messageId
    ) {
      throw new Error('Invalid conversation message selector');
    }

    return this.withMessageLock(async () => {
      const existing = await this.loadConversation(peerUsername);
      const index = existing.findIndex(message => (
        message?.id === messageId || message?.wireMessageId === messageId
      ));
      if (index === -1) return null;

      const current = existing[index];
      const updated = await mutator(current);
      if (updated === null) return null;
      if (
        updated.id !== current.id ||
        updated.wireMessageId !== current.wireMessageId ||
        this.peerOf(updated, this.username) !== peerUsername
      ) {
        throw new Error('Conversation mutation changed message ownership');
      }

      const next = existing.slice();
      next[index] = updated;
      
      const write = await this.prepareConversationWrite(peerUsername, next, peerUsername);
      if (write) {
        if (options?.grantIncomingCallPermission === true) {
          write.grantsIncomingCallPermission = true;
        }
        await this.persistConversationWrites([write]);
      } else if (options?.grantIncomingCallPermission === true) {
        throw new Error('Deliberate contact did not change local state');
      }
      return updated;
    });
  }

  async updateConversationMessages(
    peerUsername: string,
    mutations: ReadonlyMap<
      string,
      (message: StoredMessage) => StoredMessage | null | Promise<StoredMessage | null>
    >
  ): Promise<Set<string>> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    if (
      !isCanonicalUsername(peerUsername) || peerUsername === this.username ||
      mutations.size > MAX_CONVERSATION_STORED_MESSAGES
    ) {
      throw new Error('Invalid conversation mutation batch');
    }
    for (const messageId of mutations.keys()) {
      if (sanitizeMessageId(messageId) !== messageId) {
        throw new Error('Invalid conversation message selector');
      }
    }
    if (mutations.size === 0) return new Set();

    return this.withMessageLock(async () => {
      const existing = await this.loadConversation(peerUsername);
      const found = new Set<string>();
      let next: StoredMessage[] | null = null;

      for (let index = 0; index < existing.length; index += 1) {
        const current = existing[index];
        const selector = mutations.has(current.id)
          ? current.id
          : typeof current.wireMessageId === 'string' && mutations.has(current.wireMessageId)
            ? current.wireMessageId
            : null;
        const mutator = selector ? mutations.get(selector) : undefined;
        if (!mutator) continue;
        found.add(selector!);

        const updated = await mutator(current);
        if (updated === null || updated === current) continue;
        if (updated.id !== current.id || this.peerOf(updated, this.username) !== peerUsername) {
          throw new Error('Conversation mutation changed message ownership');
        }
        if (!next) next = existing.slice();
        next[index] = updated;
      }

      if (next) {
        const write = await this.prepareConversationWrite(peerUsername, next, peerUsername);
        if (write) await this.persistConversationWrites([write]);
      }
      return found;
    });
  }

  async loadConversationMessageById(
    peerUsername: string,
    messageId: string
  ): Promise<StoredMessage | null> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    if (
      !isCanonicalUsername(peerUsername) || peerUsername === this.username ||
      sanitizeMessageId(messageId) !== messageId
    ) {
      throw new Error('Invalid conversation message selector');
    }

    return this.withMessageLock(async () => {
      const layout = await this.conversationLayout(peerUsername);
      if (!layout) return null;
      for (let index = layout.lastSegment; index >= layout.firstSegment; index -= 1) {
        const segment = await this.readSegment(peerUsername, index);
        if (!segment) continue;
        const found = segment.find(message => (
          message?.id === messageId || message?.wireMessageId === messageId
        ));
        if (found) return found;
      }
      return null;
    });
  }

  async hasCompleteFileMessage(peerUsername: string, messageId: string): Promise<boolean> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    if (
      !isCanonicalUsername(peerUsername) || peerUsername === this.username ||
      sanitizeMessageId(messageId) !== messageId
    ) {
      throw new Error('Invalid file message selector');
    }

    return this.withMessageLock(async () => {
      const existing = await this.loadConversation(peerUsername);
      if (!existing.some(message => message?.id === messageId && isFileMessage(message))) return false;
      return (await this.kv()).has(STORAGE_STORES.FILES, messageId);
    });
  }

  async upsertMessages(messages: StoredMessage[], activeConversationPeer?: string): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    if (!Array.isArray(messages) || messages.length === 0) return;
    if (messages.length > MAX_CONVERSATION_INPUT_MESSAGES) {
      throw new Error('Message upsert batch limit exceeded');
    }
    if (
      activeConversationPeer !== undefined &&
      (!isCanonicalUsername(activeConversationPeer) || activeConversationPeer === this.username)
    ) {
      throw new Error('Invalid active conversation peer');
    }

    await this.withMessageLock(async () => {
      const grouped = new Map<string, StoredMessage[]>();
      for (const message of messages) {
        if (!message?.id) continue;
        const peer = this.peerOf(message, this.username);
        if (!peer) continue;
        const group = grouped.get(peer) || [];
        group.push(message);
        grouped.set(peer, group);
      }
      if (grouped.size > MAX_CONVERSATION_BATCH_WRITES) {
        throw new Error('Conversation write batch limit exceeded');
      }

      const writes: PreparedConversationWrite[] = [];
      try {
        for (const [peer, pending] of grouped) {
          const existing = await this.loadConversation(peer);
          const byId = new Map(existing.map(message => [message.id, message]));

          for (const incoming of pending) {
            const previous = byId.get(incoming.id);
            if (!previous) {
              byId.set(incoming.id, incoming);
              continue;
            }

            byId.set(incoming.id, {
              ...previous,
              ...incoming,
              ...(incoming.replyTo
                ? {
                    replyTo: {
                      ...previous.replyTo,
                      ...incoming.replyTo,
                    },
                  }
                : {}),
              receipt: mergeReceipts(previous.receipt, incoming.receipt),
            });
          }

          const write = await this.prepareConversationWrite(
            peer,
            Array.from(byId.values()),
            activeConversationPeer,
          );
          if (write) writes.push(write);
        }

        await this.persistConversationWrites(writes);
      } finally {
        for (const { segments } of writes) {
          for (const { encrypted } of segments) encrypted.fill(0);
        }
      }
    });
  }

  private async prepareFileCiphertext(fileId: string, data: ArrayBuffer | Blob): Promise<Uint8Array> {
    if (sanitizeMessageId(fileId) !== fileId) throw new Error('Invalid file ID');
    validateFileData(data, fileId);

    const source = new Uint8Array(data instanceof Blob ? await data.arrayBuffer() : data);
    
    const ownedBytes = data instanceof Blob ? source : new Uint8Array(source);
    try {
      return await this.encryptBytes(ownedBytes, STORAGE_STORES.FILES, fileId, PROTOCOL_KEYS.SECURE_DB_FILE_AAD);
    } finally {
      ownedBytes.fill(0);
    }
  }

  // Commit a file, its message, and the compact index in one native transaction
  async storeFileMessage(
    message: StoredMessage,
    data: ArrayBuffer | Blob,
    activeConversationPeer?: string,
  ): Promise<{ success: boolean; duplicate?: boolean; quotaExceeded?: boolean }> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    const messageId = typeof message?.id === 'string' ? message.id : '';
    if (sanitizeMessageId(messageId) !== messageId) throw new Error('File message ID is required');

    return this.withMessageLock(async () => {
      const peer = this.peerOf(message, this.username);
      if (!peer) throw new Error('File message peer is required');
      const existing = await this.loadConversation(peer);
      const existingMessage = existing.find((entry) => entry?.id === messageId) || null;
      const kv = await this.kv();
      const existingFile = await kv.getBinary(STORAGE_STORES.FILES, messageId);
      const hasExistingFile = existingFile !== null;
      existingFile?.fill(0);

      const sameFileIdentity = !!existingMessage &&
        isFileMessage(existingMessage) &&
        existingMessage.type === message.type &&
        existingMessage.sender === message.sender &&
        existingMessage.recipient === message.recipient &&
        existingMessage.wireMessageId === message.wireMessageId &&
        existingMessage.filename === message.filename &&
        existingMessage.fileSize === message.fileSize &&
        existingMessage.mimeType === message.mimeType;

      if (existingMessage && !sameFileIdentity) {
        return { success: false, duplicate: true };
      }
      if (sameFileIdentity && hasExistingFile) {
        return { success: true, duplicate: true };
      }
      if (!existingMessage && hasExistingFile) {
        return { success: false, duplicate: true };
      }

      let encryptedFile: Uint8Array | null = null;
      try {
        encryptedFile = await this.prepareFileCiphertext(messageId, data);
        if (sameFileIdentity) {
          await kv.mutate([{ store: STORAGE_STORES.FILES, key: messageId, value: encryptedFile }], []);
          return { success: true, duplicate: true };
        }

        const write = await this.prepareConversationWrite(
          peer,
          [...existing, message],
          activeConversationPeer,
        );
        if (!write) throw new Error('File message did not change its conversation');
        await this.persistConversationWrites(
          [write],
          [{ store: STORAGE_STORES.FILES, key: messageId, value: encryptedFile }],
        );
        return { success: true };
      } catch (error) {
        if (error instanceof Error && error.message === 'Database quota exceeded') {
          return { success: false, quotaExceeded: true };
        }
        throw error;
      } finally {
        encryptedFile?.fill(0);
      }
    });
  }

  private validateConversationMetadata(metadata: ConversationMetadata[]): ConversationMetadata[] {
    if (!Array.isArray(metadata) || metadata.length > MAX_KNOWN_PEERS) {
      throw new Error('Conversation metadata limit exceeded');
    }
    const peers = new Set<string>();
    return metadata.map((entry) => {
      if (
        !entry ||
        typeof entry !== 'object' ||
        Object.keys(entry).some((key) => !CONVERSATION_METADATA_KEYS.has(key)) ||
        !isCanonicalUsername(entry.peerUsername)
      ) {
        throw new Error('Invalid conversation metadata');
      }
      if (entry.peerUsername === this.username || peers.has(entry.peerUsername)) {
        throw new Error('Duplicate conversation metadata');
      }
      peers.add(entry.peerUsername);
      const lastReadTimestamp = entry.lastReadTimestamp;
      const isPinned = entry.isPinned === true;
      if (
        !isValidTimestamp(lastReadTimestamp) ||
        (entry.isPinned !== undefined && typeof entry.isPinned !== 'boolean') ||
        isPinned !== (entry.pinnedAt !== undefined) ||
        (entry.pinnedAt !== undefined && !isValidTimestamp(entry.pinnedAt))
      ) {
        throw new Error('Invalid conversation metadata');
      }
      const { firstSegment, lastSegment } = entry;
      if (
        !Number.isSafeInteger(firstSegment) || firstSegment < 0 ||
        !Number.isSafeInteger(lastSegment) || lastSegment < firstSegment ||
        lastSegment >= MAX_SEGMENT_INDEX ||
        (lastSegment - firstSegment + 1) >
          Math.ceil(MAX_CONVERSATION_STORED_MESSAGES / CONVERSATION_SEGMENT_SIZE)
      ) {
        throw new Error('Invalid conversation segment range');
      }
      return {
        peerUsername: entry.peerUsername,
        lastMessage: this.normalizeConversationMessage(entry.lastMessage, entry.peerUsername),
        lastReadTimestamp,
        firstSegment,
        lastSegment,
        ...(isPinned ? { isPinned: true, pinnedAt: entry.pinnedAt } : {}),
      };
    });
  }

  private async saveConversationMetadataUnlocked(metadata: ConversationMetadata[]): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    const validated = this.validateConversationMetadata(metadata);
    const encrypted = await this.encryptData(validated, STORAGE_STORES.DATA, STORAGE_KEYS.CONVERSATIONS_METADATA);
    try {
      await (await this.kv()).setBinary(STORAGE_STORES.DATA, STORAGE_KEYS.CONVERSATIONS_METADATA, encrypted);
    } finally {
      encrypted.fill(0);
    }
  }

  private async loadConversationMetadataUnlocked(): Promise<ConversationMetadata[] | null> {
    const metadata = await this.loadEncryptedArray<ConversationMetadata>(
      STORAGE_KEYS.CONVERSATIONS_METADATA,
      'load-metadata',
    );
    return metadata === null ? null : this.validateConversationMetadata(metadata);
  }

  private async loadIndexedConversationMetadataUnlocked(): Promise<ConversationMetadata[]> {
    const metadata = await this.loadConversationMetadataUnlocked();
    const rowKeys = await (await this.kv()).keysForStore(STORAGE_STORES.MESSAGE_CONVERSATIONS);
    const segmentsByPeer = new Map<string, Set<number>>();
    for (const key of rowKeys) {
      const parsed = SecureDB.parseSegmentKey(key);
      if (!parsed || parsed.peer === this.username) {
        throw new Error('Invalid conversation key index');
      }
      const indices = segmentsByPeer.get(parsed.peer) || new Set<number>();
      if (indices.has(parsed.index)) throw new Error('Invalid conversation key index');
      indices.add(parsed.index);
      segmentsByPeer.set(parsed.peer, indices);
    }
    if (metadata === null) {
      if (segmentsByPeer.size !== 0) {
        throw new Error('Conversation metadata is missing for existing rows');
      }
      return [];
    }
    if (metadata.length !== segmentsByPeer.size) {
      throw new Error('Conversation metadata does not match stored rows');
    }
    for (const entry of metadata) {
      const indices = segmentsByPeer.get(entry.peerUsername);
      if (!indices || indices.size !== entry.lastSegment - entry.firstSegment + 1) {
        throw new Error('Conversation metadata does not match stored rows');
      }
      for (let index = entry.firstSegment; index <= entry.lastSegment; index += 1) {
        if (!indices.has(index)) {
          throw new Error('Conversation metadata does not match stored rows');
        }
      }
    }
    return metadata;
  }

  async loadConversationMetadata(): Promise<ConversationMetadata[]> {
    return this.withMessageLock(() => this.loadIndexedConversationMetadataUnlocked());
  }

  async markConversationRead(peerUsername: string, readTimestamp: number): Promise<void> {
    if (
      !isCanonicalUsername(peerUsername) || peerUsername === this.username ||
      !isValidTimestamp(readTimestamp) || readTimestamp <= 0
    ) throw new Error('Invalid conversation read state');

    await this.withMessageLock(async () => {
      const metadata = await this.loadConversationMetadataUnlocked();
      if (metadata === null) {
        const peers = await (await this.kv()).keysForStore(STORAGE_STORES.MESSAGE_CONVERSATIONS);
        if (peers.length !== 0) throw new Error('Conversation metadata is missing for existing rows');
        return;
      }
      const index = metadata.findIndex((entry) => entry.peerUsername === peerUsername);
      if (index === -1) return;
      const nextReadTimestamp = Math.max(metadata[index].lastReadTimestamp, readTimestamp);
      if (nextReadTimestamp === metadata[index].lastReadTimestamp) return;
      const next = metadata.slice();
      next[index] = { ...next[index], lastReadTimestamp: nextReadTimestamp };
      await this.saveConversationMetadataUnlocked(next);
    });
  }

  // Toggle conversation pin status
  async toggleConversationPin(peerUsername: string, isPinned: boolean): Promise<void> {
    if (!isCanonicalUsername(peerUsername) || peerUsername === this.username) {
      throw new Error('Invalid conversation peer');
    }
    await this.withMessageLock(async () => {
      const metadata = await this.loadConversationMetadataUnlocked();
      if (metadata === null) {
        const peers = await (await this.kv()).keysForStore(STORAGE_STORES.MESSAGE_CONVERSATIONS);
        if (peers.length !== 0) throw new Error('Conversation metadata is missing for existing rows');
        return;
      }
      const idx = metadata.findIndex(m => m.peerUsername === peerUsername);
      if (idx === -1) return;
      const next = metadata.slice();
      next[idx] = {
        ...next[idx],
        isPinned,
        pinnedAt: isPinned ? Date.now() : undefined,
      };
      await this.saveConversationMetadataUnlocked(next);
    });
  }

  // Load encrypted array
  private async loadEncryptedArray<T>(key: string, logContext: string): Promise<T[] | null> {
    const encrypted = await (await this.kv()).getBinary(STORAGE_STORES.DATA, key);
    if (!encrypted) return null;

    try {
      const data = await this.decryptData(encrypted, STORAGE_STORES.DATA, key);
      if (!Array.isArray(data)) throw new Error('Stored array has an invalid shape');
      return data as T[];
    } catch (err: any) {
      const msg = err?.message || String(err);

      console.error(`[SecureDB] Integrity failure in ${logContext}; refusing to treat it as empty`, msg);
      throw new Error(`SecureDB integrity failure in ${logContext}: ${msg}`);
    } finally {
      encrypted.fill(0);
    }
  }

  // Load conversation messages
  async loadConversationMessages(peerUsername: string, limit = 50, offset = 0): Promise<StoredMessage[]> {
    if (
      !isCanonicalUsername(peerUsername) || peerUsername === this.username ||
      !Number.isSafeInteger(limit) || limit <= 0 || limit > CONVERSATION_SEGMENT_SIZE ||
      !Number.isSafeInteger(offset) || offset < 0 || offset > MAX_CONVERSATION_STORED_MESSAGES
    ) {
      throw new Error('Invalid conversation page');
    }
    return this.withMessageLock(async () => {
      const tail = await this.loadConversationTail(peerUsername, offset + limit);
      return tail.slice().reverse().slice(offset, offset + limit);
    });
  }

  async recordDeliberateContact(peerUsername: string): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    if (!isCanonicalUsername(peerUsername) || peerUsername === this.username) {
      throw new Error('Invalid conversation peer');
    }
    return this.withMessageLock(async () => {
      const marker = await this.encryptData(
        true,
        STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
        peerUsername,
      );
      try {
        await (await this.kv()).mutate([{
          store: STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
          key: peerUsername,
          value: marker,
        }], []);
      } finally {
        marker.fill(0);
      }
    });
  }

  async hasDeliberateContact(peerUsername: string): Promise<boolean> {
    if (!isCanonicalUsername(peerUsername) || peerUsername === this.username) {
      throw new Error('Invalid conversation peer');
    }
    return this.withMessageLock(async () => {
      const kv = await this.kv();
      const encryptedMarker = await kv.getBinary(
        STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
        peerUsername,
      );
      if (encryptedMarker) {
        try {
          const marker = await this.decryptData(
            encryptedMarker,
            STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
            peerUsername,
          );
          if (marker !== true) throw new Error('Invalid call-admission relationship marker');
          return true;
        } finally {
          encryptedMarker.fill(0);
        }
      }

      const layout = await this.conversationLayout(peerUsername);
      if (!layout) return false;
      for (let index = layout.lastSegment; index >= layout.firstSegment; index -= 1) {
        const segment = await this.readSegment(peerUsername, index);
        if (!segment) continue;
        for (let position = segment.length - 1; position >= 0; position -= 1) {
          const message = segment[position];
          if (
            message.sender === this.username &&
            message.recipient === peerUsername &&
            message.isSystemMessage !== true &&
            (message.type === 'text' || isFileMessage(message)) &&
            message.isDeliberateUserAction === true
          ) {
            const marker = await this.encryptData(
              true,
              STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
              peerUsername,
            );
            try {
              await kv.mutate([{
                store: STORAGE_KEYS.DELIBERATE_CALL_ADMISSION,
                key: peerUsername,
                value: marker,
              }], []);
            } finally {
              marker.fill(0);
            }
            return true;
          }
        }
      }
      return false;
    });
  }

  // Load recent messages by conversation
  async loadRecentMessagesByConversation(): Promise<StoredMessage[]> {
    return this.withMessageLock(async () => {
      const metadata = await this.loadIndexedConversationMetadataUnlocked();
      return metadata
        .map((entry) => entry.lastMessage)
        .sort((a, b) => (b.timestamp as number) - (a.timestamp as number));
    });
  }

  // Save users to storage
  async saveUsers(users: StoredUser[]): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    const normalized = normalizeKnownUsers(users, this.username);
    const encrypted = await this.encryptData(normalized, STORAGE_STORES.DATA, STORAGE_KEYS.USERS);
    try {
      await (await this.kv()).setBinary(STORAGE_STORES.DATA, STORAGE_KEYS.USERS, encrypted);
    } finally {
      encrypted.fill(0);
    }
  }

  // Delete the conversation, its compact index entry, and locally retained file payloads
  async deleteConversationMessages(peerUsername: string): Promise<number> {
    if (!isCanonicalUsername(peerUsername) || peerUsername === this.username) {
      throw new Error('Invalid conversation peer');
    }
    return this.withMessageLock(async () => {
      const conv = await this.loadConversation(peerUsername);
      let metadata = await this.loadConversationMetadataUnlocked();
      if (metadata === null) {
        if (conv.length !== 0) throw new Error('Conversation metadata is missing for existing rows');
        metadata = [];
      }
      const filteredMetadata = metadata.filter((entry) => entry.peerUsername !== peerUsername);
      const encryptedMetadata = await this.encryptData(filteredMetadata, STORAGE_STORES.DATA, STORAGE_KEYS.CONVERSATIONS_METADATA);
      const fileIds = conv
        .filter(isFileMessage)
        .map((message) => message.id!);
      const layout = await this.conversationLayout(peerUsername);
      const segmentKeys: string[] = [];
      if (layout) {
        for (let index = layout.firstSegment; index <= layout.lastSegment; index += 1) {
          segmentKeys.push(SecureDB.segmentKey(peerUsername, index));
        }
      }
      try {
        await (await this.kv()).mutate(
          [{ store: STORAGE_STORES.DATA, key: STORAGE_KEYS.CONVERSATIONS_METADATA, value: encryptedMetadata }],
          [
            ...segmentKeys.map((key) => ({ store: STORAGE_STORES.MESSAGE_CONVERSATIONS, key })),
            ...fileIds.map((key) => ({ store: STORAGE_STORES.FILES, key })),
          ],
        );
      } finally {
        encryptedMetadata.fill(0);
      }
      
      for (const key of segmentKeys) this.convSig.delete(key);
      return conv.length;
    });
  }

  // Load users from storage
  async loadUsers(): Promise<StoredUser[]> {
    const users = (await this.loadEncryptedArray<StoredUser>(STORAGE_KEYS.USERS, 'load-users')) ?? [];
    return normalizeKnownUsers(users, this.username);
  }

  // Store ephemeral data
  async storeEphemeral(storeName: string, keyOrData: any, maybeData?: unknown, ttl?: number, autoDelete?: boolean): Promise<void>;
  async storeEphemeral(storeName: string, key: string, data: unknown, ttl?: number, autoDelete?: boolean): Promise<void>;
  async storeEphemeral(storeName: string, a: any, b?: any, ttl?: number, autoDelete = true): Promise<void> {
    return this.withEphemeralLock(() => this.storeEphemeralUnlocked(storeName, a, b, ttl, autoDelete));
  }

  private async storeEphemeralUnlocked(
    storeName: string,
    a: unknown,
    b?: unknown,
    ttl?: number,
    autoDelete = true,
  ): Promise<void> {
    if (!this.ephemeralConfig.enabled) {
      if (typeof a === 'string') return this.store(storeName, a, b);

      return this.store(storeName, STORAGE_KEYS.SINGLETON, a);
    }
    if (typeof autoDelete !== 'boolean') throw new Error('Invalid ephemeral deletion policy');

    let key: string; let data: unknown;
    if (typeof a === 'string') { key = a; data = b; } else { key = STORAGE_KEYS.SINGLETON; data = a; }

    const validatedTTL = ttl === undefined ? this.ephemeralConfig.defaultTTL : ttl;
    if (!Number.isSafeInteger(validatedTTL) || validatedTTL <= 0) {
      throw new Error('Invalid ephemeral TTL');
    }

    const now = Date.now(); const expiresAt = now + Math.min(validatedTTL, this.ephemeralConfig.maxTTL);
    if (!isValidTimestamp(expiresAt) || expiresAt <= now) throw new Error('Invalid expiration time calculated');
    const payload: EphemeralData = { data, createdAt: now, expiresAt, ttl: expiresAt - now, autoDelete };

    await this.storeWithPrefix(`${STORAGE_PREFIXES.EPHEMERAL}${storeName}`, key, payload);
  }

  private validateEphemeralData(value: unknown): EphemeralData {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('Invalid ephemeral record');
    }
    const candidate = value as Partial<EphemeralData>;
    if (
      !isValidTimestamp(candidate.createdAt) ||
      !isValidTimestamp(candidate.expiresAt) ||
      !Number.isSafeInteger(candidate.ttl) || candidate.ttl <= 0 ||
      candidate.ttl > this.ephemeralConfig.maxTTL ||
      candidate.expiresAt <= candidate.createdAt ||
      candidate.expiresAt - candidate.createdAt !== candidate.ttl ||
      typeof candidate.autoDelete !== 'boolean'
    ) {
      throw new Error('Invalid ephemeral record');
    }
    return candidate as EphemeralData;
  }

  // Retrieve ephemeral data
  async retrieveEphemeral(storeName: string, keyOrUndefined?: string): Promise<unknown | null> {
    return this.withEphemeralLock(() => this.retrieveEphemeralUnlocked(storeName, keyOrUndefined));
  }

  private async retrieveEphemeralUnlocked(
    storeName: string,
    keyOrUndefined?: string,
  ): Promise<unknown | null> {
    const key = keyOrUndefined ?? STORAGE_KEYS.SINGLETON;
    if (!this.ephemeralConfig.enabled) return this.retrieve(storeName, key);

    const stored = await this.retrieveWithPrefix(`${STORAGE_PREFIXES.EPHEMERAL}${storeName}`, key);
    if (stored === null) return null;
    const ephe = this.validateEphemeralData(stored);

    if (Date.now() >= ephe.expiresAt) {
      if (ephe.autoDelete) await this.deleteWithPrefix(`${STORAGE_PREFIXES.EPHEMERAL}${storeName}`, key);
      return null;
    }

    return ephe.data;
  }

  // Append to ephemeral list
  async appendEphemeralList(storeName: string, listKey: string, entry: number | string, maxCount = 500, ttl?: number): Promise<(number | string)[]> {
    if (!Number.isSafeInteger(maxCount) || maxCount <= 0 || maxCount > MAX_EPHEMERAL_LIST_ITEMS) {
      throw new Error('Invalid ephemeral list limit');
    }
    const validEntry = (
      (typeof entry === 'string' && entry.length > 0 && entry.length <= 256 && !/[\u0000-\u001f\u007f]/.test(entry)) ||
      (typeof entry === 'number' && Number.isSafeInteger(entry))
    );
    if (!validEntry) throw new Error('Invalid ephemeral list entry');

    return this.withEphemeralLock(async () => {
      const existing = await this.retrieveEphemeralUnlocked(storeName, listKey);
      if (existing !== null && !Array.isArray(existing)) {
        throw new Error('Invalid ephemeral list');
      }
      const list = (existing ?? []) as unknown[];
      if (list.length > maxCount || list.some((value) => (
        !(
          (typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value)) ||
          (typeof value === 'number' && Number.isSafeInteger(value))
        )
      ))) {
        throw new Error('Invalid ephemeral list');
      }

      const deduped = (list as (number | string)[]).filter((value) => value !== entry);
      deduped.push(entry);
      const trimmed = deduped.length > maxCount ? deduped.slice(deduped.length - maxCount) : deduped;
      await this.storeEphemeralUnlocked(storeName, listKey, trimmed, ttl, true);
      return trimmed;
    });
  }

  async clearUnacknowledgedMessages(peerUsername: string, operationIds: string[]): Promise<void> {
    if (
      !this.ephemeralConfig.enabled ||
      !isCanonicalUsername(peerUsername) ||
      peerUsername === this.username ||
      !Array.isArray(operationIds) ||
      operationIds.length > MAX_EPHEMERAL_LIST_ITEMS
    ) {
      throw new Error('Invalid unacknowledged-message cleanup');
    }
    const uniqueIds = Array.from(new Set(operationIds));
    if (uniqueIds.some((operationId) => sanitizeMessageId(operationId) !== operationId)) {
      throw new Error('Invalid unacknowledged-message operation ID');
    }
    if (uniqueIds.length === 0) return;

    await this.withEphemeralLock(async () => {
      await (await this.kv()).mutate(
        [],
        uniqueIds.map((operationId) => ({
          store: `${STORAGE_PREFIXES.EPHEMERAL}unacknowledged-messages`,
          key: `${peerUsername}:${operationId}`,
        })),
      );
    });
  }

  async clearAllUnacknowledgedMessagesForPeer(peerUsername: string): Promise<void> {
    if (
      !this.ephemeralConfig.enabled ||
      !isCanonicalUsername(peerUsername) ||
      peerUsername === this.username
    ) {
      throw new Error('Invalid peer recovery cleanup');
    }

    await this.withEphemeralLock(async () => {
      const kv = await this.kv();
      const store = `${STORAGE_PREFIXES.EPHEMERAL}unacknowledged-messages`;
      const prefix = `${peerUsername}:`;
      const keys = await kv.keysForStore(store);
      const deletions = keys
        .filter((key) => key.startsWith(prefix))
        .map((key) => ({ store, key }));
      if (deletions.length > 0) await kv.mutate([], deletions);
    });
  }

  // Start ephemeral cleanup
  private startEphemeralCleanup(): void {
    if (this.disposed) throw new Error('Secure database has been disposed');
    if (this.cleanupInterval) clearInterval(this.cleanupInterval);
    this.cleanupInterval = setInterval(() => { void this.cleanupExpiredData(); }, this.ephemeralConfig.cleanupInterval);
  }

  // Cleanup expired ephemeral data
  private async cleanupExpiredData(): Promise<void> {
    if (this.cleanupRunning) return;
    this.cleanupRunning = true;
    try {
      await this.withEphemeralLock(async () => {
        if (this.disposed) return;
        const now = Date.now();
        if (now - this.lastCleanup < SECURE_DB_MIN_CLEANUP_INTERVAL) return;
        this.lastCleanup = now;
        const kv = await this.kv();
        const candidates = await kv.selectorsByStorePrefix(STORAGE_PREFIXES.EPHEMERAL);
        const toDeleteByStore = new Map<string, string[]>();

        for (const { store, key } of candidates) {
          const value = await kv.getBinary(store, key);
          if (!value) continue;
          try {
            const data = this.validateEphemeralData(await this.decryptData(value, store, key));
            if (now >= data.expiresAt && data.autoDelete) {
              const arr = toDeleteByStore.get(store) || [];
              arr.push(key);
              toDeleteByStore.set(store, arr);
              if (arr.length >= SECURE_DB_MAX_EPHEMERAL_BATCH) {
                await kv.deleteMany(store, arr.splice(0, arr.length));
              }
            }
          } catch {
          } finally {
            value.fill(0);
          }
        }

        for (const [store, keys] of toDeleteByStore.entries()) {
          if (keys.length) {
            await kv.deleteMany(store, keys);
          }
        }
      });
    } catch {
    } finally {
      this.cleanupRunning = false;
    }
  }

  // Store data with prefix
  private async storeWithPrefix(storeName: string, key: string, data: unknown): Promise<void> {
    if (!this.nativeReady) throw new Error('Native database is not initialized');
    const encrypted = await this.encryptData(data, storeName, key);
    try {
      await (await this.kv()).setBinary(storeName, key, encrypted);
    } finally {
      encrypted.fill(0);
    }
  }

  // Store data
  async store(storeName: string, key: string, data: unknown): Promise<void> {
    return this.storeWithPrefix(storeName, key, data);
  }

  // Retrieve data with prefix
  private async retrieveWithPrefix(storeName: string, key: string): Promise<unknown | null> {
    const encrypted = await (await this.kv()).getBinary(storeName, key);
    if (!encrypted) return null;

    try {
      return await this.decryptData(encrypted, storeName, key);
    } finally {
      encrypted.fill(0);
    }
  }

  // Retrieve data
  async retrieve(storeName: string, key: string): Promise<unknown | null> {
    return this.retrieveWithPrefix(storeName, key);
  }

  // Delete data with prefix
  private async deleteWithPrefix(storeName: string, key: string): Promise<void> {
    await (await this.kv()).delete(storeName, key);
  }

  // Delete data
  async delete(storeName: string, key: string): Promise<void> { return this.deleteWithPrefix(storeName, key); }

  // Clear a specific store
  async clearStore(storeName: string): Promise<number> { if (storeName === STORAGE_STORES.MESSAGE_CONVERSATIONS) this.convSig.clear(); return (await this.kv()).clearStore(storeName); }

  // Get a file from storage
  async getFile(fileId: string): Promise<Blob | null> {
    if (sanitizeMessageId(fileId) !== fileId) return null;

    const encrypted = await (await this.kv()).getBinary(STORAGE_STORES.FILES, fileId);
    if (!encrypted) return null;

    try {
      const decrypted = await this.decryptBytes(
        encrypted,
        STORAGE_STORES.FILES,
        fileId,
        PROTOCOL_KEYS.SECURE_DB_FILE_AAD,
      );
      let out: Uint8Array | null = null;
      try {
        if (decrypted.length === 0 || decrypted.length > SECURE_DB_MAX_FILE_SIZE) {
          throw new Error('Stored file has an invalid size');
        }
        const outBuffer = new ArrayBuffer(decrypted.byteLength);
        out = new Uint8Array(outBuffer);
        out.set(decrypted);
        return new Blob([outBuffer]);
      } finally {
        decrypted.fill(0);
        out?.fill(0);
      }
    } finally {
      encrypted.fill(0);
    }
  }

}
