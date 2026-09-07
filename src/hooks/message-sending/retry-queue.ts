import React from 'react';
import type { SecureDB } from '../../lib/database/secureDB';
import type { PendingRetryMessage } from '../../lib/types/message-sending-types';
import type { StoredMessage } from '../../lib/types/database-types';
import { nativeMessageContent } from '../../lib/tauri-bindings';
import {
  MAX_CONTENT_LENGTH,
  MAX_PENDING_RETRY_PER_PEER,
  MAX_PENDING_RETRY_PEERS,
  OUTBOUND_RETRY_MAX_AGE_MS,
} from '../../lib/constants';
import { SignalType } from '../../lib/types/signal-types';
import { hasPrototypePollutionKeys, isCanonicalAuthUsername, isPlainObject, sanitizeContent, sanitizeMessageId } from '../../lib/sanitizers';
import { isControlOperationId } from '../../lib/messages/message-controls';
import { STORAGE_KEYS, STORAGE_STORES } from '../../lib/database/storage-keys';

const MAX_RETRY_QUEUE_BYTES = 16 * 1024 * 1024;
const MAX_GLOBAL_PENDING_RETRIES = 500;
const persistenceChains = new WeakMap<SecureDB, Promise<void>>();

type DurableEntry = PendingRetryMessage & { content: string };

const RETRY_SIGNAL_TYPES = new Set<string>([
  SignalType.MESSAGE,
  SignalType.EDIT_MESSAGE,
  SignalType.DELETE_MESSAGE,
  SignalType.REACTION_ADD,
  SignalType.REACTION_REMOVE,
]);
const RETRY_ENTRY_KEYS = new Set([
  'content', 'editMessageId', 'messageSignalType', 'originalMessageId',
  'queuedAt', 'replyTo', 'retryCount', 'retryId', 'user'
]);
const UNACKNOWLEDGED_ENTRY_KEYS = new Set([
  ...RETRY_ENTRY_KEYS,
  'timestamp'
]);
const RETRY_USER_KEYS = new Set(['username']);
const RETRY_REPLY_KEYS = new Set(['content', 'id', 'sender']);

const hasOnlyKeys = (value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean =>
  Object.keys(value).every((key) => allowed.has(key));

const validReply = (value: unknown): boolean => {
  if (value === undefined) return true;
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) return false;
  if (!hasOnlyKeys(value, RETRY_REPLY_KEYS)) return false;
  return sanitizeMessageId(value.id) === value.id &&
    (value.sender === undefined || isCanonicalAuthUsername(value.sender)) &&
    (value.content === undefined || value.content === '');
};

export const validateDurableRetryEntry = (value: unknown, peer: string): value is DurableEntry => {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value) || !hasOnlyKeys(value, RETRY_ENTRY_KEYS)) return false;
  if (!isPlainObject(value.user) || hasPrototypePollutionKeys(value.user) || !hasOnlyKeys(value.user, RETRY_USER_KEYS)) return false;
  if (value.user.username !== peer || !isCanonicalAuthUsername(peer)) return false;
  if (typeof value.content !== 'string' || value.content.length > MAX_CONTENT_LENGTH) return false;
  if (!Number.isInteger(value.retryCount) || (value.retryCount as number) < 0 || (value.retryCount as number) > 2) return false;
  if (!Number.isSafeInteger(value.queuedAt) || (value.queuedAt as number) <= 0) return false;
  if (typeof value.messageSignalType !== 'string' || !RETRY_SIGNAL_TYPES.has(value.messageSignalType)) return false;
  if (sanitizeMessageId(value.retryId) !== value.retryId) return false;
  if (sanitizeMessageId(value.originalMessageId) !== value.originalMessageId) return false;
  if (!validReply(value.replyTo)) return false;

  const type = value.messageSignalType;
  const hasContent = value.content.length > 0 && sanitizeContent(value.content) === value.content;
  if (type === SignalType.MESSAGE) {
    return value.retryId === value.originalMessageId &&
      value.editMessageId === undefined &&
      value.content === '';
  }
  if (
    value.retryId === value.originalMessageId ||
    value.replyTo !== undefined ||
    !isControlOperationId(value.retryId)
  ) return false;
  if (type === SignalType.EDIT_MESSAGE) {
    return value.editMessageId === value.originalMessageId && value.content === '';
  }
  if (value.editMessageId !== undefined) return false;
  if (type === SignalType.DELETE_MESSAGE) return value.content === '';
  return hasContent;
};

export const recoverUnacknowledgedRetryEntry = (
  value: unknown,
  peer: string,
  expectedOperationId: string
): DurableEntry | null => {
  if (
    !isPlainObject(value) ||
    hasPrototypePollutionKeys(value) ||
    !hasOnlyKeys(value, UNACKNOWLEDGED_ENTRY_KEYS) ||
    !Number.isSafeInteger(value.timestamp) ||
    (value.timestamp as number) <= 0
  ) return null;

  const timestamp = value.timestamp as number;
  const now = Date.now();
  if (timestamp > now || now - timestamp >= OUTBOUND_RETRY_MAX_AGE_MS) return null;
  const { timestamp: _timestamp, ...entry } = value;
  const candidate = { ...entry, retryCount: 0, queuedAt: timestamp };
  return validateDurableRetryEntry(candidate, peer) &&
    candidate.retryId === expectedOperationId
    ? candidate
    : null;
};

export const isPendingRetryExpired = (
  entry: PendingRetryMessage,
  now: number = Date.now(),
): boolean => (
  !Number.isSafeInteger(entry.queuedAt) ||
  entry.queuedAt <= 0 ||
  entry.queuedAt > now ||
  now - entry.queuedAt >= OUTBOUND_RETRY_MAX_AGE_MS
);

type ExpiredRetry = { peer: string; entry: PendingRetryMessage };

export const pruneExpiredRetryEntries = (
  map: Map<string, PendingRetryMessage[]>,
  now: number = Date.now(),
): ExpiredRetry[] => {
  const expired: ExpiredRetry[] = [];
  for (const [peer, entries] of map) {
    const retained: PendingRetryMessage[] = [];
    for (const entry of entries) {
      if (isPendingRetryExpired(entry, now)) expired.push({ peer, entry });
      else retained.push(entry);
    }
    if (retained.length > 0) map.set(peer, retained);
    else map.delete(peer);
  }
  return expired;
};

const cleanupExpiredRetries = async (
  db: SecureDB,
  expired: readonly ExpiredRetry[],
  isCurrent: () => boolean,
): Promise<void> => {
  const operationIdsByPeer = new Map<string, string[]>();
  for (const { peer, entry } of expired) {
    if (!isCurrent()) throw new Error('Account changed during retry expiry cleanup');
    const operationId = entry.retryId;
    let ids = operationIdsByPeer.get(peer);
    if (!ids) {
      ids = [];
      operationIdsByPeer.set(peer, ids);
    }
    ids.push(operationId);
    if (entry.messageSignalType === SignalType.MESSAGE) {
      await nativeMessageContent.revokeSend(operationId).catch(() => false);
    } else if (entry.messageSignalType === SignalType.EDIT_MESSAGE) {
      await nativeMessageContent.delete(operationId).catch(() => false);
    }
  }
  for (const [peer, operationIds] of operationIdsByPeer) {
    if (!isCurrent()) throw new Error('Account changed during retry expiry cleanup');
    await db.clearUnacknowledgedMessages(peer, operationIds);
  }
};

// Append an entry to a peer's queue in-memory (no overwrite), enforcing caps.
// Retries are keyed by the operation's own wire ID. Mutation target IDs are not
// unique: two edits/reactions/deletes can legitimately target the same message.
export const enqueueRetry = (
  map: Map<string, PendingRetryMessage[]>,
  peer: string,
  entry: PendingRetryMessage
): boolean => {
  if (!validateDurableRetryEntry(entry, peer)) {
    throw new Error('Pending retry entry is invalid');
  }
  pruneExpiredRetryEntries(map);
  let queue = map.get(peer);
  if (!queue) {
    if (map.size >= MAX_PENDING_RETRY_PEERS && !map.has(peer)) {
      throw new Error('Pending retry peer limit reached');
    }
    let total = 0;
    for (const entries of map.values()) total += entries.length;
    if (total >= MAX_GLOBAL_PENDING_RETRIES) {
      throw new Error('Global pending retry limit reached');
    }
    queue = [];
    map.set(peer, queue);
  }
  const entryKey = entry.retryId;
  const existingIdx = queue.findIndex(e => e.retryId === entryKey);
  if (existingIdx !== -1) {
    const previous = queue[existingIdx];
    queue[existingIdx] = {
      ...entry,
      queuedAt: Math.min(previous.queuedAt, entry.queuedAt),
    };
    return false;
  } else {
    if (queue.length >= MAX_PENDING_RETRY_PER_PEER) {
      throw new Error('Pending retry limit reached for peer');
    }
    let total = 0;
    for (const entries of map.values()) total += entries.length;
    if (total >= MAX_GLOBAL_PENDING_RETRIES) throw new Error('Global pending retry limit reached');
    queue.push(entry);
    return true;
  }
};

export const pinRetryEntry = (entry: PendingRetryMessage): void => {
  void entry;
};

export const releaseRetryEntries = (entries: readonly PendingRetryMessage[]): void => {
  void entries;
};

export const releaseRetryMap = (map: ReadonlyMap<string, readonly PendingRetryMessage[]>): void => {
  for (const entries of map.values()) releaseRetryEntries(entries);
};

const cloneRetryMap = (map: Map<string, PendingRetryMessage[]>): Map<string, PendingRetryMessage[]> =>
  new Map(Array.from(map, ([peer, entries]) => [
    peer,
    entries.map((entry) => ({
      ...entry,
      user: { username: entry.user.username },
      replyTo: entry.messageSignalType === SignalType.MESSAGE && entry.replyTo && typeof entry.replyTo === 'object'
        ? { ...entry.replyTo }
        : undefined,
    })),
  ]));

const persistRetrySnapshot = async (
  db: SecureDB,
  map: Map<string, PendingRetryMessage[]>,
  isCurrent: () => boolean,
  outgoingMessage?: StoredMessage,
): Promise<void> => {
  if (!isCurrent()) throw new Error('Account changed before retry persistence');
  if (map.size === 0) {
    if (outgoingMessage) throw new Error('Outgoing message has no durable send intent');
    await db.delete(STORAGE_STORES.PENDING_RETRY, STORAGE_KEYS.PENDING_RETRY_ALL);
    return;
  }

  const obj: Record<string, DurableEntry[]> = Object.create(null);
  let usedBytes = 2;
  const encoder = new TextEncoder();
  for (const [peer, entries] of map) {
    if (!entries.length) continue;
    const durable: DurableEntry[] = [];
    let peerOverhead = encoder.encode(JSON.stringify(peer)).length + 4;
    for (const e of entries) {
      const entry: DurableEntry = { ...e };
      if (!validateDurableRetryEntry(entry, peer)) {
        throw new Error('Pending retry entry is invalid');
      }
      const entryBytes = encoder.encode(JSON.stringify(entry)).length + 1;
      if (usedBytes + peerOverhead + entryBytes > MAX_RETRY_QUEUE_BYTES) {
        throw new Error('Pending retry queue exceeds its durable byte budget');
      }
      usedBytes += entryBytes + peerOverhead;
      peerOverhead = 0;
      durable.push(entry);
    }
    if (durable.length) obj[peer] = durable;
  }
  if (Object.keys(obj).length === 0) {
    if (!isCurrent()) throw new Error('Account changed during retry persistence');
    await db.delete(STORAGE_STORES.PENDING_RETRY, STORAGE_KEYS.PENDING_RETRY_ALL);
    return;
  }
  if (!isCurrent()) throw new Error('Account changed during retry persistence');
  if (outgoingMessage) {
    await db.storeOutgoingMessageWithRetryState(outgoingMessage, obj);
  } else {
    await db.store(STORAGE_STORES.PENDING_RETRY, STORAGE_KEYS.PENDING_RETRY_ALL, obj);
  }
};

export const persistRetryQueue = async (
  secureDBRef: React.RefObject<SecureDB | null>,
  map: Map<string, PendingRetryMessage[]>,
  isCurrent: () => boolean,
  outgoingMessage?: StoredMessage,
): Promise<void> => {
  const db = secureDBRef.current;
  if (!db || !isCurrent()) throw new Error('Secure database account is not current');
  const expired = pruneExpiredRetryEntries(map);
  if (expired.length > 0) await cleanupExpiredRetries(db, expired, isCurrent);
  const snapshot = cloneRetryMap(map);
  const previous = persistenceChains.get(db) || Promise.resolve();
  const write = previous.catch(() => { }).then(() => (
    persistRetrySnapshot(db, snapshot, isCurrent, outgoingMessage)
  ));
  persistenceChains.set(db, write);
  try {
    await write;
  } finally {
    if (persistenceChains.get(db) === write) persistenceChains.delete(db);
  }
};

// Load the durable metadata and verify every private operation
export const loadRetryQueue = async (
  secureDBRef: React.RefObject<SecureDB | null>,
  isCurrent: () => boolean
): Promise<Map<string, PendingRetryMessage[]>> => {
  const map = new Map<string, PendingRetryMessage[]>();
  const db = secureDBRef.current;
  if (!isCurrent()) return map;
  if (!db) throw new Error('Secure database is not ready for retry restoration');
  const obj = (await db.retrieve(STORAGE_STORES.PENDING_RETRY, STORAGE_KEYS.PENDING_RETRY_ALL)) as Record<string, DurableEntry[]> | null;
  if (!isCurrent()) return map;
  if (obj === null || obj === undefined) return map;
  if (
    !isPlainObject(obj) ||
    hasPrototypePollutionKeys(obj) ||
    Object.keys(obj).length === 0 ||
    Object.keys(obj).length > MAX_PENDING_RETRY_PEERS ||
    new TextEncoder().encode(JSON.stringify(obj)).length > MAX_RETRY_QUEUE_BYTES
  ) throw new Error('Pending retry queue is invalid');

  const validated = new Map<string, DurableEntry[]>();
  const operationIds = new Set<string>();
  let total = 0;
  for (const [peer, entries] of Object.entries(obj)) {
    if (
      !isCanonicalAuthUsername(peer) ||
      !Array.isArray(entries) ||
      entries.length === 0 ||
      entries.length > MAX_PENDING_RETRY_PER_PEER
    ) throw new Error('Pending retry queue is invalid');
    const peerEntries: DurableEntry[] = [];
    for (const e of entries) {
      if (!validateDurableRetryEntry(e, peer)) throw new Error('Pending retry queue is invalid');
      const contentKey = e.retryId;
      if (operationIds.has(contentKey)) throw new Error('Pending retry queue contains duplicates');
      operationIds.add(contentKey);
      peerEntries.push(e);
      total += 1;
      if (total > MAX_GLOBAL_PENDING_RETRIES) throw new Error('Pending retry queue is invalid');
    }
    validated.set(peer, peerEntries);
  }

  for (const [peer, entries] of validated) {
    const arr: PendingRetryMessage[] = [];
    for (const e of entries) {
      const contentKey = e.retryId;
      if (
        (e.messageSignalType === SignalType.MESSAGE || e.messageSignalType === SignalType.EDIT_MESSAGE) &&
        !await nativeMessageContent.has(contentKey)
      ) throw new Error('Pending retry queue references missing message content');
      if (!isCurrent()) return new Map();
      arr.push({ ...e });
    }
    map.set(peer, arr);
  }
  const expired = pruneExpiredRetryEntries(map);
  if (expired.length > 0) {
    await cleanupExpiredRetries(db, expired, isCurrent);
    if (!isCurrent()) return new Map();
    await persistRetrySnapshot(db, map, isCurrent);
  }
  return map;
};
