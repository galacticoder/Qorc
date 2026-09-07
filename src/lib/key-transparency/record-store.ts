import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  KEY_TRANSPARENCY_PROTOCOL,
  exactPlainObject,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
} from '../../../shared/key-transparency-protocol.js';
import {
  assertCurrentServerContext,
  deriveLocalAccountScope,
  type CurrentServerContext,
} from '../security/local-account-scope';
import { storage } from '../tauri-bindings';
import { deriveKeyTransparencyEpochLabel } from './crypto';
import type { KeyTransparencyCheckpoint, KeyTransparencyRecord } from './types';
import { createStoreLock } from './store-lock';
import { canonicalAuthUsername } from '../sanitizers';
import { keyTransparencyStoreKey } from './store-key';
import { parseProtocolCollectionStore } from './store-serialization';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEYS, STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';


export const KEY_TRANSPARENCY_CHUNK_EPOCHS = 720;
const MAX_RECORDS_PER_CHUNK = 65_536;
const MAX_CHUNKS = Math.ceil(KEY_TRANSPARENCY_MAX_LOG_SIZE / 1024);
const RECORD_ENTRY_KEYS = ['epoch', 'epochLabel', 'recordHash', 'version'];
const MAX_TRANSITION_CHARS = 64 * 1024;

const enqueue = createStoreLock();

export class KeyTransparencyRecordStoreCorruptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyTransparencyRecordStoreCorruptionError';
  }
}

function corruptRecordStore(message: string): never {
  throw new KeyTransparencyRecordStoreCorruptionError(message);
}

export type StoredKeyTransparencyRecord = KeyTransparencyRecord;

function normalizeOwner(owner: string): string {
  return canonicalAuthUsername(owner, 'key-transparency record owner');
}

function storageKey(accountScope: string, suffix: string): string {
  return keyTransparencyStoreKey(
    STORAGE_PREFIXES.KEY_TRANSPARENCY_RECORD,
    STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_RECORD,
    accountScope,
    suffix
  );
}

export function keyTransparencyChunkIndex(epoch: number): number {
  return Math.floor(epoch / KEY_TRANSPARENCY_CHUNK_EPOCHS);
}

function parseEntry(value: unknown): StoredKeyTransparencyRecord {
  const entry = value as StoredKeyTransparencyRecord;
  if (
    !exactPlainObject(entry, RECORD_ENTRY_KEYS) ||
    !Number.isSafeInteger(entry.epoch) ||
    entry.epoch < 0 ||
    !isKeyTransparencyLabel(entry.epochLabel) ||
    !isKeyTransparencyHash(entry.recordHash) ||
    !Number.isSafeInteger(entry.version) ||
    entry.version < 1
  ) corruptRecordStore('Stored key-transparency record is corrupt');
  return entry;
}

function parseChunk(raw: string | null): StoredKeyTransparencyRecord[] {
  return parseProtocolCollectionStore(raw, {
    protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_RECORD_STORE,
    collectionKey: 'records',
    maxEntries: MAX_RECORDS_PER_CHUNK,
    parseEntry,
    corrupt: corruptRecordStore,
    parseError: 'Stored key-transparency record chunk is corrupt',
    structureError: 'Stored key-transparency record chunk is corrupt',
  });
}

export async function loadKeyTransparencyCheckpoint(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<KeyTransparencyCheckpoint | null> {
  const accountScope = deriveLocalAccountScope(context, normalizeOwner(ownerUsername));
  const raw = await storage.get(storageKey(accountScope, STORAGE_KEYS.KEY_TRANSPARENCY_CHECKPOINT));
  await assertCurrentServerContext(context);
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    corruptRecordStore('Stored key-transparency checkpoint is corrupt');
  }
  const value = parsed as Omit<KeyTransparencyCheckpoint, 'protocol'> & { protocol?: unknown };
  if (
    !exactPlainObject(value, ['entryCount', 'epoch', 'protocol', 'rootHash']) ||
    value.protocol !== PROTOCOL_KEYS.KEY_TRANSPARENCY_CHECKPOINT ||
    !Number.isSafeInteger(value.epoch) ||
    value.epoch < 0 ||
    !Number.isSafeInteger(value.entryCount) ||
    value.entryCount < 0 ||
    value.entryCount > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
    !isKeyTransparencyHash(value.rootHash)
  ) corruptRecordStore('Stored key-transparency checkpoint is corrupt');
  return {
    protocol: KEY_TRANSPARENCY_PROTOCOL,
    epoch: value.epoch,
    entryCount: value.entryCount,
    rootHash: value.rootHash,
  };
}

// Persist verified records and advance the checkpoint together.
export async function commitKeyTransparencyDelta(
  context: CurrentServerContext,
  ownerUsername: string,
  records: StoredKeyTransparencyRecord[],
  checkpoint: KeyTransparencyCheckpoint,
): Promise<void> {
  const owner = normalizeOwner(ownerUsername);
  await enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, owner);
    const byChunk = new Map<number, StoredKeyTransparencyRecord[]>();
    for (const record of records) {
      const index = keyTransparencyChunkIndex(record.epoch);
      if (index >= MAX_CHUNKS) throw new Error('Key-transparency epoch is out of range');
      const bucket = byChunk.get(index);
      if (bucket) bucket.push(record); else byChunk.set(index, [record]);
    }

    for (const [index, appended] of byChunk) {
      const key = storageKey(accountScope, `chunk:${index}`);
      const existing = parseChunk(await storage.get(key));
      await assertCurrentServerContext(context);
      const seen = new Set(existing.map((entry) => `${entry.epoch}\0${entry.epochLabel}`));
      const merged = [...existing];
      for (const record of appended) {
        if (seen.has(`${record.epoch}\0${record.epochLabel}`)) continue;
        merged.push(record);
      }
      if (merged.length > MAX_RECORDS_PER_CHUNK) {
        throw new Error('Key-transparency record chunk is full');
      }
      const serialized = JSON.stringify({
        protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_RECORD_STORE,
        records: merged,
      });
      if (!await storage.set(key, serialized)) {
        throw new Error('Key-transparency records could not be persisted');
      }
    }

    const checkpointValue = JSON.stringify({
      protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_CHECKPOINT,
      epoch: checkpoint.epoch,
      entryCount: checkpoint.entryCount,
      rootHash: checkpoint.rootHash,
    });
    const checkpointKey = storageKey(accountScope, STORAGE_KEYS.KEY_TRANSPARENCY_CHECKPOINT);
    if (
      !await storage.set(checkpointKey, checkpointValue) ||
      await storage.get(checkpointKey) !== checkpointValue
    ) throw new Error('Key-transparency checkpoint could not be persisted');
    await assertCurrentServerContext(context);
  });
}

// Every record published under a contacts label, from genesis to `throughEpoch`
export async function findKeyTransparencyRecordsForContact(
  context: CurrentServerContext,
  ownerUsername: string,
  discoveryEncryptionKey: Uint8Array,
  throughEpoch: number,
): Promise<StoredKeyTransparencyRecord[]> {
  if (!(discoveryEncryptionKey instanceof Uint8Array) || discoveryEncryptionKey.length !== 32) {
    throw new Error('Invalid key-transparency discovery key');
  }
  if (!Number.isSafeInteger(throughEpoch) || throughEpoch < 0) {
    throw new Error('Invalid key-transparency epoch');
  }
  const accountScope = deriveLocalAccountScope(context, normalizeOwner(ownerUsername));
  const lastChunk = keyTransparencyChunkIndex(throughEpoch);
  const matches: StoredKeyTransparencyRecord[] = [];

  for (let index = 0; index <= lastChunk; index += 1) {
    const chunk = parseChunk(await storage.get(storageKey(accountScope, `chunk:${index}`)));
    await assertCurrentServerContext(context);
    if (chunk.length === 0) continue;
    
    const labelByEpoch = new Map<number, string>();
    for (const record of chunk) {
      if (record.epoch > throughEpoch) continue;
      let label = labelByEpoch.get(record.epoch);
      if (label === undefined) {
        label = deriveKeyTransparencyEpochLabel(discoveryEncryptionKey, record.epoch);
        labelByEpoch.set(record.epoch, label);
      }
      if (record.epochLabel === label) matches.push(record);
    }
  }

  matches.sort((left, right) => left.epoch - right.epoch || left.version - right.version);
  return matches;
}

// Cache a signed transition received out of band.
export async function saveKeyTransparencyTransition(
  context: CurrentServerContext,
  ownerUsername: string,
  recordHash: string,
  transition: unknown,
): Promise<void> {
  if (!isKeyTransparencyHash(recordHash)) throw new Error('Invalid key-transparency record hash');
  const owner = normalizeOwner(ownerUsername);
  await enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, owner);
    const serialized = JSON.stringify(transition);
    if (serialized.length > MAX_TRANSITION_CHARS) {
      throw new Error('Key-transparency transition is too large');
    }
    if (!await storage.set(storageKey(accountScope, `transition:${recordHash}`), serialized)) {
      throw new Error('Key-transparency transition could not be persisted');
    }
    await assertCurrentServerContext(context);
  });
}

export async function loadKeyTransparencyTransition(
  context: CurrentServerContext,
  ownerUsername: string,
  recordHash: string,
): Promise<unknown | null> {
  if (!isKeyTransparencyHash(recordHash)) throw new Error('Invalid key-transparency record hash');
  const accountScope = deriveLocalAccountScope(context, normalizeOwner(ownerUsername));
  const raw = await storage.get(storageKey(accountScope, `transition:${recordHash}`));
  await assertCurrentServerContext(context);
  if (raw === null) return null;
  if (raw.length > MAX_TRANSITION_CHARS) {
    corruptRecordStore('Stored key-transparency transition is corrupt');
  }
  try {
    return JSON.parse(raw);
  } catch {
    corruptRecordStore('Stored key-transparency transition is corrupt');
  }
}

export async function saveOwnKeyTransparencyTransition(
  context: CurrentServerContext,
  ownerUsername: string,
  transition: unknown,
): Promise<void> {
  const owner = normalizeOwner(ownerUsername);
  await enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, owner);
    const serialized = JSON.stringify(transition);
    if (serialized.length > MAX_TRANSITION_CHARS) {
      throw new Error('Key-transparency transition is too large');
    }
    if (!await storage.set(storageKey(accountScope, STORAGE_KEYS.KEY_TRANSPARENCY_OWN_TRANSITION), serialized)) {
      throw new Error('Key-transparency transition could not be persisted');
    }
    await assertCurrentServerContext(context);
  });
}

export async function loadOwnKeyTransparencyTransition(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<unknown | null> {
  const accountScope = deriveLocalAccountScope(context, normalizeOwner(ownerUsername));
  const raw = await storage.get(storageKey(accountScope, STORAGE_KEYS.KEY_TRANSPARENCY_OWN_TRANSITION));
  await assertCurrentServerContext(context);
  if (raw === null) return null;
  if (raw.length > MAX_TRANSITION_CHARS) {
    corruptRecordStore('Stored key-transparency transition is corrupt');
  }
  try {
    return JSON.parse(raw);
  } catch {
    corruptRecordStore('Stored key-transparency transition is corrupt');
  }
}
