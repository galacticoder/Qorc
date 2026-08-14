import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  exactPlainObject,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
} from '../../../shared/key-transparency-protocol.js';
import { Base64 } from '../cryptography/base64';
import {
  assertCurrentServerContext,
  deriveLocalAccountScope,
  type CurrentServerContext,
} from '../security/local-account-scope';
import { storage } from '../tauri-bindings';
import { deriveKeyTransparencyLabel } from './crypto';
import { createStoreLock } from './store-lock';
import { canonicalAuthUsername } from '../sanitizers';
import { keyTransparencyStoreKey } from './store-key';
import {
  hasUniqueCollectionFields,
  parseProtocolCollectionStore,
} from './store-serialization';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';

const MAX_MONITORED_CONTACTS = 2048;
const MONITOR_ENTRY_KEYS = ['discoveryKey', 'label', 'lastCheckedAt', 'peer', 'rootCommitment', 'version'];
const enqueue = createStoreLock();

export class KeyTransparencyMonitorStoreCorruptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyTransparencyMonitorStoreCorruptionError';
  }
}

function corruptMonitorStore(message: string): never {
  throw new KeyTransparencyMonitorStoreCorruptionError(message);
}

export interface KeyTransparencyMonitorTarget {
  peer: string;
  label: string;
  discoveryEncryptionKey: Uint8Array;
  lastCheckedAt: number;
  rootCommitment: string;
  version: number;
}

interface StoredMonitorTarget {
  peer: string;
  label: string;
  discoveryKey: string;
  lastCheckedAt: number;
  rootCommitment: string;
  version: number;
}

function normalizePeer(peer: string): string {
  return canonicalAuthUsername(peer, 'key-transparency monitor peer');
}

function monitorStorageKey(accountScope: string): string {
  return keyTransparencyStoreKey(
    STORAGE_PREFIXES.KEY_TRANSPARENCY_MONITOR,
    STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_MONITOR,
    accountScope
  );
}

function parseEntry(value: unknown): StoredMonitorTarget {
  const entry = value as StoredMonitorTarget;
  let peer: string;
  try {
    peer = normalizePeer(entry?.peer);
  } catch {
    corruptMonitorStore('Stored key-transparency monitor target is corrupt');
  }
  if (
    !exactPlainObject(entry, MONITOR_ENTRY_KEYS) ||
    peer !== entry.peer ||
    !isKeyTransparencyLabel(entry.label) ||
    typeof entry.discoveryKey !== 'string' ||
    !Number.isSafeInteger(entry.lastCheckedAt) ||
    entry.lastCheckedAt < 0 ||
    !isKeyTransparencyHash(entry.rootCommitment) ||
    !Number.isSafeInteger(entry.version) ||
    entry.version < 1 ||
    entry.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
  ) corruptMonitorStore('Stored key-transparency monitor target is corrupt');
  let key: Uint8Array | null = null;
  try {
    key = Base64.base64ToUint8Array(entry.discoveryKey);
    if (
      key.length !== 32 ||
      Base64.arrayBufferToBase64(key) !== entry.discoveryKey ||
      deriveKeyTransparencyLabel(key) !== entry.label
    ) corruptMonitorStore('Stored key-transparency monitor target is corrupt');
  } catch (error) {
    if (error instanceof KeyTransparencyMonitorStoreCorruptionError) throw error;
    corruptMonitorStore('Stored key-transparency monitor target is corrupt');
  } finally {
    key?.fill(0);
  }
  return { ...entry };
}

function parseStore(raw: string | null): StoredMonitorTarget[] {
  const targets = parseProtocolCollectionStore(raw, {
    protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_MONITOR_STORE,
    collectionKey: 'targets',
    maxEntries: MAX_MONITORED_CONTACTS,
    parseEntry,
    corrupt: corruptMonitorStore,
    parseError: 'Stored key-transparency monitor list is corrupt',
    structureError: 'Stored key-transparency monitor list is corrupt',
  });
  if (!hasUniqueCollectionFields(targets, ['peer', 'label'])) {
    corruptMonitorStore('Stored key-transparency monitor list contains duplicates');
  }
  return targets;
}

async function readStore(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<{ key: string; targets: StoredMonitorTarget[] }> {
  const accountScope = deriveLocalAccountScope(context, normalizePeer(ownerUsername));
  const key = monitorStorageKey(accountScope);
  const targets = parseStore(await storage.get(key));
  await assertCurrentServerContext(context);
  return { key, targets };
}

async function writeStore(key: string, targets: StoredMonitorTarget[]): Promise<void> {
  if (targets.length > MAX_MONITORED_CONTACTS) throw new Error('Too many monitored contacts');
  const serialized = JSON.stringify({
    protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_MONITOR_STORE,
    targets: [...targets].sort((left, right) => left.peer.localeCompare(right.peer)),
  });
  if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
    throw new Error('Key-transparency monitor list could not be persisted');
  }
}

export async function upsertKeyTransparencyMonitorTarget(
  context: CurrentServerContext,
  ownerUsername: string,
  peer: string,
  discoveryEncryptionKey: Uint8Array,
  contact: { label: string; rootCommitment: string; version: number },
  expectedPrevious: { rootCommitment: string; version: number } | null,
): Promise<void> {
  if (!(discoveryEncryptionKey instanceof Uint8Array) || discoveryEncryptionKey.length !== 32) {
    throw new Error('Invalid key-transparency monitor key');
  }
  const normalized = normalizePeer(peer);
  const label = deriveKeyTransparencyLabel(discoveryEncryptionKey);
  if (
    contact?.label !== label ||
    !isKeyTransparencyHash(contact.rootCommitment) ||
    !Number.isSafeInteger(contact.version) ||
    contact.version < 1 ||
    contact.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
  ) throw new Error('Invalid key-transparency monitor contact state');
  const discoveryKey = Base64.arrayBufferToBase64(discoveryEncryptionKey);
  await enqueue(async () => {
    const store = await readStore(context, ownerUsername);
    const existing = store.targets.find((entry) => entry.peer === normalized);
    if (existing && existing.label !== label) {
      throw new Error('Monitored contact transparency label changed');
    }
    if (
      (existing === undefined) !== (expectedPrevious === null) ||
      (existing && expectedPrevious &&
        (existing.rootCommitment !== expectedPrevious.rootCommitment ||
          existing.version !== expectedPrevious.version))
    ) {
      corruptMonitorStore('Stored key-transparency monitor checkpoint changed during verification');
    }
    if (existing && (
      contact.version < existing.version ||
      (contact.version === existing.version && contact.rootCommitment !== existing.rootCommitment)
    )) {
      corruptMonitorStore('Stored key-transparency monitor checkpoint is not append-only');
    }
    const next = store.targets.filter((entry) => entry.peer !== normalized);
    next.push({
      peer: normalized,
      label,
      discoveryKey,
      lastCheckedAt: existing?.lastCheckedAt ?? 0,
      rootCommitment: contact.rootCommitment,
      version: contact.version,
    });
    await writeStore(store.key, next);
    await assertCurrentServerContext(context);
  });
}

export async function listKeyTransparencyMonitorTargets(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<KeyTransparencyMonitorTarget[]> {
  return enqueue(async () => {
    const store = await readStore(context, ownerUsername);
    return store.targets.map((entry) => ({
      peer: entry.peer,
      label: entry.label,
      discoveryEncryptionKey: Base64.base64ToUint8Array(entry.discoveryKey),
      lastCheckedAt: entry.lastCheckedAt,
      rootCommitment: entry.rootCommitment,
      version: entry.version,
    }));
  });
}

export async function readKeyTransparencyMonitorTarget(
  context: CurrentServerContext,
  ownerUsername: string,
  peer: string,
): Promise<KeyTransparencyMonitorTarget | null> {
  const normalized = normalizePeer(peer);
  return enqueue(async () => {
    const store = await readStore(context, ownerUsername);
    const entry = store.targets.find((candidate) => candidate.peer === normalized);
    if (!entry) return null;
    return {
      peer: entry.peer,
      label: entry.label,
      discoveryEncryptionKey: Base64.base64ToUint8Array(entry.discoveryKey),
      lastCheckedAt: entry.lastCheckedAt,
      rootCommitment: entry.rootCommitment,
      version: entry.version,
    };
  });
}

export async function markKeyTransparencyMonitorTargetChecked(
  context: CurrentServerContext,
  ownerUsername: string,
  label: string,
  checkedAt: number,
  contact: { label: string; rootCommitment: string; version: number },
): Promise<void> {
  if (
    !isKeyTransparencyLabel(label) ||
    !Number.isSafeInteger(checkedAt) ||
    checkedAt < 0 ||
    contact?.label !== label ||
    !isKeyTransparencyHash(contact.rootCommitment) ||
    !Number.isSafeInteger(contact.version) ||
    contact.version < 1 ||
    contact.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
  ) {
    throw new Error('Invalid key-transparency monitor checkpoint');
  }
  await enqueue(async () => {
    const store = await readStore(context, ownerUsername);
    const target = store.targets.find((entry) => entry.label === label);
    if (!target) throw new Error('Key-transparency monitor target disappeared');
    if (
      contact.version < target.version ||
      (contact.version === target.version && contact.rootCommitment !== target.rootCommitment)
    ) {
      corruptMonitorStore('Stored key-transparency monitor checkpoint is not append-only');
    }
    target.lastCheckedAt = Math.floor(checkedAt / 60_000) * 60_000;
    target.rootCommitment = contact.rootCommitment;
    target.version = contact.version;
    await writeStore(store.key, store.targets);
    await assertCurrentServerContext(context);
  });
}

export async function removeKeyTransparencyMonitorPeer(
  context: CurrentServerContext,
  ownerUsername: string,
  peer: string,
): Promise<void> {
  const normalized = normalizePeer(peer);
  await enqueue(async () => {
    const store = await readStore(context, ownerUsername);
    const next = store.targets.filter((entry) => entry.peer !== normalized);
    if (next.length === store.targets.length) return;
    await writeStore(store.key, next);
    await assertCurrentServerContext(context);
  });
}
