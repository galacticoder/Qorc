import { useEffect, useState } from 'react';

import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  exactPlainObject,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
} from '../../../shared/key-transparency-protocol.js';
import {
  assertCurrentServerContext,
  captureCurrentServerContext,
  deriveLocalAccountScope,
  type CurrentServerContext,
} from '../security/local-account-scope';
import { storage } from '../tauri-bindings';
import type { VerifiedKeyTransparencyContactState } from './types';
import { createStoreLock } from './store-lock';
import { canonicalAuthUsername } from '../sanitizers';
import { keyTransparencyStoreKey } from './store-key';
import {
  hasUniqueCollectionFields,
  parseProtocolCollectionStore,
} from './store-serialization';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';

const WARNING_KEYS = [
  'activatesAtEpoch',
  'label',
  'peer',
  'pendingRootCommitment',
  'version',
];
const MAX_WARNINGS = 2048;

export interface KeyTransparencyRecoveryWarning {
  peer: string;
  label: string;
  version: number;
  pendingRootCommitment: string;
  activatesAtEpoch: number;
}

const warnings = new Map<string, KeyTransparencyRecoveryWarning>();
const listeners = new Set<() => void>();
let activeAccountScope: string | null = null;
let activeStorageKey: string | null = null;
let generation = 0;
const enqueue = createStoreLock();

export class KeyTransparencyWarningStoreCorruptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyTransparencyWarningStoreCorruptionError';
  }
}

function corruptWarningStore(message: string): never {
  throw new KeyTransparencyWarningStoreCorruptionError(message);
}

function emit(): void {
  for (const listener of listeners) listener();
}

function normalizedPeer(peer: string): string {
  return canonicalAuthUsername(peer, 'key-transparency warning peer');
}

function warningStorageKey(accountScope: string): string {
  return keyTransparencyStoreKey(
    STORAGE_PREFIXES.KEY_TRANSPARENCY_WARNING,
    STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_WARNING,
    accountScope
  );
}

function parseWarning(value: unknown): KeyTransparencyRecoveryWarning {
  const warning = value as KeyTransparencyRecoveryWarning;
  let peer: string;
  try {
    peer = normalizedPeer(warning?.peer);
  } catch {
    corruptWarningStore('Stored key-transparency warning is corrupt');
  }
  if (
    !exactPlainObject(warning, WARNING_KEYS) ||
    peer !== warning.peer ||
    !isKeyTransparencyLabel(warning.label) ||
    !Number.isSafeInteger(warning.version) ||
    warning.version < 1 ||
    warning.version > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
    !isKeyTransparencyHash(warning.pendingRootCommitment) ||
    !Number.isSafeInteger(warning.activatesAtEpoch) ||
    warning.activatesAtEpoch < 0
  ) corruptWarningStore('Stored key-transparency warning is corrupt');
  return { ...warning };
}

function parseWarningStore(raw: string | null): KeyTransparencyRecoveryWarning[] {
  const result = parseProtocolCollectionStore(raw, {
    protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_WARNING_STORE,
    collectionKey: 'warnings',
    maxEntries: MAX_WARNINGS,
    parseEntry: parseWarning,
    corrupt: corruptWarningStore,
    parseError: 'Stored key-transparency warnings are corrupt',
    structureError: 'Stored key-transparency warnings are corrupt',
  });
  if (!hasUniqueCollectionFields(result, ['peer', 'label'])) {
    corruptWarningStore('Stored key-transparency warnings contain duplicates');
  }
  return result;
}

function serializedWarnings(): string {
  return JSON.stringify({
    protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_WARNING_STORE,
    warnings: Array.from(warnings.values()).sort((left, right) => left.peer.localeCompare(right.peer)),
  });
}

async function loadScope(
  context: CurrentServerContext,
  ownerUsername: string,
  expectedGeneration: number,
): Promise<void> {
  const accountScope = deriveLocalAccountScope(context, ownerUsername);
  const key = warningStorageKey(accountScope);
  const stored = parseWarningStore(await storage.get(key));
  await assertCurrentServerContext(context);
  if (expectedGeneration !== generation) throw new Error('Key-transparency warning account changed');
  warnings.clear();
  for (const warning of stored) warnings.set(warning.peer, warning);
  activeAccountScope = accountScope;
  activeStorageKey = key;
  emit();
}

async function persist(expectedGeneration: number): Promise<void> {
  if (expectedGeneration !== generation || !activeStorageKey) {
    throw new Error('Key-transparency warning account changed');
  }
  const serialized = serializedWarnings();
  if (!await storage.set(activeStorageKey, serialized) || await storage.get(activeStorageKey) !== serialized) {
    throw new Error('Key-transparency warning could not be persisted');
  }
}

export const keyTransparencyWarningStore = {
  async activate(ownerUsername: string): Promise<void> {
    const expectedGeneration = ++generation;
    warnings.clear();
    activeAccountScope = null;
    activeStorageKey = null;
    emit();
    const context = await captureCurrentServerContext();
    await enqueue(() => loadScope(context, normalizedPeer(ownerUsername), expectedGeneration));
  },

  async update(
    context: CurrentServerContext,
    ownerUsername: string,
    peer: string,
    contact: VerifiedKeyTransparencyContactState,
  ): Promise<void> {
    const expectedGeneration = generation;
    const normalizedOwner = normalizedPeer(ownerUsername);
    const normalized = normalizedPeer(peer);
    await enqueue(async () => {
      await assertCurrentServerContext(context);
      if (expectedGeneration !== generation) throw new Error('Key-transparency warning account changed');
      const accountScope = deriveLocalAccountScope(context, normalizedOwner);
      if (activeAccountScope !== accountScope) {
        await loadScope(context, normalizedOwner, expectedGeneration);
      }
      if (
        contact.state === 'recovery-pending' &&
        contact.pendingRootCommitment &&
        contact.recoveryActivatesAtEpoch !== null
      ) {
        warnings.set(normalized, {
          peer: normalized,
          label: contact.label,
          version: contact.version,
          pendingRootCommitment: contact.pendingRootCommitment,
          activatesAtEpoch: contact.recoveryActivatesAtEpoch,
        });
      } else {
        warnings.delete(normalized);
      }
      if (warnings.size > MAX_WARNINGS) throw new Error('Too many key-transparency warnings');
      await persist(expectedGeneration);
      emit();
    });
  },

  clear(): void {
    generation += 1;
    warnings.clear();
    activeAccountScope = null;
    activeStorageKey = null;
    emit();
  },

  get(peer: string | null | undefined): KeyTransparencyRecoveryWarning | null {
    if (!peer) return null;
    try {
      return warnings.get(normalizedPeer(peer)) ?? null;
    } catch {
      return null;
    }
  },

  list(): KeyTransparencyRecoveryWarning[] {
    return Array.from(warnings.values()).map((warning) => ({ ...warning }));
  },

  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  },
};

export function useKeyTransparencyRecoveryWarning(
  peer: string | null | undefined,
): KeyTransparencyRecoveryWarning | null {
  const [warning, setWarning] = useState(() => keyTransparencyWarningStore.get(peer));
  useEffect(() => {
    const refresh = () => setWarning(keyTransparencyWarningStore.get(peer));
    refresh();
    return keyTransparencyWarningStore.subscribe(refresh);
  }, [peer]);
  return warning;
}
