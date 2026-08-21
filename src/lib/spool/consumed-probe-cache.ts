import { isSpoolProbeHex } from '../../../shared/spool-tag-protocol.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { canonicalAuthUsername, hasExactKeys, isPlainObject } from '../sanitizers';
import { getCurrentLocalAccountScope } from '../security/local-account-scope';
import { deriveScopedStorageKey } from '../security/scoped-storage-key';
import { storage } from '../tauri-bindings';

const CONSUMED_PROBE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_CONSUMED_PROBES = 32_768;
const MAX_SERIALIZED_CHARS = 4 * 1024 * 1024;
const MAX_ACCOUNT_STATES = 4;

type ProbeEntries = Map<string, number>;

interface AccountState {
  entries: ProbeEntries;
  loaded: boolean;
  loading: Promise<void> | null;
  writeTail: Promise<void>;
}

export interface ConsumedSpoolProbeCache {
  readonly scope: string;
  readonly probes: ReadonlySet<string>;
  remember(probes: readonly string[]): Promise<void>;
}

const states = new Map<string, AccountState>();

function prune(entries: ProbeEntries, now: number): void {
  for (const [probe, expiresAt] of entries) {
    if (expiresAt <= now) entries.delete(probe);
  }
  if (entries.size <= MAX_CONSUMED_PROBES) return;
  const oldest = [...entries.entries()]
    .sort((left, right) => left[1] - right[1] || left[0].localeCompare(right[0]));
  for (let index = 0; index < oldest.length - MAX_CONSUMED_PROBES; index += 1) {
    entries.delete(oldest[index][0]);
  }
}

function parseSnapshot(raw: string | null, now: number): ProbeEntries {
  const entries: ProbeEntries = new Map();
  if (!raw || raw.length > MAX_SERIALIZED_CHARS) return entries;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      !isPlainObject(parsed) ||
      !hasExactKeys(parsed, ['entries', 'protocol']) ||
      parsed.protocol !== PROTOCOL_KEYS.SPOOL_CONSUMED_PROBE_STORE ||
      !Array.isArray(parsed.entries) ||
      parsed.entries.length > MAX_CONSUMED_PROBES
    ) return entries;
    for (const value of parsed.entries) {
      if (
        !Array.isArray(value) ||
        value.length !== 2 ||
        !isSpoolProbeHex(value[0]) ||
        !Number.isSafeInteger(value[1]) ||
        value[1] <= now ||
        value[1] > now + CONSUMED_PROBE_TTL_MS ||
        entries.has(value[0])
      ) return new Map();
      entries.set(value[0], value[1]);
    }
    return entries;
  } catch {
    return new Map();
  }
}

function serializeSnapshot(entries: ProbeEntries): string {
  const serialized = JSON.stringify({
    protocol: PROTOCOL_KEYS.SPOOL_CONSUMED_PROBE_STORE,
    entries: [...entries.entries()]
      .sort((left, right) => left[1] - right[1] || left[0].localeCompare(right[0])),
  });
  if (serialized.length > MAX_SERIALIZED_CHARS) {
    throw new Error('Consumed spool probe cache is too large');
  }
  return serialized;
}

async function cacheKey(owner: string): Promise<string> {
  const normalized = canonicalAuthUsername(owner, 'spool probe cache owner');
  const accountScope = await getCurrentLocalAccountScope(normalized);
  return deriveScopedStorageKey(
    STORAGE_PREFIXES.SPOOL_CONSUMED_PROBES,
    STORAGE_KEY_DOMAINS.SPOOL_CONSUMED_PROBES,
    accountScope,
  );
}

function stateFor(key: string): AccountState {
  let state = states.get(key);
  if (!state) {
    state = {
      entries: new Map(),
      loaded: false,
      loading: null,
      writeTail: Promise.resolve(),
    };
  } else {
    states.delete(key);
  }
  states.set(key, state);
  while (states.size > MAX_ACCOUNT_STATES) {
    const oldest = states.keys().next().value;
    if (oldest === undefined || oldest === key) break;
    states.delete(oldest);
  }
  return state;
}

async function loadState(key: string, state: AccountState): Promise<void> {
  if (state.loaded) return;
  if (!state.loading) {
    state.loading = (async () => {
      const raw = await storage.get(key).catch(() => null);
      state.entries = parseSnapshot(raw, Date.now());
      state.loaded = true;
    })().finally(() => {
      state.loading = null;
    });
  }
  await state.loading;
}

async function rememberInState(
  key: string,
  state: AccountState,
  probes: readonly string[],
): Promise<void> {
  await loadState(key, state);
  const now = Date.now();
  prune(state.entries, now);
  for (const probe of probes) {
    if (!isSpoolProbeHex(probe)) continue;
    const currentExpiry = state.entries.get(probe);
    if (currentExpiry === undefined || currentExpiry <= now) {
      state.entries.set(probe, now + CONSUMED_PROBE_TTL_MS);
    }
  }
  prune(state.entries, now);
  state.writeTail = state.writeTail.catch(() => {}).then(async () => {
    prune(state.entries, Date.now());
    const serialized = serializeSnapshot(state.entries);
    if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
      throw new Error('Consumed spool probe cache could not be persisted');
    }
  });
  await state.writeTail.catch(() => {});
}

export async function loadConsumedSpoolProbeCache(
  owner: string,
): Promise<ConsumedSpoolProbeCache> {
  const key = await cacheKey(owner);
  const state = stateFor(key);
  await loadState(key, state);
  prune(state.entries, Date.now());
  return {
    scope: key,
    probes: new Set(state.entries.keys()),
    remember: (probes) => rememberInState(key, state, probes),
  };
}
