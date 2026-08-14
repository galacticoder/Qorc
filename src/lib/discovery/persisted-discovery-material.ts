/**
 * Persisted Discovery Material
 */

import { storage } from '../tauri-bindings';
import { getCurrentLocalAccountScope } from '../security/local-account-scope';
import { canonicalAuthUsername, isPlainRecord as plainObject } from '../sanitizers';
import { deriveScopedStorageKey } from '../security/scoped-storage-key';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';

const MAX_PERSISTED_DISCOVERY_CHARS = 256 * 1024;

const persistedKey = async (owner: string, peer: string): Promise<string> => {
  const accountScope = await getCurrentLocalAccountScope(
    canonicalAuthUsername(owner, 'discovery material owner')
  );
  return deriveScopedStorageKey(
    STORAGE_PREFIXES.DISCOVERY_MATERIAL,
    STORAGE_KEY_DOMAINS.DISCOVERY_MATERIAL,
    accountScope,
    canonicalAuthUsername(peer, 'discovery material peer')
  );
};

export interface PersistedDiscoveryTransparency {
  rootCommitment: string;
  version: number;
}

export interface PersistedDiscoveryRecord {
  material: Record<string, unknown>;
  transparency: PersistedDiscoveryTransparency | null;
}

const ROOT_COMMITMENT_RE = /^[a-f0-9]{64}$/;

function validTransparency(value: unknown): PersistedDiscoveryTransparency | null {
  if (!plainObject(value)) return null;
  if (
    typeof value.rootCommitment !== 'string' ||
    !ROOT_COMMITMENT_RE.test(value.rootCommitment) ||
    !Number.isSafeInteger(value.version) ||
    (value.version as number) < 0
  ) return null;
  return { rootCommitment: value.rootCommitment, version: value.version as number };
}

export async function loadPersistedDiscoveryMaterial(
  owner: string,
  peer: string
): Promise<PersistedDiscoveryRecord | null> {
  try {
    const raw = await storage.get(await persistedKey(owner, peer));
    if (!raw || raw.length > MAX_PERSISTED_DISCOVERY_CHARS) return null;
    const parsed = JSON.parse(raw, (key, value) => (
      key === '__proto__' || key === 'prototype' || key === 'constructor' ? undefined : value
    ));
    if (!plainObject(parsed) || !plainObject(parsed.material)) return null;
    const material = parsed.material;
    
    if (!plainObject(material.publicKeys) || typeof material.publicKeys.kyberPublicBase64 !== 'string') {
      return null;
    }
    return { material, transparency: validTransparency(parsed.transparency) };
  } catch {
    return null;
  }
}

export async function savePersistedDiscoveryMaterial(
  owner: string,
  peer: string,
  material: unknown,
  transparency: PersistedDiscoveryTransparency | null
): Promise<void> {
  if (!plainObject(material)) return;
  try {
    const serialized = JSON.stringify({
      material,
      ...(validTransparency(transparency) ? { transparency } : {}),
    });
    if (
      typeof serialized !== 'string' ||
      serialized.length > MAX_PERSISTED_DISCOVERY_CHARS
    ) return;
    await storage.set(await persistedKey(owner, peer), serialized);
  } catch {
  }
}

export function discoveryMaterialStillVouchedFor(
  record: PersistedDiscoveryRecord | null,
  live: PersistedDiscoveryTransparency | null
): Record<string, unknown> | null {
  if (!record || !record.transparency || !live) return null;
  if (
    record.transparency.rootCommitment !== live.rootCommitment ||
    record.transparency.version !== live.version
  ) return null;
  return record.material;
}

export async function clearPersistedDiscoveryMaterial(owner: string, peer: string): Promise<void> {
  try {
    await storage.remove(await persistedKey(owner, peer));
  } catch {
  }
}
