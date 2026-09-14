/**
 * Persisted Discovery Material
 */

import { storage } from '../tauri-bindings';
import { getCurrentLocalAccountScope } from '../security/local-account-scope';
import { canonicalAuthUsername, hasExactKeys, hasPrototypePollutionKeys, isPlainRecord } from '../sanitizers';
import { deriveScopedStorageKey } from '../security/scoped-storage-key';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { SPOOL_DETECTION_KEY_BYTES } from '../../../shared/spool-tag-protocol.js';
import { isKeyTransparencyHash } from '../../../shared/key-transparency-protocol.js';

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

const DETECTION_KEY_RE = new RegExp(`^[a-f0-9]{${SPOOL_DETECTION_KEY_BYTES * 2}}$`);

function parseTransparency(value: unknown): PersistedDiscoveryTransparency | null {
  if (value === null) return null;
  if (
    !isPlainRecord(value) ||
    hasPrototypePollutionKeys(value) ||
    !hasExactKeys(value, ['rootCommitment', 'version']) ||
    !isKeyTransparencyHash(value.rootCommitment) ||
    !Number.isSafeInteger(value.version) ||
    (value.version as number) < 1
  ) throw new Error('Invalid persisted discovery transparency state');
  return { rootCommitment: value.rootCommitment as string, version: value.version as number };
}

export async function loadPersistedDiscoveryMaterial(
  owner: string,
  peer: string
): Promise<PersistedDiscoveryRecord | null> {
  const raw = await storage.get(await persistedKey(owner, peer));
  if (raw === null) return null;
  if (raw.length === 0 || raw.length > MAX_PERSISTED_DISCOVERY_CHARS) {
    throw new Error('Invalid persisted discovery material');
  }
  const parsed = JSON.parse(raw);
  if (
    !isPlainRecord(parsed) ||
    hasPrototypePollutionKeys(parsed) ||
    !hasExactKeys(parsed, ['material', 'protocol', 'transparency']) ||
    parsed.protocol !== PROTOCOL_KEYS.DISCOVERY_MATERIAL_STORE ||
    !isPlainRecord(parsed.material) ||
    hasPrototypePollutionKeys(parsed.material) ||
    !isPlainRecord(parsed.material.publicKeys) ||
    hasPrototypePollutionKeys(parsed.material.publicKeys) ||
    typeof parsed.material.publicKeys.kyberPublicBase64 !== 'string' ||
    typeof parsed.material.spoolDetectionKey !== 'string' ||
    !DETECTION_KEY_RE.test(parsed.material.spoolDetectionKey)
  ) throw new Error('Invalid persisted discovery material');
  return { material: parsed.material, transparency: parseTransparency(parsed.transparency) };
}

export async function savePersistedDiscoveryMaterial(
  owner: string,
  peer: string,
  material: unknown,
  transparency: PersistedDiscoveryTransparency | null
): Promise<void> {
  if (!isPlainRecord(material) || hasPrototypePollutionKeys(material)) {
    throw new Error('Invalid discovery material');
  }
  const validatedTransparency = parseTransparency(transparency);
  const serialized = JSON.stringify({
    protocol: PROTOCOL_KEYS.DISCOVERY_MATERIAL_STORE,
    material,
    transparency: validatedTransparency,
  });
  if (serialized.length > MAX_PERSISTED_DISCOVERY_CHARS) {
    throw new Error('Persisted discovery material is too large');
  }
  const key = await persistedKey(owner, peer);
  if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
    throw new Error('Persisted discovery material could not be verified');
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
  const key = await persistedKey(owner, peer);
  if (!await storage.remove(key) || await storage.has(key)) {
    throw new Error('Persisted discovery material could not be removed');
  }
}
