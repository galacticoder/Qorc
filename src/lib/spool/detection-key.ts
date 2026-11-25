import { MAX_SPOOL_PEER_DETECTION_KEYS } from '../constants';
import { x25519 } from '@noble/curves/ed25519.js';
import { storage } from '../tauri-bindings';
import { getCurrentLocalAccountScope } from '../security/local-account-scope';
import { PostQuantumRandom } from '../cryptography/random';
import { canonicalAuthUsername } from '../sanitizers';
import { deriveScopedStorageKey } from '../security/scoped-storage-key';
import {
  SPOOL_DETECTION_KEY_BYTES,
  SPOOL_DETECTION_PROBE_HEX_CHARS,
  spoolDetectionTag,
} from '../../../shared/spool-tag-protocol.js';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { bytesToHex, hexToBytes } from '../../../shared/bytes.js';

export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function fromHex(value: unknown, expectedBytes: number): Uint8Array | null {
  return hexToBytes(value, { exactBytes: expectedBytes });
}

type DetectionKey = { privateKey: Uint8Array; publicHex: string };

let generation = 0;
let cachedKey: { scope: string; key: DetectionKey } | null = null;
const pendingKeys = new Map<string, { generation: number; task: Promise<DetectionKey> }>();

function assertCurrent(expected: number): void {
  if (generation !== expected) throw new DOMException('Detection key account changed', 'AbortError');
}

async function loadOrCreate(accountScope: string, expected: number): Promise<DetectionKey> {
  assertCurrent(expected);
  if (cachedKey?.scope === accountScope) return cachedKey.key;
  const pending = pendingKeys.get(accountScope);
  if (pending?.generation === expected) return pending.task;
  if (pending) {
    await pending.task.catch(() => { });
    return loadOrCreate(accountScope, expected);
  }

  const storageKey = deriveScopedStorageKey(
    STORAGE_PREFIXES.SPOOL_DETECTION,
    STORAGE_KEY_DOMAINS.SPOOL_DETECTION,
    accountScope,
  );
  const loading = (async () => {
    const stored = await storage.get(storageKey);
    assertCurrent(expected);
    const privateKey = stored === null
      ? PostQuantumRandom.randomBytes(SPOOL_DETECTION_KEY_BYTES)
      : fromHex(stored, SPOOL_DETECTION_KEY_BYTES);
    if (!privateKey) throw new Error('Stored detection key is invalid');

    try {
      if (stored === null) {
        const serialized = toHex(privateKey);
        if (!await storage.set(storageKey, serialized)) throw new Error('Detection key could not be stored');
        assertCurrent(expected);
        if (await storage.get(storageKey) !== serialized) throw new Error('Detection key could not be verified');
      }
      assertCurrent(expected);
      const key = { privateKey, publicHex: toHex(x25519.getPublicKey(privateKey)) };
      cachedKey?.key.privateKey.fill(0);
      cachedKey = { scope: accountScope, key };
      return key;
    } catch (error) {
      privateKey.fill(0);
      throw error;
    }
  })();
  pendingKeys.set(accountScope, { generation: expected, task: loading });
  try {
    return await loading;
  } finally {
    if (pendingKeys.get(accountScope)?.task === loading) pendingKeys.delete(accountScope);
  }
}

export async function ownDetectionPublicKeyHex(owner: string): Promise<string> {
  const expected = generation;
  const scope = await getCurrentLocalAccountScope(owner);
  const key = await loadOrCreate(scope, expected);
  assertCurrent(expected);
  return key.publicHex;
}

export async function createDetectionTagMatcher(accountScope: string, signal?: AbortSignal) {
  const expected = generation;
  signal?.throwIfAborted();
  const key = await loadOrCreate(accountScope, expected);
  return (probeHex: string): string | null => {
    signal?.throwIfAborted();
    assertCurrent(expected);
    if (cachedKey?.key !== key || probeHex.length !== SPOOL_DETECTION_PROBE_HEX_CHARS) return null;
    const probe = fromHex(probeHex, SPOOL_DETECTION_KEY_BYTES);
    if (!probe) return null;
    let shared: Uint8Array | null = null;
    try {
      shared = x25519.getSharedSecret(key.privateKey, probe);
      return spoolDetectionTag(shared);
    } catch {
      return null;
    } finally {
      shared?.fill(0);
      probe.fill(0);
    }
  };
}

export async function detectionTagForProbe(owner: string, probeHex: string): Promise<string | null> {
  if (typeof probeHex !== 'string' || probeHex.length !== SPOOL_DETECTION_PROBE_HEX_CHARS) return null;
  const expected = generation;
  const scope = await getCurrentLocalAccountScope(owner);
  assertCurrent(expected);
  const matchProbe = await createDetectionTagMatcher(scope);
  return matchProbe(probeHex);
}

export function firstContactProbe(recipientPublicHex: unknown): { probe: string; tag: string } | null {
  const recipient = fromHex(recipientPublicHex, SPOOL_DETECTION_KEY_BYTES);
  if (!recipient) return null;
  const ephemeral = PostQuantumRandom.randomBytes(SPOOL_DETECTION_KEY_BYTES);
  let shared: Uint8Array | null = null;
  try {
    shared = x25519.getSharedSecret(ephemeral, recipient);
    return { probe: toHex(x25519.getPublicKey(ephemeral)), tag: spoolDetectionTag(shared) };
  } catch {
    return null;
  } finally {
    shared?.fill(0);
    ephemeral.fill(0);
    recipient.fill(0);
  }
}

const peerDetectionKeys = new Map<string, string>();
const peerDetectionStorageKey = (accountScope: string, peer: string): string => deriveScopedStorageKey(
  STORAGE_PREFIXES.SPOOL_PEER_DETECTION,
  STORAGE_KEY_DOMAINS.SPOOL_PEER_DETECTION,
  accountScope,
  canonicalAuthUsername(peer, 'peer detection key peer'),
);

function cachePeerKey(key: string, publicHex: unknown): void {
  const decoded = fromHex(publicHex, SPOOL_DETECTION_KEY_BYTES);
  if (!decoded) throw new Error('Peer detection key is invalid');
  decoded.fill(0);
  if (peerDetectionKeys.size >= MAX_SPOOL_PEER_DETECTION_KEYS && !peerDetectionKeys.has(key)) {
    const oldest = peerDetectionKeys.keys().next().value;
    if (oldest !== undefined) peerDetectionKeys.delete(oldest);
  }
  peerDetectionKeys.set(key, publicHex as string);
}

export async function resolvePeerDetectionKey(owner: string, peer: string): Promise<string | null> {
  const expected = generation;
  const accountScope = await getCurrentLocalAccountScope(owner);
  assertCurrent(expected);
  const key = peerDetectionStorageKey(accountScope, peer);
  const cached = peerDetectionKeys.get(key);
  if (cached) return cached;
  const stored = await storage.get(key);
  assertCurrent(expected);
  if (stored === null) return null;
  const updated = peerDetectionKeys.get(key);
  if (updated) return updated;
  cachePeerKey(key, stored);
  return stored;
}

export async function persistPeerDetectionKey(owner: string, peer: string, publicHex: unknown): Promise<void> {
  const decoded = fromHex(publicHex, SPOOL_DETECTION_KEY_BYTES);
  if (!decoded) throw new Error('Peer detection key is invalid');
  decoded.fill(0);
  const expected = generation;
  const accountScope = await getCurrentLocalAccountScope(owner);
  assertCurrent(expected);
  const key = peerDetectionStorageKey(accountScope, peer);
  if (!await storage.set(key, publicHex as string)) throw new Error('Peer detection key could not be stored');
  assertCurrent(expected);
  if (await storage.get(key) !== publicHex) throw new Error('Peer detection key could not be verified');
  assertCurrent(expected);
  cachePeerKey(key, publicHex);
}

export function clearDetectionKeyCaches(): void {
  generation += 1;
  cachedKey?.key.privateKey.fill(0);
  cachedKey = null;
  peerDetectionKeys.clear();
}
