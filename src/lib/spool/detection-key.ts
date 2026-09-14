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

const detectionKeyStorageKey = async (owner: string): Promise<string> => {
  const accountScope = await getCurrentLocalAccountScope(
    canonicalAuthUsername(owner, 'detection key owner')
  );
  return deriveScopedStorageKey(
    STORAGE_PREFIXES.SPOOL_DETECTION,
    STORAGE_KEY_DOMAINS.SPOOL_DETECTION,
    accountScope
  );
};

export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function fromHex(value: unknown, expectedBytes: number): Uint8Array | null {
  return hexToBytes(value, { exactBytes: expectedBytes });
}

let cachedOwner: string | null = null;
let cachedPrivate: Uint8Array | null = null;
let cachedPublicHex: string | null = null;

async function loadOrCreate(owner: string): Promise<Uint8Array> {
  const normalizedOwner = canonicalAuthUsername(owner, 'detection key owner');
  if (cachedOwner === normalizedOwner && cachedPrivate) return cachedPrivate;
  const key = await detectionKeyStorageKey(normalizedOwner);
  const stored = await storage.get(key);
  if (stored !== null) {
    const existing = fromHex(stored, SPOOL_DETECTION_KEY_BYTES);
    if (!existing) throw new Error('Stored detection key is invalid');
    cachedOwner = normalizedOwner;
    cachedPrivate = existing;
    cachedPublicHex = toHex(x25519.getPublicKey(existing));
    return existing;
  }
  const secret = PostQuantumRandom.randomBytes(SPOOL_DETECTION_KEY_BYTES);
  const serialized = toHex(secret);
  if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
    secret.fill(0);
    throw new Error('Detection key could not be verified');
  }
  cachedOwner = normalizedOwner;
  cachedPrivate = secret;
  cachedPublicHex = toHex(x25519.getPublicKey(secret));
  return secret;
}

export async function ownDetectionPublicKeyHex(owner: string): Promise<string> {
  const normalizedOwner = canonicalAuthUsername(owner, 'detection key owner');
  await loadOrCreate(normalizedOwner);
  if (cachedOwner !== normalizedOwner || cachedPublicHex === null) {
    throw new Error('Detection key cache is unavailable');
  }
  return cachedPublicHex;
}

export async function detectionTagForProbe(owner: string, probeHex: string): Promise<string | null> {
  if (probeHex.length !== SPOOL_DETECTION_PROBE_HEX_CHARS) return null;
  const secret = await loadOrCreate(owner);
  const probe = fromHex(probeHex, SPOOL_DETECTION_KEY_BYTES);
  if (!probe) return null;
  let shared: Uint8Array | null = null;
  try {
    shared = x25519.getSharedSecret(secret, probe);
    return spoolDetectionTag(shared);
  } catch {
    return null;
  } finally {
    shared?.fill(0);
    probe.fill(0);
  }
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
const MAX_PEER_KEYS = 512;
const peerDetectionCacheKey = (owner: string, peer: string): string => `${
  canonicalAuthUsername(owner, 'peer detection key owner')
}\0${canonicalAuthUsername(peer, 'peer detection key peer')}`;
const peerDetectionStorageKey = async (owner: string, peer: string): Promise<string> => {
  const accountScope = await getCurrentLocalAccountScope(
    canonicalAuthUsername(owner, 'peer detection key owner')
  );
  return deriveScopedStorageKey(
    STORAGE_PREFIXES.SPOOL_PEER_DETECTION,
    STORAGE_KEY_DOMAINS.SPOOL_PEER_DETECTION,
    accountScope,
    canonicalAuthUsername(peer, 'peer detection key peer')
  );
};

export function rememberPeerDetectionKey(owner: string, peer: string, publicHex: unknown): void {
  const cacheKey = peerDetectionCacheKey(owner, peer);
  const decoded = fromHex(publicHex, SPOOL_DETECTION_KEY_BYTES);
  if (!decoded) throw new Error('Peer detection key is invalid');
  decoded.fill(0);
  if (peerDetectionKeys.size >= MAX_PEER_KEYS && !peerDetectionKeys.has(cacheKey)) {
    const oldest = peerDetectionKeys.keys().next().value;
    if (oldest !== undefined) peerDetectionKeys.delete(oldest);
  }
  peerDetectionKeys.set(cacheKey, publicHex as string);
}

export async function resolvePeerDetectionKey(
  owner: string,
  peer: string
): Promise<string | null> {
  const cacheKey = peerDetectionCacheKey(owner, peer);
  const cached = peerDetectionKeys.get(cacheKey);
  if (cached) return cached;
  const stored = await storage.get(await peerDetectionStorageKey(owner, peer));
  if (stored === null) return null;
  const decoded = fromHex(stored, SPOOL_DETECTION_KEY_BYTES);
  if (!decoded) throw new Error('Stored peer detection key is invalid');
  decoded.fill(0);
  peerDetectionKeys.set(cacheKey, stored);
  return stored;
}

export async function persistPeerDetectionKey(
  owner: string,
  peer: string,
  publicHex: unknown
): Promise<void> {
  const decoded = fromHex(publicHex, SPOOL_DETECTION_KEY_BYTES);
  if (!decoded) throw new Error('Peer detection key is invalid');
  decoded.fill(0);
  const key = await peerDetectionStorageKey(owner, peer);
  if (!await storage.set(key, publicHex as string) || await storage.get(key) !== publicHex) {
    throw new Error('Peer detection key could not be verified');
  }
  rememberPeerDetectionKey(owner, peer, publicHex);
}

export function clearDetectionKeyCaches(): void {
  cachedPrivate?.fill(0);
  cachedOwner = null;
  cachedPrivate = null;
  cachedPublicHex = null;
  peerDetectionKeys.clear();
}
