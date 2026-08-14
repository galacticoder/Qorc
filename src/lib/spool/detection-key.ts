/**
 * First-contact detection key
 */

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
import { bytesToHex, hexToBytes } from '../utils/byte-utils';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';

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

async function loadOrCreate(owner: string): Promise<Uint8Array | null> {
  if (cachedOwner === owner && cachedPrivate) return cachedPrivate;
  const key = await detectionKeyStorageKey(owner);
  const existing = fromHex(await storage.get(key), SPOOL_DETECTION_KEY_BYTES);
  if (existing) {
    cachedOwner = owner;
    cachedPrivate = existing;
    cachedPublicHex = toHex(x25519.getPublicKey(existing));
    return existing;
  }
  const secret = PostQuantumRandom.randomBytes(SPOOL_DETECTION_KEY_BYTES);
  if (!await storage.set(key, toHex(secret))) {
    secret.fill(0);
    return null;
  }
  cachedOwner = owner;
  cachedPrivate = secret;
  cachedPublicHex = toHex(x25519.getPublicKey(secret));
  return secret;
}

// Published in the discovery blob
export async function ownDetectionPublicKeyHex(owner: string): Promise<string | null> {
  try {
    await loadOrCreate(owner);
    return cachedOwner === owner ? cachedPublicHex : null;
  } catch {
    return null;
  }
}

export async function detectionTagForProbe(owner: string, probeHex: string): Promise<string | null> {
  try {
    if (probeHex.length !== SPOOL_DETECTION_PROBE_HEX_CHARS) return null;
    const secret = await loadOrCreate(owner);
    const probe = fromHex(probeHex, SPOOL_DETECTION_KEY_BYTES);
    if (!secret || !probe) return null;
    let shared: Uint8Array | null = null;
    try {
      shared = x25519.getSharedSecret(secret, probe);
      return spoolDetectionTag(shared);
    } finally {
      shared?.fill(0);
      probe.fill(0);
    }
  } catch {
    return null;
  }
}

// a fresh probe plus the tag its first message must carry
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

export function rememberPeerDetectionKey(peer: string, publicHex: unknown): void {
  if (typeof peer !== 'string' || !peer) return;
  if (!fromHex(publicHex, SPOOL_DETECTION_KEY_BYTES)) return;
  if (peerDetectionKeys.size >= MAX_PEER_KEYS && !peerDetectionKeys.has(peer)) {
    const oldest = peerDetectionKeys.keys().next().value;
    if (oldest !== undefined) peerDetectionKeys.delete(oldest);
  }
  peerDetectionKeys.set(peer, publicHex as string);
}

// peers detection key, from memory or from disk
export async function resolvePeerDetectionKey(
  owner: string,
  peer: string
): Promise<string | null> {
  const cached = peerDetectionKeys.get(peer);
  if (cached) return cached;
  try {
    const stored = await storage.get(await peerDetectionStorageKey(owner, peer));
    if (!fromHex(stored, SPOOL_DETECTION_KEY_BYTES)) return null;
    peerDetectionKeys.set(peer, stored as string);
    return stored as string;
  } catch {
    return null;
  }
}

// Records key for this account so it survives a restart
export async function persistPeerDetectionKey(
  owner: string,
  peer: string,
  publicHex: unknown
): Promise<void> {
  if (!fromHex(publicHex, SPOOL_DETECTION_KEY_BYTES)) return;
  rememberPeerDetectionKey(peer, publicHex);
  try {
    await storage.set(await peerDetectionStorageKey(owner, peer), publicHex as string);
  } catch {
  }
}

export function peerDetectionKey(peer: string): string | null {
  return peerDetectionKeys.get(peer) ?? null;
}

export function clearDetectionKeyCaches(): void {
  cachedPrivate?.fill(0);
  cachedOwner = null;
  cachedPrivate = null;
  cachedPublicHex = null;
  peerDetectionKeys.clear();
}
