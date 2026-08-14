import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  exactPlainObject,
  isKeyTransparencyHash,
} from '../../../shared/key-transparency-protocol.js';
import {
  isValidDilithiumPublicKeyBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64,
} from '../utils/messaging-validators';
import {
  assertCurrentServerContext,
  deriveLocalAccountScope,
  type CurrentServerContext,
} from '../security/local-account-scope';
import { storage } from '../tauri-bindings';
import { createStoreLock } from './store-lock';
import { canonicalAuthUsername } from '../sanitizers';
import { keyTransparencyStoreKey } from './store-key';
import { HEX_64_RE } from '../../../shared/patterns.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';

const MAX_STORED_AUTHORIZATIONS = 2048;
const AUTHORIZED_KEYS = [
  'dilithiumPublicBase64',
  'expiresAt',
  'identityBundleFingerprint',
  'identityRootFingerprint',
  'kyberPublicBase64',
  'peer',
  'peerCertificateFingerprint',
  'rootCommitment',
  'version',
  'x25519PublicBase64',
];
const REVOKED_KEYS = ['peer', 'rootCommitment', 'version'];

const enqueue = createStoreLock();

export interface StoredPeerAuthorization {
  peer: string;
  expiresAt: number;
  rootCommitment: string;
  version: number;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
  peerCertificateFingerprint: string;
  identityRootFingerprint: string;
  identityBundleFingerprint: string;
}

export interface StoredPeerRevocation {
  peer: string;
  rootCommitment: string;
  version: number;
}

export interface KeyTransparencyAuthorizationSnapshot {
  authorized: StoredPeerAuthorization[];
  revoked: StoredPeerRevocation[];
}

function normalizePeer(peer: unknown): string {
  return canonicalAuthUsername(peer, 'key-transparency authorization peer');
}

function isFingerprint(value: unknown): value is string {
  return typeof value === 'string' && HEX_64_RE.test(value);
}

function isContactState(rootCommitment: unknown, version: unknown): boolean {
  return isKeyTransparencyHash(rootCommitment) &&
    Number.isSafeInteger(version) &&
    (version as number) >= 1 &&
    (version as number) <= KEY_TRANSPARENCY_MAX_LOG_SIZE;
}

function authorizationStorageKey(accountScope: string): string {
  return keyTransparencyStoreKey(
    STORAGE_PREFIXES.KEY_TRANSPARENCY_AUTHORIZATION,
    STORAGE_KEY_DOMAINS.KEY_TRANSPARENCY_AUTHORIZATION,
    accountScope
  );
}

function parseAuthorized(value: unknown): StoredPeerAuthorization | null {
  const entry = value as StoredPeerAuthorization;
  let peer: string;
  try {
    peer = normalizePeer(entry?.peer);
  } catch {
    return null;
  }
  if (
    !exactPlainObject(entry, AUTHORIZED_KEYS) ||
    peer !== entry.peer ||
    !Number.isSafeInteger(entry.expiresAt) ||
    entry.expiresAt <= 0 ||
    !isContactState(entry.rootCommitment, entry.version) ||
    !isValidKyberPublicKeyBase64(entry.kyberPublicBase64) ||
    !isValidDilithiumPublicKeyBase64(entry.dilithiumPublicBase64) ||
    !isValidX25519PublicKeyBase64(entry.x25519PublicBase64) ||
    !isFingerprint(entry.peerCertificateFingerprint) ||
    !isFingerprint(entry.identityRootFingerprint) ||
    !isFingerprint(entry.identityBundleFingerprint)
  ) return null;
  return { ...entry };
}

function parseRevoked(value: unknown): StoredPeerRevocation | null {
  const entry = value as StoredPeerRevocation;
  let peer: string;
  try {
    peer = normalizePeer(entry?.peer);
  } catch {
    return null;
  }
  if (
    !exactPlainObject(entry, REVOKED_KEYS) ||
    peer !== entry.peer ||
    !isContactState(entry.rootCommitment, entry.version)
  ) return null;
  return { ...entry };
}

function parseStore(raw: string | null): KeyTransparencyAuthorizationSnapshot {
  const empty: KeyTransparencyAuthorizationSnapshot = { authorized: [], revoked: [] };
  if (raw === null) return empty;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return empty;
  }
  const value = parsed as { protocol?: unknown; authorized?: unknown; revoked?: unknown };
  if (
    !exactPlainObject(value, ['authorized', 'protocol', 'revoked']) ||
    value.protocol !== PROTOCOL_KEYS.KEY_TRANSPARENCY_AUTHORIZATION_STORE ||
    !Array.isArray(value.authorized) ||
    !Array.isArray(value.revoked) ||
    value.authorized.length > MAX_STORED_AUTHORIZATIONS ||
    value.revoked.length > MAX_STORED_AUTHORIZATIONS
  ) return empty;

  const revoked: StoredPeerRevocation[] = [];
  for (const candidate of value.revoked as unknown[]) {
    const entry = parseRevoked(candidate);
    if (!entry) return empty;
    revoked.push(entry);
  }
  const revokedPeers = new Set(revoked.map((entry) => entry.peer));
  if (revokedPeers.size !== revoked.length) return empty;

  const authorized: StoredPeerAuthorization[] = [];
  const seen = new Set<string>();
  for (const candidate of value.authorized as unknown[]) {
    const entry = parseAuthorized(candidate);
    if (!entry) continue;
    
    if (revokedPeers.has(entry.peer) || seen.has(entry.peer)) continue;
    seen.add(entry.peer);
    authorized.push(entry);
  }
  return { authorized, revoked };
}

export async function readKeyTransparencyAuthorizations(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<KeyTransparencyAuthorizationSnapshot> {
  return enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, normalizePeer(ownerUsername));
    const snapshot = parseStore(await storage.get(authorizationStorageKey(accountScope)));
    await assertCurrentServerContext(context);
    
    const now = Date.now();
    return {
      authorized: snapshot.authorized.filter((entry) => entry.expiresAt > now),
      revoked: snapshot.revoked,
    };
  });
}

export async function writeKeyTransparencyAuthorizations(
  context: CurrentServerContext,
  ownerUsername: string,
  snapshot: KeyTransparencyAuthorizationSnapshot,
): Promise<void> {
  return enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, normalizePeer(ownerUsername));
    const key = authorizationStorageKey(accountScope);
    const now = Date.now();
    const authorized = snapshot.authorized
      .filter((entry) => entry.expiresAt > now)
      .slice(0, MAX_STORED_AUTHORIZATIONS)
      .sort((left, right) => left.peer.localeCompare(right.peer));
    const revoked = snapshot.revoked
      .slice(0, MAX_STORED_AUTHORIZATIONS)
      .sort((left, right) => left.peer.localeCompare(right.peer));
    const serialized = JSON.stringify({
      protocol: PROTOCOL_KEYS.KEY_TRANSPARENCY_AUTHORIZATION_STORE,
      authorized,
      revoked,
    });
    await assertCurrentServerContext(context);
    if (!await storage.set(key, serialized)) {
      throw new Error('Key-transparency authorizations could not be persisted');
    }
  });
}

export async function clearKeyTransparencyAuthorizations(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<void> {
  return enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, normalizePeer(ownerUsername));
    await storage.remove(authorizationStorageKey(accountScope));
  });
}
