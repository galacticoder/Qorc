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
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { STORAGE_KEY_DOMAINS, STORAGE_PREFIXES } from '../database/storage-keys';
import { SESSION_FINGERPRINT_RE } from '../../../shared/patterns.js';

const MAX_STORED_AUTHORIZATIONS = 2048;
const AUTHORIZED_KEYS = [
  'dilithiumPublicBase64',
  'identityBundleFingerprint',
  'identityRootFingerprint',
  'kyberPublicBase64',
  'peer',
  'peerCertificateFingerprint',
  'rootCommitment',
  'verifiedAt',
  'version',
  'x25519PublicBase64',
];
const REVOKED_KEYS = ['peer', 'rootCommitment', 'version'];

const enqueue = createStoreLock();

export interface StoredPeerAuthorization {
  peer: string;
  verifiedAt: number;
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
  return typeof value === 'string' && SESSION_FINGERPRINT_RE.test(value);
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

function parseAuthorized(value: unknown): StoredPeerAuthorization {
  const entry = value as StoredPeerAuthorization;
  let peer: string;
  try {
    peer = normalizePeer(entry?.peer);
  } catch {
    throw new Error('Invalid stored key-transparency authorization');
  }
  if (
    !exactPlainObject(entry, AUTHORIZED_KEYS) ||
    peer !== entry.peer ||
    !Number.isSafeInteger(entry.verifiedAt) ||
    entry.verifiedAt <= 0 ||
    entry.verifiedAt > Date.now() ||
    !isContactState(entry.rootCommitment, entry.version) ||
    !isValidKyberPublicKeyBase64(entry.kyberPublicBase64) ||
    !isValidDilithiumPublicKeyBase64(entry.dilithiumPublicBase64) ||
    !isValidX25519PublicKeyBase64(entry.x25519PublicBase64) ||
    !isFingerprint(entry.peerCertificateFingerprint) ||
    !isFingerprint(entry.identityRootFingerprint) ||
    !isFingerprint(entry.identityBundleFingerprint)
  ) throw new Error('Invalid stored key-transparency authorization');
  return { ...entry };
}

function parseRevoked(value: unknown): StoredPeerRevocation {
  const entry = value as StoredPeerRevocation;
  let peer: string;
  try {
    peer = normalizePeer(entry?.peer);
  } catch {
    throw new Error('Invalid stored key-transparency revocation');
  }
  if (
    !exactPlainObject(entry, REVOKED_KEYS) ||
    peer !== entry.peer ||
    !isContactState(entry.rootCommitment, entry.version)
  ) throw new Error('Invalid stored key-transparency revocation');
  return { ...entry };
}

function parseStore(raw: string | null): KeyTransparencyAuthorizationSnapshot {
  const empty: KeyTransparencyAuthorizationSnapshot = { authorized: [], revoked: [] };
  if (raw === null) return empty;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Invalid stored key-transparency authorizations');
  }
  const value = parsed as { protocol?: unknown; authorized?: unknown; revoked?: unknown };
  if (
    !exactPlainObject(value, ['authorized', 'protocol', 'revoked']) ||
    value.protocol !== PROTOCOL_KEYS.KEY_TRANSPARENCY_AUTHORIZATION_STORE ||
    !Array.isArray(value.authorized) ||
    !Array.isArray(value.revoked) ||
    value.authorized.length > MAX_STORED_AUTHORIZATIONS ||
    value.revoked.length > MAX_STORED_AUTHORIZATIONS
  ) throw new Error('Invalid stored key-transparency authorizations');

  const revoked: StoredPeerRevocation[] = [];
  for (const candidate of value.revoked as unknown[]) {
    const entry = parseRevoked(candidate);
    revoked.push(entry);
  }
  const revokedPeers = new Set(revoked.map((entry) => entry.peer));
  if (revokedPeers.size !== revoked.length) {
    throw new Error('Stored key-transparency revocations contain duplicate peers');
  }

  const authorized: StoredPeerAuthorization[] = [];
  const seen = new Set<string>();
  for (const candidate of value.authorized as unknown[]) {
    const entry = parseAuthorized(candidate);
    if (revokedPeers.has(entry.peer)) {
      throw new Error('Stored key-transparency peer is both authorized and revoked');
    }
    if (seen.has(entry.peer)) {
      throw new Error('Stored key-transparency authorizations contain duplicate peers');
    }
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
    
    return {
      authorized: snapshot.authorized,
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
    if (
      snapshot.authorized.length > MAX_STORED_AUTHORIZATIONS ||
      snapshot.revoked.length > MAX_STORED_AUTHORIZATIONS
    ) throw new Error('Key-transparency authorization snapshot exceeds its fixed capacity');
    const authorized = snapshot.authorized
      .slice()
      .sort((left, right) => left.peer.localeCompare(right.peer));
    const revoked = snapshot.revoked
      .slice()
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
    if (await storage.get(key) !== serialized) {
      throw new Error('Key-transparency authorization update could not be verified');
    }
  });
}

export async function clearKeyTransparencyAuthorizations(
  context: CurrentServerContext,
  ownerUsername: string,
): Promise<void> {
  return enqueue(async () => {
    const accountScope = deriveLocalAccountScope(context, normalizePeer(ownerUsername));
    const key = authorizationStorageKey(accountScope);
    if (!await storage.remove(key) || await storage.has(key)) {
      throw new Error('Key-transparency authorizations could not be removed');
    }
  });
}
