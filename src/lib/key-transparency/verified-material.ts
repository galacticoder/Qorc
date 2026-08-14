import { isValidDilithiumPublicKeyBase64, isValidKyberPublicKeyBase64, isValidX25519PublicKeyBase64 } from '../utils/messaging-validators';
import {
  clearPeerIdentityRevocations,
  consumeCompletedPeerIdentityRevocation,
} from './revocation';
import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  isKeyTransparencyHash,
} from '../../../shared/key-transparency-protocol.js';
import { keyTransparencyPeerKey } from './peer-key';
import { canonicalAuthUsername } from '../sanitizers';

const MAX_AUTHORIZED_PEERS = 2048;
const AUTHORIZATION_TTL_MS = 24 * 60 * 60 * 1000;
let verifiedMaterials = new WeakMap<object, {
  account: string;
  peer: string;
  expiresAt: number;
  authorizationGeneration: number;
}>();
const authorizedPeerKeys = new Map<string, {
  expiresAt: number;
  authorizationGeneration: number;
  rootCommitment: string;
  version: number;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
  peerCertificateFingerprint: string;
  identityRootFingerprint: string;
  identityBundleFingerprint: string;
}>();
const revokedPeers = new Map<string, {
  rootCommitment: string;
  version: number;
}>();
let nextAuthorizationGeneration = 1;

function fingerprint(value: unknown, required: boolean): string {
  const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if ((required || normalized.length > 0) && !/^[a-f0-9]{64}$/.test(normalized)) {
    throw new Error('Invalid verified key-transparency fingerprint');
  }
  return normalized;
}

function authorizationKey(account: string, peer: string): string {
  return keyTransparencyPeerKey(
    canonicalAuthUsername(account, 'verified key-transparency account'),
    canonicalAuthUsername(peer, 'verified key-transparency peer')
  );
}

export function markKeyTransparencyVerifiedMaterial(
  material: object,
  account: string,
  peer: string,
  contact: { rootCommitment: string; version: number },
): void {
  if (!material || typeof material !== 'object' || Array.isArray(material)) {
    throw new Error('Invalid verified key-transparency material');
  }
  const value = material as Record<string, any>;
  const keys = value.publicKeys;
  if (
    !isValidKyberPublicKeyBase64(keys?.kyberPublicBase64) ||
    !isValidDilithiumPublicKeyBase64(keys?.dilithiumPublicBase64) ||
    !isValidX25519PublicKeyBase64(keys?.x25519PublicBase64)
  ) throw new Error('Invalid verified key-transparency transport keys');
  const expiresAt = Date.now() + AUTHORIZATION_TTL_MS;
  const normalizedAccount = canonicalAuthUsername(account, 'verified key-transparency account');
  const normalizedPeer = canonicalAuthUsername(peer, 'verified key-transparency peer');
  if (
    !isKeyTransparencyHash(contact?.rootCommitment) ||
    !Number.isSafeInteger(contact?.version) ||
    contact.version < 1 ||
    contact.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
  ) throw new Error('Invalid verified key-transparency contact state');
  const authorizationGeneration = nextAuthorizationGeneration;
  nextAuthorizationGeneration = nextAuthorizationGeneration >= Number.MAX_SAFE_INTEGER
    ? 1
    : nextAuthorizationGeneration + 1;
  const entry = {
    expiresAt,
    authorizationGeneration,
    rootCommitment: contact.rootCommitment,
    version: contact.version,
    kyberPublicBase64: keys.kyberPublicBase64,
    dilithiumPublicBase64: keys.dilithiumPublicBase64,
    x25519PublicBase64: keys.x25519PublicBase64,
    peerCertificateFingerprint: fingerprint(value.peerCertificateFingerprint, true),
    identityRootFingerprint: fingerprint(value.identityRootFingerprint, true),
    identityBundleFingerprint: fingerprint(value.identityBundleFingerprint, true),
  };
  verifiedMaterials.set(material, {
    account: normalizedAccount,
    peer: normalizedPeer,
    expiresAt,
    authorizationGeneration,
  });
  const key = authorizationKey(normalizedAccount, normalizedPeer);
  const revoked = revokedPeers.get(key);
  if (revoked) {
    if (
      revoked.rootCommitment !== contact.rootCommitment ||
      revoked.version !== contact.version
    ) throw new Error('Stale key-transparency contact state cannot clear revocation');
    if (!consumeCompletedPeerIdentityRevocation(normalizedAccount, normalizedPeer)) {
      throw new Error('Native peer-identity revocation has not completed');
    }
  }
  revokedPeers.delete(key);
  authorizedPeerKeys.delete(key);
  authorizedPeerKeys.set(key, entry);
  while (authorizedPeerKeys.size > MAX_AUTHORIZED_PEERS) {
    const oldest = authorizedPeerKeys.keys().next().value as string | undefined;
    if (!oldest) break;
    authorizedPeerKeys.delete(oldest);
  }
}

export function getKeyTransparencyAuthorizedPeerState(
  account: string,
  peer: string,
): { rootCommitment: string; version: number } | null {
  let key: string;
  try {
    key = authorizationKey(account, peer);
  } catch {
    return null;
  }
  const authorized = authorizedPeerKeys.get(key);
  if (!authorized) return null;
  if (authorized.expiresAt < Date.now()) {
    authorizedPeerKeys.delete(key);
    return null;
  }
  return {
    rootCommitment: authorized.rootCommitment,
    version: authorized.version,
  };
}

export function isKeyTransparencyVerifiedMaterial(
  material: unknown,
  account: string,
  peer: string,
): boolean {
  if (!material || typeof material !== 'object') return false;
  let normalizedAccount: string;
  let normalizedPeer: string;
  try {
    normalizedAccount = canonicalAuthUsername(account, 'verified key-transparency account');
    normalizedPeer = canonicalAuthUsername(peer, 'verified key-transparency peer');
  } catch {
    return false;
  }
  const verified = verifiedMaterials.get(material as object);
  if (!verified) return false;
  if (verified.expiresAt < Date.now()) {
    verifiedMaterials.delete(material as object);
    return false;
  }
  const authorized = authorizedPeerKeys.get(authorizationKey(normalizedAccount, normalizedPeer));
  return verified.account === normalizedAccount &&
    verified.peer === normalizedPeer &&
    authorized?.authorizationGeneration === verified.authorizationGeneration;
}

export function isKeyTransparencyAuthorizedPeerKeySet(input: {
  account: string;
  peer: string;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
  peerCertificateFingerprint: string;
  identityRootFingerprint: string;
  identityBundleFingerprint: string;
}): boolean {
  let key: string;
  try {
    key = authorizationKey(input.account, input.peer);
  } catch {
    return false;
  }
  const authorized = authorizedPeerKeys.get(key);
  if (!authorized) return false;
  if (authorized.expiresAt < Date.now()) {
    authorizedPeerKeys.delete(key);
    return false;
  }
  return authorized.kyberPublicBase64 === input.kyberPublicBase64 &&
    authorized.dilithiumPublicBase64 === input.dilithiumPublicBase64 &&
    authorized.x25519PublicBase64 === input.x25519PublicBase64 &&
    authorized.peerCertificateFingerprint === input.peerCertificateFingerprint &&
    authorized.identityRootFingerprint === input.identityRootFingerprint &&
    authorized.identityBundleFingerprint === input.identityBundleFingerprint;
}

export function isKeyTransparencyAuthorizedPeerCertificate(input: {
  account: string;
  peer: string;
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
  peerCertificateFingerprint: string;
}): boolean {
  let key: string;
  let peerCertificateFingerprint: string;
  try {
    key = authorizationKey(input.account, input.peer);
    peerCertificateFingerprint = fingerprint(input.peerCertificateFingerprint, true);
  } catch {
    return false;
  }
  const authorized = authorizedPeerKeys.get(key);
  if (!authorized) return false;
  if (authorized.expiresAt < Date.now()) {
    authorizedPeerKeys.delete(key);
    return false;
  }
  return authorized.kyberPublicBase64 === input.kyberPublicBase64 &&
    authorized.dilithiumPublicBase64 === input.dilithiumPublicBase64 &&
    authorized.x25519PublicBase64 === input.x25519PublicBase64 &&
    authorized.peerCertificateFingerprint === peerCertificateFingerprint;
}

export type KeyTransparencyPeerAuthorization = Readonly<{
  authorizationGeneration: number;
  identityRootFingerprint: string;
  identityBundleFingerprint: string;
}>;

export function captureKeyTransparencyPeerAuthorization(
  account: string,
  peer: string,
  expectedDilithiumPublicBase64?: string,
): KeyTransparencyPeerAuthorization | null {
  let key: string;
  try {
    key = authorizationKey(account, peer);
  } catch {
    return null;
  }
  const authorized = authorizedPeerKeys.get(key);
  if (!authorized) return null;
  if (authorized.expiresAt < Date.now()) {
    authorizedPeerKeys.delete(key);
    return null;
  }
  if (
    expectedDilithiumPublicBase64 !== undefined &&
    authorized.dilithiumPublicBase64 !== expectedDilithiumPublicBase64
  ) return null;
  return Object.freeze({
    authorizationGeneration: authorized.authorizationGeneration,
    identityRootFingerprint: authorized.identityRootFingerprint,
    identityBundleFingerprint: authorized.identityBundleFingerprint,
  });
}

export function isKeyTransparencyPeerAuthorizationCurrent(
  account: string,
  peer: string,
  authorization: KeyTransparencyPeerAuthorization,
): boolean {
  if (
    !authorization ||
    !Number.isSafeInteger(authorization.authorizationGeneration) ||
    authorization.authorizationGeneration < 1 ||
    !/^[a-f0-9]{64}$/.test(authorization.identityRootFingerprint) ||
    !/^[a-f0-9]{64}$/.test(authorization.identityBundleFingerprint)
  ) return false;
  let key: string;
  try {
    key = authorizationKey(account, peer);
  } catch {
    return false;
  }
  const authorized = authorizedPeerKeys.get(key);
  if (!authorized) return false;
  if (authorized.expiresAt < Date.now()) {
    authorizedPeerKeys.delete(key);
    return false;
  }
  return authorized.authorizationGeneration === authorization.authorizationGeneration &&
    authorized.identityRootFingerprint === authorization.identityRootFingerprint &&
    authorized.identityBundleFingerprint === authorization.identityBundleFingerprint;
}

export function revokeKeyTransparencyPeerAuthorization(
  account: string,
  peer: string,
  contact: { rootCommitment: string; version: number },
): void {
  let key: string;
  try {
    key = authorizationKey(account, peer);
  } catch {
    return;
  }
  if (
    !isKeyTransparencyHash(contact?.rootCommitment) ||
    !Number.isSafeInteger(contact?.version) ||
    contact.version < 1 ||
    contact.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
  ) return;
  authorizedPeerKeys.delete(key);
  revokedPeers.delete(key);
  revokedPeers.set(key, {
    rootCommitment: contact.rootCommitment,
    version: contact.version,
  });
  while (revokedPeers.size > MAX_AUTHORIZED_PEERS) {
    const oldest = revokedPeers.keys().next().value as string | undefined;
    if (!oldest) break;
    revokedPeers.delete(oldest);
  }
}

export function isKeyTransparencyPeerRevoked(account: string, peer: string): boolean {
  try {
    return revokedPeers.has(authorizationKey(account, peer));
  } catch {
    return false;
  }
}

/**
 * Snapshot of the authorizations and revocations for one account, for persistence.
 * `expiresAt` is carried verbatim so restoring can never widen the trust window.
 * `authorizationGeneration` is deliberately NOT exported: it identifies in-flight
 * material within a single process and is reassigned on restore.
 */
export function exportKeyTransparencyAuthorizations(account: string): {
  authorized: Array<{
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
  }>;
  revoked: Array<{ peer: string; rootCommitment: string; version: number }>;
} {
  let normalizedAccount: string;
  try {
    normalizedAccount = canonicalAuthUsername(account, 'verified key-transparency account');
  } catch {
    return { authorized: [], revoked: [] };
  }
  const prefix = `${normalizedAccount}\0`;
  const now = Date.now();
  const authorized: any[] = [];
  for (const [key, entry] of authorizedPeerKeys) {
    if (!key.startsWith(prefix) || entry.expiresAt <= now) continue;
    authorized.push({
      peer: key.slice(prefix.length),
      expiresAt: entry.expiresAt,
      rootCommitment: entry.rootCommitment,
      version: entry.version,
      kyberPublicBase64: entry.kyberPublicBase64,
      dilithiumPublicBase64: entry.dilithiumPublicBase64,
      x25519PublicBase64: entry.x25519PublicBase64,
      peerCertificateFingerprint: entry.peerCertificateFingerprint,
      identityRootFingerprint: entry.identityRootFingerprint,
      identityBundleFingerprint: entry.identityBundleFingerprint,
    });
  }
  const revoked: any[] = [];
  for (const [key, entry] of revokedPeers) {
    if (!key.startsWith(prefix)) continue;
    revoked.push({
      peer: key.slice(prefix.length),
      rootCommitment: entry.rootCommitment,
      version: entry.version,
    });
  }
  return { authorized, revoked };
}

// Restore persisted authorizations for one account.
export function importKeyTransparencyAuthorizations(
  account: string,
  snapshot: {
    authorized: ReadonlyArray<{
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
    }>;
    revoked: ReadonlyArray<{ peer: string; rootCommitment: string; version: number }>;
  },
): number {
  let normalizedAccount: string;
  try {
    normalizedAccount = canonicalAuthUsername(account, 'verified key-transparency account');
  } catch {
    return 0;
  }
  const now = Date.now();

  const revokedNow = new Set<string>();
  for (const entry of snapshot?.revoked || []) {
    try {
      const peer = canonicalAuthUsername(entry.peer, 'verified key-transparency peer');
      if (
        !isKeyTransparencyHash(entry.rootCommitment) ||
        !Number.isSafeInteger(entry.version) ||
        entry.version < 1 ||
        entry.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
      ) continue;
      const key = authorizationKey(normalizedAccount, peer);
      revokedNow.add(peer);
      authorizedPeerKeys.delete(key);
      revokedPeers.set(key, {
        rootCommitment: entry.rootCommitment,
        version: entry.version,
      });
    } catch {
      continue;
    }
  }

  let restored = 0;
  for (const entry of snapshot?.authorized || []) {
    try {
      const peer = canonicalAuthUsername(entry.peer, 'verified key-transparency peer');
      if (revokedNow.has(peer)) continue;
      if (!Number.isSafeInteger(entry.expiresAt) || entry.expiresAt <= now) continue;
      if (
        !isValidKyberPublicKeyBase64(entry.kyberPublicBase64) ||
        !isValidDilithiumPublicKeyBase64(entry.dilithiumPublicBase64) ||
        !isValidX25519PublicKeyBase64(entry.x25519PublicBase64) ||
        !isKeyTransparencyHash(entry.rootCommitment) ||
        !Number.isSafeInteger(entry.version) ||
        entry.version < 1 ||
        entry.version > KEY_TRANSPARENCY_MAX_LOG_SIZE
      ) continue;
      const key = authorizationKey(normalizedAccount, peer);
      if (revokedPeers.has(key)) continue;
      const authorizationGeneration = nextAuthorizationGeneration;
      nextAuthorizationGeneration = nextAuthorizationGeneration >= Number.MAX_SAFE_INTEGER
        ? 1
        : nextAuthorizationGeneration + 1;
      authorizedPeerKeys.delete(key);
      authorizedPeerKeys.set(key, {
        expiresAt: entry.expiresAt,
        authorizationGeneration,
        rootCommitment: entry.rootCommitment,
        version: entry.version,
        kyberPublicBase64: entry.kyberPublicBase64,
        dilithiumPublicBase64: entry.dilithiumPublicBase64,
        x25519PublicBase64: entry.x25519PublicBase64,
        peerCertificateFingerprint: fingerprint(entry.peerCertificateFingerprint, true),
        identityRootFingerprint: fingerprint(entry.identityRootFingerprint, true),
        identityBundleFingerprint: fingerprint(entry.identityBundleFingerprint, true),
      });
      restored += 1;
    } catch {
      continue;
    }
  }
  while (authorizedPeerKeys.size > MAX_AUTHORIZED_PEERS) {
    const oldest = authorizedPeerKeys.keys().next().value as string | undefined;
    if (!oldest) break;
    authorizedPeerKeys.delete(oldest);
  }
  return restored;
}

export function clearKeyTransparencyVerifiedMaterials(): void {
  verifiedMaterials = new WeakMap();
  authorizedPeerKeys.clear();
  revokedPeers.clear();
  clearPeerIdentityRevocations();
}
