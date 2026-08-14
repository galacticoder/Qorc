import type { StoredUser } from '../types/database-types';
import { CERT_CLOCK_SKEW_MS, MAX_KNOWN_PEERS } from '../constants';
import {
  hasPrototypePollutionKeys,
  isCanonicalAuthUsername,
  isPlainObject,
} from '../sanitizers';
import {
  isValidDilithiumPublicKeyBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64,
} from '../utils/messaging-validators';

const USER_RECORD_KEYS = new Set([
  'hybridPublicKeys',
  'id',
  'identityBundleFingerprint',
  'identityRootFingerprint',
  'peerCertificateFingerprint',
  'peerCertificateVerifiedAt',
  'username',
]);
const HYBRID_KEY_FIELDS = [
  'dilithiumPublicBase64',
  'kyberPublicBase64',
  'x25519PublicBase64',
].sort().join(',');
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINGERPRINT = /^[a-f0-9]{64}$/;

function optionalFingerprint(value: unknown, field: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !FINGERPRINT.test(value)) {
    throw new Error(`Invalid known-peer ${field}`);
  }
  return value;
}

function normalizeKnownUser(value: unknown, ownerUsername: string): StoredUser {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) {
    throw new Error('Invalid known-peer record');
  }
  if (Object.keys(value).some((key) => !USER_RECORD_KEYS.has(key))) {
    throw new Error('Known-peer record contains unexpected fields');
  }

  const id = value.id;
  const username = value.username;
  if (typeof id !== 'string' || !UUID_V4.test(id)) {
    throw new Error('Invalid known-peer ID');
  }
  if (!isCanonicalAuthUsername(username) || username === ownerUsername) {
    throw new Error('Invalid known-peer username');
  }

  const peerCertificateFingerprint = optionalFingerprint(
    value.peerCertificateFingerprint,
    'certificate fingerprint',
  );
  const identityRootFingerprint = optionalFingerprint(
    value.identityRootFingerprint,
    'identity-root fingerprint',
  );
  const identityBundleFingerprint = optionalFingerprint(
    value.identityBundleFingerprint,
    'identity-bundle fingerprint',
  );
  const rawPeerCertificateVerifiedAt = value.peerCertificateVerifiedAt;
  const hasVerifiedAt = rawPeerCertificateVerifiedAt !== undefined;
  if (
    hasVerifiedAt !== (peerCertificateFingerprint !== undefined) ||
    (hasVerifiedAt && (
      !Number.isSafeInteger(rawPeerCertificateVerifiedAt) ||
      (rawPeerCertificateVerifiedAt as number) < 0 ||
      (rawPeerCertificateVerifiedAt as number) > Date.now() + CERT_CLOCK_SKEW_MS
    ))
  ) {
    throw new Error('Invalid known-peer certificate verification timestamp');
  }
  const peerCertificateVerifiedAt = hasVerifiedAt
    ? rawPeerCertificateVerifiedAt as number
    : undefined;
  if (
    (peerCertificateFingerprint !== undefined || identityBundleFingerprint !== undefined) &&
    identityRootFingerprint === undefined
  ) {
    throw new Error('Known-peer identity fingerprints are incomplete');
  }

  let hybridPublicKeys: StoredUser['hybridPublicKeys'];
  if (value.hybridPublicKeys !== undefined) {
    const keys = value.hybridPublicKeys;
    if (
      !isPlainObject(keys) ||
      hasPrototypePollutionKeys(keys) ||
      Object.keys(keys).sort().join(',') !== HYBRID_KEY_FIELDS ||
      !isValidKyberPublicKeyBase64(keys.kyberPublicBase64) ||
      !isValidDilithiumPublicKeyBase64(keys.dilithiumPublicBase64) ||
      !isValidX25519PublicKeyBase64(keys.x25519PublicBase64) ||
      !peerCertificateFingerprint ||
      !identityRootFingerprint ||
      !identityBundleFingerprint
    ) {
      throw new Error('Invalid known-peer hybrid public keys');
    }
    hybridPublicKeys = {
      kyberPublicBase64: keys.kyberPublicBase64,
      dilithiumPublicBase64: keys.dilithiumPublicBase64,
      x25519PublicBase64: keys.x25519PublicBase64,
    };
  }

  return {
    id,
    username,
    ...(peerCertificateFingerprint ? { peerCertificateFingerprint } : {}),
    ...(peerCertificateVerifiedAt !== undefined ? { peerCertificateVerifiedAt } : {}),
    ...(identityRootFingerprint ? { identityRootFingerprint } : {}),
    ...(identityBundleFingerprint ? { identityBundleFingerprint } : {}),
    ...(hybridPublicKeys ? { hybridPublicKeys } : {}),
  };
}

function mergeMatchingUsers(existing: StoredUser, incoming: StoredUser): StoredUser {
  if (
    existing.peerCertificateFingerprint &&
    incoming.peerCertificateFingerprint &&
    existing.peerCertificateFingerprint !== incoming.peerCertificateFingerprint
  ) {
    throw new Error('Conflicting known-peer certificate fingerprints');
  }
  if (
    existing.identityRootFingerprint &&
    incoming.identityRootFingerprint &&
    existing.identityRootFingerprint !== incoming.identityRootFingerprint
  ) {
    throw new Error('Conflicting known-peer identity roots');
  }
  if (
    existing.hybridPublicKeys &&
    incoming.hybridPublicKeys &&
    (
      existing.hybridPublicKeys.kyberPublicBase64 !== incoming.hybridPublicKeys.kyberPublicBase64 ||
      existing.hybridPublicKeys.dilithiumPublicBase64 !== incoming.hybridPublicKeys.dilithiumPublicBase64 ||
      existing.hybridPublicKeys.x25519PublicBase64 !== incoming.hybridPublicKeys.x25519PublicBase64
    )
  ) {
    throw new Error('Conflicting known-peer hybrid public keys');
  }

  const peerCertificateVerifiedAt = existing.peerCertificateVerifiedAt !== undefined && incoming.peerCertificateVerifiedAt !== undefined
    ? Math.max(existing.peerCertificateVerifiedAt, incoming.peerCertificateVerifiedAt)
    : existing.peerCertificateVerifiedAt ?? incoming.peerCertificateVerifiedAt;
  return {
    id: existing.id,
    username: existing.username,
    peerCertificateFingerprint: existing.peerCertificateFingerprint ?? incoming.peerCertificateFingerprint,
    peerCertificateVerifiedAt,
    identityRootFingerprint: existing.identityRootFingerprint ?? incoming.identityRootFingerprint,
    identityBundleFingerprint: incoming.identityBundleFingerprint ?? existing.identityBundleFingerprint,
    hybridPublicKeys: existing.hybridPublicKeys ?? incoming.hybridPublicKeys,
  };
}

export function normalizeKnownUsers(
  value: unknown,
  ownerUsername: string,
  duplicatePolicy: 'reject' | 'merge' = 'reject',
): StoredUser[] {
  if (!isCanonicalAuthUsername(ownerUsername)) throw new Error('Invalid known-peer owner');
  if (!Array.isArray(value) || value.length > MAX_KNOWN_PEERS) {
    throw new Error('Known-peer list limit exceeded');
  }

  const byUsername = new Map<string, StoredUser>();
  for (const raw of value) {
    const user = normalizeKnownUser(raw, ownerUsername);
    const existing = byUsername.get(user.username);
    if (!existing) {
      byUsername.set(user.username, user);
      continue;
    }
    if (duplicatePolicy === 'reject') {
      throw new Error('Known-peer list contains duplicate usernames');
    }
    byUsername.set(user.username, mergeMatchingUsers(existing, user));
  }
  return Array.from(byUsername.values());
}
