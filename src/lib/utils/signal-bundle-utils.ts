import { EventType } from '../types/event-types';
import { shouldAttemptDiscovery } from './discovery-utils';
import { extractX25519FromSignalBundle } from './peer-certificate-utils';
import { validateCertifiedPeerBundleV2 } from './certified-identity-utils';

export interface PeerIdentityLike {
  username: string;
  inboxId?: string;
  peerCertificateFingerprint?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
  hybridPublicKeys?: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
    inboxId?: string;
  };
}

export interface SignalBundleValidationResult {
  valid: boolean;
  bundleX25519: string | null;
  expectedX25519?: string | null;
  reason?: string;
}

export interface PeerDilithiumValidationResult {
  valid: boolean;
  expectedDilithium?: string | null;
  reason?: string;
}

export interface TrustedPeerHybridKeysResult {
  valid: boolean;
  hybridKeys?: {
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
    x25519PublicBase64: string;
    inboxId?: string;
    routeId?: string;
    mailboxLookupId?: string;
    bundleLookupId?: string;
  } | null;
  peerCertificateFingerprint?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
  reason?: string;
}

function dispatchPeerMaterial(peerUsername: string, material: any) {
  if (!material?.publicKeys) return;
  try {
    window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
      detail: {
        username: peerUsername,
        hybridKeys: {
          ...material.publicKeys,
          inboxId: material.inboxId,
          routeId: material.routeId,
          mailboxLookupId: material.mailboxLookupId,
          bundleLookupId: material.bundleLookupId
        },
        inboxId: material.inboxId,
        routeId: material.routeId,
        mailboxLookupId: material.mailboxLookupId,
        bundleLookupId: material.bundleLookupId,
        peerCertificateFingerprint: material.peerCertificateFingerprint,
        identityRootFingerprint: material.identityRootFingerprint,
        identityBundleFingerprint: material.identityBundleFingerprint
      }
    }));
  } catch { }
}

async function validateCertifiedDiscoveryMaterial(
  peerUsername: string,
  material: any
): Promise<{
  valid: boolean;
  reason?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
  peerCertificateFingerprint?: string;
  signalIdentityX25519PublicKey?: string;
  transportX25519PublicKey?: string;
}> {
  const certified = await validateCertifiedPeerBundleV2(material?.certifiedPeerBundle, {
    targetHandle: peerUsername,
    inboxId: material?.inboxId,
    publicKeys: material?.publicKeys,
    fullBundle: material?.fullBundle,
    peerCertificate: material?.peerCertificate,
    peerCertificateFingerprint: material?.peerCertificateFingerprint
  });
  if (!certified.valid) {
    return { valid: false, reason: certified.reason || 'CERTIFIED_IDENTITY_INVALID' };
  }
  const advertisedRootFingerprint = typeof material?.identityRootFingerprint === 'string'
    ? material.identityRootFingerprint.trim().toLowerCase()
    : '';
  const advertisedBundleFingerprint = typeof material?.identityBundleFingerprint === 'string'
    ? material.identityBundleFingerprint.trim().toLowerCase()
    : '';
  if (advertisedRootFingerprint && advertisedRootFingerprint !== certified.identityRootFingerprint) {
    return { valid: false, reason: 'CERTIFIED_IDENTITY_ROOT_MISMATCH' };
  }
  if (advertisedBundleFingerprint && advertisedBundleFingerprint !== certified.bundleFingerprint) {
    return { valid: false, reason: 'CERTIFIED_IDENTITY_BUNDLE_MISMATCH' };
  }
  return {
    valid: true,
    identityRootFingerprint: certified.identityRootFingerprint,
    identityBundleFingerprint: certified.bundleFingerprint,
    peerCertificateFingerprint: certified.peerCertificateFingerprint,
    signalIdentityX25519PublicKey: certified.bundle?.subkeyBinding?.signalIdentityX25519PublicKey,
    transportX25519PublicKey: certified.bundle?.subkeyBinding?.x25519PublicKey
  };
}

export async function validateSignalBundleForPeerIdentity(
  peerUsername: string,
  bundle: any,
  users?: PeerIdentityLike[] | null,
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<SignalBundleValidationResult> {
  const normalizedPeerUsername = typeof peerUsername === 'string' ? peerUsername.trim() : '';
  if (!normalizedPeerUsername) {
    return { valid: false, bundleX25519: null, reason: 'MISSING_PEER_USERNAME' };
  }

  const bundleX25519 = extractX25519FromSignalBundle(bundle) || null;
  if (!bundleX25519) {
    return { valid: false, bundleX25519: null, reason: 'BUNDLE_MISSING_X25519_IDENTITY' };
  }

  const peer = (Array.isArray(users) ? users : []).find((user) => user?.username === normalizedPeerUsername);
  const existingPinnedFingerprint = typeof peer?.peerCertificateFingerprint === 'string'
    ? peer.peerCertificateFingerprint.trim().toLowerCase()
    : '';
  const existingIdentityRootFingerprint = typeof peer?.identityRootFingerprint === 'string'
    ? peer.identityRootFingerprint.trim().toLowerCase()
    : '';
  const cachedX25519 = peer?.hybridPublicKeys?.x25519PublicBase64 || null;

  // Older cache entries stored the Signal identity in the hybrid x25519 slot.
  if (cachedX25519 && cachedX25519 === bundleX25519 && existingPinnedFingerprint && existingIdentityRootFingerprint) {
    return { valid: true, bundleX25519, expectedX25519: cachedX25519 };
  }

  if (!findUser) {
    return {
      valid: false,
      bundleX25519,
      expectedX25519: cachedX25519,
      reason: 'NO_TRUSTED_SIGNAL_IDENTITY'
    };
  }

  const knownPeers = (Array.isArray(users) ? users : []).map((user) => user?.username).filter(Boolean) as string[];
  if (!shouldAttemptDiscovery(normalizedPeerUsername, knownPeers)) {
    return {
      valid: false,
      bundleX25519,
      expectedX25519: cachedX25519,
      reason: 'DISCOVERY_NOT_ALLOWED'
    };
  }

  try {
    const material = await findUser(normalizedPeerUsername, { forceRefresh: true });
    const certified = await validateCertifiedDiscoveryMaterial(normalizedPeerUsername, material);
    if (!certified.valid) {
      return {
        valid: false,
        bundleX25519,
        expectedX25519: cachedX25519,
        reason: certified.reason || 'CERTIFIED_IDENTITY_INVALID'
      };
    }
    const discoveredSignalX25519 = certified.signalIdentityX25519PublicKey
      || extractX25519FromSignalBundle(material?.fullBundle)
      || null;
    const discoveredFingerprint = typeof certified.peerCertificateFingerprint === 'string'
      ? certified.peerCertificateFingerprint.trim().toLowerCase()
      : '';
    const discoveredRoot = typeof certified.identityRootFingerprint === 'string'
      ? certified.identityRootFingerprint.trim().toLowerCase()
      : '';

    if (!discoveredFingerprint || !discoveredRoot) {
      return {
        valid: false,
        bundleX25519,
        expectedX25519: discoveredSignalX25519 || cachedX25519,
        reason: 'DISCOVERY_CERTIFIED_IDENTITY_MISSING'
      };
    }

    if (existingPinnedFingerprint) {
      if (!discoveredFingerprint || discoveredFingerprint !== existingPinnedFingerprint) {
        return {
          valid: false,
          bundleX25519,
          expectedX25519: discoveredSignalX25519,
          reason: 'PINNED_CERTIFICATE_MISMATCH'
        };
      }
    }
    if (existingIdentityRootFingerprint && discoveredRoot !== existingIdentityRootFingerprint) {
      return {
        valid: false,
        bundleX25519,
        expectedX25519: discoveredSignalX25519,
        reason: 'PINNED_IDENTITY_ROOT_MISMATCH'
      };
    }

    if (discoveredSignalX25519 && discoveredSignalX25519 === bundleX25519) {
      dispatchPeerMaterial(normalizedPeerUsername, material);
      return {
        valid: true,
        bundleX25519,
        expectedX25519: discoveredSignalX25519
      };
    }

    return {
      valid: false,
      bundleX25519,
      expectedX25519: discoveredSignalX25519 || cachedX25519,
      reason: discoveredSignalX25519 ? 'DISCOVERY_SIGNAL_IDENTITY_MISMATCH' : 'DISCOVERY_SIGNAL_IDENTITY_MISSING'
    };
  } catch {
    return {
      valid: false,
      bundleX25519,
      expectedX25519: cachedX25519,
      reason: 'DISCOVERY_LOOKUP_FAILED'
    };
  }
}

export async function resolveTrustedPeerDilithiumPublicKey(
  peerUsername: string,
  observedDilithiumPublicKey: string,
  users?: PeerIdentityLike[] | null,
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<PeerDilithiumValidationResult> {
  const normalizedPeerUsername = typeof peerUsername === 'string' ? peerUsername.trim() : '';
  if (!normalizedPeerUsername) {
    return { valid: false, expectedDilithium: null, reason: 'MISSING_PEER_USERNAME' };
  }
  if (typeof observedDilithiumPublicKey !== 'string' || !observedDilithiumPublicKey.trim()) {
    return { valid: false, expectedDilithium: null, reason: 'MISSING_OBSERVED_DILITHIUM_KEY' };
  }

  const observed = observedDilithiumPublicKey.trim();
  const peer = (Array.isArray(users) ? users : []).find((user) => user?.username === normalizedPeerUsername);
  const existingPinnedFingerprint = typeof peer?.peerCertificateFingerprint === 'string'
    ? peer.peerCertificateFingerprint.trim().toLowerCase()
    : '';
  const existingIdentityRootFingerprint = typeof peer?.identityRootFingerprint === 'string'
    ? peer.identityRootFingerprint.trim().toLowerCase()
    : '';
  const cachedDilithium = peer?.hybridPublicKeys?.dilithiumPublicBase64 || null;

  if (cachedDilithium && cachedDilithium === observed && existingPinnedFingerprint && existingIdentityRootFingerprint) {
    return { valid: true, expectedDilithium: cachedDilithium };
  }

  if (cachedDilithium && existingPinnedFingerprint) {
    return {
      valid: false,
      expectedDilithium: cachedDilithium,
      reason: 'PINNED_DILITHIUM_IDENTITY_MISMATCH'
    };
  }

  if (!findUser) {
    return {
      valid: false,
      expectedDilithium: cachedDilithium,
      reason: cachedDilithium ? 'DILITHIUM_IDENTITY_MISMATCH' : 'NO_TRUSTED_DILITHIUM_IDENTITY'
    };
  }

  const knownPeers = (Array.isArray(users) ? users : []).map((user) => user?.username).filter(Boolean) as string[];
  if (!shouldAttemptDiscovery(normalizedPeerUsername, knownPeers)) {
    return {
      valid: false,
      expectedDilithium: cachedDilithium,
      reason: 'DISCOVERY_NOT_ALLOWED'
    };
  }

  try {
    const material = await findUser(normalizedPeerUsername, { forceRefresh: true });
    const certified = await validateCertifiedDiscoveryMaterial(normalizedPeerUsername, material);
    if (!certified.valid) {
      return {
        valid: false,
        expectedDilithium: cachedDilithium,
        reason: certified.reason || 'CERTIFIED_IDENTITY_INVALID'
      };
    }
    const discoveredDilithium = material?.publicKeys?.dilithiumPublicBase64 || null;
    const discoveredFingerprint = typeof certified.peerCertificateFingerprint === 'string'
      ? certified.peerCertificateFingerprint.trim().toLowerCase()
      : '';
    const discoveredRoot = typeof certified.identityRootFingerprint === 'string'
      ? certified.identityRootFingerprint.trim().toLowerCase()
      : '';

    if (!discoveredFingerprint || !discoveredRoot) {
      return {
        valid: false,
        expectedDilithium: discoveredDilithium || cachedDilithium,
        reason: 'DISCOVERY_CERTIFIED_IDENTITY_MISSING'
      };
    }

    if (existingPinnedFingerprint) {
      if (!discoveredFingerprint || discoveredFingerprint !== existingPinnedFingerprint) {
        return {
          valid: false,
          expectedDilithium: discoveredDilithium,
          reason: 'PINNED_CERTIFICATE_MISMATCH'
        };
      }
    }
    if (existingIdentityRootFingerprint && discoveredRoot !== existingIdentityRootFingerprint) {
      return {
        valid: false,
        expectedDilithium: discoveredDilithium,
        reason: 'PINNED_IDENTITY_ROOT_MISMATCH'
      };
    }

    if (discoveredDilithium && discoveredDilithium === observed) {
      dispatchPeerMaterial(normalizedPeerUsername, material);
      return {
        valid: true,
        expectedDilithium: discoveredDilithium
      };
    }

    return {
      valid: false,
      expectedDilithium: discoveredDilithium || cachedDilithium,
      reason: discoveredDilithium ? 'DISCOVERY_DILITHIUM_IDENTITY_MISMATCH' : 'DISCOVERY_DILITHIUM_IDENTITY_MISSING'
    };
  } catch {
    return {
      valid: false,
      expectedDilithium: cachedDilithium,
      reason: 'DISCOVERY_LOOKUP_FAILED'
    };
  }
}

export async function resolveTrustedPeerHybridPublicKeys(
  peerUsername: string,
  material: any,
  users?: PeerIdentityLike[] | null
): Promise<TrustedPeerHybridKeysResult> {
  const normalizedPeerUsername = typeof peerUsername === 'string' ? peerUsername.trim() : '';
  if (!normalizedPeerUsername) {
    return { valid: false, hybridKeys: null, reason: 'MISSING_PEER_USERNAME' };
  }
  if (!material || typeof material !== 'object') {
    return { valid: false, hybridKeys: null, reason: 'MISSING_DISCOVERY_MATERIAL' };
  }

  const publicKeys = material?.publicKeys;
  const kyberPublicBase64 = typeof publicKeys?.kyberPublicBase64 === 'string'
    ? publicKeys.kyberPublicBase64.trim()
    : '';
  const dilithiumPublicBase64 = typeof publicKeys?.dilithiumPublicBase64 === 'string'
    ? publicKeys.dilithiumPublicBase64.trim()
    : '';
  let x25519PublicBase64 = typeof publicKeys?.x25519PublicBase64 === 'string'
    ? publicKeys.x25519PublicBase64.trim()
    : '';
  const inboxId = typeof material?.inboxId === 'string' ? material.inboxId.trim() : undefined;
  const peerCertificateFingerprint = typeof material?.peerCertificateFingerprint === 'string'
    ? material.peerCertificateFingerprint.trim().toLowerCase()
    : '';
  const certified = await validateCertifiedDiscoveryMaterial(normalizedPeerUsername, material);
  if (!certified.valid) {
    return { valid: false, hybridKeys: null, reason: certified.reason || 'CERTIFIED_IDENTITY_INVALID' };
  }
  const certifiedPeerCertificateFingerprint = typeof certified.peerCertificateFingerprint === 'string'
    ? certified.peerCertificateFingerprint.trim().toLowerCase()
    : peerCertificateFingerprint;
  const certifiedIdentityRootFingerprint = typeof certified.identityRootFingerprint === 'string'
    ? certified.identityRootFingerprint.trim().toLowerCase()
    : '';
  const certifiedIdentityBundleFingerprint = typeof certified.identityBundleFingerprint === 'string'
    ? certified.identityBundleFingerprint.trim().toLowerCase()
    : '';

  if (!kyberPublicBase64 || !dilithiumPublicBase64) {
    return { valid: false, hybridKeys: null, reason: 'MISSING_HYBRID_KEYS' };
  }
  if (!certifiedPeerCertificateFingerprint || !certifiedIdentityRootFingerprint) {
    return { valid: false, hybridKeys: null, reason: 'DISCOVERY_CERTIFIED_IDENTITY_MISSING' };
  }

  if (!x25519PublicBase64 && certified.transportX25519PublicKey) {
    x25519PublicBase64 = certified.transportX25519PublicKey;
  }

  if (!x25519PublicBase64) {
    return { valid: false, hybridKeys: null, reason: 'MISSING_X25519_IDENTITY' };
  }

  const peer = (Array.isArray(users) ? users : []).find((user) => user?.username === normalizedPeerUsername);
  const existingPinnedFingerprint = typeof peer?.peerCertificateFingerprint === 'string'
    ? peer.peerCertificateFingerprint.trim().toLowerCase()
    : '';
  const existingIdentityRootFingerprint = typeof peer?.identityRootFingerprint === 'string'
    ? peer.identityRootFingerprint.trim().toLowerCase()
    : '';
  const cachedDilithium = peer?.hybridPublicKeys?.dilithiumPublicBase64 || '';
  const cachedX25519 = peer?.hybridPublicKeys?.x25519PublicBase64 || '';

  if (existingPinnedFingerprint && certifiedPeerCertificateFingerprint && existingPinnedFingerprint !== certifiedPeerCertificateFingerprint) {
    return { valid: false, hybridKeys: null, reason: 'PINNED_CERTIFICATE_MISMATCH' };
  }
  if (existingIdentityRootFingerprint && certifiedIdentityRootFingerprint && existingIdentityRootFingerprint !== certifiedIdentityRootFingerprint) {
    return { valid: false, hybridKeys: null, reason: 'PINNED_IDENTITY_ROOT_MISMATCH' };
  }

  if (cachedDilithium && cachedDilithium !== dilithiumPublicBase64 && existingPinnedFingerprint) {
    return { valid: false, hybridKeys: null, reason: 'PINNED_DILITHIUM_IDENTITY_MISMATCH' };
  }

  if (cachedX25519 && cachedX25519 !== x25519PublicBase64 && existingPinnedFingerprint) {
    return { valid: false, hybridKeys: null, reason: 'PINNED_X25519_IDENTITY_MISMATCH' };
  }

  return {
    valid: true,
    hybridKeys: {
      kyberPublicBase64,
      dilithiumPublicBase64,
      x25519PublicBase64,
      inboxId,
      routeId: material.routeId,
      mailboxLookupId: material.mailboxLookupId,
      bundleLookupId: material.bundleLookupId,
    },
    peerCertificateFingerprint: certifiedPeerCertificateFingerprint || undefined,
    identityRootFingerprint: certifiedIdentityRootFingerprint || undefined,
    identityBundleFingerprint: certifiedIdentityBundleFingerprint || undefined,
  };
}
