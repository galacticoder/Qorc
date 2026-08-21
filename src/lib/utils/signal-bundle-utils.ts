import { shouldAttemptDiscovery } from './discovery-utils';
import { extractX25519FromSignalBundle } from './peer-certificate-utils';
import { validateCertifiedPeerBundleV3 } from './certified-identity-utils';
import {
  captureKeyTransparencyPeerAuthorization,
  getKeyTransparencyAuthorizedPeerState,
  hydrateKeyTransparencyVerifiedMaterial,
  isKeyTransparencyAuthorizedPeerKeySet,
  isKeyTransparencyVerifiedMaterial,
} from '../key-transparency/verified-material';
import {
  discoveryMaterialStillVouchedFor,
  loadPersistedDiscoveryMaterial,
} from '../discovery/persisted-discovery-material';
import { persistPeerDetectionKey } from '../spool/detection-key';

export async function loadTrustedPersistedDiscoveryMaterial(
    accountUsername: string,
    peerUsername: string
): Promise<any | null> {
  try {
    const record = await loadPersistedDiscoveryMaterial(accountUsername, peerUsername);
    const material = discoveryMaterialStillVouchedFor(
      record,
      getKeyTransparencyAuthorizedPeerState(accountUsername, peerUsername)
    );
    const keys = (material as any)?.publicKeys;
    if (
      material &&
      keys &&
      isKeyTransparencyAuthorizedPeerKeySet({
        account: accountUsername,
        peer: peerUsername,
        kyberPublicBase64: keys.kyberPublicBase64,
        dilithiumPublicBase64: keys.dilithiumPublicBase64,
        x25519PublicBase64: keys.x25519PublicBase64,
        peerCertificateFingerprint: (material as any).peerCertificateFingerprint,
        identityRootFingerprint: (material as any).identityRootFingerprint,
        identityBundleFingerprint: (material as any).identityBundleFingerprint,
      })
    ) {
      const live = getKeyTransparencyAuthorizedPeerState(accountUsername, peerUsername);
      if (live) {
        if (!hydrateKeyTransparencyVerifiedMaterial(material, accountUsername, peerUsername)) {
          return null;
        }
        const certified = await validateCertifiedDiscoveryMaterial(
          accountUsername,
          peerUsername,
          material,
          undefined,
          true,
        );
        if (!certified.valid) return null;
        await persistPeerDetectionKey(
          accountUsername,
          peerUsername,
          (material as any).spoolDetectionKey,
        ).catch(() => { });
        return material;
      }
    }
  } catch {
  }
  return null;
}

async function discoveryMaterialForIdentityCheck(
  accountUsername: string,
  peerUsername: string,
  findUser: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<any> {
  const persisted = await loadTrustedPersistedDiscoveryMaterial(accountUsername, peerUsername);
  if (persisted) return persisted;
  return findUser(peerUsername, { forceRefresh: true });
}

export interface PeerIdentityLike {
  username: string;
  peerCertificateFingerprint?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
  hybridPublicKeys?: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
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
  } | null;
  peerCertificateFingerprint?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
  reason?: string;
}

async function validateCertifiedDiscoveryMaterial(
  accountUsername: string,
  peerUsername: string,
  material: any,
  observedFullBundle?: unknown,
  allowExpired = false,
): Promise<{
  valid: boolean;
  reason?: string;
  identityRootFingerprint?: string;
  identityBundleFingerprint?: string;
  peerCertificateFingerprint?: string;
  signalIdentityX25519PublicKey?: string;
  transportX25519PublicKey?: string;
}> {
  if (!isKeyTransparencyVerifiedMaterial(material, accountUsername, peerUsername)) {
    return { valid: false, reason: 'KEY_TRANSPARENCY_NOT_VERIFIED' };
  }
  const certified = await validateCertifiedPeerBundleV3(material?.certifiedPeerBundle, {
    targetHandle: peerUsername,
    publicKeys: material?.publicKeys,
    fullBundle: observedFullBundle ?? material?.fullBundle,
    peerCertificate: material?.peerCertificate,
    peerCertificateFingerprint: material?.peerCertificateFingerprint,
    allowExpired,
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
  accountUsername: string,
  peerUsername: string,
  bundle: any,
  users?: PeerIdentityLike[] | null,
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>,
  discoveryMaterial?: any,
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
  const cachedX25519 = peer?.hybridPublicKeys?.x25519PublicBase64 || null;

  if (!findUser) {
    return {
      valid: false,
      bundleX25519,
      expectedX25519: cachedX25519,
      reason: 'NO_TRUSTED_SIGNAL_IDENTITY'
    };
  }

  if (!shouldAttemptDiscovery(normalizedPeerUsername)) {
    return {
      valid: false,
      bundleX25519,
      expectedX25519: cachedX25519,
      reason: 'DISCOVERY_NOT_ALLOWED'
    };
  }

  try {
    const material = discoveryMaterial ?? await discoveryMaterialForIdentityCheck(
      accountUsername,
      normalizedPeerUsername,
      findUser,
    );
    const certified = await validateCertifiedDiscoveryMaterial(
      accountUsername,
      normalizedPeerUsername,
      material,
      bundle
    );
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

    if (discoveredSignalX25519 && discoveredSignalX25519 === bundleX25519) {
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
  accountUsername: string,
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
  const cachedDilithium = peer?.hybridPublicKeys?.dilithiumPublicBase64 || null;

  if (captureKeyTransparencyPeerAuthorization(
    accountUsername,
    normalizedPeerUsername,
    observed,
  )) {
    return { valid: true, expectedDilithium: observed };
  }

  if (!findUser) {
    return {
      valid: false,
      expectedDilithium: cachedDilithium,
      reason: cachedDilithium ? 'DILITHIUM_IDENTITY_MISMATCH' : 'NO_TRUSTED_DILITHIUM_IDENTITY'
    };
  }

  if (!shouldAttemptDiscovery(normalizedPeerUsername)) {
    return {
      valid: false,
      expectedDilithium: cachedDilithium,
      reason: 'DISCOVERY_NOT_ALLOWED'
    };
  }

  try {
    const material = await discoveryMaterialForIdentityCheck(accountUsername, normalizedPeerUsername, findUser);
    const certified = await validateCertifiedDiscoveryMaterial(accountUsername, normalizedPeerUsername, material);
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

    if (discoveredDilithium && discoveredDilithium === observed) {
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
  accountUsername: string,
  peerUsername: string,
  material: any
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
  const peerCertificateFingerprint = typeof material?.peerCertificateFingerprint === 'string'
    ? material.peerCertificateFingerprint.trim().toLowerCase()
    : '';
  const certified = await validateCertifiedDiscoveryMaterial(accountUsername, normalizedPeerUsername, material);
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
  if (
    !certifiedPeerCertificateFingerprint ||
    !certifiedIdentityRootFingerprint ||
    !certifiedIdentityBundleFingerprint
  ) {
    return { valid: false, hybridKeys: null, reason: 'DISCOVERY_CERTIFIED_IDENTITY_MISSING' };
  }

  if (!x25519PublicBase64 && certified.transportX25519PublicKey) {
    x25519PublicBase64 = certified.transportX25519PublicKey;
  }

  if (!x25519PublicBase64) {
    return { valid: false, hybridKeys: null, reason: 'MISSING_X25519_IDENTITY' };
  }

  return {
    valid: true,
    hybridKeys: {
      kyberPublicBase64,
      dilithiumPublicBase64,
      x25519PublicBase64
    },
    peerCertificateFingerprint: certifiedPeerCertificateFingerprint || undefined,
    identityRootFingerprint: certifiedIdentityRootFingerprint || undefined,
    identityBundleFingerprint: certifiedIdentityBundleFingerprint || undefined,
  };
}
