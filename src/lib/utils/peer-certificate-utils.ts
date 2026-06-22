import { blake3 } from '@noble/hashes/blake3.js';
import type { PeerCertificateBundle } from '../types/p2p-types';
import { normalizeP2PEndpointUrl } from './p2p-endpoint';
import { CryptoUtils } from './crypto-utils';
import { toUint8 } from './p2p-utils';
import { CERT_CLOCK_SKEW_MS } from '../constants';

// Fully validate a peer certificate bundle
export async function validatePeerCertificateBundle(
  fetched: PeerCertificateBundle | null | undefined,
  expectedUsername: string,
  now: number = Date.now()
): Promise<PeerCertificateBundle | null> {
  try {
    if (!fetched) return null;
    const cert = normalizePeerCertificateBundle(fetched);
    if (cert.username !== expectedUsername) return null;
    const dilithiumKey = toUint8(cert.dilithiumPublicKey);
    const signature = toUint8(cert.signature);
    if (!dilithiumKey || !signature) return null;
    if (!isSelfSignedPeerCertificate(cert)) return null;
    const canonical = encodePeerCertificateSigningPayload(cert);
    const issuerKey = toUint8(cert.proof);
    if (!issuerKey) return null;
    const valid = await CryptoUtils.Dilithium.verify(signature, canonical, issuerKey);
    if (!valid) return null;
    const notYetValid = cert.issuedAt > (now + CERT_CLOCK_SKEW_MS);
    const alreadyExpired = cert.expiresAt <= (now - CERT_CLOCK_SKEW_MS);
    if (notYetValid || alreadyExpired) return null;
    return cert;
  } catch {
    return null;
  }
}

export function computePeerCertificateFingerprint(cert: PeerCertificateBundle): string {
  const canonical = JSON.stringify({
    schema: 'qor-peer-certificate-identity-v2',
    username: cert.username,
    dilithiumPublicKey: cert.dilithiumPublicKey,
    kyberPublicKey: cert.kyberPublicKey,
    x25519PublicKey: cert.x25519PublicKey,
    proof: cert.proof
  });
  const digest = blake3(new TextEncoder().encode(canonical), { dkLen: 32 });
  return Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function normalizePeerCertificateBundle(cert: PeerCertificateBundle): PeerCertificateBundle {
  return {
    ...cert,
    username: typeof cert.username === 'string' ? cert.username.trim() : '',
    inboxId: typeof cert.inboxId === 'string' ? cert.inboxId.trim() : cert.inboxId,
    p2pEndpointUrl: normalizeP2PEndpointUrl(cert.p2pEndpointUrl)
  };
}

export function isSelfSignedPeerCertificate(cert: PeerCertificateBundle): boolean {
  return (
    typeof cert?.proof === 'string' &&
    typeof cert?.dilithiumPublicKey === 'string' &&
    cert.proof === cert.dilithiumPublicKey
  );
}

export function encodePeerCertificateSigningPayload(cert: PeerCertificateBundle): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      schema: 'qor-peer-certificate-v2',
      version: 2,
      username: cert.username,
      inboxId: cert.inboxId,
      dilithiumPublicKey: cert.dilithiumPublicKey,
      kyberPublicKey: cert.kyberPublicKey,
      x25519PublicKey: cert.x25519PublicKey,
      p2pEndpointUrl: cert.p2pEndpointUrl,
      proof: cert.proof,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt
    })
  );
}

export function extractX25519FromSignalBundle(fullBundle: any): string | undefined {
  if (!fullBundle) return undefined;

  if (fullBundle.identityKeyBase64 && typeof fullBundle.identityKeyBase64 === 'string') {
    try {
      const keyBytes = Uint8Array.from(atob(fullBundle.identityKeyBase64), (c) => c.charCodeAt(0));

      if (keyBytes.length === 33 && keyBytes[0] === 0x05) {
        const rawKey = keyBytes.slice(1);
        return btoa(String.fromCharCode(...rawKey));
      }

      if (keyBytes.length === 32) {
        return fullBundle.identityKeyBase64;
      }
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export function areHybridPublicKeysEquivalent(
  left: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
    inboxId?: string;
    routeId?: string;
    mailboxLookupId?: string;
  } | null | undefined,
  right: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
    inboxId?: string;
    routeId?: string;
    mailboxLookupId?: string;
  } | null | undefined
): boolean {
  return (
    (left?.kyberPublicBase64 || '') === (right?.kyberPublicBase64 || '') &&
    (left?.dilithiumPublicBase64 || '') === (right?.dilithiumPublicBase64 || '') &&
    (left?.x25519PublicBase64 || '') === (right?.x25519PublicBase64 || '') &&
    (left?.inboxId || '') === (right?.inboxId || '') &&
    (left?.routeId || '') === (right?.routeId || '') &&
    (left?.mailboxLookupId || '') === (right?.mailboxLookupId || '')
  );
}
