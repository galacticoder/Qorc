import { RefObject } from "react";
import type { PeerCertificateBundle, CertCacheEntry } from "../../lib/types/p2p-types";
import { validatePeerCertificateBundle } from "../../lib/utils/peer-certificate-utils";
import { computePeerCertificateFingerprint } from "../../lib/utils/peer-certificate-utils";
import { loadPersistedPeerCert, savePersistedPeerCert } from "../../lib/p2p/persisted-peer-cert";
import { MAX_P2P_CERT_CACHE_SIZE, P2P_PEER_CACHE_TTL_MS } from "../../lib/constants";
import { isKeyTransparencyAuthorizedPeerCertificate } from "../../lib/key-transparency/verified-material";

export interface CertificateRefs {
  peerCertificateCacheRef: RefObject<Map<string, CertCacheEntry>>;
}

export interface CertificateOptions {
  ownerUsername: string;
  fetchPeerCertificates?: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>;
  isCurrentOwner?: () => boolean;
}

export function createGetPeerCertificate(
  refs: CertificateRefs,
  options: CertificateOptions
) {
    const persistedWriteTails = new Map<string, Promise<void>>();

    const isTransparencyAuthorized = (
      peerUsername: string,
      cert: PeerCertificateBundle
    ): boolean => isKeyTransparencyAuthorizedPeerCertificate({
      account: options.ownerUsername,
      peer: peerUsername,
      kyberPublicBase64: cert.kyberPublicKey,
      dilithiumPublicBase64: cert.dilithiumPublicKey,
      x25519PublicBase64: cert.x25519PublicKey,
      peerCertificateFingerprint: computePeerCertificateFingerprint(cert),
    });

    const cacheValidatedCert = (
      peerUsername: string,
      cert: PeerCertificateBundle
    ): { cert: PeerCertificateBundle; accepted: boolean } => {
      const existing = refs.peerCertificateCacheRef.current.get(peerUsername);
      if (existing) {
        const sameIdentity = computePeerCertificateFingerprint(existing.cert) ===
          computePeerCertificateFingerprint(cert);
        const now = Date.now();
        if (
          sameIdentity &&
          existing.cert.issuedAt >= cert.issuedAt &&
          isTransparencyAuthorized(peerUsername, existing.cert)
        ) {
          refs.peerCertificateCacheRef.current.set(peerUsername, {
            cert: existing.cert,
            expiresAt: now + P2P_PEER_CACHE_TTL_MS,
          });
          return { cert: existing.cert, accepted: false };
        }
      }

      const snapshot = Object.freeze({ ...cert });
      refs.peerCertificateCacheRef.current.set(peerUsername, {
        cert: snapshot,
        expiresAt: Date.now() + P2P_PEER_CACHE_TTL_MS,
      });
      if (refs.peerCertificateCacheRef.current.size > MAX_P2P_CERT_CACHE_SIZE) {
        const entries = [...refs.peerCertificateCacheRef.current.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
        while (entries.length > MAX_P2P_CERT_CACHE_SIZE) {
          const [key] = entries.shift()!;
          refs.peerCertificateCacheRef.current.delete(key);
        }
      }
      return { cert: snapshot, accepted: true };
    };

    const persistLatestCachedCert = async (peerUsername: string): Promise<void> => {
      const previous = persistedWriteTails.get(peerUsername) ?? Promise.resolve();
      const write = previous.catch(() => { }).then(async () => {
        if (options.isCurrentOwner?.() === false) return;
        const latest = refs.peerCertificateCacheRef.current.get(peerUsername)?.cert;
        if (!latest) return;
        await savePersistedPeerCert(options.ownerUsername, peerUsername, latest);
      });
      const tail = write.then(() => { }, () => { });
      persistedWriteTails.set(peerUsername, tail);
      try {
        await write;
      } finally {
        if (persistedWriteTails.get(peerUsername) === tail) {
          persistedWriteTails.delete(peerUsername);
        }
      }
    };

  return async (
    peerUsername: string,
    bypassCache = false,
    cacheOnly = false,
  ): Promise<PeerCertificateBundle | null> => {
    const isCurrentOwner = () => options.isCurrentOwner?.() !== false;
    if (!isCurrentOwner()) return null;
    const now = Date.now();
    const cached = bypassCache ? null : refs.peerCertificateCacheRef.current.get(peerUsername);
    if (cached && cached.expiresAt > now && isTransparencyAuthorized(peerUsername, cached.cert)) {
      return cached.cert;
    }
    if (cached) refs.peerCertificateCacheRef.current.delete(peerUsername);

    if (!bypassCache) {
      const persisted = await loadPersistedPeerCert(options.ownerUsername, peerUsername, true);
      if (!isCurrentOwner()) return null;
      if (persisted && isTransparencyAuthorized(peerUsername, persisted)) {
        return cacheValidatedCert(peerUsername, persisted).cert;
      }
    }

    if (cacheOnly) return null;

    if (!options?.fetchPeerCertificates) {
      return null;
    }
    try {
      const fetched = await options.fetchPeerCertificates(peerUsername, bypassCache);
      const cert = await validatePeerCertificateBundle(fetched, peerUsername, Date.now());
      if (!isCurrentOwner()) return null;
      if (!cert) {
        return null;
      }
      if (!isTransparencyAuthorized(peerUsername, cert)) return null;
      const cachedResult = cacheValidatedCert(peerUsername, cert);
      if (cachedResult.accepted) {
        await persistLatestCachedCert(peerUsername).catch(() => { });
      }
      if (!isCurrentOwner()) return null;
      return cachedResult.cert;
    } catch {
      return null;
    }
  };
}
