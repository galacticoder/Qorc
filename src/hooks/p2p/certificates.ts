import { RefObject } from "react";
import type { PeerCertificateBundle, HybridKeys, RouteProofRecord, CertCacheEntry } from "../../lib/types/p2p-types";
import {
  toUint8,
  buildRouteProof,
  getChannelId,
  buildAuthenticator
} from "../../lib/utils/p2p-utils";
import { validatePeerCertificateBundle } from "../../lib/utils/peer-certificate-utils";
import { loadPersistedPeerCert, savePersistedPeerCert, removePersistedPeerCert } from "../../lib/p2p/persisted-peer-cert";
import { P2P_ROUTE_PROOF_TTL_MS, MAX_P2P_CERT_CACHE_SIZE, MAX_P2P_ROUTE_PROOF_CACHE_SIZE, P2P_PEER_CACHE_TTL_MS } from "../../lib/constants";

// Core cache references used by all certificate helpers
export interface CertificateRefs {
  peerCertificateCacheRef: RefObject<Map<string, CertCacheEntry>>;
  routeProofCacheRef: RefObject<Map<string, RouteProofRecord>>;
  peerAuthCacheRef: RefObject<ReturnType<typeof buildAuthenticator>>;
  channelSequenceRef: RefObject<Map<string, number>>;
}

// Optional hooks injected by the hook consumer to fetch certificates or pin a trusted issuer
export interface CertificateOptions {
  fetchPeerCertificates?: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>;
}

// Certificate retriever that validates signatures
export function createGetPeerCertificate(
  refs: CertificateRefs,
  options: CertificateOptions
) {
    const cacheValidatedCert = (peerUsername: string, cert: PeerCertificateBundle): void => {
      refs.peerCertificateCacheRef.current.set(peerUsername, {
        cert,
        expiresAt: Math.min(cert.expiresAt, Date.now() + P2P_PEER_CACHE_TTL_MS),
      });
      if (refs.peerCertificateCacheRef.current.size > MAX_P2P_CERT_CACHE_SIZE) {
        const entries = [...refs.peerCertificateCacheRef.current.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
        while (entries.length > MAX_P2P_CERT_CACHE_SIZE) {
          const [key] = entries.shift()!;
          refs.peerCertificateCacheRef.current.delete(key);
        }
      }
    };

  return async (peerUsername: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
    const now = Date.now();
    const cached = bypassCache ? null : refs.peerCertificateCacheRef.current.get(peerUsername);
    if (cached && cached.expiresAt > now) {
      return cached.cert;
    }

    if (!bypassCache) {
      const persisted = await loadPersistedPeerCert(peerUsername);
      if (persisted) {
        cacheValidatedCert(peerUsername, persisted);
        return persisted;
      }
    }

    if (!options?.fetchPeerCertificates) {
      return null;
    }
    try {
      const fetched = await options.fetchPeerCertificates(peerUsername, bypassCache);
      const cert = await validatePeerCertificateBundle(fetched, peerUsername, now);
      if (!cert) {
        return null;
      }
      cacheValidatedCert(peerUsername, cert);
      savePersistedPeerCert(peerUsername, cert);
      return cert;
    } catch {
      return null;
    }
  };
}

// Removes cached entries for a peer so future requests do a fresh fetch
export function createInvalidatePeerCert(refs: CertificateRefs) {
  return (peerUsername: string) => {
    if (!peerUsername) return;
    refs.peerCertificateCacheRef.current.delete(peerUsername);
    
    removePersistedPeerCert(peerUsername);
    const keysToDelete: string[] = [];
    for (const [key] of refs.routeProofCacheRef.current) {
      if (key.includes(peerUsername)) {
        keysToDelete.push(key);
      }
    }
    for (const key of keysToDelete) {
      refs.routeProofCacheRef.current.delete(key);
    }
  };
}

// Derives a deterministic conversation key between the local profile and a peer
export function createDeriveConversationKey(hybridKeys: HybridKeys | null) {
  return (peer: string) => {
    if (!hybridKeys?.dilithium?.publicKeyBase64) return null;
    return `${hybridKeys.dilithium.publicKeyBase64}:${peer}`;
  };
}

// Makes sure a peer proves ownership of their certificate and route-proof before allowing messages
