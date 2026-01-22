import { RefObject } from "react";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import type { PeerCertificateBundle, HybridKeys, RouteProofRecord, CertCacheEntry } from "../../lib/types/p2p-types";
import {
  toUint8,
  buildRouteProof,
  getChannelId,
  buildAuthenticator
} from "../../lib/utils/p2p-utils";
import { CERT_CLOCK_SKEW_MS, P2P_ROUTE_PROOF_TTL_MS, MAX_P2P_CERT_CACHE_SIZE, MAX_P2P_ROUTE_PROOF_CACHE_SIZE, P2P_PEER_CACHE_TTL_MS } from "../../lib/constants";

// Core cache references used by all certificate helpers
export interface CertificateRefs {
  peerCertificateCacheRef: RefObject<Map<string, CertCacheEntry>>;
  routeProofCacheRef: RefObject<Map<string, RouteProofRecord>>;
  peerAuthCacheRef: RefObject<ReturnType<typeof buildAuthenticator>>;
  channelSequenceRef: RefObject<Map<string, number>>;
}

// Optional hooks injected by the hook consumer to fetch certificates or pin a trusted issuer
export interface CertificateOptions {
  fetchPeerCertificates?: (peer: string) => Promise<PeerCertificateBundle | null>;
  trustedIssuerDilithiumPublicKeyBase64?: string;
}

// Certificate retriever that validates signatures
export function createGetPeerCertificate(
  refs: CertificateRefs,
  options: CertificateOptions
) {
  return async (peerUsername: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
    const now = Date.now();
    const cached = bypassCache ? null : refs.peerCertificateCacheRef.current.get(peerUsername);
    if (cached && cached.expiresAt > now) {
      return cached.cert;
    }
    if (!options?.fetchPeerCertificates) {
      return null;
    }
    try {
      const cert = await options.fetchPeerCertificates(peerUsername);
      if (!cert) {
        return null;
      }
      const dilithiumKey = toUint8(cert.dilithiumPublicKey);
      const signature = toUint8(cert.signature);
      if (!dilithiumKey || !signature) {
        return null;
      }
      const canonical = new TextEncoder().encode(
        JSON.stringify({
          username: cert.username,
          dilithiumPublicKey: cert.dilithiumPublicKey,
          kyberPublicKey: cert.kyberPublicKey,
          x25519PublicKey: cert.x25519PublicKey,
          proof: cert.proof,
          issuedAt: cert.issuedAt,
          expiresAt: cert.expiresAt,
        }),
      );
      const issuerKey = toUint8(cert.proof);
      if (!issuerKey) return null;

      const valid = await CryptoUtils.Dilithium.verify(signature, canonical, issuerKey);
      if (!valid) {
        throw new Error('CERT_INVALID_SIGNATURE');
      }

      if (options?.trustedIssuerDilithiumPublicKeyBase64 && cert.proof !== options.trustedIssuerDilithiumPublicKeyBase64) {
        throw new Error('CERT_UNTRUSTED_ISSUER');
      }

      const notYetValid = cert.issuedAt > (now + CERT_CLOCK_SKEW_MS);
      const alreadyExpired = cert.expiresAt <= (now - CERT_CLOCK_SKEW_MS);
      if (notYetValid || alreadyExpired) {
        throw new Error('CERT_INVALID_WINDOW');
      }
      refs.peerCertificateCacheRef.current.set(peerUsername, {
        cert,
        expiresAt: Math.min(cert.expiresAt, now + P2P_PEER_CACHE_TTL_MS),
      });

      if (refs.peerCertificateCacheRef.current.size > MAX_P2P_CERT_CACHE_SIZE) {
        const entries = [...refs.peerCertificateCacheRef.current.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
        while (entries.length > MAX_P2P_CERT_CACHE_SIZE) {
          const [key] = entries.shift()!;
          refs.peerCertificateCacheRef.current.delete(key);
        }
      }
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
export function createEnsurePeerAuthenticated(
  refs: CertificateRefs,
  hybridKeys: HybridKeys | null,
  deriveConversationKey: (peer: string) => string | null,
  getPeerCertificate: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>
) {
  return async (peerUsername: string, envelope?: any): Promise<boolean> => {
    const conversationKey = deriveConversationKey(peerUsername);
    if (!conversationKey) return false;
    if (refs.peerAuthCacheRef.current.memoize(conversationKey)) {
      return true;
    }

    const cert = await getPeerCertificate(peerUsername);
    if (!cert) {
      return false;
    }

    const dilithiumKey = toUint8(cert.dilithiumPublicKey);
    const kyberKey = toUint8(cert.kyberPublicKey);
    if (!dilithiumKey || !kyberKey) {
      return false;
    }

    const senderKey = envelope?.metadata?.sender?.dilithiumPublicKey ||
      (envelope?.routing && typeof envelope.routing === 'object' ? envelope.routing.from : null);

    if (senderKey && senderKey !== cert.dilithiumPublicKey) {
      return false;
    }

    if (!hybridKeys?.dilithium) return false;

    const proofRecord = refs.routeProofCacheRef.current.get(conversationKey);
    if (!proofRecord || proofRecord.expiresAt <= Date.now()) {
      const routeProof = await buildRouteProof(
        hybridKeys.dilithium.secretKey,
        hybridKeys.dilithium.publicKeyBase64,
        cert.dilithiumPublicKey,
        getChannelId(hybridKeys.dilithium.publicKeyBase64, cert.dilithiumPublicKey),
        (refs.channelSequenceRef.current.get(conversationKey) ?? 0) + 1,
      );
      refs.routeProofCacheRef.current.set(conversationKey, {
        proof: routeProof,
        expiresAt: Date.now() + P2P_ROUTE_PROOF_TTL_MS,
      });
      if (refs.routeProofCacheRef.current.size > MAX_P2P_ROUTE_PROOF_CACHE_SIZE) {
        const entries = [...refs.routeProofCacheRef.current.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
        while (entries.length > MAX_P2P_ROUTE_PROOF_CACHE_SIZE) {
          const [key] = entries.shift()!;
          refs.routeProofCacheRef.current.delete(key);
        }
      }
      refs.channelSequenceRef.current.set(conversationKey, (refs.channelSequenceRef.current.get(conversationKey) ?? 0) + 1);
    }

    refs.peerAuthCacheRef.current.store(conversationKey, P2P_PEER_CACHE_TTL_MS);
    return true;
  };
}
