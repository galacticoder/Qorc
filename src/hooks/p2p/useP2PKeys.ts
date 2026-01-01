import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { EventType } from '../../lib/event-types';
import { SignalType } from '../../lib/signal-types';
import websocketClient from '../../lib/websocket';
import { storeUsernameMapping } from '../../lib/username-display';
import type { HybridKeys, PeerCertificateBundle } from '../../lib/types/p2p-types';

// Refs and state from authentication needed to derive P2P keys
export interface AuthenticationRefs {
  hybridKeysRef: React.RefObject<{
    dilithium?: { secretKey: Uint8Array; publicKeyBase64: string };
    kyber?: { secretKey: Uint8Array };
    x25519?: { private: Uint8Array };
  } | null>;
  loginUsernameRef: React.RefObject<string | null>;
  serverHybridPublic?: { dilithiumPublicBase64?: string };
}

export interface DatabaseRefs {
  secureDBRef: React.RefObject<{ getOriginalUsername?: (h: string) => Promise<string | null> } | null>;
  users: Array<{ username: string; hybridPublicKeys?: any }>;
}

// Derives P2P hybrid keys from authentication state and provides certificate fetching
export function useP2PKeys(authRefs: AuthenticationRefs, dbRefs: DatabaseRefs) {
  const [p2pKeysVersion, setP2pKeysVersion] = useState(0);

  useEffect(() => {
    const bump = () => setP2pKeysVersion((v) => v + 1);
    window.addEventListener(EventType.HYBRID_KEYS_UPDATED, bump as EventListener);
    window.addEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, bump as EventListener);
    return () => {
      window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, bump as EventListener);
      window.removeEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, bump as EventListener);
    };
  }, []);

  const p2pHybridKeys = useMemo<HybridKeys | null>(() => {
    const keys = authRefs.hybridKeysRef.current;
    if (!keys?.dilithium?.secretKey || !keys?.dilithium?.publicKeyBase64) {
      return null;
    }
    return {
      dilithium: {
        secretKey: keys.dilithium.secretKey,
        publicKeyBase64: keys.dilithium.publicKeyBase64,
      },
      kyber: keys.kyber ? {
        secretKey: keys.kyber.secretKey,
      } : undefined,
      x25519: keys.x25519 ? {
        private: keys.x25519.private,
      } : undefined,
    };
  }, [authRefs.hybridKeysRef.current, p2pKeysVersion]);

  const fetchPeerCertificates = useCallback(async (peerUsername: string): Promise<PeerCertificateBundle | null> => {
    try {
      return await new Promise<PeerCertificateBundle | null>(async (resolve) => {
        let settled = false;

        const wsHandler = (evt: Event) => {
          try {
            const msg: any = (evt as CustomEvent).detail || {};
            if (!msg || typeof msg !== 'object') return;
            if (msg.type !== SignalType.P2P_PEER_CERT) return;
            if (typeof msg.username !== 'string' || msg.username !== peerUsername) return;
            if (typeof msg.dilithiumPublicKey !== 'string' || typeof msg.kyberPublicKey !== 'string' || typeof msg.signature !== 'string' || typeof msg.proof !== 'string') return;
            try { window.removeEventListener(EventType.P2P_PEER_CERT, wsHandler as EventListener); } catch { }
            try { window.removeEventListener(EventType.USER_EXISTS_RESPONSE, userExistsHandler as EventListener); } catch { }
            const bundle = {
              username: msg.username,
              dilithiumPublicKey: msg.dilithiumPublicKey,
              kyberPublicKey: msg.kyberPublicKey,
              x25519PublicKey: msg.x25519PublicKey,
              proof: msg.proof,
              issuedAt: msg.issuedAt,
              expiresAt: msg.expiresAt,
              signature: msg.signature
            } as PeerCertificateBundle;

            if (dbRefs.secureDBRef.current) {
              storeUsernameMapping(bundle.username, dbRefs.secureDBRef.current as any).catch(() => { });
            }

            try {
              const hybridKeys = {
                kyberPublicBase64: bundle.kyberPublicKey,
                dilithiumPublicBase64: bundle.dilithiumPublicKey,
                x25519PublicBase64: bundle.x25519PublicKey,
              };
              window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                detail: { username: bundle.username, hybridKeys },
              }));
            } catch { }

            settled = true;
            resolve(bundle);
          } catch { }
        };

        const userExistsHandler = (evt: Event) => {
          try {
            const data: any = (evt as CustomEvent).detail || {};
            if (typeof data?.username !== 'string' || data.username !== peerUsername) return;
            const pc = data?.peerCertificate || data?.p2pCertificate || data?.cert || null;
            if (!pc) return;
            const dpk = pc.dilithiumPublicKey;
            const kpk = pc.kyberPublicKey;
            const sig = pc.signature;
            const proof = pc.proof;
            if (typeof dpk !== 'string' || typeof kpk !== 'string' || typeof sig !== 'string' || typeof proof !== 'string') return;
            try { (websocketClient as any).unregisterMessageHandler?.(SignalType.P2P_PEER_CERT); } catch { }
            try { window.removeEventListener(EventType.USER_EXISTS_RESPONSE, userExistsHandler as EventListener); } catch { }
            const bundle = {
              username: peerUsername,
              dilithiumPublicKey: dpk,
              kyberPublicKey: kpk,
              x25519PublicKey: pc.x25519PublicKey,
              proof,
              issuedAt: pc.issuedAt,
              expiresAt: pc.expiresAt,
              signature: sig
            } as PeerCertificateBundle;

            if (dbRefs.secureDBRef.current) {
              storeUsernameMapping(bundle.username, dbRefs.secureDBRef.current as any).catch(() => { });
            }
            try {
              const hybridKeys = {
                kyberPublicBase64: bundle.kyberPublicKey,
                dilithiumPublicBase64: bundle.dilithiumPublicKey,
                x25519PublicBase64: bundle.x25519PublicKey,
              };
              window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                detail: { username: bundle.username, hybridKeys },
              }));
            } catch { }

            settled = true;
            resolve(bundle);
          } catch { }
        };

        try { window.addEventListener(EventType.P2P_PEER_CERT, wsHandler as EventListener); } catch { }
        try { window.addEventListener(EventType.USER_EXISTS_RESPONSE, userExistsHandler as EventListener); } catch { }

        try { await websocketClient.sendSecureControlMessage({ type: SignalType.P2P_FETCH_PEER_CERT, username: peerUsername }); } catch { }
        try { await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: peerUsername }); } catch { }

        setTimeout(() => {
          if (!settled) {
            try { window.removeEventListener(EventType.P2P_PEER_CERT, wsHandler as EventListener); } catch { }
            try { window.removeEventListener(EventType.USER_EXISTS_RESPONSE, userExistsHandler as EventListener); } catch { }
            resolve(null);
          }
        }, 5000);
      });
    } catch {
      return null;
    }
  }, [dbRefs.secureDBRef]);

  const getPeerHybridKeys = useCallback(async (peerUsername: string) => {
    const existingUser = dbRefs.users.find(u => u.username === peerUsername);
    if (existingUser?.hybridPublicKeys?.kyberPublicBase64 && existingUser?.hybridPublicKeys?.dilithiumPublicBase64) {
      return existingUser.hybridPublicKeys;
    }

    try {
      await websocketClient.sendSecureControlMessage({
        type: SignalType.P2P_FETCH_PEER_CERT,
        username: peerUsername
      });
      await websocketClient.sendSecureControlMessage({
        type: SignalType.CHECK_USER_EXISTS,
        username: peerUsername
      });
    } catch {
      return null;
    }

    return new Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          resolve(null);
        }
      }, 5000);

      const cleanup = () => {
        window.removeEventListener(EventType.USER_EXISTS_RESPONSE, onUserExists as EventListener);
        window.removeEventListener(EventType.P2P_PEER_CERT, onPeerCert as EventListener);
      };

      const handleCert = (pc: any) => {
        if (pc && pc.kyberPublicKey && pc.dilithiumPublicKey) {
          if (!settled) {
            settled = true;
            clearTimeout(timeout);
            cleanup();

            const keys = {
              kyberPublicBase64: pc.kyberPublicKey,
              dilithiumPublicBase64: pc.dilithiumPublicKey,
              x25519PublicBase64: pc.x25519PublicKey
            };

            if (dbRefs.secureDBRef.current) {
              storeUsernameMapping(peerUsername, dbRefs.secureDBRef.current as any).catch(() => { });
            }

            try {
              window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                detail: { username: peerUsername, hybridKeys: keys }
              }));
            } catch { }

            resolve(keys);
          }
        }
      };

      const onUserExists = (e: Event) => {
        const d = (e as CustomEvent).detail || {};
        if (d?.username === peerUsername) {
          const pc = d?.peerCertificate || d?.p2pCertificate || d?.cert || null;
          if (pc) handleCert(pc);
        }
      };

      const onPeerCert = (e: Event) => {
        const d = (e as CustomEvent).detail || {};
        if (d?.username === peerUsername) {
          handleCert(d);
        }
      };

      window.addEventListener(EventType.USER_EXISTS_RESPONSE, onUserExists as EventListener);
      window.addEventListener(EventType.P2P_PEER_CERT, onPeerCert as EventListener);
    });
  }, [dbRefs.users, dbRefs.secureDBRef]);

  const trustedIssuerDilithiumPublicKeyBase64 = authRefs.serverHybridPublic?.dilithiumPublicBase64 || '';

  const signalingTokenProvider = useCallback(async () => {
    try {
      const tokens = await (window as any).edgeApi?.retrieveAuthTokens?.();
      return tokens?.accessToken || null;
    } catch {
      return null;
    }
  }, []);

  return {
    p2pHybridKeys,
    fetchPeerCertificates,
    getPeerHybridKeys,
    trustedIssuerDilithiumPublicKeyBase64,
    signalingTokenProvider,
    username: authRefs.loginUsernameRef.current || '',
  };
}
