import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { EventType } from '../../lib/types/event-types';
import type { HybridKeys } from '../../lib/types/p2p-types';
import { toUint8 } from '../../lib/utils/p2p-utils';
import { retrieveAuthTokens } from '../../lib/signals/token-storage';

// Refs and state from authentication needed to derive P2P keys
export interface AuthenticationRefs {
  hybridKeysRef: React.RefObject<{
    dilithium?: { secretKey: Uint8Array; publicKeyBase64: string };
    kyber?: { secretKey: Uint8Array; publicKeyBase64: string };
    x25519?: { private: Uint8Array; publicKeyBase64: string };
  } | null>;
  loginUsernameRef: React.RefObject<string | null>;
  serverHybridPublic?: { dilithiumPublicBase64?: string };
}

export interface DatabaseRefs {
  secureDBRef: React.RefObject<{ getOriginalUsername?: (h: string) => Promise<string | null> } | null>;
  users: Array<{ username: string; hybridPublicKeys?: any }>;
}

// Derives P2P hybrid keys from authentication state
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
      kyber: (keys.kyber?.secretKey && keys.kyber?.publicKeyBase64) ? {
        publicKey: toUint8(keys.kyber.publicKeyBase64)!,
        secretKey: keys.kyber.secretKey,
      } : undefined,
      x25519: (keys.x25519?.private && keys.x25519?.publicKeyBase64) ? {
        publicKey: toUint8(keys.x25519.publicKeyBase64)!,
        private: keys.x25519.private,
      } : undefined,
    };
  }, [authRefs.hybridKeysRef.current, p2pKeysVersion]);

  const getPeerHybridKeys = useCallback(async (peerUsername: string) => {
    const existingUser = dbRefs.users.find(u => u.username === peerUsername);
    if (existingUser?.hybridPublicKeys?.kyberPublicBase64 && existingUser?.hybridPublicKeys?.dilithiumPublicBase64) {
      return existingUser.hybridPublicKeys;
    }
    return null;
  }, [dbRefs.users]);

  const trustedIssuerDilithiumPublicKeyBase64 = authRefs.serverHybridPublic?.dilithiumPublicBase64 || '';

  const signalingTokenProvider = useCallback(async () => {
    try {
      const tokens = await retrieveAuthTokens();
      return tokens?.accessToken || null;
    } catch {
      return null;
    }
  }, []);

  return {
    p2pHybridKeys,
    getPeerHybridKeys,
    trustedIssuerDilithiumPublicKeyBase64,
    signalingTokenProvider,
    username: authRefs.loginUsernameRef.current || '',
  };
}
