import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { EventType } from '../../lib/types/event-types';
import type { HybridKeys } from '../../lib/types/p2p-types';
import { toUint8 } from '../../lib/utils/p2p-utils';
import { account } from '../../lib/tauri-bindings';
import type { HybridKeys as NativeAccountPublicKeys } from '../../lib/types/auth-types';
import type { HybridPublicKeys } from '../../lib/types/message-sending-types';
import {
  isKeyTransparencyAuthorizedPeerKeySet,
  isKeyTransparencyPeerRevoked,
} from '../../lib/key-transparency/verified-material';
import { PROTOCOL_KEYS } from '../../lib/config/protocol-keys';
import { ML_DSA_87_SIGNATURE_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES, X25519_KEY_BYTES } from '../../../shared/crypto-sizes.js';

// Refs and state from authentication needed to derive P2P keys
export interface AuthenticationRefs {
  hybridKeysRef: React.RefObject<NativeAccountPublicKeys | null>;
  loginUsernameRef: React.RefObject<string | null>;
}

export interface DatabaseRefs {
  users: Array<{
    username: string;
    hybridPublicKeys?: any;
    peerCertificateFingerprint?: string;
    identityRootFingerprint?: string;
    identityBundleFingerprint?: string;
  }>;
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
    if (
      keys?.native !== true ||
      !keys.dilithium.publicKeyBase64 ||
      !keys.kyber.publicKeyBase64 ||
      !keys.x25519.publicKeyBase64
    ) {
      return null;
    }
    const kyberPublic = toUint8(keys.kyber.publicKeyBase64, ML_KEM_1024_PUBLIC_KEY_BYTES);
    const x25519Public = toUint8(keys.x25519.publicKeyBase64, X25519_KEY_BYTES);
    if (
      kyberPublic?.length !== ML_KEM_1024_PUBLIC_KEY_BYTES ||
      x25519Public?.length !== X25519_KEY_BYTES
    ) {
      kyberPublic?.fill(0);
      x25519Public?.fill(0);
      return null;
    }
    return {
      native: true,
      dilithium: {
        publicKeyBase64: keys.dilithium.publicKeyBase64,
      },
      kyber: {
        publicKey: kyberPublic,
      },
      x25519: {
        publicKey: x25519Public,
      },
      signTranscript: async (message: Uint8Array): Promise<Uint8Array> => {
        const signatureBase64 = await account.sign(PROTOCOL_KEYS.P2P_TRANSCRIPT_SIGNING, message);
        const signature = toUint8(signatureBase64, ML_DSA_87_SIGNATURE_BYTES);
        if (!signature || signature.length !== ML_DSA_87_SIGNATURE_BYTES) {
          signature?.fill(0);
          throw new Error('Native P2P signer returned an invalid signature');
        }
        return signature;
      },
      respondToHandshake: async (
        kemCiphertext: Uint8Array,
        peerX25519Public: Uint8Array,
      ): Promise<{ pqSecret: Uint8Array; x25519Secret: Uint8Array }> => {
        const result = await account.p2pHandshakeSecrets(kemCiphertext, peerX25519Public);
        const pqSecret = toUint8(result.pqSecretBase64, 32);
        const x25519Secret = toUint8(result.x25519SecretBase64, 32);
        if (!pqSecret || !x25519Secret) {
          pqSecret?.fill(0);
          x25519Secret?.fill(0);
          throw new Error('Native P2P handshake returned invalid session material');
        }
        return { pqSecret, x25519Secret };
      },
    };
  }, [authRefs.hybridKeysRef.current, p2pKeysVersion]);

  const getPeerHybridKeys = useCallback(async (peerUsername: string): Promise<HybridPublicKeys | null> => {
    const ownerUsername = authRefs.loginUsernameRef.current;
    if (
      !ownerUsername ||
      isKeyTransparencyPeerRevoked(ownerUsername, peerUsername)
    ) return null;
    const existingUser = dbRefs.users.find(u => u.username === peerUsername);
    if (
      existingUser?.hybridPublicKeys?.kyberPublicBase64 &&
      existingUser?.hybridPublicKeys?.dilithiumPublicBase64 &&
      existingUser?.hybridPublicKeys?.x25519PublicBase64 &&
      existingUser?.peerCertificateFingerprint &&
      existingUser?.identityRootFingerprint &&
      existingUser?.identityBundleFingerprint &&
      isKeyTransparencyAuthorizedPeerKeySet({
        account: ownerUsername,
        peer: peerUsername,
        kyberPublicBase64: existingUser.hybridPublicKeys.kyberPublicBase64,
        dilithiumPublicBase64: existingUser.hybridPublicKeys.dilithiumPublicBase64,
        x25519PublicBase64: existingUser.hybridPublicKeys.x25519PublicBase64,
        peerCertificateFingerprint: existingUser.peerCertificateFingerprint,
        identityRootFingerprint: existingUser.identityRootFingerprint,
        identityBundleFingerprint: existingUser.identityBundleFingerprint,
      })
    ) {
      return {
        kyberPublicBase64: existingUser.hybridPublicKeys.kyberPublicBase64,
        dilithiumPublicBase64: existingUser.hybridPublicKeys.dilithiumPublicBase64,
        x25519PublicBase64: existingUser.hybridPublicKeys.x25519PublicBase64
      };
    }
    return null;
  }, [authRefs.loginUsernameRef, dbRefs.users]);

  return {
    p2pHybridKeys,
    getPeerHybridKeys,
    username: authRefs.loginUsernameRef.current || '',
  };
}
