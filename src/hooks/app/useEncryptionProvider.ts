import { useEffect } from 'react';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { User } from '../../components/chat/messaging/UserList';

interface EncryptionProviderProps {
  isLoggedIn: boolean;
  loginUsernameRef: React.RefObject<string | null>;
  getPeerHybridKeys: (peer: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>;
  users: User[];
}

export function useEncryptionProvider({
  isLoggedIn,
  loginUsernameRef,
  getPeerHybridKeys,
  users,
}: EncryptionProviderProps) {
  useEffect(() => {
    if (!isLoggedIn) return;

    unifiedSignalTransport.setEncryptionProvider(async (to, payload, type) => {
      try {
        const currentUser = loginUsernameRef.current;
        if (!currentUser || to === 'SERVER') return null;

        let peerKeys = await getPeerHybridKeys(to);
        let resolvedUsername = to;

        if ((!peerKeys || !peerKeys.kyberPublicBase64) && to.length === 32) {
          const usersList = Array.isArray(users) ? users : [];
          const found = usersList.find((u: any) =>
            (u.id === to || u.pixelId === to || u.uuid === to) && u.username
          );
          if (found) {
            resolvedUsername = found.username;
            peerKeys = await getPeerHybridKeys(resolvedUsername);

            try {
              const { quicTransport } = await import('../../lib/transport/quic-transport');
              quicTransport.registerUsernameAlias(resolvedUsername, to);
            } catch { }
          } else {
            try {
              const { quicTransport } = await import('../../lib/transport/quic-transport');
              const alias = quicTransport.resolveUsernameAlias(to);
              if (alias && alias !== to) {
                console.debug('[UnifiedTransport] Resolved hash', to, 'via QuicTransport alias to', alias);
                resolvedUsername = alias;
                peerKeys = await getPeerHybridKeys(resolvedUsername);
              }
            } catch (err) {
              console.warn('[UnifiedTransport] Failed to query QuicTransport alias:', err);
            }
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          console.warn('[UnifiedTransport] Auto-encryption failed: No peer keys for', to, resolvedUsername !== to ? `(alias: ${resolvedUsername})` : '');
          return null;
        }

        const signalPayload = {
          type: 'signal-fallback',
          kind: type,
          content: payload.content || JSON.stringify(payload),
          from: currentUser,
          timestamp: Date.now(),
          ...payload
        };

        const result = await (window as any).edgeApi?.encrypt?.({
          fromUsername: currentUser,
          toUsername: resolvedUsername,
          plaintext: JSON.stringify(signalPayload),
          recipientKyberPublicKey: peerKeys.kyberPublicBase64,
          recipientHybridKeys: peerKeys
        });

        if (result?.success && result?.encryptedPayload) {
          return {
            encryptedPayload: result.encryptedPayload,
            messageId: payload.messageId || crypto.randomUUID().replace(/-/g, '')
          };
        }
      } catch (e) {
        console.error('[UnifiedTransport] Auto-encryption provider failed:', e);
      }
      return null;
    });

    return () => {
      (unifiedSignalTransport as any).encryptionProvider = null;
      (unifiedSignalTransport as any).p2pEncryptionProvider = null;
    };
  }, [isLoggedIn, getPeerHybridKeys, users]);
}
