import { useEffect } from 'react';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { quicTransport } from '../../lib/transport/quic-transport';
import { User } from '../../components/chat/messaging/UserList';
import { signal } from '../../lib/tauri-bindings';

interface EncryptionProviderProps {
  isLoggedIn: boolean;
  loginUsernameRef: React.RefObject<string | null>;
  getPeerHybridKeys: (peer: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>;
  users: User[];
  getKeysOnDemand: () => Promise<any>;
  secureDBRef?: React.RefObject<any>;
}

export function useEncryptionProvider({
  isLoggedIn,
  loginUsernameRef,
  getPeerHybridKeys,
  users,
  getKeysOnDemand,
  secureDBRef,
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
              quicTransport.registerUsernameAlias(resolvedUsername, to);
            } catch { }
          } else {
            try {
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

        // Sync PQ key to Rust backend
        if (peerKeys.kyberPublicBase64) {
          await signal.setPeerKyberKey(resolvedUsername, peerKeys.kyberPublicBase64).catch(e => {
            console.warn('[UnifiedTransport] Failed to sync peer Kyber key to backend:', e);
          });
        }

        // Check if Signal Protocol session exists
        let hasSession = await signal.hasSession(currentUser, resolvedUsername, 1);

        // Request bundle if session doesnt exist
        if (!hasSession) {
          await unifiedSignalTransport.send('SERVER', { username: resolvedUsername }, 'libsignal-request-bundle' as any);

          try {
            await new Promise<void>((resolve, reject) => {
              const timeout = setTimeout(() => {
                cleanup();
                reject(new Error('Timeout waiting for Signal session'));
              }, 10000);

              const onSessionReady = (e: CustomEvent) => {
                if (e.detail?.peer === resolvedUsername) {
                  cleanup();
                  resolve();
                }
              };

              const onBundleFailed = (e: CustomEvent) => {
                if (e.detail?.peer === resolvedUsername) {
                  cleanup();
                  reject(new Error(e.detail.error || 'Bundle fetch failed'));
                }
              };

              const cleanup = () => {
                clearTimeout(timeout);
                window.removeEventListener('libsignal-session-ready' as any, onSessionReady as EventListener);
                window.removeEventListener('libsignal-bundle-failed' as any, onBundleFailed as EventListener);
              };

              window.addEventListener('libsignal-session-ready' as any, onSessionReady as EventListener);
              window.addEventListener('libsignal-bundle-failed' as any, onBundleFailed as EventListener);
            });

            // Re-verify session
            hasSession = await signal.hasSession(currentUser, resolvedUsername, 1);
            if (!hasSession) throw new Error('Session missing after successful bundle processing');

          } catch (waitError) {
            console.error('[UnifiedTransport] Failed to establish Signal session:', waitError);
            return null;
          }
        }

        const signalPayload = {
          type: 'signal-fallback',
          kind: type,
          content: payload.content || JSON.stringify(payload),
          from: currentUser,
          timestamp: Date.now(),
          ...payload
        };

        const performEncrypt = async () => {
          return await signal.encrypt(
            currentUser,
            resolvedUsername,
            JSON.stringify(signalPayload)
          );
        };

        let result: any;
        try {
          result = await performEncrypt();
        } catch (err) {
          const msg = String(err);
          if (msg.includes('session') && msg.includes('not found')) {
            console.warn('[UnifiedTransport] Signal session lost, re-establishing for', resolvedUsername);
            await signal.deleteSession(currentUser, resolvedUsername, 1).catch(() => { });
            await unifiedSignalTransport.send('SERVER', { username: resolvedUsername }, 'libsignal-request-bundle' as any);
            return null;
          }
          throw err;
        }

        if (result) {
          return {
            encryptedPayload: result,
            messageId: payload.messageId || crypto.randomUUID().replace(/-/g, ''),
            from: currentUser
          };
        }
      } catch (err) {
        console.error('[UnifiedTransport] Auto-encryption error:', err);
        return null;
      }
    });

    // P2P Encryption Provider
    unifiedSignalTransport.setP2PEncryptionProvider(async (to, payload, type) => {
      try {
        const currentUser = loginUsernameRef.current;
        if (!currentUser || to === 'SERVER') return payload;

        // Transient P2P signals
        const isTransient = type === SignalType.TYPING ||
          type === SignalType.TYPING_START ||
          type === SignalType.TYPING_STOP ||
          type === SignalType.READ_RECEIPT ||
          type === SignalType.DELIVERY_ACK ||
          type === SignalType.SIGNAL;

        if (isTransient) {
          return payload;
        }

        // Normalize 'to' username
        let resolvedTo = to;
        const usersList = users;

        // Check current users list
        const foundByHash = usersList.find(u => u.username === to);

        // If it looks like a hash and not found as a regular user try DB resolution
        if (to.length === 32 && (!foundByHash || foundByHash.hybridPublicKeys === undefined)) {
          if (secureDBRef?.current) {
            try {
              const original = await secureDBRef.current.getOriginalUsername(to);
              if (original) {
                resolvedTo = original;
              }
            } catch (err) {
              console.warn('[UnifiedTransport] Failed to resolve hash', to, err);
            }
          }
        }

        const peerKeys = await getPeerHybridKeys(resolvedTo);
        if (!peerKeys?.kyberPublicBase64 || !peerKeys?.dilithiumPublicBase64) {
          console.warn('[UnifiedTransport] P2P encryption failed: No peer keys for', resolvedTo);
          return null;
        }

        const localKeys = await getKeysOnDemand();
        if (!localKeys?.kyber?.secretKey || !localKeys?.x25519?.private) {
          console.warn('[UnifiedTransport] P2P encryption failed: No local secret keys');
          return null;
        }

        // Wrap in Hybrid Envelope
        const envelope = await CryptoUtils.Hybrid.encryptForClient(
          payload,
          {
            kyberPublicBase64: peerKeys.kyberPublicBase64,
            dilithiumPublicBase64: peerKeys.dilithiumPublicBase64,
            x25519PublicBase64: peerKeys.x25519PublicBase64
          },
          {
            senderDilithiumSecretKey: localKeys.dilithium.secretKey,
            senderDilithiumPublicKey: localKeys.dilithium.publicKeyBase64,
            to: resolvedTo,
            from: currentUser,
            type
          }
        );

        return envelope;
      } catch (err) {
        console.error('[UnifiedTransport] P2P encryption error:', err);

        // Server fallback
        return null;
      }
    });

    return () => {
      unifiedSignalTransport.setEncryptionProvider(null as any);
      unifiedSignalTransport.setP2PEncryptionProvider(null as any);
    };
  }, [isLoggedIn, getPeerHybridKeys, users, getKeysOnDemand]);
}
