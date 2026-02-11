import { useEffect, useRef } from 'react';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import { EventType } from '../../lib/types/event-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { quicTransport } from '../../lib/transport/quic-transport';
import { getBlindRoutingClient } from '../../lib/transport/blind-routing-client';
import { PostQuantumUtils } from '../../lib/utils/pq-utils';
import { User } from '../../components/chat/messaging/UserList';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';

const discoveryCache = new Map<string, any>();
const INBOX_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/i;
const RELAY_HASH_REGEX = /^[a-f0-9]{32}$/i;

// Extract x25519 public key from Signal PreKeyBundle
function extractX25519FromBundle(fullBundle: any): string | undefined {
  if (!fullBundle) return undefined;
  
  if (fullBundle.identityKeyBase64 && typeof fullBundle.identityKeyBase64 === 'string') {
    try {
      const keyBytes = Uint8Array.from(atob(fullBundle.identityKeyBase64), c => c.charCodeAt(0));
      console.log('[X25519Extract] Raw key length:', keyBytes.length, 'first byte:', keyBytes[0]?.toString(16));

      if (keyBytes.length === 33 && keyBytes[0] === 0x05) {
        const rawKey = keyBytes.slice(1);
        const result = btoa(String.fromCharCode(...rawKey));
        console.log('[X25519Extract] Stripped 0x05 prefix, new length:', rawKey.length);
        return result;
      }

      if (keyBytes.length === 32) {
        console.log('[X25519Extract] Key already 32 bytes, no stripping needed');
        return fullBundle.identityKeyBase64;
      }
      console.warn('[X25519Extract] Unexpected key length:', keyBytes.length);
    } catch (e) {
      console.error('[X25519Extract] Error extracting key:', e);
      return undefined;
    }
  }
  
  console.warn('[X25519Extract] No identityKeyBase64 found in bundle');
  return undefined;
}

interface EncryptionProviderProps {
  isLoggedIn: boolean;
  loginUsernameRef: React.RefObject<string | null>;
  getPeerHybridKeys: (peer: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>;
  users: User[];
  getKeysOnDemand: () => Promise<any>;
  secureDBRef?: React.RefObject<any>;
  findUser?: (handle: string) => Promise<any>;
}

export function useEncryptionProvider({
  isLoggedIn,
  loginUsernameRef,
  getPeerHybridKeys,
  users,
  getKeysOnDemand,
  findUser,
}: EncryptionProviderProps) {
  const sessionEnsureRef = useRef(new Map<string, Promise<boolean>>());
  const preKeyPendingRef = useRef(new Set<string>());
  const sessionReadyWaitersRef = useRef(new Map<string, { resolve: () => void; timeoutId: number }>());
  const discoveryInFlightRef = useRef(new Map<string, Promise<any>>());
  const discoveryAttemptRef = useRef(new Map<string, number>());
  const discoveryResultMemoRef = useRef(new Map<string, { value: any | null; expiresAt: number }>());

  const waitForSessionReady = (peer: string, timeoutMs = 8000): Promise<void> => {
    if (!peer) return Promise.resolve();
    if (!preKeyPendingRef.current.has(peer)) return Promise.resolve();

    const existing = sessionReadyWaitersRef.current.get(peer);
    if (existing) {
      return new Promise(resolve => {
        const previousResolve = existing.resolve;
        existing.resolve = () => {
          try { previousResolve(); } catch { }
          resolve();
        };
      });
    }

    return new Promise(resolve => {
      const timeoutId = window.setTimeout(() => {
        sessionReadyWaitersRef.current.delete(peer);
        preKeyPendingRef.current.delete(peer);
        resolve();
      }, timeoutMs);
      sessionReadyWaitersRef.current.set(peer, { resolve, timeoutId });
    });
  };

  useEffect(() => {
    const handleSessionReady = (evt: Event) => {
      try {
        const detail = (evt as CustomEvent).detail || {};
        const peer = detail.peer || detail.peerUsername || detail.fromPeer;
        if (!peer || typeof peer !== 'string') return;
        preKeyPendingRef.current.delete(peer);
        const waiter = sessionReadyWaitersRef.current.get(peer);
        if (waiter) {
          try { clearTimeout(waiter.timeoutId); } catch { }
          sessionReadyWaitersRef.current.delete(peer);
          try { waiter.resolve(); } catch { }
        }
      } catch { }
    };
    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionReady as EventListener);
    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    return () => {
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionReady as EventListener);
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    };
  }, []);

  useEffect(() => {
    if (!isLoggedIn) return;

    const resolveDiscoveryMaterial = async (peer: string, reason: string): Promise<any | null> => {
      if (!findUser) return null;
      if (!peer) return null;
      const normalizedPeer = peer.trim().toLowerCase();
      if (!normalizedPeer) return null;
      const knownUsernames = new Set((Array.isArray(users) ? users : []).map(u => u.username).filter(Boolean));
      if (!shouldAttemptDiscovery(peer, knownUsernames)) {
        return null;
      }

      const existing = discoveryInFlightRef.current.get(normalizedPeer);
      if (existing) {
        return existing;
      }

      const now = Date.now();
      const memoized = discoveryResultMemoRef.current.get(normalizedPeer);
      if (memoized && memoized.expiresAt > now) {
        return memoized.value;
      }

      const lastAttempt = discoveryAttemptRef.current.get(normalizedPeer) || 0;
      if (now - lastAttempt < 5000) {
        const cached = discoveryCache.get(peer) || discoveryCache.get(normalizedPeer);
        if (cached) return cached;
      }
      discoveryAttemptRef.current.set(normalizedPeer, now);

      console.log(`[UnifiedTransport] ${reason}`, peer);
      const promise = findUser(peer)
        .then((material) => {
              discoveryResultMemoRef.current.set(normalizedPeer, {
                value: material ?? null,
                expiresAt: Date.now() + (material ? 30000 : 12000)
              });

          if (discoveryResultMemoRef.current.size > 300) {
            const tsNow = Date.now();
            for (const [key, value] of discoveryResultMemoRef.current.entries()) {
              if (value.expiresAt <= tsNow) {
                discoveryResultMemoRef.current.delete(key);
              }
            }
          }
          return material;
        })
        .catch((err) => {
          console.warn('[UnifiedTransport] On-demand discovery failed:', err);
          return null;
        })
        .finally(() => {
          discoveryInFlightRef.current.delete(normalizedPeer);
        });

      discoveryInFlightRef.current.set(normalizedPeer, promise);
      return promise;
    };

    unifiedSignalTransport.setEncryptionProvider(async (to, payload, type) => {
      try {
        const currentUser = loginUsernameRef.current;
        if (!currentUser || to === 'SERVER') return null;

        let peerKeys = await getPeerHybridKeys(to);
        let resolvedUsername = to;
        if ((peerKeys as any)?.inboxId) {
          try { quicTransport.registerUsernameAlias(resolvedUsername, (peerKeys as any).inboxId); } catch { }
        }

        const isRelayId = INBOX_ID_REGEX.test(to);
        const isLegacyRelayHash = RELAY_HASH_REGEX.test(to);

        if ((!peerKeys || !peerKeys.kyberPublicBase64) && (isRelayId || isLegacyRelayHash)) {
          const usersList = Array.isArray(users) ? users : [];
          const found = usersList.find((u: any) =>
            (isRelayId
              ? (u.inboxId === to || u?.hybridPublicKeys?.inboxId === to)
              : (u.id === to || u.pixelId === to || u.uuid === to)) && u.username
          );
          if (found) {
            resolvedUsername = found.username;
            peerKeys = await getPeerHybridKeys(resolvedUsername);
            if (isRelayId) {
              try { quicTransport.registerUsernameAlias(resolvedUsername, to); } catch { }
            }
          } else {
            try {
              const alias = quicTransport.resolveUsernameAlias(to);
              if (alias && alias !== to) {
                console.debug('[UnifiedTransport] Resolved relay ID', to, 'via QuicTransport alias to', alias);
                resolvedUsername = alias;
                peerKeys = await getPeerHybridKeys(resolvedUsername);
              }
            } catch (err) {
              console.warn('[UnifiedTransport] Failed to query QuicTransport alias:', err);
            }
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          const cached = discoveryCache.get(resolvedUsername);
          if (cached) {
            peerKeys = cached.publicKeys;
            if (cached.inboxId) {
              try { quicTransport.registerUsernameAlias(resolvedUsername, cached.inboxId); } catch { }
            }
            if (cached.fullBundle) {
              const hasSession = await signal.hasSession(currentUser, resolvedUsername, 1).catch(() => false);
              if (!hasSession) {
                await signal.processPreKeyBundle(currentUser, resolvedUsername, cached.fullBundle).catch(() => { });
              }
              // Extract x25519 from bundle if not present in publicKeys
              if (!peerKeys?.x25519PublicBase64) {
                const x25519FromBundle = extractX25519FromBundle(cached.fullBundle);
                if (x25519FromBundle) {
                  peerKeys = { ...peerKeys, x25519PublicBase64: x25519FromBundle };
                }
              }
            }
          } else {
            const material = await resolveDiscoveryMaterial(resolvedUsername, 'Attempting on-demand discovery for');
            if (material?.publicKeys?.kyberPublicBase64) {
              discoveryCache.set(resolvedUsername, material);
              if (material.inboxId) {
                try { quicTransport.registerUsernameAlias(resolvedUsername, material.inboxId); } catch { }
              }
              const x25519FromKeys = material.publicKeys.x25519PublicBase64;
              const x25519FromBundle = !x25519FromKeys && material.fullBundle ?
                extractX25519FromBundle(material.fullBundle) : undefined;
              peerKeys = {
                kyberPublicBase64: material.publicKeys.kyberPublicBase64,
                dilithiumPublicBase64: material.publicKeys.dilithiumPublicBase64,
                x25519PublicBase64: x25519FromKeys || x25519FromBundle
              };
              if (material.fullBundle) {
                const hasSession = await signal.hasSession(currentUser, resolvedUsername, 1).catch(() => false);
                if (!hasSession) {
                  await signal.processPreKeyBundle(currentUser, resolvedUsername, material.fullBundle);
                }
              }
            }
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          console.warn('[UnifiedTransport] Auto-encryption failed: No peer keys for', to, resolvedUsername !== to ? `(alias: ${resolvedUsername})` : '');
          return null;
        }

        // Sync PQ key to Rust backend
        await signal.setPeerKyberKey(resolvedUsername, peerKeys.kyberPublicBase64).catch(e => {
          console.warn('[UnifiedTransport] Failed to sync peer Kyber key to backend:', e);
        });

        // Ensure Signal Protocol session
        const ensureSession = async (peer: string): Promise<{ hasSession: boolean; isOwner: boolean }> => {
          const key = `${currentUser}:${peer}`;
          const existing = sessionEnsureRef.current.get(key);
          if (existing) {
            const hasSession = await existing;
            return { hasSession, isOwner: false };
          }

          const hadSession = await signal.hasSession(currentUser, peer, 1);
          if (hadSession) {
            return { hasSession: true, isOwner: false };
          }

          preKeyPendingRef.current.add(peer);

          const promise = (async () => {
            try {
              let hasSession = await signal.hasSession(currentUser, peer, 1);
              if (hasSession) return true;

              const cached = discoveryCache.get(peer);
              if (cached?.fullBundle) {
                const hasExistingSession = await signal.hasSession(currentUser, peer, 1).catch(() => false);
                if (!hasExistingSession) {
                  await signal.processPreKeyBundle(currentUser, peer, cached.fullBundle).catch(() => { });
                }
                hasSession = await signal.hasSession(currentUser, peer, 1);
                if (hasSession) return true;
              }

              const material = await resolveDiscoveryMaterial(peer, 'Establishing Signal session via Anonymous Discovery for');
              if (!material || !material.fullBundle) {
                return false;
              }
              discoveryCache.set(peer, material);
              const hasExistingSession = await signal.hasSession(currentUser, peer, 1).catch(() => false);
              if (!hasExistingSession) {
                await signal.processPreKeyBundle(currentUser, peer, material.fullBundle);
              }
              hasSession = await signal.hasSession(currentUser, peer, 1);
              return !!hasSession;
            } finally {
              sessionEnsureRef.current.delete(key);
            }
          })();

          sessionEnsureRef.current.set(key, promise);
          const hasSession = await promise;
          if (!hasSession) {
            preKeyPendingRef.current.delete(peer);
          }
          return { hasSession, isOwner: true };
        };

        await waitForSessionReady(resolvedUsername);

        const { hasSession, isOwner } = await ensureSession(resolvedUsername);
        if (!hasSession) return null;

        if (!isOwner && preKeyPendingRef.current.has(resolvedUsername)) {
          await waitForSessionReady(resolvedUsername);
        }

        const signalPayload = {
          type: 'signal-payload',
          kind: type,
          content: payload.content || JSON.stringify(payload),
          from: currentUser,
          timestamp: Date.now(),
          ...payload
        };

        let signalResult: any;
        try {
          signalResult = await signal.encrypt(
            currentUser,
            resolvedUsername,
            JSON.stringify(signalPayload)
          );
        } catch (err) {
          const msg = String(err);
          if (msg.includes('session') && msg.includes('not found')) {
            console.warn('[UnifiedTransport] Signal session lost, re-establishing for', resolvedUsername);
            await signal.deleteSession(currentUser, resolvedUsername, 1).catch(() => { });
            return null;
          }
          throw err;
        }

        if (!signalResult) {
          console.error('[UnifiedTransport] Signal encryption returned null');
          return null;
        }

        const localKeys = await getKeysOnDemand();
        if (!localKeys?.dilithium?.secretKey || !localKeys?.dilithium?.publicKeyBase64) {
          console.error('[UnifiedTransport] Local Dilithium keys unavailable');
          return null;
        }

        // Ensure peerKeys has x25519PublicBase64
        if (!peerKeys?.x25519PublicBase64) {
          const cached = discoveryCache.get(resolvedUsername);
          const x25519FromBundle = cached?.fullBundle ? extractX25519FromBundle(cached.fullBundle) : undefined;
          if (x25519FromBundle) {
            peerKeys = { ...peerKeys, x25519PublicBase64: x25519FromBundle };
          } else {
            console.error('[UnifiedTransport] Peer x25519 key unavailable for Hybrid encryption');
            return null;
          }
        }

        let fromInbox: string | undefined;
        try {
          fromInbox = getBlindRoutingClient().getMyInboxId() || undefined;
        } catch { }

        const hybridEnvelope = await CryptoUtils.Hybrid.encryptForClient(
          { 
            signalCiphertext: signalResult,
            from: currentUser,
            fromInbox
          },
          peerKeys,
          {
            to: peerKeys.dilithiumPublicBase64,
            from: localKeys.dilithium.publicKeyBase64,
            type: 'libsignal-message',
            senderDilithiumSecretKey: localKeys.dilithium.secretKey,
            senderDilithiumPublicKey: localKeys.dilithium.publicKeyBase64,
            timestamp: Date.now(),
          }
        );

        const inboxId = (peerKeys as any)?.inboxId || discoveryCache.get(resolvedUsername)?.inboxId;

        try {
          if (localKeys?.kyber?.secretKey && localKeys?.kyber?.publicKeyBase64) {
            const blindClient = getBlindRoutingClient();
            blindClient.setKyberKeys({
              publicKey: PostQuantumUtils.base64ToUint8Array(localKeys.kyber.publicKeyBase64),
              secretKey: localKeys.kyber.secretKey
            });
          }
        } catch { }

        return {
          encryptedPayload: hybridEnvelope,
          messageId: payload.messageId || crypto.randomUUID().replace(/-/g, ''),
          from: currentUser,
          destinationInbox: inboxId,
          recipientKyberPublicBase64: peerKeys.kyberPublicBase64
        };
      } catch (err) {
        console.error('[UnifiedTransport] Unified encryption error:', err);
        return null;
      }
    });

    return () => {
      unifiedSignalTransport.setEncryptionProvider(null as any);
    };
  }, [isLoggedIn, getPeerHybridKeys, users, getKeysOnDemand, findUser]);
}
