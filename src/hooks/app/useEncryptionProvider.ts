import { useEffect, useRef } from 'react';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import { EventType } from '../../lib/types/event-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { p2pTransport } from '../../lib/transport/p2p-transport';
import { getBlindRoutingClient } from '../../lib/transport/blind-routing-client';
import { PostQuantumUtils } from '../../lib/utils/pq-utils';
import { User } from '../../components/chat/messaging/UserList';
import { signal } from '../../lib/tauri-bindings';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { extractX25519FromSignalBundle } from '../../lib/utils/peer-certificate-utils';
import { resolveTrustedPeerHybridPublicKeys } from '../../lib/utils/signal-bundle-utils';
import {
  deriveMailboxMetadataId,
  deriveRendezvousRouteId,
  isRendezvousRouteId
} from '../../lib/transport/rendezvous-routing';

const discoveryCache = new Map<string, any>();
const INBOX_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/i;
const DISCOVERY_REFRESH_SUCCESS_TTL_MS = 5 * 60 * 1000;
const DISCOVERY_REFRESH_FAILURE_TTL_MS = 30 * 1000;
const DISCOVERY_STALE_BG_REFRESH_GRACE_MS = 60 * 1000;

interface EncryptionProviderProps {
  isLoggedIn: boolean;
  loginUsernameRef: React.RefObject<string | null>;
  getPeerHybridKeys: (peer: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string; inboxId?: string; routeId?: string; mailboxLookupId?: string } | null>;
  users: User[];
  getKeysOnDemand: () => Promise<any>;
  secureDBRef?: React.RefObject<any>;
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>;
  ensureDiscoveryPublished?: (force?: boolean) => Promise<boolean>;
}

export function useEncryptionProvider({
  isLoggedIn,
  loginUsernameRef,
  getPeerHybridKeys,
  users,
  getKeysOnDemand,
  findUser,
  ensureDiscoveryPublished,
}: EncryptionProviderProps) {
  const sessionEnsureRef = useRef(new Map<string, Promise<boolean>>());
  const preKeyPendingRef = useRef(new Set<string>());
  const sessionReadyWaitersRef = useRef(new Map<string, { resolve: () => void; timeoutId: number }>());
  const discoveryInFlightRef = useRef(new Map<string, Promise<any>>());
  const discoveryAttemptRef = useRef(new Map<string, number>());
  const discoveryResultMemoRef = useRef(new Map<string, { value: any | null; expiresAt: number }>());
  const discoveryFreshUntilRef = useRef(new Map<string, number>());
  const discoveryPublishWarnAtRef = useRef(new Map<string, number>());

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
    const resetDiscoveryState = () => {
      discoveryCache.clear();
      discoveryInFlightRef.current.clear();
      discoveryAttemptRef.current.clear();
      discoveryResultMemoRef.current.clear();
      discoveryFreshUntilRef.current.clear();
    };

    // Clear only negative (failed) discovery results so successful lookups
    // are preserved but failed ones from before auth are retried.
    const clearNegativeDiscoveryResults = () => {
      for (const [key, entry] of discoveryResultMemoRef.current.entries()) {
        if (entry.value === null) {
          discoveryResultMemoRef.current.delete(key);
        }
      }
      discoveryAttemptRef.current.clear();
      // Also clear the unified transport's per-peer force-refresh cooldowns
      // so retries aren't blocked by cooldowns set before auth succeeded.
      unifiedSignalTransport.clearRefreshCooldowns();
    };

    window.addEventListener(EventType.WS_RECONNECTED, resetDiscoveryState as EventListener);
    window.addEventListener(EventType.HYBRID_KEYS_UPDATED, resetDiscoveryState as EventListener);
    window.addEventListener(EventType.SERVER_ENTRY_GRANTED, clearNegativeDiscoveryResults as EventListener);
    window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, clearNegativeDiscoveryResults as EventListener);

    return () => {
      window.removeEventListener(EventType.WS_RECONNECTED, resetDiscoveryState as EventListener);
      window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, resetDiscoveryState as EventListener);
      window.removeEventListener(EventType.SERVER_ENTRY_GRANTED, clearNegativeDiscoveryResults as EventListener);
      window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, clearNegativeDiscoveryResults as EventListener);
    };
  }, []);

  useEffect(() => {
    if (!isLoggedIn) return;

    const resolveDiscoveryMaterial = async (
      peer: string,
      reason: string,
      options?: { force?: boolean }
    ): Promise<any | null> => {
      if (!findUser) return null;
      if (!peer) return null;
      const normalizedPeer = peer.trim().toLowerCase();
      if (!normalizedPeer) return null;
      const force = !!options?.force;
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
        if (!force && memoized.value !== null) {
          return memoized.value;
        }
        if (!force && memoized.value === null) {
          return null;
        }
        
        if (memoized.value === null) {
          discoveryResultMemoRef.current.delete(normalizedPeer);
        }
      }

      if (force) {
        discoveryResultMemoRef.current.delete(normalizedPeer);
      } else {
        const lastAttempt = discoveryAttemptRef.current.get(normalizedPeer) || 0;
        if (now - lastAttempt < 15000) {
          const cached = discoveryCache.get(peer) || discoveryCache.get(normalizedPeer);
          if (cached) return cached;
        }
      }
      discoveryAttemptRef.current.set(normalizedPeer, now);

      if (ensureDiscoveryPublished) {
        try {
          ensureDiscoveryPublished(force).then((published) => {
            if (!published) {
              const lastWarn = discoveryPublishWarnAtRef.current.get(normalizedPeer) || 0;
              if (Date.now() - lastWarn > 30000) {
                discoveryPublishWarnAtRef.current.set(normalizedPeer, Date.now());
                console.warn('[UnifiedTransport] Discovery self-publish failed before lookup; continuing');
              }
            }
          }).catch(() => {
            const lastWarn = discoveryPublishWarnAtRef.current.get(normalizedPeer) || 0;
            if (Date.now() - lastWarn > 30000) {
              discoveryPublishWarnAtRef.current.set(normalizedPeer, Date.now());
              console.warn('[UnifiedTransport] Discovery self-publish failed before lookup; continuing');
            }
          });
          const published = true;
          if (!published) {
            const lastWarn = discoveryPublishWarnAtRef.current.get(normalizedPeer) || 0;
            if (Date.now() - lastWarn > 30000) {
              discoveryPublishWarnAtRef.current.set(normalizedPeer, Date.now());
              console.warn('[UnifiedTransport] Discovery self-publish not ready; continuing on-demand lookup');
            }
          }
        } catch {
          const lastWarn = discoveryPublishWarnAtRef.current.get(normalizedPeer) || 0;
          if (Date.now() - lastWarn > 30000) {
            discoveryPublishWarnAtRef.current.set(normalizedPeer, Date.now());
            console.warn('[UnifiedTransport] Discovery self-publish failed before lookup; continuing');
          }
        }
      }

      const promise = findUser(peer, { forceRefresh: !!options?.force })
        .then((material) => {
              discoveryResultMemoRef.current.set(normalizedPeer, {
                value: material ?? null,
                expiresAt: Date.now() + (material ? 30000 : 30000)
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
        .catch(() => {
          console.warn('[UnifiedTransport] On-demand discovery failed');
          return null;
        })
        .finally(() => {
          discoveryInFlightRef.current.delete(normalizedPeer);
        });

      discoveryInFlightRef.current.set(normalizedPeer, promise);
      return promise;
    };

    const resolveTrustedDiscoveryKeys = async (
      peerUsername: string,
      material: any
    ): Promise<{
      hybridKeys: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64: string; inboxId?: string };
      peerCertificateFingerprint?: string;
      identityRootFingerprint?: string;
      identityBundleFingerprint?: string;
    } | null> => {
      const trusted = await resolveTrustedPeerHybridPublicKeys(peerUsername, material, users as any);
      if (!trusted.valid || !trusted.hybridKeys) {
        console.warn('[UnifiedTransport] Rejected untrusted discovery material', {
          hasPeer: !!peerUsername,
          reason: trusted.reason
        });
        return null;
      }
      return {
        hybridKeys: trusted.hybridKeys,
        peerCertificateFingerprint: trusted.peerCertificateFingerprint,
        identityRootFingerprint: trusted.identityRootFingerprint,
        identityBundleFingerprint: trusted.identityBundleFingerprint
      };
    };

    unifiedSignalTransport.setEncryptionProvider(async (to, payload, type, transportHints) => {
      try {
        const currentUser = loginUsernameRef.current;
        if (!currentUser || to === 'SERVER') return null;
        const forceDiscoveryRefresh = !!transportHints?.forceDiscoveryRefresh;

        let peerKeys = await getPeerHybridKeys(to);
        let resolvedUsername = to;
        let resolvedInboxId: string | undefined = (peerKeys as any)?.inboxId;
        let resolvedRouteId: string | undefined = (peerKeys as any)?.routeId;
        let resolvedMailboxLookupId: string | undefined = (peerKeys as any)?.mailboxLookupId;
        if ((peerKeys as any)?.inboxId) {
          try { p2pTransport.registerUsernameAlias(resolvedUsername, (peerKeys as any).inboxId); } catch { }
        }

        const isRelayId = INBOX_ID_REGEX.test(to);

        if ((!peerKeys || !peerKeys.kyberPublicBase64) && isRelayId) {
          const usersList = Array.isArray(users) ? users : [];
          const found = usersList.find((u: any) =>
            (u.inboxId === to || u?.hybridPublicKeys?.inboxId === to) && u.username
          );
          if (found) {
            resolvedUsername = found.username;
            resolvedInboxId = found.inboxId || found?.hybridPublicKeys?.inboxId || resolvedInboxId;
            peerKeys = await getPeerHybridKeys(resolvedUsername);
            try { p2pTransport.registerUsernameAlias(resolvedUsername, to); } catch { }
          } else {
            try {
              const alias = p2pTransport.resolveUsernameAlias(to);
              if (alias && alias !== to) {
                resolvedUsername = alias;
                peerKeys = await getPeerHybridKeys(resolvedUsername);
              }
            } catch (err) {
              console.warn('[UnifiedTransport] Failed to query P2PTransport alias');
            }
          }
        }
        if (!resolvedInboxId) {
          try {
            const alias = p2pTransport.resolveUsernameAlias(resolvedUsername);
            if (alias && INBOX_ID_REGEX.test(alias)) {
              resolvedInboxId = alias;
            }
          } catch { }
        }

        // EARLY CACHE HYDRATION
        if (!forceDiscoveryRefresh && !peerKeys?.kyberPublicBase64) {
          const cachedMaterial = discoveryCache.get(resolvedUsername) || discoveryCache.get(resolvedUsername.trim().toLowerCase());
          if (cachedMaterial) {
            const trustedCached = await resolveTrustedDiscoveryKeys(resolvedUsername, cachedMaterial).catch(() => null);
            if (trustedCached) {
              resolvedInboxId = trustedCached.hybridKeys.inboxId || cachedMaterial.inboxId || resolvedInboxId;
              resolvedRouteId = (trustedCached.hybridKeys as any).routeId || cachedMaterial.routeId || resolvedRouteId;
              resolvedMailboxLookupId = (trustedCached.hybridKeys as any).mailboxLookupId || cachedMaterial.mailboxLookupId || resolvedMailboxLookupId;
              peerKeys = {
                ...(peerKeys || {}),
                kyberPublicBase64: trustedCached.hybridKeys.kyberPublicBase64,
                dilithiumPublicBase64: trustedCached.hybridKeys.dilithiumPublicBase64,
                x25519PublicBase64: trustedCached.hybridKeys.x25519PublicBase64,
                inboxId: trustedCached.hybridKeys.inboxId || cachedMaterial.inboxId || resolvedInboxId,
                routeId: (trustedCached.hybridKeys as any).routeId || resolvedRouteId,
                mailboxLookupId: (trustedCached.hybridKeys as any).mailboxLookupId || resolvedMailboxLookupId
              };
              if (cachedMaterial.inboxId) {
                try { p2pTransport.registerUsernameAlias(resolvedUsername, cachedMaterial.inboxId); } catch { }
              }
              if (cachedMaterial.fullBundle) {
                const hasSession = await signal.hasSession(currentUser, resolvedUsername, 1).catch(() => false);
                if (!hasSession) {
                  await signal.processPreKeyBundle(currentUser, resolvedUsername, cachedMaterial.fullBundle).catch(() => { });
                }
              }
            }
          }
        }

        // Refresh discovery material periodically
        const refreshPeer = resolvedUsername || to;
        const normalizedRefreshPeer = refreshPeer.trim().toLowerCase();
        const hasCachedInbox = !!resolvedInboxId;
        const hasCachedKyber = !!peerKeys?.kyberPublicBase64;
        const hasCachedX25519 = !!peerKeys?.x25519PublicBase64;
        const refreshUntil = discoveryFreshUntilRef.current.get(refreshPeer) || 0;
        const now = Date.now();
        const memoizedDiscovery = discoveryResultMemoRef.current.get(normalizedRefreshPeer);
        const hasFreshNegativeMemo =
          !!memoizedDiscovery &&
          memoizedDiscovery.expiresAt > now &&
          memoizedDiscovery.value === null;
          
        const haveAllCachedRouting = hasCachedInbox && hasCachedKyber && hasCachedX25519;
        const mustRefreshDiscoveryNow =
          !hasFreshNegativeMemo && (forceDiscoveryRefresh || !haveAllCachedRouting);
        const staleDiscoveryRefreshDue =
          !hasFreshNegativeMemo && haveAllCachedRouting && !forceDiscoveryRefresh && Date.now() >= refreshUntil;

        if (forceDiscoveryRefresh && !hasFreshNegativeMemo) {
          discoveryFreshUntilRef.current.delete(refreshPeer);
          discoveryResultMemoRef.current.delete(normalizedRefreshPeer);
          discoveryCache.delete(refreshPeer);
        }

        if (staleDiscoveryRefreshDue) {
          discoveryFreshUntilRef.current.set(refreshPeer, Date.now() + DISCOVERY_STALE_BG_REFRESH_GRACE_MS);
          void resolveDiscoveryMaterial(refreshPeer, 'Background-refreshing discovery material for', { force: false })
            .then(async (bgMaterial: any) => {
              if (bgMaterial?.publicKeys?.kyberPublicBase64) {
                const trusted = await resolveTrustedDiscoveryKeys(refreshPeer, bgMaterial).catch(() => null);
                if (trusted) {
                  discoveryCache.set(refreshPeer, bgMaterial);
                  discoveryFreshUntilRef.current.set(refreshPeer, Date.now() + DISCOVERY_REFRESH_SUCCESS_TTL_MS);
                }
              }
            })
            .catch(() => { });
        }

        if (mustRefreshDiscoveryNow) {
          const previousKyber = peerKeys?.kyberPublicBase64;
          const refreshedMaterial = await resolveDiscoveryMaterial(
            refreshPeer,
            hasCachedInbox
              ? 'Refreshing discovery material for'
              : 'Resolving discovery material for',
            { force: forceDiscoveryRefresh }
          );
          if (refreshedMaterial?.publicKeys?.kyberPublicBase64) {
            const trustedDiscovery = await resolveTrustedDiscoveryKeys(refreshPeer, refreshedMaterial);
            if (!trustedDiscovery) {
              discoveryFreshUntilRef.current.set(
                refreshPeer,
                Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
              );
              return null;
            }
            discoveryCache.set(refreshPeer, refreshedMaterial);
            discoveryFreshUntilRef.current.set(
              refreshPeer,
              Date.now() + DISCOVERY_REFRESH_SUCCESS_TTL_MS
            );

            if (refreshedMaterial.inboxId) {
              resolvedInboxId = refreshedMaterial.inboxId;
              try { p2pTransport.registerUsernameAlias(refreshPeer, refreshedMaterial.inboxId); } catch { }
            }
            if (refreshedMaterial.routeId) {
              resolvedRouteId = refreshedMaterial.routeId;
            }
            if (refreshedMaterial.mailboxLookupId) {
              resolvedMailboxLookupId = refreshedMaterial.mailboxLookupId;
            }

            const refreshedKyber = trustedDiscovery.hybridKeys.kyberPublicBase64;

            peerKeys = {
              ...(peerKeys || {}),
              kyberPublicBase64: refreshedKyber,
              dilithiumPublicBase64: trustedDiscovery.hybridKeys.dilithiumPublicBase64,
              x25519PublicBase64: trustedDiscovery.hybridKeys.x25519PublicBase64,
              inboxId: trustedDiscovery.hybridKeys.inboxId || refreshedMaterial.inboxId || resolvedInboxId,
              routeId: (trustedDiscovery.hybridKeys as any).routeId || refreshedMaterial.routeId || resolvedRouteId,
              mailboxLookupId: (trustedDiscovery.hybridKeys as any).mailboxLookupId || refreshedMaterial.mailboxLookupId || resolvedMailboxLookupId
            };

            if (previousKyber && refreshedKyber && previousKyber !== refreshedKyber) {
              await signal.deleteSession(currentUser, refreshPeer, 1).catch(() => { });
              preKeyPendingRef.current.delete(refreshPeer);
              if (refreshedMaterial.fullBundle) {
                await signal.processPreKeyBundle(currentUser, refreshPeer, refreshedMaterial.fullBundle).catch(() => { });
              }
            }

            try {
              window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                detail: {
                  username: refreshPeer,
                  hybridKeys: {
                    kyberPublicBase64: peerKeys.kyberPublicBase64,
                    dilithiumPublicBase64: peerKeys.dilithiumPublicBase64,
                    x25519PublicBase64: peerKeys.x25519PublicBase64,
                    inboxId: peerKeys.inboxId,
                    routeId: (peerKeys as any).routeId,
                    mailboxLookupId: (peerKeys as any).mailboxLookupId
                  },
                  inboxId: peerKeys.inboxId,
                  routeId: (peerKeys as any).routeId,
                  mailboxLookupId: (peerKeys as any).mailboxLookupId,
                  peerCertificateFingerprint: trustedDiscovery.peerCertificateFingerprint,
                  identityRootFingerprint: trustedDiscovery.identityRootFingerprint,
                  identityBundleFingerprint: trustedDiscovery.identityBundleFingerprint
                }
              }));
            } catch { }
          } else {
            discoveryFreshUntilRef.current.set(
              refreshPeer,
              Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
            );
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          const cached = discoveryCache.get(resolvedUsername);
          if (cached) {
            if (cached.inboxId) {
              resolvedInboxId = cached.inboxId;
            }
            if (cached.routeId) resolvedRouteId = cached.routeId;
            if (cached.mailboxLookupId) resolvedMailboxLookupId = cached.mailboxLookupId;
            const trustedCached = await resolveTrustedDiscoveryKeys(resolvedUsername, cached);
            if (trustedCached) {
              peerKeys = {
                ...trustedCached.hybridKeys,
                inboxId: trustedCached.hybridKeys.inboxId || resolvedInboxId,
                routeId: (trustedCached.hybridKeys as any).routeId || resolvedRouteId,
                mailboxLookupId: (trustedCached.hybridKeys as any).mailboxLookupId || resolvedMailboxLookupId
              };
            }
            if (cached.inboxId) {
              try { p2pTransport.registerUsernameAlias(resolvedUsername, cached.inboxId); } catch { }
            }
            if (peerKeys && cached.fullBundle) {
              const hasSession = await signal.hasSession(currentUser, resolvedUsername, 1).catch(() => false);
              if (!hasSession) {
                await signal.processPreKeyBundle(currentUser, resolvedUsername, cached.fullBundle).catch(() => { });
              }
            }
          } else {
            const material = await resolveDiscoveryMaterial(
              resolvedUsername,
              'Attempting on-demand discovery for',
              { force: forceDiscoveryRefresh }
            );
            if (material?.publicKeys?.kyberPublicBase64) {
              const trustedDiscovery = await resolveTrustedDiscoveryKeys(resolvedUsername, material);
              if (!trustedDiscovery) {
                return null;
              }
              discoveryCache.set(resolvedUsername, material);
              if (material.inboxId) {
                try { p2pTransport.registerUsernameAlias(resolvedUsername, material.inboxId); } catch { }
              }
              if (material.inboxId) {
                resolvedInboxId = material.inboxId;
              }
              peerKeys = {
                kyberPublicBase64: trustedDiscovery.hybridKeys.kyberPublicBase64,
                dilithiumPublicBase64: trustedDiscovery.hybridKeys.dilithiumPublicBase64,
                x25519PublicBase64: trustedDiscovery.hybridKeys.x25519PublicBase64,
                inboxId: trustedDiscovery.hybridKeys.inboxId || material.inboxId || resolvedInboxId,
                routeId: (trustedDiscovery.hybridKeys as any).routeId || material.routeId || resolvedRouteId,
                mailboxLookupId: (trustedDiscovery.hybridKeys as any).mailboxLookupId || material.mailboxLookupId || resolvedMailboxLookupId
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
          console.warn('[UnifiedTransport] Auto-encryption failed: no peer keys', {
            hasAlias: resolvedUsername !== to
          });
          return null;
        }

        // Sync PQ key to Rust backend
        await signal.setPeerKyberKey(resolvedUsername, peerKeys.kyberPublicBase64).catch(e => {
          console.warn('[UnifiedTransport] Failed to sync peer Kyber key to backend');
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
                const trustedCached = await resolveTrustedDiscoveryKeys(peer, cached);
                if (trustedCached) {
                  const hasExistingSession = await signal.hasSession(currentUser, peer, 1).catch(() => false);
                  if (!hasExistingSession) {
                    await signal.processPreKeyBundle(currentUser, peer, cached.fullBundle).catch(() => { });
                  }
                  hasSession = await signal.hasSession(currentUser, peer, 1);
                  if (hasSession) return true;
                }
              }

              const material = await resolveDiscoveryMaterial(
                peer,
                'Establishing Signal session via Anonymous Discovery for',
                { force: forceDiscoveryRefresh }
              );
              if (!material || !material.fullBundle) {
                return false;
              }
              const trustedDiscovery = await resolveTrustedDiscoveryKeys(peer, material);
              if (!trustedDiscovery) {
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

        const profileVersion = profilePictureSystem.getOwnProfileVersion?.() || Date.now();
        const shareWithOthers = profilePictureSystem.getShareWithOthers?.() ?? true;
        const ownAvatarHash = profilePictureSystem.getOwnAvatarHash?.() ?? null;
        const signalPayload = {
          type: 'signal-payload',
          kind: type,
          content: payload.content || JSON.stringify(payload),
          from: currentUser,
          timestamp: Date.now(),
          ...payload,
          senderProfileMeta: {
            profileVersion,
            avatarHash: shareWithOthers ? ownAvatarHash : null
          }
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
            console.warn('[UnifiedTransport] Signal session lost, re-establishing');
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
          const x25519FromBundle = cached?.fullBundle ? extractX25519FromSignalBundle(cached.fullBundle) : undefined;
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

        let inboxId = (peerKeys as any)?.inboxId || resolvedInboxId || discoveryCache.get(resolvedUsername)?.inboxId;
        if (!inboxId) {
          try {
            const alias = p2pTransport.resolveUsernameAlias(resolvedUsername);
            if (alias && INBOX_ID_REGEX.test(alias)) {
              inboxId = alias;
            }
          } catch { }
        }
        if (!inboxId) {
          const material = await resolveDiscoveryMaterial(
            resolvedUsername,
            'Resolving destination inbox for',
            { force: forceDiscoveryRefresh }
          );
          if (material?.inboxId) {
            inboxId = material.inboxId;
            discoveryCache.set(resolvedUsername, material);
            try { p2pTransport.registerUsernameAlias(resolvedUsername, material.inboxId); } catch { }
          }
        }
        const destinationRouteId = isRendezvousRouteId((peerKeys as any)?.routeId || resolvedRouteId)
          ? ((peerKeys as any)?.routeId || resolvedRouteId)
          : deriveRendezvousRouteId(inboxId);
        const destinationMailboxLookupId = isRendezvousRouteId((peerKeys as any)?.mailboxLookupId || resolvedMailboxLookupId)
          ? ((peerKeys as any)?.mailboxLookupId || resolvedMailboxLookupId)
          : deriveMailboxMetadataId(inboxId);

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
          recipientInboxId: inboxId,
          destinationRouteId,
          destinationMailboxLookupId,
          recipientKyberPublicBase64: peerKeys.kyberPublicBase64
        };
      } catch (err) {
        console.error('[UnifiedTransport] Unified encryption error', {
          hasError: !!err
        });
        return null;
      }
    });

    return () => {
      unifiedSignalTransport.setEncryptionProvider(null as any);
    };
  }, [isLoggedIn, getPeerHybridKeys, users, getKeysOnDemand, findUser, ensureDiscoveryPublished]);
}
