import { useEffect, useRef } from 'react';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import {
  isAckTrackedSignalType,
  unifiedSignalTransport,
} from '../../lib/transport/unified-signal-transport';
import { keyTransparencyClient } from '../../lib/key-transparency/client';
import {
  getKeyTransparencyAuthorizedPeerState,
  isKeyTransparencyAuthorizedPeerKeySet,
  isKeyTransparencyPeerRevoked,
} from '../../lib/key-transparency/verified-material';
import { awaitPeerIdentityRevocation } from '../../lib/key-transparency/revocation';
import { User } from '../../components/chat/messaging/UserList';
import { account, signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { extractX25519FromSignalBundle } from '../../lib/utils/peer-certificate-utils';
import { resolveTrustedPeerHybridPublicKeys } from '../../lib/utils/signal-bundle-utils';
import { p2pTransport } from '../../lib/transport/p2p-transport';
import {
  isValidDilithiumPublicKeyBase64,
  isValidKyberPublicKeyBase64,
  isValidX25519PublicKeyBase64,
} from '../../lib/utils/messaging-validators';
import {
  AUTH_USERNAME_REGEX,
  MAX_SIGNAL_PAYLOAD_JSON_BYTES,
} from '../../lib/constants';
import { hasPrototypePollutionKeys, isPlainObject, sanitizeMessageId } from '../../lib/sanitizers';
import { persistPeerDetectionKey, rememberPeerDetectionKey } from '../../lib/spool/detection-key';
import {
  clearPersistedDiscoveryMaterial,
  loadPersistedDiscoveryMaterial,
  savePersistedDiscoveryMaterial,
} from '../../lib/discovery/persisted-discovery-material';
import { createBoundedMapSetter } from '../../lib/utils/message-state-limits';
import { PROTOCOL_KEYS } from '../../lib/config/protocol-keys';

const DISCOVERY_REFRESH_SUCCESS_TTL_MS = 30 * 60 * 1000;
const DISCOVERY_REFRESH_FAILURE_TTL_MS = 30 * 1000;
const DISCOVERY_LOOKUP_SEND_TIMEOUT_MS = 4 * 60 * 1000;
const DEFERRABLE_SIGNAL_TYPES: ReadonlySet<string> = new Set([
  'typing-start',
  'typing-stop',
  'receipt-batch',
]);

const DEFERRABLE_DISCOVERY_WAIT_MS = 1500;
const MAX_DISCOVERY_PEER_CACHE_ENTRIES = 300;
const signalPayloadEncoder = new TextEncoder();

const setBoundedPeerEntry = createBoundedMapSetter(MAX_DISCOVERY_PEER_CACHE_ENTRIES);

function isSessionReadyDetail(value: unknown): value is { account: string; peer: string } {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) return false;
  if (Object.keys(value).sort().join(',') !== 'account,peer') return false;
  const detail = value as Record<string, unknown>;
  return typeof detail.account === 'string' &&
    typeof detail.peer === 'string' &&
    detail.account === detail.account.trim().toLowerCase() &&
    detail.peer === detail.peer.trim().toLowerCase() &&
    AUTH_USERNAME_REGEX.test(detail.account) &&
    AUTH_USERNAME_REGEX.test(detail.peer);
}

async function getPrivateLocalP2PEndpoint(localUsername: string): Promise<string | undefined> {
  return p2pTransport.getLocalEndpointForIdentity(localUsername);
}

interface EncryptionProviderProps {
  isLoggedIn: boolean;
  loginUsernameRef: React.RefObject<string | null>;
  getPeerHybridKeys: (peer: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64: string } | null>;
  users: User[];
  getKeysOnDemand: () => Promise<any>;
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
  const discoveryCacheRef = useRef(new Map<string, any>());
  const preKeyPendingRef = useRef(new Set<string>());
  const sessionReadyWaitersRef = useRef(new Map<string, { resolve: () => void; timeoutId: number }>());
  const discoveryInFlightRef = useRef(new Map<string, Promise<any>>());
  const discoveryAttemptRef = useRef(new Map<string, number>());
  const discoveryResultMemoRef = useRef(new Map<string, { value: any | null; expiresAt: number }>());
  const discoveryFreshUntilRef = useRef(new Map<string, number>());
  const discoveryPublishWarnAtRef = useRef(new Map<string, number>());
  const peerBundleInstalledRef = useRef(new Map<string, true>());
  const mlKemInstallInFlightRef = useRef(new Map<string, Promise<void>>());
  const discoveryGenerationRef = useRef(0);
  const encryptionGenerationRef = useRef(0);
  const activeAccountRef = useRef<string | null>(null);

  // Caches discovery material in memory and on disk together
  const rememberDiscoveryMaterial = (peer: string, material: any): void => {
    setBoundedPeerEntry(discoveryCacheRef.current, peer, material);
    const account = activeAccountRef.current;
    if (!account || !material) return;
    const normalizedPeer = String(peer).trim().toLowerCase();
    
    void persistPeerDetectionKey(account, normalizedPeer, material.spoolDetectionKey)
      .catch(() => { });
    rememberPeerDetectionKey(String(peer), material.spoolDetectionKey);
    
    void savePersistedDiscoveryMaterial(
      account,
      normalizedPeer,
      material,
      getKeyTransparencyAuthorizedPeerState(account, normalizedPeer)
    ).catch(() => { });
  };

  useEffect(() => {
    const account = isLoggedIn && loginUsernameRef.current
      ? loginUsernameRef.current
      : null;
    if (activeAccountRef.current === account) return;

    const previousAccount = activeAccountRef.current;
    activeAccountRef.current = account;
    discoveryGenerationRef.current += 1;
    encryptionGenerationRef.current += 1;
    discoveryCacheRef.current.clear();
    discoveryInFlightRef.current.clear();
    discoveryAttemptRef.current.clear();
    discoveryResultMemoRef.current.clear();
    discoveryFreshUntilRef.current.clear();
    discoveryPublishWarnAtRef.current.clear();
    peerBundleInstalledRef.current.clear();
    mlKemInstallInFlightRef.current.clear();
    sessionEnsureRef.current.clear();
    preKeyPendingRef.current.clear();
    for (const waiter of sessionReadyWaitersRef.current.values()) {
      clearTimeout(waiter.timeoutId);
      waiter.resolve();
    }
    sessionReadyWaitersRef.current.clear();

    if (previousAccount !== null) {
      unifiedSignalTransport.resetForAccountTransition();
    }
  }, [isLoggedIn, loginUsernameRef, loginUsernameRef.current]);

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
        const entry = sessionReadyWaitersRef.current.get(peer);
        sessionReadyWaitersRef.current.delete(peer);
        preKeyPendingRef.current.delete(peer);
        try { (entry?.resolve ?? resolve)(); } catch { resolve(); }
      }, timeoutMs);
      sessionReadyWaitersRef.current.set(peer, { resolve, timeoutId });
    });
  };

  useEffect(() => {
    const handleSessionReady = (evt: Event) => {
      try {
        const detail = (evt as CustomEvent).detail;
        if (!isSessionReadyDetail(detail)) return;
        if (!activeAccountRef.current || detail.account !== activeAccountRef.current) return;
        const peer = detail.peer;
        preKeyPendingRef.current.delete(peer);
        const waiter = sessionReadyWaitersRef.current.get(peer);
        if (waiter) {
          try { clearTimeout(waiter.timeoutId); } catch { }
          sessionReadyWaitersRef.current.delete(peer);
          try { waiter.resolve(); } catch { }
        }
      } catch { }
    };
    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    return () => {
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    };
  }, []);

  useEffect(() => {
    const resetDiscoveryState = () => {
      discoveryGenerationRef.current += 1;
      discoveryCacheRef.current.clear();
      discoveryInFlightRef.current.clear();
      discoveryAttemptRef.current.clear();
      discoveryResultMemoRef.current.clear();
      discoveryFreshUntilRef.current.clear();
    };

    const resetEncryptionAndDiscoveryState = () => {
      encryptionGenerationRef.current += 1;
      resetDiscoveryState();
      sessionEnsureRef.current.clear();
      preKeyPendingRef.current.clear();
      for (const waiter of sessionReadyWaitersRef.current.values()) {
        clearTimeout(waiter.timeoutId);
        waiter.resolve();
      }
      sessionReadyWaitersRef.current.clear();
    };

    // Clear only failed discovery results so successful lookups are preserved but failed ones from before auth are retried
    const clearNegativeDiscoveryResults = () => {
      for (const [key, entry] of discoveryResultMemoRef.current.entries()) {
        if (entry.value === null) {
          discoveryResultMemoRef.current.delete(key);
        }
      }
      discoveryAttemptRef.current.clear();
      unifiedSignalTransport.clearRefreshCooldowns();
    };

    window.addEventListener(EventType.WS_RECONNECTED, resetDiscoveryState as EventListener);
    window.addEventListener(EventType.HYBRID_KEYS_UPDATED, resetEncryptionAndDiscoveryState as EventListener);
    window.addEventListener(EventType.SERVER_ENTRY_GRANTED, clearNegativeDiscoveryResults as EventListener);
    window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, clearNegativeDiscoveryResults as EventListener);

    return () => {
      window.removeEventListener(EventType.WS_RECONNECTED, resetDiscoveryState as EventListener);
      window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, resetEncryptionAndDiscoveryState as EventListener);
      window.removeEventListener(EventType.SERVER_ENTRY_GRANTED, clearNegativeDiscoveryResults as EventListener);
      window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, clearNegativeDiscoveryResults as EventListener);
    };
  }, []);

  useEffect(() => {
    if (!isLoggedIn) return;

    const resolveDiscoveryMaterial = async (
      peer: string,
      _reason: string,
      options?: { force?: boolean }
    ): Promise<any | null> => {
      if (!findUser) return null;
      if (!peer) return null;
      const normalizedPeer = peer.trim().toLowerCase();
      if (!normalizedPeer) return null;
      const generation = discoveryGenerationRef.current;
      const account = activeAccountRef.current;
      const isCurrentGeneration = () => (
        generation === discoveryGenerationRef.current &&
        account !== null &&
        activeAccountRef.current === account &&
        loginUsernameRef.current === account
      );
      const force = !!options?.force;
      if (!shouldAttemptDiscovery(peer)) {
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
          const cached = discoveryCacheRef.current.get(peer) || discoveryCacheRef.current.get(normalizedPeer);
          if (cached) return cached;
          return null;
        }
      }
      setBoundedPeerEntry(discoveryAttemptRef.current, normalizedPeer, now);

      if (ensureDiscoveryPublished) {
        const warnPublishFailed = () => {
          if (!isCurrentGeneration()) return;
          const lastWarn = discoveryPublishWarnAtRef.current.get(normalizedPeer) || 0;
          if (Date.now() - lastWarn > 30000) {
            setBoundedPeerEntry(discoveryPublishWarnAtRef.current, normalizedPeer, Date.now());
            console.warn('[UnifiedTransport] Discovery self-publish failed before lookup');
          }
        };
        try {
          ensureDiscoveryPublished(force)
            .then((published) => { if (!published) warnPublishFailed(); })
            .catch(warnPublishFailed);
        } catch {
          warnPublishFailed();
        }
      }

      let promise: Promise<any | null>;
      promise = findUser(peer, { forceRefresh: !!options?.force })
        .then((material) => {
          if (!isCurrentGeneration()) return null;
          setBoundedPeerEntry(discoveryResultMemoRef.current, normalizedPeer, {
            value: material ?? null,
            expiresAt: Date.now() + 30000
          });
          return material;
        })
        .catch(() => {
          if (!isCurrentGeneration()) return null;
          setBoundedPeerEntry(discoveryResultMemoRef.current, normalizedPeer, {
            value: null,
            expiresAt: Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
          });
          console.warn('[UnifiedTransport] On-demand discovery failed');
          return null;
        })
        .finally(() => {
          if (discoveryInFlightRef.current.get(normalizedPeer) === promise) {
            discoveryInFlightRef.current.delete(normalizedPeer);
          }
        });

      discoveryInFlightRef.current.set(normalizedPeer, promise);
      return promise;
    };

    const resolveTrustedDiscoveryKeys = async (
      peerUsername: string,
      material: any
    ): Promise<{
      hybridKeys: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64: string };
      peerCertificateFingerprint: string;
      identityRootFingerprint: string;
      identityBundleFingerprint: string;
    } | null> => {
      const generation = discoveryGenerationRef.current;
      const account = activeAccountRef.current;
      if (!account) return null;
      const trusted = await resolveTrustedPeerHybridPublicKeys(account, peerUsername, material);
      if (
        generation !== discoveryGenerationRef.current ||
        account === null ||
        activeAccountRef.current !== account ||
        loginUsernameRef.current !== account
      ) {
        return null;
      }
      if (
        !trusted.valid ||
        !trusted.hybridKeys ||
        !trusted.peerCertificateFingerprint ||
        !trusted.identityRootFingerprint ||
        !trusted.identityBundleFingerprint
      ) {
        return null;
      }
      const signalIdentity = typeof material?.fullBundle?.identityKeyBase64 === 'string'
        ? material.fullBundle.identityKeyBase64
        : '';
      if (!signalIdentity) {
        return null;
      }
      const installed = await signal.installTransparencyVerifiedPeerIdentity(
        account,
        peerUsername,
        signalIdentity,
      ).catch(() => false);
      if (!installed) {
        return null;
      }
      if (
        generation !== discoveryGenerationRef.current ||
        activeAccountRef.current !== account ||
        loginUsernameRef.current !== account
      ) {
        return null;
      }
      const remainsAuthorized = !isKeyTransparencyPeerRevoked(account, peerUsername) &&
        isKeyTransparencyAuthorizedPeerKeySet({
          account,
          peer: peerUsername,
          kyberPublicBase64: trusted.hybridKeys.kyberPublicBase64,
          dilithiumPublicBase64: trusted.hybridKeys.dilithiumPublicBase64,
          x25519PublicBase64: trusted.hybridKeys.x25519PublicBase64,
          peerCertificateFingerprint: trusted.peerCertificateFingerprint,
          identityRootFingerprint: trusted.identityRootFingerprint,
          identityBundleFingerprint: trusted.identityBundleFingerprint,
        });
      if (!remainsAuthorized) {
        await signal.revokeTransparencyPeerIdentity(account, peerUsername).catch(() => false);
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
      const generation = encryptionGenerationRef.current;
      const currentUser = loginUsernameRef.current;
      const isCurrentOperation = () => (
        generation === encryptionGenerationRef.current &&
        !keyTransparencyClient.isSecurityIncidentActive() &&
        currentUser !== null &&
        activeAccountRef.current === currentUser &&
        loginUsernameRef.current === currentUser
      );
      
      const deny = (reason: string, _extra?: Record<string, unknown>): null => {
        try { unifiedSignalTransport.noteEncryptionDenial(to, String(type), reason); } catch { }
        return null;
      };

      const processPeerBundle = async (
        peer: string,
        fullBundle: any,
        _source: string
      ): Promise<boolean> => {
        try {
          await signal.processVerifiedPreKeyBundle(currentUser as string, peer, fullBundle);
          
          setBoundedPeerEntry(peerBundleInstalledRef.current, `${currentUser}:${peer}`, true);
          return true;
        } catch {
          return false;
        }
      };
      try {
        if (!isCurrentOperation() || to === 'SERVER') {
          return to === 'SERVER' ? null : deny('stale-operation:entry');
        }
        let forceDiscoveryRefresh = !!transportHints?.forceDiscoveryRefresh;
        const peerWasRevoked = isKeyTransparencyPeerRevoked(currentUser, to);
        if (peerWasRevoked) {
          if (!await awaitPeerIdentityRevocation(currentUser, to) || !isCurrentOperation()) return deny('peer-revoked:revocation-wait-failed');
          forceDiscoveryRefresh = true;
          discoveryFreshUntilRef.current.delete(to);
          discoveryResultMemoRef.current.delete(to);
          discoveryCacheRef.current.delete(to);
          
          if (activeAccountRef.current) {
            await clearPersistedDiscoveryMaterial(
              activeAccountRef.current,
              String(to).trim().toLowerCase()
            ).catch(() => { });
          }
        }

        let peerKeys = peerWasRevoked ? null : await getPeerHybridKeys(to);
        if (!isCurrentOperation()) return deny('stale-operation');
        let resolvedUsername = to;

        // EARLY CACHE HYDRATION
        if (!forceDiscoveryRefresh && !peerKeys?.kyberPublicBase64) {
          const normalizedTo = resolvedUsername.trim().toLowerCase();
          let cachedMaterial = discoveryCacheRef.current.get(resolvedUsername)
            || discoveryCacheRef.current.get(normalizedTo);

          if (!cachedMaterial && activeAccountRef.current) {
            cachedMaterial = (await loadPersistedDiscoveryMaterial(
              activeAccountRef.current,
              normalizedTo
            ).catch(() => null))?.material ?? null;
            if (!isCurrentOperation()) return deny('stale-operation');
            if (cachedMaterial) {
              rememberDiscoveryMaterial(resolvedUsername, cachedMaterial);
            }
          }
          if (cachedMaterial) {
            const trustedCached = await resolveTrustedDiscoveryKeys(resolvedUsername, cachedMaterial).catch(() => null);
            if (!isCurrentOperation()) return deny('stale-operation');
            if (trustedCached) {
              peerKeys = {
                ...(peerKeys || {}),
                kyberPublicBase64: trustedCached.hybridKeys.kyberPublicBase64,
                dilithiumPublicBase64: trustedCached.hybridKeys.dilithiumPublicBase64,
                x25519PublicBase64: trustedCached.hybridKeys.x25519PublicBase64
              };
              if (cachedMaterial.fullBundle) {
                const hasSession = await signal.hasSession(currentUser, resolvedUsername).catch(() => false);
                if (!isCurrentOperation()) return deny('stale-operation');
                if (!hasSession) {
                  await processPeerBundle(resolvedUsername, cachedMaterial.fullBundle, 'early-hydration');
                  if (!isCurrentOperation()) return deny('stale-operation');
                }
              }
            }
          }
        }

        // Refresh discovery material periodically
        const refreshPeer = resolvedUsername || to;
        const normalizedRefreshPeer = refreshPeer.trim().toLowerCase();
        const hasCachedKyber = !!peerKeys?.kyberPublicBase64;
        const hasCachedX25519 = !!peerKeys?.x25519PublicBase64;
        const refreshUntil = discoveryFreshUntilRef.current.get(refreshPeer) || 0;
        const now = Date.now();
        const memoizedDiscovery = discoveryResultMemoRef.current.get(normalizedRefreshPeer);
        const hasFreshNegativeMemo =
          !!memoizedDiscovery &&
          memoizedDiscovery.expiresAt > now &&
          memoizedDiscovery.value === null;
          
        const haveAllCachedRouting = hasCachedKyber && hasCachedX25519;
        const isDeferrable = DEFERRABLE_SIGNAL_TYPES.has(String(type));
        
        const mustRefreshDiscoveryNow = forceDiscoveryRefresh || (
          !hasFreshNegativeMemo &&
          (!haveAllCachedRouting || (now >= refreshUntil && !isDeferrable))
        );

        if (forceDiscoveryRefresh) {
          discoveryFreshUntilRef.current.delete(refreshPeer);
          discoveryResultMemoRef.current.delete(normalizedRefreshPeer);
        }

        if (mustRefreshDiscoveryNow) {
          if (isDeferrable && forceDiscoveryRefresh) {
            return deny('deferrable-signal-skipped-forced-discovery', {
              haveAllCachedRouting,
            });
          }

          if (isDeferrable && discoveryInFlightRef.current.has(normalizedRefreshPeer)) {
            return deny('deferrable-signal-awaiting-in-flight-discovery');
          }
          const discoveryBudgetMs = isDeferrable
            ? DEFERRABLE_DISCOVERY_WAIT_MS
            : DISCOVERY_LOOKUP_SEND_TIMEOUT_MS;

          const previousKyber = peerKeys?.kyberPublicBase64;
          const discoveryStartedAt = Date.now();
          let discoveryTimedOut = false;
          const refreshedMaterial = await Promise.race([
            resolveDiscoveryMaterial(
              refreshPeer,
              'Resolving discovery material for',
              { force: forceDiscoveryRefresh }
            ),
            new Promise<null>((resolve) =>
              setTimeout(() => {
                discoveryTimedOut = true;
                resolve(null);
              }, discoveryBudgetMs)
            ),
          ]);
          if (!isCurrentOperation()) return deny('stale-operation');
          if (discoveryTimedOut && isDeferrable) {
            return deny('deferrable-signal-discovery-not-warm-yet', {
              waitedMs: Date.now() - discoveryStartedAt,
            });
          }
          if (discoveryTimedOut) {
            setBoundedPeerEntry(
              discoveryFreshUntilRef.current,
              refreshPeer,
              Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
            );
            return deny('discovery-lookup-timed-out', { timeoutMs: DISCOVERY_LOOKUP_SEND_TIMEOUT_MS });
          }
          if (refreshedMaterial?.publicKeys?.kyberPublicBase64) {
            const trustedDiscovery = await resolveTrustedDiscoveryKeys(refreshPeer, refreshedMaterial);
            if (!isCurrentOperation()) return deny('stale-operation');
            if (!trustedDiscovery) {
              setBoundedPeerEntry(discoveryFreshUntilRef.current,
                refreshPeer,
                Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
              );
              return deny('discovery-material-untrusted', { peer: refreshPeer, forced: forceDiscoveryRefresh });
            }
            rememberDiscoveryMaterial(refreshPeer, refreshedMaterial);
            setBoundedPeerEntry(discoveryFreshUntilRef.current,
              refreshPeer,
              Date.now() + DISCOVERY_REFRESH_SUCCESS_TTL_MS
            );

            const refreshedKyber = trustedDiscovery.hybridKeys.kyberPublicBase64;

            peerKeys = {
              ...(peerKeys || {}),
              kyberPublicBase64: refreshedKyber,
              dilithiumPublicBase64: trustedDiscovery.hybridKeys.dilithiumPublicBase64,
              x25519PublicBase64: trustedDiscovery.hybridKeys.x25519PublicBase64
            };

            if (previousKyber && refreshedKyber && previousKyber !== refreshedKyber) {
              peerBundleInstalledRef.current.delete(`${currentUser}:${refreshPeer}`);
              await signal.deleteAllSessions(currentUser, refreshPeer).catch(() => { });
              if (!isCurrentOperation()) return deny('stale-operation');
              preKeyPendingRef.current.delete(refreshPeer);
              if (refreshedMaterial.fullBundle) {
                const rebuilt = await processPeerBundle(refreshPeer, refreshedMaterial.fullBundle, 'key-rotation');
                if (!isCurrentOperation()) return deny('stale-operation');
                if (!rebuilt) {
                  setBoundedPeerEntry(discoveryFreshUntilRef.current,
                    refreshPeer,
                    Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
                  );
                  return deny('session-rebuild-failed-after-key-rotation', { peer: refreshPeer });
                }
              }
            }

            try {
              window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                detail: {
                  account: currentUser,
                  username: refreshPeer,
                  hybridKeys: {
                    kyberPublicBase64: peerKeys.kyberPublicBase64,
                    dilithiumPublicBase64: peerKeys.dilithiumPublicBase64,
                    x25519PublicBase64: peerKeys.x25519PublicBase64
                  },
                  peerCertificateFingerprint: trustedDiscovery.peerCertificateFingerprint,
                  identityRootFingerprint: trustedDiscovery.identityRootFingerprint,
                  identityBundleFingerprint: trustedDiscovery.identityBundleFingerprint
                }
              }));
            } catch { }
          } else {
            setBoundedPeerEntry(discoveryFreshUntilRef.current,
              refreshPeer,
              Date.now() + DISCOVERY_REFRESH_FAILURE_TTL_MS
            );
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          const cached = discoveryCacheRef.current.get(resolvedUsername);
          if (cached) {
            const trustedCached = await resolveTrustedDiscoveryKeys(resolvedUsername, cached);
            if (!isCurrentOperation()) return deny('stale-operation');
            if (trustedCached) {
              peerKeys = trustedCached.hybridKeys;
            }
            if (peerKeys && cached.fullBundle) {
              const hasSession = await signal.hasSession(currentUser, resolvedUsername).catch(() => false);
              if (!isCurrentOperation()) return deny('stale-operation');
              if (!hasSession) {
                await processPeerBundle(resolvedUsername, cached.fullBundle, 'cache-fallback');
                if (!isCurrentOperation()) return deny('stale-operation');
              }
            }
          } else {
            const material = await resolveDiscoveryMaterial(
              resolvedUsername,
              'Attempting on-demand discovery for',
              { force: forceDiscoveryRefresh }
            );
            if (!isCurrentOperation()) return deny('stale-operation');
            if (material?.publicKeys?.kyberPublicBase64) {
              const trustedDiscovery = await resolveTrustedDiscoveryKeys(resolvedUsername, material);
              if (!isCurrentOperation()) return deny('stale-operation');
              if (!trustedDiscovery) {
                return deny('on-demand-discovery-material-untrusted', { peer: resolvedUsername });
              }
              rememberDiscoveryMaterial(resolvedUsername, material);
              peerKeys = {
                kyberPublicBase64: trustedDiscovery.hybridKeys.kyberPublicBase64,
                dilithiumPublicBase64: trustedDiscovery.hybridKeys.dilithiumPublicBase64,
                x25519PublicBase64: trustedDiscovery.hybridKeys.x25519PublicBase64
              };
              if (material.fullBundle) {
                const hasSession = await signal.hasSession(currentUser, resolvedUsername).catch(() => false);
                if (!isCurrentOperation()) return deny('stale-operation');
                if (!hasSession) {
                  await signal.processVerifiedPreKeyBundle(currentUser, resolvedUsername, material.fullBundle);
                  if (!isCurrentOperation()) return deny('stale-operation');
                }
              }
            }
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          console.warn('[UnifiedTransport] Auto-encryption failed: no peer keys', {
            hasAlias: resolvedUsername !== to
          });
          return deny('no-peer-routing-keys', { hasAlias: resolvedUsername !== to });
        }

        if (isKeyTransparencyPeerRevoked(currentUser, resolvedUsername)) return deny('peer-revoked:pre-session');

        // Ensure Signal Protocol session
        const ensureSession = async (peer: string): Promise<{ hasSession: boolean; isOwner: boolean }> => {
          const key = `${currentUser}:${peer}`;
          const existing = sessionEnsureRef.current.get(key);
          if (existing) {
            const hasSession = await existing;
            return { hasSession: isCurrentOperation() && hasSession, isOwner: false };
          }

          const hadSession = await signal.hasSession(currentUser, peer);
          if (!isCurrentOperation()) return { hasSession: false, isOwner: false };
          if (hadSession) {
            const installKey = `${currentUser}:${peer}`;
            if (!peerBundleInstalledRef.current.has(installKey)) {
              const restoredNativeKey = await signal.hasPeerStaticMlkemKey(
                currentUser,
                peer,
              ).catch(() => false);
              if (!isCurrentOperation()) return { hasSession: false, isOwner: false };
              if (restoredNativeKey) {
                setBoundedPeerEntry(peerBundleInstalledRef.current, installKey, true);
              }
            }
            if (!peerBundleInstalledRef.current.has(installKey)) {
              const cached = discoveryCacheRef.current.get(peer);
              if (cached?.fullBundle) {
                const trustedCached = await resolveTrustedDiscoveryKeys(peer, cached);
                if (!isCurrentOperation()) return { hasSession: false, isOwner: false };
                if (trustedCached) {
                  await processPeerBundle(peer, cached.fullBundle, 'existing-session-mlkem');
                  if (!isCurrentOperation()) return { hasSession: false, isOwner: false };
                }
              } else {
                let install = mlKemInstallInFlightRef.current.get(installKey);
                if (!install) {
                  let created!: Promise<void>;
                  created = (async () => {
                    try {
                      const fetched = await resolveDiscoveryMaterial(
                        peer,
                        'Installing peer ML-KEM key for',
                        {},
                      );
                      if (!isCurrentOperation() || !fetched?.fullBundle) {
                        return;
                      }
                      const trustedFetched = await resolveTrustedDiscoveryKeys(peer, fetched);
                      if (!isCurrentOperation()) return;
                      if (!trustedFetched) {
                        return;
                      }
                      rememberDiscoveryMaterial(peer, fetched);
                      await processPeerBundle(peer, fetched.fullBundle, 'existing-session-mlkem-fetched');
                    } finally {
                      if (mlKemInstallInFlightRef.current.get(installKey) === created) {
                        mlKemInstallInFlightRef.current.delete(installKey);
                      }
                    }
                  })();
                  install = created;
                  mlKemInstallInFlightRef.current.set(installKey, created);
                }

                if (isDeferrable) {
                  void install.catch(() => { });
                  return { hasSession: false, isOwner: false };
                }
                await install;
                if (!isCurrentOperation()) return { hasSession: false, isOwner: false };
              }
            }
            return {
              hasSession: peerBundleInstalledRef.current.has(installKey),
              isOwner: false,
            };
          }

          preKeyPendingRef.current.add(peer);

          let promise!: Promise<boolean>;
          promise = (async () => {
            try {
              let hasSession = await signal.hasSession(currentUser, peer);
              if (!isCurrentOperation()) return false;
              if (hasSession) return true;

              const cached = discoveryCacheRef.current.get(peer);
              if (cached?.fullBundle) {
                const trustedCached = await resolveTrustedDiscoveryKeys(peer, cached);
                if (!isCurrentOperation()) return false;
                if (trustedCached) {
                  const hasExistingSession = await signal.hasSession(currentUser, peer).catch(() => false);
                  if (!isCurrentOperation()) return false;
                  if (!hasExistingSession) {
                    await processPeerBundle(peer, cached.fullBundle, 'cached');
                    if (!isCurrentOperation()) return false;
                  }
                  hasSession = await signal.hasSession(currentUser, peer);
                  if (!isCurrentOperation()) return false;
                  if (hasSession) return true;
                }
              }

              const material = await resolveDiscoveryMaterial(
                peer,
                'Establishing Signal session for',
                { force: forceDiscoveryRefresh }
              );
              if (!isCurrentOperation()) return false;
              if (!material || !material.fullBundle) {
                return false;
              }
              const trustedDiscovery = await resolveTrustedDiscoveryKeys(peer, material);
              if (!isCurrentOperation()) return false;
              if (!trustedDiscovery) {
                return false;
              }
              rememberDiscoveryMaterial(peer, material);
              const hasExistingSession = await signal.hasSession(currentUser, peer).catch(() => false);
              if (!isCurrentOperation()) return false;
              if (!hasExistingSession) {
                await signal.processVerifiedPreKeyBundle(currentUser, peer, material.fullBundle);
                if (!isCurrentOperation()) return false;
              }
              hasSession = await signal.hasSession(currentUser, peer);
              return isCurrentOperation() && !!hasSession;
            } finally {
              if (sessionEnsureRef.current.get(key) === promise) {
                sessionEnsureRef.current.delete(key);
              }
            }
          })();

          if (!isCurrentOperation()) return { hasSession: false, isOwner: false };
          sessionEnsureRef.current.set(key, promise);
          const hasSession = await promise;
          if (!isCurrentOperation()) return { hasSession: false, isOwner: true };
          
          preKeyPendingRef.current.delete(peer);
          const waiter = sessionReadyWaitersRef.current.get(peer);
          if (waiter) {
            try { clearTimeout(waiter.timeoutId); } catch { }
            sessionReadyWaitersRef.current.delete(peer);
            try { waiter.resolve(); } catch { }
          }
          return { hasSession, isOwner: true };
        };

        await waitForSessionReady(resolvedUsername);
        if (!isCurrentOperation()) return deny('stale-operation');

        const { hasSession, isOwner } = await ensureSession(resolvedUsername);
        if (!isCurrentOperation()) return deny('stale-operation');
        if (!hasSession) return deny('no-signal-session', { isOwner });
        if (isKeyTransparencyPeerRevoked(currentUser, resolvedUsername)) return deny('peer-revoked:post-session');

        if (!isOwner && preKeyPendingRef.current.has(resolvedUsername)) {
          await waitForSessionReady(resolvedUsername);
          if (!isCurrentOperation()) return deny('stale-operation');
        }

        const localKeys = await getKeysOnDemand();
        if (!isCurrentOperation()) return deny('stale-operation');
        if (
          localKeys?.native !== true ||
          !isValidDilithiumPublicKeyBase64(localKeys?.dilithium?.publicKeyBase64)
        ) {
          console.error('[UnifiedTransport] Local Dilithium keys unavailable');
          return deny('local-dilithium-keys-unavailable');
        }

        if (!peerKeys?.x25519PublicBase64) {
          const cached = discoveryCacheRef.current.get(resolvedUsername);
          const x25519FromBundle = cached?.fullBundle ? extractX25519FromSignalBundle(cached.fullBundle) : undefined;
          if (x25519FromBundle) {
            peerKeys = { ...peerKeys, x25519PublicBase64: x25519FromBundle };
          }
        }
        if (
          !isValidKyberPublicKeyBase64(peerKeys?.kyberPublicBase64) ||
          !isValidDilithiumPublicKeyBase64(peerKeys?.dilithiumPublicBase64) ||
          !isValidX25519PublicKeyBase64(peerKeys?.x25519PublicBase64)
        ) {
          console.error('[UnifiedTransport] Peer hybrid keys unavailable for encryption');
          return deny('peer-hybrid-keys-invalid', {
            kyberOk: isValidKyberPublicKeyBase64(peerKeys?.kyberPublicBase64),
            dilithiumOk: isValidDilithiumPublicKeyBase64(peerKeys?.dilithiumPublicBase64),
            x25519Ok: isValidX25519PublicKeyBase64(peerKeys?.x25519PublicBase64),
          });
        }

        const privateP2PEndpoint = await getPrivateLocalP2PEndpoint(currentUser);
        if (!isCurrentOperation()) return deny('stale-operation');

        const applicationMessageId = sanitizeMessageId(payload?.messageId);
        if (isAckTrackedSignalType(type) && !applicationMessageId) {
          console.error('[UnifiedTransport] Ack-tracked payload has no valid operation ID');
          return deny('ack-tracked-payload-missing-message-id');
        }
        
        const transportMessageId = isAckTrackedSignalType(type)
          ? applicationMessageId!
          : crypto.randomUUID().replace(/-/g, '');

        const nativeContentRef = sanitizeMessageId(payload?.nativeContentRef);
        const isNativePrivateText = type === SignalType.MESSAGE || type === SignalType.EDIT_MESSAGE;
        if (
          (isNativePrivateText && (!nativeContentRef || (payload?.content !== '' && payload?.content !== undefined))) ||
          (!isNativePrivateText && payload?.nativeContentRef !== undefined)
        ) {
          return deny('invalid-native-content-reference');
        }
        const { nativeContentRef: _rendererOnlyContentRef, ...wirePayload } = payload;
        const signalPayload = {
          ...wirePayload,
          type,
          from: currentUser,
          to: resolvedUsername,
          timestamp: Date.now(),
          keyTransparencyHead: keyTransparencyClient.getGossipHead()
        };

        const signalPlaintext = JSON.stringify(signalPayload);
        const signalPlaintextBytes = signalPayloadEncoder.encode(signalPlaintext);
        try {
          if (signalPlaintextBytes.length > MAX_SIGNAL_PAYLOAD_JSON_BYTES) {
            throw new Error('Signal payload exceeds the authenticated plaintext limit');
          }
        } finally {
          signalPlaintextBytes.fill(0);
        }

        let signalResult: any;
        try {
          if (isKeyTransparencyPeerRevoked(currentUser, resolvedUsername)) return deny('peer-revoked:pre-encrypt');
          signalResult = nativeContentRef
            ? await signal.encryptContentRef(
                currentUser,
                resolvedUsername,
                signalPlaintext,
                nativeContentRef,
              )
            : await signal.encrypt(
                currentUser,
                resolvedUsername,
                signalPlaintext,
              );
        } catch (err) {
          if (!isCurrentOperation()) return deny('stale-operation');
          const msg = String(err);
          if (msg.includes('session') && msg.includes('not found')) {
            console.warn('[UnifiedTransport] Signal session lost, re-establishing');
            peerBundleInstalledRef.current.delete(`${currentUser}:${resolvedUsername}`);
            await signal.deleteAllSessions(currentUser, resolvedUsername).catch(() => { });
            return deny('signal-session-lost-during-encrypt');
          }
          throw err;
        }
        if (
          !isCurrentOperation() ||
          isKeyTransparencyPeerRevoked(currentUser, resolvedUsername)
        ) return deny('stale-or-revoked:post-signal-encrypt');

        if (!signalResult) {
          console.error('[UnifiedTransport] Signal encryption returned null');
          return deny('signal-encrypt-returned-null');
        }

        const hybridEnvelope = await CryptoUtils.Hybrid.encryptForClient(
          { 
            signalCiphertext: signalResult,
            from: currentUser,
            transportMessageId,
            applicationType: type,
            p2pEndpointUrl: privateP2PEndpoint ?? null
          },
          peerKeys,
          {
            to: peerKeys.dilithiumPublicBase64,
            from: localKeys.dilithium.publicKeyBase64,
            type: 'libsignal-message',
            senderDilithiumPublicKey: localKeys.dilithium.publicKeyBase64,
            signRoutingHeader: (canonicalHeader) =>
              account.sign(PROTOCOL_KEYS.DEVICE_ENVELOPE_SIGNING, canonicalHeader),
            timestamp: Date.now(),
          }
        );
        if (
          !isCurrentOperation() ||
          isKeyTransparencyPeerRevoked(currentUser, resolvedUsername)
        ) return deny('stale-or-revoked:post-hybrid-envelope');

        return {
          encryptedPayload: hybridEnvelope,
          messageId: transportMessageId,
          from: currentUser,
          recipientKyberPublicBase64: peerKeys.kyberPublicBase64
        };
      } catch (err) {
        if (!isCurrentOperation()) return deny('stale-operation');
        console.error('[UnifiedTransport] Unified encryption error', {
          error: err instanceof Error ? err.message : String(err)
        });
        return deny('unhandled-exception', { error: String(err).slice(0, 300) });
      }
    });

    return () => {
      unifiedSignalTransport.setEncryptionProvider(null);
    };
  }, [isLoggedIn, getPeerHybridKeys, users, getKeysOnDemand, findUser, ensureDiscoveryPublished]);
}
