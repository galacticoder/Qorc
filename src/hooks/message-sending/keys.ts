import { EventType } from '../../lib/types/event-types';
import type { HybridPublicKeys, UserWithKeys } from '../../lib/types/message-sending-types';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { resolveTrustedPeerHybridPublicKeys } from '../../lib/utils/signal-bundle-utils';

const findingCacheMap = new Map<string, Promise<HybridPublicKeys | null>>();

// Resolve peer hybrid keys with fallback to discovery
export const createDefaultResolvePeerHybridKeys = (
  recipientDirectory: Map<string, UserWithKeys>,
  _getKeysOnDemand: () => Promise<{
    x25519: { private: Uint8Array; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>,
  loginUsernameRef: React.RefObject<string>,
  _currentUsername: string,
  findUser?: (handle: string) => Promise<any>
) => {
  return async (peerUsername: string): Promise<HybridPublicKeys | null> => {
    if (!peerUsername) return null;

    const existing = recipientDirectory.get(peerUsername);
    if (
      existing?.hybridPublicKeys?.kyberPublicBase64 &&
      existing.hybridPublicKeys.dilithiumPublicBase64 &&
      existing.hybridPublicKeys.x25519PublicBase64 &&
      existing.peerCertificateFingerprint &&
      existing.identityRootFingerprint
    ) {
      return existing.hybridPublicKeys;
    }

    if (findingCacheMap.has(peerUsername)) {
      return findingCacheMap.get(peerUsername)!;
    }

    const finding = (async () => {
      // Use Discovery Service
      if (findUser) {
        try {
          if (!shouldAttemptDiscovery(peerUsername)) {
            return null;
          }
          const material = await findUser(peerUsername);
          if (material) {
            const trustedPeerKeys = await resolveTrustedPeerHybridPublicKeys(
              peerUsername,
              material,
              Array.from(recipientDirectory.values()) as any
            );
            if (!trustedPeerKeys.valid || !trustedPeerKeys.hybridKeys) {
              return null;
            }

            if (material.fullBundle && loginUsernameRef.current) {
              const hasSession = await signal.hasSession(loginUsernameRef.current, peerUsername, 1).catch(() => false);
              if (!hasSession) {
                await signal.processPreKeyBundle(loginUsernameRef.current, peerUsername, material.fullBundle);
              }
            }

            // Notify about the discovered keys
            window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
              detail: {
                username: peerUsername,
                hybridKeys: {
                  ...trustedPeerKeys.hybridKeys,
                  routeId: material.routeId,
                  mailboxLookupId: material.mailboxLookupId,
                  bundleLookupId: material.bundleLookupId
                },
                inboxId: trustedPeerKeys.hybridKeys.inboxId,
                routeId: material.routeId,
                mailboxLookupId: material.mailboxLookupId,
                bundleLookupId: material.bundleLookupId,
                peerCertificateFingerprint: trustedPeerKeys.peerCertificateFingerprint,
                identityRootFingerprint: trustedPeerKeys.identityRootFingerprint,
                identityBundleFingerprint: trustedPeerKeys.identityBundleFingerprint
              }
            }));

            return trustedPeerKeys.hybridKeys;
          }
        } catch (discoveryErr) {
          console.warn('[Keys] Discovery-based key resolution failed:', discoveryErr);
        }
      }

      // Fallback wait for keys event
      const hybrid = await new Promise<any>((resolve) => {
        let settled = false;
        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(null); } }, 3000);

        const onKeys = async (e: Event) => {
          const d = (e as CustomEvent).detail || {};
          if (
            d?.username === peerUsername &&
            d?.hybridKeys &&
            d.hybridKeys.kyberPublicBase64 &&
            d.hybridKeys.dilithiumPublicBase64 &&
            d.hybridKeys.x25519PublicBase64 &&
            d.peerCertificateFingerprint &&
            d.identityRootFingerprint
          ) {
            const inboxId = d.inboxId || d.hybridKeys.inboxId;
            const result = {
              ...d.hybridKeys,
              inboxId,
              routeId: d.routeId || d.hybridKeys.routeId,
              mailboxLookupId: d.mailboxLookupId || d.hybridKeys.mailboxLookupId,
              bundleLookupId: d.bundleLookupId || d.hybridKeys.bundleLookupId
            };
            cleanup();
            settled = true;
            resolve(result);
          }
        };

        const cleanup = () => {
          try { clearTimeout(timeout); } catch { }
          try { window.removeEventListener(EventType.USER_KEYS_AVAILABLE, onKeys as EventListener); } catch { }
        };

        window.addEventListener(EventType.USER_KEYS_AVAILABLE, onKeys as EventListener);
      });

      if (hybrid && hybrid.kyberPublicBase64 && hybrid.dilithiumPublicBase64 && hybrid.x25519PublicBase64) return hybrid;
      const refreshed = recipientDirectory.get(peerUsername)?.hybridPublicKeys || null;
      const refreshedUser = recipientDirectory.get(peerUsername);
      if (
        refreshed?.kyberPublicBase64 &&
        refreshed?.dilithiumPublicBase64 &&
        refreshed?.x25519PublicBase64 &&
        refreshedUser?.peerCertificateFingerprint &&
        refreshedUser?.identityRootFingerprint
      ) {
        return refreshed;
      }
      return null;
    })().finally(() => {
      findingCacheMap.delete(peerUsername);
    });

    findingCacheMap.set(peerUsername, finding);
    return finding;
  };
};
