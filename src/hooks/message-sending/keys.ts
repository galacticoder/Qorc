import { EventType } from '../../lib/types/event-types';
import type { HybridPublicKeys, UserWithKeys } from '../../lib/types/message-sending-types';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';

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
    if (existing?.hybridPublicKeys?.kyberPublicBase64 && existing.hybridPublicKeys.dilithiumPublicBase64) {
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
                hybridKeys: material.publicKeys,
                inboxId: material.inboxId
              }
            }));

            return {
              kyberPublicBase64: material.publicKeys?.kyberPublicBase64,
              dilithiumPublicBase64: material.publicKeys?.dilithiumPublicBase64,
              inboxId: material.inboxId
            };
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
          if (d?.username === peerUsername && d?.hybridKeys && d.hybridKeys.kyberPublicBase64 && d.hybridKeys.dilithiumPublicBase64) {
            const inboxId = d.inboxId || d.hybridKeys.inboxId;
            const result = { ...d.hybridKeys, inboxId };
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

      if (hybrid && hybrid.kyberPublicBase64 && hybrid.dilithiumPublicBase64) return hybrid;
      const refreshed = recipientDirectory.get(peerUsername)?.hybridPublicKeys || null;
      return refreshed || null;
    })().finally(() => {
      findingCacheMap.delete(peerUsername);
    });

    findingCacheMap.set(peerUsername, finding);
    return finding;
  };
};
