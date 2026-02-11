import { EventType } from '../../lib/types/event-types';
import { signal } from '../../lib/tauri-bindings';
import type { HybridKeys, ResolvedSenderKeys, UserWithHybridKeys } from '../../lib/types/message-handling-types';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';

// Resolve sender's PQ Kyber and hybrid keys
export const resolveSenderHybridKeys = async (
  senderUsername: string,
  usersRef: React.RefObject<UserWithHybridKeys[]> | undefined,
  keyRequestCacheRef: React.RefObject<Map<string, number>>,
  loginUsernameRef: React.RefObject<string>,
  keyRequestCacheDuration: number,
  findUser?: (handle: string) => Promise<any>
): Promise<ResolvedSenderKeys> => {
  const user = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
  let kyber = user?.hybridPublicKeys?.kyberPublicBase64 || null;
  let retried = false;

  if (!kyber) {
    const now = Date.now();
    const lastReq = keyRequestCacheRef.current.get(senderUsername);
    if (!lastReq || (now - lastReq) > keyRequestCacheDuration) {
      keyRequestCacheRef.current.set(senderUsername, now);
      try {
        if (!findUser) {
          console.warn('[Keys] findUser not available for background discovery');
          return { kyber: null, hybrid: null, retried: false };
        }

        const known = usersRef?.current?.map?.((u: any) => u.username).filter(Boolean) ?? [];
        if (!shouldAttemptDiscovery(senderUsername, known)) {
          return { kyber: null, hybrid: null, retried: false };
        }
        const material = await findUser(senderUsername);
        if (material) {
          const { inboxId, publicKeys, fullBundle } = material;

          if (fullBundle && loginUsernameRef.current) {
            const hasSession = await signal.hasSession(loginUsernameRef.current, senderUsername, 1).catch(() => false);
            if (!hasSession) {
              await signal.processPreKeyBundle(loginUsernameRef.current, senderUsername, fullBundle);
            }
          }

          window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
            detail: {
              username: senderUsername,
              hybridKeys: publicKeys,
              inboxId
            }
          }));
        }
      } catch (discoveryErr) {
        console.error('[Keys] Discovery failure:', discoveryErr);
      }
      retried = true;

      await new Promise<void>((resolve) => {
        let settled = false;
        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 2000);
        const handler = (event: Event) => {
          const d = (event as CustomEvent).detail;
          if (d?.username === senderUsername && d?.hybridKeys) {
            window.removeEventListener(EventType.USER_KEYS_AVAILABLE, handler as EventListener);
            if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
          }
        };
        window.addEventListener(EventType.USER_KEYS_AVAILABLE, handler as EventListener, { once: true });
      });
      const refreshed = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
      kyber = refreshed?.hybridPublicKeys?.kyberPublicBase64 || null;
    }
  }

  let refreshedUser = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
  let hybrid: HybridKeys | null = refreshedUser?.hybridPublicKeys
    ? { ...refreshedUser.hybridPublicKeys, kyberPublicBase64: kyber ?? refreshedUser.hybridPublicKeys?.kyberPublicBase64 }
    : null;

  const hasFullHybrid = (obj: any) => obj && typeof obj.dilithiumPublicBase64 === 'string' && (typeof obj.x25519PublicBase64 === 'string' || obj.x25519PublicBase64 === undefined);

  if (!hasFullHybrid(hybrid)) {
    await new Promise<void>((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1200);
      const handler = (event: Event) => {
        const d = (event as CustomEvent).detail;
        if (d?.username === senderUsername && d?.hybridKeys) {
          window.removeEventListener(EventType.USER_KEYS_AVAILABLE, handler as EventListener);
          if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
        }
      };
      window.addEventListener(EventType.USER_KEYS_AVAILABLE, handler as EventListener, { once: true });
    });
    refreshedUser = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
    hybrid = refreshedUser?.hybridPublicKeys
      ? { ...refreshedUser.hybridPublicKeys, kyberPublicBase64: kyber ?? refreshedUser.hybridPublicKeys?.kyberPublicBase64 }
      : null;
  }

  return { kyber, hybrid, retried };
};

// Request bundle
export const requestBundleOnce = async (
  peerUsername: string,
  keyRequestCacheRef: React.RefObject<Map<string, number>>,
  inFlightBundleRequestsRef: React.RefObject<Map<string, Promise<void>>>,
  loginUsernameRef: React.RefObject<string>,
  findUser?: (handle: string) => Promise<any>
): Promise<void> => {
  if (!peerUsername) return;
  const now = Date.now();
  const last = keyRequestCacheRef.current.get(peerUsername) || 0;
  if (now - last < 1200) return;

  const inflight = inFlightBundleRequestsRef.current.get(peerUsername);
  if (inflight) {
    try { await inflight; } catch { }
    return;
  }

  const promise = (async () => {
    try {
      if (!findUser) {
        return;
      }

      if (!shouldAttemptDiscovery(peerUsername)) {
        return;
      }

      const material = await findUser(peerUsername);
      if (material) {
        if (material.fullBundle && loginUsernameRef.current) {
          const hasSession = await signal.hasSession(loginUsernameRef.current, peerUsername, 1).catch(() => false);
          if (!hasSession) {
            await signal.processPreKeyBundle(loginUsernameRef.current, peerUsername, material.fullBundle);
          }
        }

        window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
          detail: {
            username: peerUsername,
            hybridKeys: material.publicKeys,
            inboxId: material.inboxId
          }
        }));
      }

      keyRequestCacheRef.current.set(peerUsername, now);

      await new Promise<void>((resolve) => {
        let settled = false;
        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
        const handler = (event: Event) => {
          const d = (event as CustomEvent).detail || {};
          if (d?.username === peerUsername) {
            try { window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handler as EventListener); } catch { }
            if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
          }
        };
        window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handler as EventListener, { once: true });
      });
    } finally {
      inFlightBundleRequestsRef.current.delete(peerUsername);
    }
  })();

  inFlightBundleRequestsRef.current.set(peerUsername, promise);
  await promise;
};
