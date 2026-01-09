import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import websocketClient from '../../lib/websocket/websocket';
import type { HybridKeys, ResolvedSenderKeys, UserWithHybridKeys } from '../../lib/types/message-handling-types';

// Resolve sender's PQ Kyber and hybrid keys
export const resolveSenderHybridKeys = async (
  senderUsername: string,
  usersRef: React.RefObject<UserWithHybridKeys[]> | undefined,
  keyRequestCacheRef: React.RefObject<Map<string, number>>,
  getKeysOnDemand: (() => Promise<any>) | undefined,
  loginUsernameRef: React.RefObject<string>,
  keyRequestCacheDuration: number
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
        await websocketClient.sendSecureControlMessage({
          type: SignalType.CHECK_USER_EXISTS,
          username: senderUsername
        });
      } catch { }
      try {
        const keys = await getKeysOnDemand?.();

        if (keys?.dilithium?.secretKey && keys?.dilithium?.publicKeyBase64) {
          const requestBase = {
            type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
            username: senderUsername,
            from: loginUsernameRef.current,
            timestamp: Date.now(),
            challenge: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))),
            senderDilithium: keys.dilithium.publicKeyBase64,
          } as const;

          const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
          let signature: string | undefined;
          
          try {
            const sigRaw = await (window as any).CryptoUtils?.Dilithium?.sign(keys.dilithium.secretKey, canonical);
            signature = (window as any).CryptoUtils?.Base64?.arrayBufferToBase64
              ? (window as any).CryptoUtils.Base64.arrayBufferToBase64(sigRaw)
              : btoa(String.fromCharCode(...new Uint8Array(sigRaw)));
          } catch { }
          
          await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
        }
      } catch { }
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

// Request bundle once with dedup/throttle
export const requestBundleOnce = async (
  peerUsername: string,
  keyRequestCacheRef: React.RefObject<Map<string, number>>,
  inFlightBundleRequestsRef: React.RefObject<Map<string, Promise<void>>>,
  getKeysOnDemand: (() => Promise<any>) | undefined,
  loginUsernameRef: React.RefObject<string>,
  reason?: string
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
      const keys = await getKeysOnDemand?.();
      if (!keys?.dilithium?.secretKey || !keys?.dilithium?.publicKeyBase64) return;
      const requestBase = {
        type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
        username: peerUsername,
        from: loginUsernameRef.current,
        timestamp: Date.now(),
        challenge: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))),
        senderDilithium: keys.dilithium.publicKeyBase64,
        reason,
      } as const;
      const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
      let signature: string | undefined;
      try {
        const sig = await (window as any).CryptoUtils?.Dilithium?.sign(keys.dilithium.secretKey, canonical);
        signature = btoa(String.fromCharCode(...new Uint8Array(sig)));
      } catch { }
      await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
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
