import { SignalType } from '../../lib/signal-types';
import { EventType } from '../../lib/event-types';
import { CryptoUtils } from '../../lib/unified-crypto';
import websocketClient from '../../lib/websocket';
import type { HybridPublicKeys, UserWithKeys } from '../../lib/types/message-sending-types';

// Resolve peer hybrid keys with fallback to bundle request
export const createDefaultResolvePeerHybridKeys = (
  recipientDirectory: Map<string, UserWithKeys>,
  getKeysOnDemand: () => Promise<{
    x25519: { private: Uint8Array; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>,
  loginUsernameRef: React.RefObject<string>,
  currentUsername: string
) => {
  return async (peerUsername: string): Promise<HybridPublicKeys | null> => {
    if (!peerUsername) return null;

    const existing = recipientDirectory.get(peerUsername)?.hybridPublicKeys;
    if (existing && existing.kyberPublicBase64 && existing.dilithiumPublicBase64) {
      return existing;
    }
    try {
      await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: peerUsername });
    } catch { }

    try {
      const keys = await getKeysOnDemand?.();
      
      if (keys?.dilithium?.publicKeyBase64 && keys?.dilithium?.secretKey) {
        const requestBase = {
          type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
          username: peerUsername,
          from: currentUsername || loginUsernameRef.current,
          timestamp: Date.now(),
          challenge: CryptoUtils.Base64.arrayBufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
          senderDilithium: keys.dilithium.publicKeyBase64,
          reason: 'resolve-keys',
        } as const;

        const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
        const sigRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
        const signature = CryptoUtils.Base64.arrayBufferToBase64(sigRaw);
        await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
      }
    } catch { }

    const hybrid = await new Promise<any>((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(null); } }, 2000);

      const onKeys = (e: Event) => {
        const d = (e as CustomEvent).detail || {};
        if (d?.username === peerUsername && d?.hybridKeys && d.hybridKeys.kyberPublicBase64 && d.hybridKeys.dilithiumPublicBase64) {
          cleanup();
          resolve(d.hybridKeys);
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
  };
};
