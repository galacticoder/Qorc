import { SignalType } from '../../lib/signal-types';
import { EventType } from '../../lib/event-types';
import { CryptoUtils } from '../../lib/unified-crypto';
import websocketClient from '../../lib/websocket';
import { SESSION_WAIT_MS, SESSION_POLL_BASE_MS, SESSION_POLL_MAX_MS, BUNDLE_REQUEST_COOLDOWN_MS } from '../../lib/constants';
import { TEXT_ENCODER, getSessionApi } from '../../lib/utils/message-sending-utils';
import type { SigningKeys } from '../../lib/types/message-sending-types';

// Track last bundle request time per peer to avoid excessive requests
export const bundleRequestTracker = new Map<string, number>();

// Ensure session is established with peer before sending messages
export const ensureSession = async (
  sessionLocks: WeakMap<object, Map<string, Promise<boolean>>>,
  lockContext: object,
  currentUser: string,
  peer: string,
  signingKeys: SigningKeys,
) => {
  let contextMap = sessionLocks.get(lockContext);
  if (!contextMap) {
    contextMap = new Map();
    sessionLocks.set(lockContext, contextMap);
  }
  const key = `${currentUser}:${peer}`;
  const existing = contextMap.get(key);
  if (existing) {
    return existing;
  }

  const promise = (async () => {
    const sessionApi = getSessionApi();
    try {
      const initial = await sessionApi.hasSession({
        selfUsername: currentUser,
        peerUsername: peer,
        deviceId: 1,
      });
      if (initial?.hasSession) {
        return true;
      }

      const deadline = Date.now() + SESSION_WAIT_MS;
      let delay = SESSION_POLL_BASE_MS;
      const MAX_REPLIES = 1;
      let requestCount = 0;

      let sessionReadyFlag = false;
      const readyHandler = (event: Event) => {
        const customEvent = event as CustomEvent;
        if (customEvent.detail?.peer === peer) {
          sessionReadyFlag = true;
          try { window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener); } catch { }
        }
      };
      window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener);

      try {
        let lastRequestAt = 0;
        // Check if recently requested this peer's bundle
        const lastBundleRequest = bundleRequestTracker.get(peer) || 0;
        const nowTs = Date.now();
        const canRequestBundle = (nowTs - lastBundleRequest) >= BUNDLE_REQUEST_COOLDOWN_MS;

        if (canRequestBundle) {
          requestCount++;
          const requestBase = {
            type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
            username: peer,
            from: currentUser,
            timestamp: nowTs,
            challenge: CryptoUtils.Base64.arrayBufferToBase64(
              globalThis.crypto.getRandomValues(new Uint8Array(32)),
            ),
            senderDilithium: signingKeys.publicKeyBase64,
          } as const;
          const canonical = TEXT_ENCODER.encode(JSON.stringify(requestBase));
          const signatureRaw = await CryptoUtils.Dilithium.sign(signingKeys.secretKey, canonical);
          const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureRaw);
          await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
          lastRequestAt = nowTs;
          bundleRequestTracker.set(peer, nowTs);
        }

        while (Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, delay));

          if (sessionReadyFlag) {
            return true;
          }

          const check = await sessionApi.hasSession({
            selfUsername: currentUser,
            peerUsername: peer,
            deviceId: 1,
          });
          if (check?.hasSession) {
            return true;
          }

          if (requestCount <= MAX_REPLIES && Date.now() - lastRequestAt >= 3000) {
            const nowTs = Date.now();
            const lastBundleRequest = bundleRequestTracker.get(peer) || 0;
            const canRetryBundle = (nowTs - lastBundleRequest) >= BUNDLE_REQUEST_COOLDOWN_MS;

            if (canRetryBundle) {
              requestCount++;
              const requestBase = {
                type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                username: peer,
                from: currentUser,
                timestamp: nowTs,
                challenge: CryptoUtils.Base64.arrayBufferToBase64(
                  globalThis.crypto.getRandomValues(new Uint8Array(32)),
                ),
                senderDilithium: signingKeys.publicKeyBase64,
              } as const;
              
              const canonical = TEXT_ENCODER.encode(JSON.stringify(requestBase));
              const signatureRaw = await CryptoUtils.Dilithium.sign(signingKeys.secretKey, canonical);
              const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureRaw);
              await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
              lastRequestAt = nowTs;
              bundleRequestTracker.set(peer, nowTs);
            }
          }

          const randomSource = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 0xffffffff;
          const poisson = -Math.log(Math.max(1 - randomSource, 1e-6));
          delay = Math.min(delay + poisson * SESSION_POLL_BASE_MS, SESSION_POLL_MAX_MS);
        }
      } finally {
        try { window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener); } catch { }
      }

      console.error(`[MessageSender] Failed to establish session with ${peer} after ${requestCount} attempts`);
      return false;
    } finally {
      contextMap?.delete(key);
    }
  })();

  contextMap.set(key, promise);
  return promise;
};
