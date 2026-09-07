import { EventType } from '../../lib/types/event-types';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import {
  resolveTrustedPeerHybridPublicKeys,
} from '../../lib/utils/signal-bundle-utils';

// Request bundle
export const requestBundleOnce = async (
  peerUsername: string,
  keyRequestCacheRef: React.RefObject<Map<string, number>>,
  inFlightBundleRequestsRef: React.RefObject<Map<string, Promise<void>>>,
  findUser: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>,
  options: {
    account: string;
    isCurrent: () => boolean;
    force?: boolean;
    forceRefreshDiscovery?: boolean;
  }
): Promise<void> => {
  if (!peerUsername || !options.account || !options.isCurrent()) return;
  const account = options.account;
  const isCurrent = options.isCurrent;
  const force = options?.force === true;
  const forceRefreshDiscovery = options?.forceRefreshDiscovery === true;
  const now = Date.now();
  const last = keyRequestCacheRef.current.get(peerUsername) || 0;
  if (!force && (now - last < 1200)) return;

  const inflight = inFlightBundleRequestsRef.current.get(peerUsername);
  if (inflight) {
    await inflight;
    return;
  }

  const promise = (async () => {
    if (!shouldAttemptDiscovery(peerUsername)) {
      return;
    }

    const material = await findUser(
      peerUsername,
      forceRefreshDiscovery ? { forceRefresh: true } : undefined
    );
    if (!isCurrent()) return;
    if (material) {
      const trusted = await resolveTrustedPeerHybridPublicKeys(
        account,
        peerUsername,
        material
      );
      if (!isCurrent() || !trusted.valid || !trusted.hybridKeys) return;

      if (material.fullBundle) {
        const processed = await signal.processVerifiedPreKeyBundle(account, peerUsername, material.fullBundle);
        if (!isCurrent()) return;
        if (processed) {
          window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
            detail: { peer: peerUsername, account }
          }));
        }
      }

      window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
        detail: {
          username: peerUsername,
          account,
          hybridKeys: trusted.hybridKeys,
          peerCertificateFingerprint: trusted.peerCertificateFingerprint,
          identityRootFingerprint: trusted.identityRootFingerprint,
          identityBundleFingerprint: trusted.identityBundleFingerprint
        }
      }));
    }

    if (!isCurrent()) return;
    keyRequestCacheRef.current.set(peerUsername, Date.now());

  })();

  inFlightBundleRequestsRef.current.set(peerUsername, promise);
  try {
    await promise;
  } finally {
    if (inFlightBundleRequestsRef.current.get(peerUsername) === promise) {
      inFlightBundleRequestsRef.current.delete(peerUsername);
    }
  }
};
