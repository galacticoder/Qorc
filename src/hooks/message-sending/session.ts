import { getSessionApi } from '../../lib/utils/message-sending-utils';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { validateSignalBundleForPeerIdentity } from '../../lib/utils/signal-bundle-utils';

// Track last bundle request time per peer to avoid excessive requests
export const bundleRequestTracker = new Map<string, number>();

// Ensure session is established with peer before sending messages
export const ensureSession = async (
  sessionLocks: WeakMap<object, Map<string, Promise<boolean>>>,
  lockContext: object,
  currentUser: string,
  peer: string,
  users?: Array<{ username: string; hybridPublicKeys?: any; peerCertificateFingerprint?: string; identityRootFingerprint?: string }>,
  findUser?: (handle: string) => Promise<any>
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

      if (!findUser) {
        console.warn('[MessageSender] Cannot establish session: findUser not provided');
        return false;
      }

      try {
        if (!shouldAttemptDiscovery(peer)) {
          return false;
        }
        const material = await findUser(peer);
        if (material && material.fullBundle) {
          const validation = await validateSignalBundleForPeerIdentity(
            peer,
            material.fullBundle,
            users as any,
            findUser as any
          );
          if (!validation.valid) {
            return false;
          }
          const success = await signal.processPreKeyBundle(
            currentUser,
            peer,
            material.fullBundle
          );

          if (success) {
            const check = await sessionApi.hasSession({
              selfUsername: currentUser,
              peerUsername: peer,
              deviceId: 1,
            });
            return !!check?.hasSession;
          }
        } else {
          console.warn('[MessageSender] No discovery material found');
        }
      } catch (err) {
        console.error('[MessageSender] Discovery-based session establishment failed');
      }

      return false;
    } finally {
      contextMap?.delete(key);
    }
  })();

  contextMap.set(key, promise);
  return promise;
};
