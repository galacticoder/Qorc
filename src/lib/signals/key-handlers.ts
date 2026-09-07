/**
 * Key Signal Handlers
 */

import websocketClient from '../websocket/websocket';
import { sanitizeHybridKeys } from '../utils/messaging-validators';
import type { AuthRefs } from '../types/signal-handler-types';

// Handle server public key
export async function handleServerPublicKey(data: any, auth: AuthRefs): Promise<void> {
  const rawKeys = data?.hybridKeys;
  const serverId = data?.serverId;

  const rejectServerIdentity = async (): Promise<void> => {
    auth.setServerHybridPublic(null);
    auth.serverHybridPublicRef.current = null;
    auth.setLoginError('Server identity verification failed. Connection blocked.');
    await websocketClient.close({ killSession: true }).catch(() => { });
  };

  if (!rawKeys) {
    await rejectServerIdentity();
    return;
  }

  const hybridKeys = sanitizeHybridKeys(rawKeys);
  if (!hybridKeys || !hybridKeys.kyberPublicBase64 || !hybridKeys.dilithiumPublicBase64 || !hybridKeys.x25519PublicBase64) {
    await rejectServerIdentity();
    return;
  }

  const connectionEpoch = websocketClient.captureConnectionPrivacyEpoch();
  if (!websocketClient.isConnectionPrivacyEpochCurrent(connectionEpoch)) return;

  const status = websocketClient.setServerKeyMaterial(hybridKeys as any, serverId);
  if (status !== 'activated') {
    await rejectServerIdentity();
    return;
  }

  const validatedKeys = {
    kyberPublicBase64: hybridKeys.kyberPublicBase64,
    dilithiumPublicBase64: hybridKeys.dilithiumPublicBase64,
    x25519PublicBase64: hybridKeys.x25519PublicBase64,
  };
  auth.setServerHybridPublic(validatedKeys);
  auth.serverHybridPublicRef.current = validatedKeys;
}
