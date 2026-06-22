/**
 * Key Signal Handlers
 */

import websocketClient from '../websocket/websocket';
import { sanitizeHybridKeys } from '../utils/messaging-validators';
import { clusterKeyManager } from '../cryptography/cluster-key-manager';
import { encryptedStorage } from '../database/encrypted-storage';
import type { AuthRefs, DatabaseRefs } from '../types/signal-handler-types';

// Handle server public key
export async function handleServerPublicKey(data: any, auth: AuthRefs): Promise<void> {
  const rawKeys = data?.hybridKeys;
  const serverId = data?.serverId;

  if (!rawKeys) {
    console.error('[SIGNALS] SERVER_PUBLIC_KEY missing hybridKeys!');
    return;
  }

  const hybridKeys = sanitizeHybridKeys(rawKeys);
  if (!hybridKeys || !hybridKeys.kyberPublicBase64 || !hybridKeys.dilithiumPublicBase64 || !hybridKeys.x25519PublicBase64) {
    console.warn('[signals] server-key invalid-key-material');
    return;
  }

  try {
    websocketClient.setServerKeyMaterial(hybridKeys as any, serverId);
    if (serverId) clusterKeyManager.updateServerKeys(serverId, hybridKeys as any);
    try { await encryptedStorage.setItem('qorchat_server_pin_v2', JSON.stringify(hybridKeys)); } catch { }
  } catch (_err) {
    console.error('[signals] server-key persist-failed', (_err as Error).message);
  }

  auth.setServerHybridPublic?.(hybridKeys);
  if (auth.serverHybridPublicRef) {
    auth.serverHybridPublicRef.current = hybridKeys;
  }
}

// Handle hybrid keys
export function handleHybridKeys(data: any, db: DatabaseRefs): void {
  if (!db.setUsers) return;
  const { username } = data ?? {};
  if (typeof username !== 'string') {
    console.warn('[signals] hybrid-keys invalid-payload');
    return;
  }
  console.warn('[signals] rejected unauthenticated peer hybrid key update; use certified discovery material', { hasUsername: !!username });
}
