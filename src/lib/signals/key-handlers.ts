/**
 * Key Signal Handlers
 */

import websocketClient from '../websocket/websocket';
import { sanitizeHybridKeys } from '../utils/messaging-validators';
import { clusterKeyManager } from '../cryptography/cluster-key-manager';
import { encryptedStorage } from '../database/encrypted-storage';
import { EventType } from '../types/event-types';
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
  if (!hybridKeys || !hybridKeys.kyberPublicBase64) {
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
  const { username, hybridKeys } = data ?? {};
  if (typeof username !== 'string' || !hybridKeys) {
    console.warn('[signals] hybrid-keys invalid-payload');
    return;
  }

  const sanitized = sanitizeHybridKeys(hybridKeys);
  db.setUsers((prev: any[]) => prev.map((user: any) => user.username === username ? { ...user, hybridPublicKeys: sanitized } : user));
  window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, { detail: { username, hybridKeys: sanitized } }));
}
