/**
 * Key Signal Handlers
 */

import { v4 as uuidv4 } from 'uuid';
import websocketClient from '../websocket/websocket';
import { sanitizeHybridKeys } from '../utils/messaging-validators';
import { clusterKeyManager } from '../cryptography/cluster-key-manager';
import { encryptedStorage } from '../database/encrypted-storage';
import { EventType } from '../types/event-types';
import type { AuthRefs, DatabaseRefs } from '../types/signal-handler-types';

// Handle public keys
export function handlePublicKeys(data: any, db: DatabaseRefs): void {
  const { message } = data ?? {};
  if (!Array.isArray(Object.keys(data?.message ?? {}))) {
    console.warn('[signals] publickeys invalid-payload');
    return;
  }
  
  const usersData = JSON.parse(message) as Record<string, { x25519PublicBase64: string; kyberPublicBase64: string }>;
  if (!db.setUsers) {
    console.warn('[signals] publickeys setusers-unavailable');
    return;
  }
  
  db.setUsers(
    Object.entries(usersData)
      .filter(([username]) => typeof username === 'string' && username.length > 0 && username.length <= 64)
      .map(([username, keys]) => {
        const sanitized = sanitizeHybridKeys(keys);
        return { id: uuidv4(), username, isTyping: false, isOnline: true, hybridPublicKeys: sanitized };
      })
  );

  // Trigger events to process queued messages for each user
  for (const [username, hybridKeys] of Object.entries(usersData)) {
    const sanitized = sanitizeHybridKeys(hybridKeys);
    window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, { detail: { username, hybridKeys: sanitized } }));
  }
}

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

// Handle PQ session init
export async function handlePQSessionInit(data: any): Promise<void> {
  if (!data?.serverKeys || typeof data.serverKeys !== 'object') {
    console.warn('[signals] pq-session missing-server-keys');
    return;
  }
  try { await encryptedStorage.setItem('qorchat_server_pin_v2', JSON.stringify(data.serverKeys)); } catch { }
  (websocketClient as any).initiateSessionKeyExchange?.(data.serverKeys);
}

// Handle PQ session response
export function handlePQSessionResponse(data: any): void {
  if (!data?.kemCiphertext || !data?.sessionId) {
    console.warn('[signals] pq-session invalid-response');
    return;
  }
  (websocketClient as any).handleSessionKeyExchangeResponse?.(data);
}
