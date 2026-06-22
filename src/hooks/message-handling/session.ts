import { EventType } from '../../lib/types/event-types';
import type { PendingRetryEntry, AttemptsLedgerEntry, ResetCounterEntry } from '../../lib/types/message-handling-types';
import { computeBackoffMs } from '../../lib/utils/message-handler-utils';
import { BUNDLE_REQUEST_COOLDOWN_MS, MAX_RETRY_ATTEMPTS, PENDING_QUEUE_MAX_PER_PEER } from '../../lib/constants';
import { signal } from '../../lib/tauri-bindings';
import websocketClient from '../../lib/websocket/websocket';
import { getBlindRoutingClient } from '../../lib/transport/blind-routing-client';

const REPLENISH_MISSING_INBOX_WARN_COOLDOWN_MS = 30_000;
let lastReplenishMissingInboxWarnAt = 0;
const REPLENISH_NOT_READY_WARN_COOLDOWN_MS = 30_000;
let lastReplenishNotReadyWarnAt = 0;

// Handle session reset and queue message for retry
export const handleSessionResetAndRetry = async (
  senderUsername: string,
  encryptedMessage: any,
  currentUser: string,
  pendingRetryMessagesRef: React.RefObject<Map<string, PendingRetryEntry[]>>,
  pendingRetryIdsRef: React.RefObject<Map<string, Set<string>>>,
  attemptsLedgerRef: React.RefObject<Map<string, AttemptsLedgerEntry>>,
  lastKyberFpRef: React.RefObject<Map<string, string>>,
  bundleRequestCooldownRef: React.RefObject<Map<string, number>>,
  resetCooldownRef: React.RefObject<Map<string, number>>,
  resetCounterRef: React.RefObject<Map<string, ResetCounterEntry>>,
  requestBundleOnce: (peer: string, reason?: string, options?: { force?: boolean; forceRefreshDiscovery?: boolean }) => Promise<void>,
  maxResetsPerPeer: number,
  resetWindowMs: number,
  options?: {
    resolvePeerInboxId?: (peer: string) => Promise<string | null>;
    senderInboxId?: string | null;
    forceRefreshDiscovery?: boolean;
    invalidateCache?: (handle: string) => void;
  }
): Promise<boolean> => {
  const nowTs = Date.now();
  if (options?.invalidateCache) {
    options.invalidateCache(senderUsername);
  }
  const _lastReset = resetCooldownRef.current.get(senderUsername) || 0;

  if (nowTs - _lastReset < 3000) {
    return false;
  }

  const counterEntry = resetCounterRef.current.get(senderUsername);
  if (counterEntry) {
    if (nowTs - counterEntry.windowStart > resetWindowMs) {
      resetCounterRef.current.set(senderUsername, { count: 1, windowStart: nowTs });
    } else if (counterEntry.count >= maxResetsPerPeer) {
      console.warn('[EncryptedMessageHandler] Max session resets reached, waiting for window to expire', {
        maxResetsPerPeer
      });
      return false;
    } else {
      counterEntry.count += 1;
    }
  } else {
    resetCounterRef.current.set(senderUsername, { count: 1, windowStart: nowTs });
  }

  resetCooldownRef.current.set(senderUsername, nowTs);

  const messageRetryCount = (encryptedMessage as any).__retryCount || 0;
  const env = (encryptedMessage as any)?.encryptedPayload;
  const dedupId: string = typeof env?.kemCiphertext === 'string' ? env.kemCiphertext : ((encryptedMessage as any)?.messageId || '');
  const ledgerKey = `${senderUsername}|${dedupId || crypto.randomUUID()}`;

  const entry = attemptsLedgerRef.current.get(ledgerKey) || { attempts: 0, lastTriedKyberFp: null as string | null, nextAt: 0 };
  if (nowTs < entry.nextAt) {
    return false;
  }
  if (entry.attempts >= MAX_RETRY_ATTEMPTS) {
    return false;
  }

  const currentFp = lastKyberFpRef.current.get(senderUsername) || null;
  entry.attempts += 1;
  entry.lastTriedKyberFp = currentFp;
  entry.nextAt = nowTs + computeBackoffMs(entry.attempts - 1);
  attemptsLedgerRef.current.set(ledgerKey, entry);

  const pendingQueue = pendingRetryMessagesRef.current.get(senderUsername) || [];
  const messageWithRetryCount = { ...encryptedMessage, __retryCount: messageRetryCount + 1 };
  const idSet = pendingRetryIdsRef.current.get(senderUsername) || new Set<string>();
  if (!dedupId || !idSet.has(dedupId)) {
    if (pendingQueue.length >= PENDING_QUEUE_MAX_PER_PEER) {
      pendingQueue.shift();
    }
    pendingQueue.push({ message: messageWithRetryCount, timestamp: nowTs, retryCount: messageRetryCount + 1 });
    pendingRetryMessagesRef.current.set(senderUsername, pendingQueue);
    if (dedupId) {
      idSet.add(dedupId);
      pendingRetryIdsRef.current.set(senderUsername, idSet);
    }
  }

  // Request a fresh bundle non destructively
  const lastBundle = bundleRequestCooldownRef.current.get(senderUsername) || 0;
  if (nowTs - lastBundle >= BUNDLE_REQUEST_COOLDOWN_MS) {
    bundleRequestCooldownRef.current.set(senderUsername, nowTs);
    try {
      await requestBundleOnce(
        senderUsername,
        EventType.SESSION_KEY_REFRESH,
        { forceRefreshDiscovery: options?.forceRefreshDiscovery }
      );
    } catch (bundleReqError) {
      console.error('[EncryptedMessageHandler] Failed to request bundle for session recovery');
    }
  }

  return true;
};

// Retry pending messages for a peer
export const retryPendingMessages = (
  peer: string,
  pendingRetryMessagesRef: React.RefObject<Map<string, PendingRetryEntry[]>>,
  pendingRetryIdsRef: React.RefObject<Map<string, Set<string>>>,
  callbackRef: React.RefObject<((msg: any) => Promise<void>) | null>
): void => {
  const pending = pendingRetryMessagesRef.current.get(peer);
  if (pending && pending.length > 0) {
    pendingRetryMessagesRef.current.delete(peer);
    pendingRetryIdsRef.current.delete(peer);
    pending.forEach(({ message }) => {
      setTimeout(() => {
        if (callbackRef.current) {
          callbackRef.current(message).catch(() => { });
        }
      }, 150);
    });
  }
};

// Replenish PQ Kyber prekey
export const replenishPqKyberPrekey = async (
  isAuthenticated: boolean | undefined,
  loginUsernameRef: React.RefObject<string>,
  lastPqKeyReplenishRef: React.RefObject<number>,
  replenishmentInProgressRef: React.RefObject<boolean>,
  pqKeyReplenishCooldownMs: number,
  options?: { force?: boolean }
): Promise<void> => {
  const now = Date.now();
  const lastReplenish = lastPqKeyReplenishRef.current;
  const force = options?.force === true;

  if (replenishmentInProgressRef.current) return;
  if (!force && now - lastReplenish < pqKeyReplenishCooldownMs) return;
  if (!isAuthenticated || !loginUsernameRef.current) return;
  if (!websocketClient.isConnectedToServer()) return;

  const warnNotReady = (message: string) => {
    const nowWarn = Date.now();
    if (nowWarn - lastReplenishNotReadyWarnAt >= REPLENISH_NOT_READY_WARN_COOLDOWN_MS) {
      lastReplenishNotReadyWarnAt = nowWarn;
      console.warn(message);
    }
  };

  replenishmentInProgressRef.current = true;

  try {
    const isUnlinkedMode = typeof websocketClient.isUnlinkedMode === 'function' && websocketClient.isUnlinkedMode();
    if (!isUnlinkedMode) {
      warnNotReady('[EncryptedMessageHandler] Skipping replenishment bundle publish - waiting for unlinked mode');
      return;
    }

    const resolveLocalInboxId = (): string | undefined => {
      const username = loginUsernameRef.current || undefined;
      const tryGet = (targetUsername?: string): string | undefined => {
        try {
          const client = targetUsername ? getBlindRoutingClient(targetUsername) : getBlindRoutingClient();
          return client.getMyInboxId() || undefined;
        } catch {
          return undefined;
        }
      };

      // Prefer username scoped client lookup then fall back to singleton access
      return tryGet(username) || tryGet();
    };


    const unlinkedReady = typeof websocketClient.isUnlinkedSessionReady === 'function'
      ? websocketClient.isUnlinkedSessionReady()
      : false;
    if (!unlinkedReady) {
      warnNotReady('[EncryptedMessageHandler] Skipping replenishment bundle publish - unlinked session not ready');
      return;
    }

    const inboxId = resolveLocalInboxId();
    if (!inboxId) {
      const nowWarn = Date.now();
      if (nowWarn - lastReplenishMissingInboxWarnAt >= REPLENISH_MISSING_INBOX_WARN_COOLDOWN_MS) {
        lastReplenishMissingInboxWarnAt = nowWarn;
        const mode = isUnlinkedMode ? 'unlinked' : 'linked';
        console.warn(`[EncryptedMessageHandler] Skipping replenishment bundle publish - inbox claim not ready (${mode})`);
      }
      return;
    }

    lastPqKeyReplenishRef.current = now;

    // Refill the local one-time prekey store for forward secrecy. The refreshed bundle reaches peers
    // via the discovery blob (republished on its own schedule), not a server-side bundle table.
    try {
      await signal.generatePreKeys(loginUsernameRef.current, 1, 50);
    } catch { }
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Error during PQ key replenishment:', _error);
  } finally {
    replenishmentInProgressRef.current = false;
  }
};
