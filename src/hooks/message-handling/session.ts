import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import websocketClient from '../../lib/websocket/websocket';
import type { PendingRetryEntry, AttemptsLedgerEntry, ResetCounterEntry } from '../../lib/types/message-handling-types';
import { computeBackoffMs } from '../../lib/utils/message-handler-utils';
import { BUNDLE_REQUEST_COOLDOWN_MS, MAX_RETRY_ATTEMPTS, PENDING_QUEUE_MAX_PER_PEER } from '../../lib/constants';
import { signal } from '../../lib/tauri-bindings';

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
  requestBundleOnce: (peer: string, reason?: string) => Promise<void>,
  maxResetsPerPeer: number,
  resetWindowMs: number
): Promise<boolean> => {
  const nowTs = Date.now();
  const _lastReset = resetCooldownRef.current.get(senderUsername) || 0;

  if (nowTs - _lastReset < 3000) {
    return false;
  }

  const counterEntry = resetCounterRef.current.get(senderUsername);
  if (counterEntry) {
    if (nowTs - counterEntry.windowStart > resetWindowMs) {
      resetCounterRef.current.set(senderUsername, { count: 1, windowStart: nowTs });
    } else if (counterEntry.count >= maxResetsPerPeer) {
      console.warn(`[EncryptedMessageHandler] Max session resets (${maxResetsPerPeer}) reached for ${senderUsername}, waiting for window to expire`);
      return false;
    } else {
      counterEntry.count += 1;
    }
  } else {
    resetCounterRef.current.set(senderUsername, { count: 1, windowStart: nowTs });
  }

  resetCooldownRef.current.set(senderUsername, nowTs);

  try {
    await signal.deleteSession(currentUser, senderUsername, 1);

    try {
      await websocketClient.sendSecureControlMessage({
        type: SignalType.SESSION_RESET_REQUEST,
        from: currentUser,
        targetUsername: senderUsername,
        deviceId: 1,
        timestamp: Date.now(),
        reason: 'decryption-failure'
      });

      try {
        window.dispatchEvent(new CustomEvent(EventType.P2P_SESSION_RESET_SEND, {
          detail: { to: senderUsername, reason: 'decryption-failure' }
        }));

        window.dispatchEvent(new CustomEvent(EventType.LOCAL_INITIATED_RESET, {
          detail: { peerUsername: senderUsername, reason: 'decryption-failure' }
        }));
      } catch { }

      window.dispatchEvent(new CustomEvent(EventType.SESSION_RESET_RECEIVED, {
        detail: { peerUsername: senderUsername, reason: EventType.LOCAL_INITIATED_RESET }
      }));
    } catch (notifyErr) {
      console.error('[EncryptedMessageHandler] Failed to send session reset notification:', notifyErr);
    }
  } catch {
    console.error('[EncryptedMessageHandler] Failed to delete stale session');
  }

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

  const lastBundle = bundleRequestCooldownRef.current.get(senderUsername) || 0;
  if (nowTs - lastBundle >= BUNDLE_REQUEST_COOLDOWN_MS) {
    bundleRequestCooldownRef.current.set(senderUsername, nowTs);
    try {
      await requestBundleOnce(senderUsername, EventType.SESSION_KEY_REFRESH);
    } catch (bundleReqError) {
      console.error('[EncryptedMessageHandler] Failed to request bundle for session recovery:', bundleReqError);
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

  replenishmentInProgressRef.current = true;

  try {
    lastPqKeyReplenishRef.current = now;

    try {
      await signal.generatePreKeys(loginUsernameRef.current, 1, 50);
    } catch { }

    const bundle = await signal.createPreKeyBundle(loginUsernameRef.current);

    if (!bundle || !bundle.registrationId || !bundle.identityKeyBase64 || !bundle.signedPreKey || !bundle.kyberPreKey?.keyId) {
      console.error('[EncryptedMessageHandler] Invalid bundle structure during PQ key replenishment');
      return;
    }

    try {
      await websocketClient.sendSecureControlMessage({
        type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE,
        bundle,
        isReplenishment: true
      });
    } catch (sendErr) {
      console.error('[EncryptedMessageHandler] Failed to publish replenishment bundle:', sendErr);
      return;
    }
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Error during PQ key replenishment:', _error);
  } finally {
    replenishmentInProgressRef.current = false;
  }
};
