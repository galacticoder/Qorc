/**
 * User Signal Handlers
 */

import { sanitizeHybridKeys } from '../utils/messaging-validators';
import { EventType } from '../types/event-types';
import { profilePictureSystem } from '../avatar/profile-picture-system';
import type { DatabaseRefs } from '../types/signal-handler-types';

const __userExistsDebounce = new Map<string, number>();

// Handle user exists response 
export function handleUserExistsResponse(data: any, db: DatabaseRefs): void {
  try {
    const uname = typeof data?.username === 'string' ? data.username : '';

    if (uname) {
      const now = Date.now();
      const last = __userExistsDebounce.get(uname) || 0;
      if (now - last < 2000) return;
      __userExistsDebounce.set(uname, now);
    }

    setTimeout(() => {
      try {
        window.dispatchEvent(new CustomEvent(EventType.USER_EXISTS_RESPONSE, { detail: data }));
      } catch { }
    }, 0);
  } catch (_error) {
    console.error('[signals] user-exists dispatch-failed', (_error as Error).message);
  }

  // Handle user keys available
  try {
    if (data?.exists && data?.username && data?.hybridPublicKeys) {
      const sanitized = sanitizeHybridKeys(data.hybridPublicKeys);

      if (sanitized) {
        setTimeout(() => {
          try {
            window.dispatchEvent(
              new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                detail: { username: data.username, hybridKeys: sanitized }
              })
            );
          } catch { }
        }, 0);
      }

      if (db.setUsers) {
        setTimeout(() => {
          try {
            db.setUsers!((prev: any[]) => {
              const found = prev.find((u) => u.username === data.username);

              if (!found) {
                return [
                  ...prev,
                  {
                    id: crypto.randomUUID?.() || String(Date.now()),
                    username: data.username,
                    isOnline: true,
                    hybridPublicKeys: sanitized || data.hybridPublicKeys
                  }
                ];
              }

              if (!found.hybridPublicKeys && data.hybridPublicKeys) {
                return prev.map((u) =>
                  u.username === data.username
                    ? { ...u, hybridPublicKeys: sanitized || data.hybridPublicKeys, isOnline: true }
                    : u
                );
              }

              return prev;
            });
          } catch { }
        }, 0);
      }
    }
  } catch { }
}

// Handle offline messages response
export function handleOfflineMessagesResponse(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.OFFLINE_MESSAGES_RESPONSE, { detail: data }));
  } catch (_error) {
    console.error('[signals] offline-messages dispatch-failed', (_error as Error).message);
  }
}

// Handle block tokens update
export function handleBlockTokensUpdate(data: any): void {
  window.dispatchEvent(new CustomEvent(EventType.BLOCK_TOKENS_UPDATED, { detail: data }));
}

// Handle block list sync
export function handleBlockListSync(data: any): void {
  window.dispatchEvent(new CustomEvent(EventType.BLOCK_LIST_SYNCED, { detail: data }));
}

// Handle block list update
export function handleBlockListUpdate(data: any): void {
  window.dispatchEvent(new CustomEvent(EventType.BLOCK_LIST_UPDATE, { detail: data }));
}

// Handle block list response
export function handleBlockListResponse(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.BLOCK_LIST_RESPONSE, { detail: data }));
  } catch (_error) {
    console.error('[signals] block-list-response dispatch-failed', (_error as Error).message);
  }
}

// Handle client generate prekeys
export function handleClientGeneratePrekeys(data: any): void {
  window.dispatchEvent(new CustomEvent(EventType.GENERATE_PREKEYS_REQUEST, { detail: data }));
}

// Handle prekey status
export function handlePrekeyStatus(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_PUBLISH_STATUS, { detail: data }));
  } catch (_error) {
    console.error('[signals] prekey-status dispatch-failed', (_error as Error).message);
  }
}

// Handle libsignal publish status
export function handleLibsignalPublishStatus(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_PUBLISH_STATUS, { detail: data }));
  } catch (_error) {
    console.error('[signals] libsignal-publish dispatch-failed', (_error as Error).message);
  }
}

// Handle avatar fetch response
export function handleAvatarFetchResponse(data: any): void {
  try {
    if (data && typeof data.target === 'string') {
      profilePictureSystem.handleServerAvatarResponse({
        target: data.target,
        envelope: data.envelope,
        found: !!data.found
      }).catch(() => { });
    }
  } catch (error) {
    console.error('[signals] avatar-fetch handler-failed', error instanceof Error ? error.message : 'unknown');
  }
}

// Handle profile picture signal
export function handleProfilePictureSignal(data: any, message: any): void {
  try {
    const from = data?.from || message?.from;
    if (from) {
      profilePictureSystem.handleIncomingMessage(data || message, from).catch(() => { });
    }
  } catch (error) {
    console.error('[signals] profile-picture-signal handler-failed', error instanceof Error ? error.message : 'unknown');
  }
}
