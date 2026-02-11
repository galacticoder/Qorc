/**
 * User Signal Handlers
 */

import { EventType } from '../types/event-types';

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

// Handle libsignal publish status
export function handleLibsignalPublishStatus(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_PUBLISH_STATUS, { detail: data }));
  } catch (_error) {
    console.error('[signals] libsignal-publish dispatch-failed', (_error as Error).message);
  }
}
