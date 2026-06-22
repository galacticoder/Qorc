/**
 * User Signal Handlers
 */

import { EventType } from '../types/event-types';

export function handlePirManifest(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.PIR_MANIFEST, { detail: data }));
  } catch (_error) {
    console.error('[signals] pir-manifest dispatch-failed', (_error as Error).message);
  }
}

export function handlePirResponse(data: any): void {
  try {
    window.dispatchEvent(new CustomEvent(EventType.PIR_RESPONSE, { detail: data }));
  } catch (_error) {
    console.error('[signals] pir-response dispatch-failed', (_error as Error).message);
  }
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
