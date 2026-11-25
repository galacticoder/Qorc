import {
  MAX_HELD_BYTES,
  MAX_HELD_GLOBAL,
  MAX_HELD_MESSAGE_BYTES,
  MAX_HELD_PER_PEER,
  MAX_PENDING_PEERS,
  IDENTITY_CHANGE_STORE_PEER_LENGTH_LIMIT,
  IDENTITY_CHANGE_STORE_NEW_KEY_LENGTH_LIMIT,
  IDENTITY_CHANGE_STORE_STABLE_DEDUP_KEY_LENGTH_MINIMUM,
  IDENTITY_CHANGE_STORE_ENCRYPTED_MESSAGE_MESSAGE_ID_LENGTH_MINIMUM,
  IDENTITY_CHANGE_STORE_DISPLAY_DEDUP_KEY_LENGTH_MINIMUM,
} from '../constants';
import { useEffect, useState } from 'react';

export interface HeldMessage {
  encryptedMessage: any;
}

export interface PendingIdentityChange {
  peer: string;
  newKey: string;
  heldCount: number;
}

interface Entry extends PendingIdentityChange {
  held: Array<HeldMessage & {
    estimatedBytes: number;
    dedupKey: string | null;
    displayDedupKey: string | null;
  }>;
}

const pending = new Map<string, Entry>();
const listeners = new Set<() => void>();
let heldGlobal = 0;
let heldBytes = 0;

function estimateHeldBytes(value: unknown): number | null {
  try {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== 'string') return null;
    return serialized.length * 2;
  } catch {
    return null;
  }
}

function releaseHeld(messages: Entry['held']): void {
  for (const message of messages) {
    heldGlobal = Math.max(0, heldGlobal - 1);
    heldBytes = Math.max(0, heldBytes - message.estimatedBytes);
  }
}

function updateHeldCount(entry: Entry): void {
  entry.heldCount = new Set(
    entry.held
      .map(message => message.displayDedupKey)
      .filter((key): key is string => key !== null),
  ).size;
}

function emit() {
  for (const listener of listeners) listener();
}

function snapshot(): PendingIdentityChange[] {
  return Array.from(pending.values()).map(({ peer, newKey, heldCount }) => ({
    peer,
    newKey,
    heldCount,
  }));
}

export const identityChangeStore = {
  add(peer: string, newKey: string): boolean {
    if (!peer || peer.length > IDENTITY_CHANGE_STORE_PEER_LENGTH_LIMIT) return false;
    if (!newKey || newKey.length > IDENTITY_CHANGE_STORE_NEW_KEY_LENGTH_LIMIT) return false;
    const existing = pending.get(peer);
    if (existing) {
      return existing.newKey === newKey;
    }
    if (pending.size >= MAX_PENDING_PEERS) return false;
    pending.set(peer, { peer, newKey, held: [], heldCount: 0 });
    emit();
    return true;
  },
  
  hold(
    peer: string,
    encryptedMessage: any,
    stableDedupKey?: string | null,
    displayDedupKey?: string | null,
  ): boolean {
    const entry = pending.get(peer);
    if (!entry || entry.held.length >= MAX_HELD_PER_PEER || heldGlobal >= MAX_HELD_GLOBAL) return false;
    const suppliedKey = typeof stableDedupKey === 'string' && stableDedupKey.length <= IDENTITY_CHANGE_STORE_STABLE_DEDUP_KEY_LENGTH_MINIMUM
      ? stableDedupKey
      : null;
    const visibleMessageId = typeof encryptedMessage?.messageId === 'string' && encryptedMessage.messageId.length <= IDENTITY_CHANGE_STORE_ENCRYPTED_MESSAGE_MESSAGE_ID_LENGTH_MINIMUM
      ? encryptedMessage.messageId
      : null;
    const dedupKey = suppliedKey || visibleMessageId;
    if (dedupKey && entry.held.some(held => held.dedupKey === dedupKey)) return true;
    const suppliedDisplayKey = typeof displayDedupKey === 'string' && displayDedupKey.length <= IDENTITY_CHANGE_STORE_DISPLAY_DEDUP_KEY_LENGTH_MINIMUM
      ? displayDedupKey
      : null;
    const resolvedDisplayKey = displayDedupKey === undefined
      ? dedupKey
      : suppliedDisplayKey;
    const estimatedBytes = estimateHeldBytes(encryptedMessage);
    if (
      estimatedBytes === null ||
      estimatedBytes > MAX_HELD_MESSAGE_BYTES ||
      heldBytes + estimatedBytes > MAX_HELD_BYTES
    ) return false;
    entry.held.push({
      encryptedMessage,
      estimatedBytes,
      dedupKey,
      displayDedupKey: resolvedDisplayKey,
    });
    heldGlobal += 1;
    heldBytes += estimatedBytes;
    updateHeldCount(entry);
    emit();
    return true;
  },

  peekHeld(peer: string): HeldMessage | null {
    const entry = pending.get(peer);
    const first = entry?.held[0];
    return first ? { encryptedMessage: first.encryptedMessage } : null;
  },

  // Take and clear held messages for peer after verify
  takeHeld(peer: string): HeldMessage[] {
    const entry = pending.get(peer);
    if (!entry) return [];
    const held = entry.held;
    releaseHeld(held);
    entry.held = [];
    entry.heldCount = 0;
    return held.map(({ encryptedMessage }) => ({ encryptedMessage }));
  },
  matches(peer: string, expectedNewKey: string): boolean {
    const entry = pending.get(peer);
    return !!entry && entry.newKey === expectedNewKey;
  },
  removeIfMatches(peer: string, expectedNewKey: string): boolean {
    const entry = pending.get(peer);
    if (!entry || entry.newKey !== expectedNewKey) return false;
    releaseHeld(entry.held);
    pending.delete(peer);
    emit();
    return true;
  },
  clear(): void {
    if (pending.size === 0) return;
    for (const entry of pending.values()) releaseHeld(entry.held);
    pending.clear();
    emit();
  },
  has(peer: string): boolean {
    return pending.has(peer);
  },
  list(): PendingIdentityChange[] {
    return snapshot();
  },
  subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  },
};

// Subscribe to live list of unresolved identity changes
export function usePendingIdentityChanges(): PendingIdentityChange[] {
  const [list, setList] = useState<PendingIdentityChange[]>(() => identityChangeStore.list());
  useEffect(() => identityChangeStore.subscribe(() => setList(identityChangeStore.list())), []);
  return list;
}

export function useHasPendingIdentityChange(peer?: string | null): boolean {
  const list = usePendingIdentityChanges();
  return !!peer && list.some(entry => entry.peer === peer);
}
