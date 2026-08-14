import type { Message } from '../../components/chat/messaging/types';
import {
  MAX_UI_MESSAGES_PER_CONVERSATION,
  MAX_UI_MESSAGES_TOTAL,
} from '../constants';

export const setBoundedMapEntry = <K, V>(
  map: Map<K, V>,
  key: K,
  value: V,
  maxEntries: number
): void => {
  map.delete(key);
  while (map.size >= maxEntries) {
    const oldest = map.keys().next();
    if (oldest.done) break;
    map.delete(oldest.value);
  }
  map.set(key, value);
};

export const createBoundedMapSetter = (maxEntries: number) => (
  <K, V>(map: Map<K, V>, key: K, value: V): void => {
    setBoundedMapEntry(map, key, value, maxEntries);
  }
);

const conversationKey = (message: Message): string => {
  const sender = typeof message.sender === 'string' ? message.sender : '';
  const recipient = typeof message.recipient === 'string' ? message.recipient : '';
  if (sender && recipient) {
    return sender < recipient ? `${sender}\0${recipient}` : `${recipient}\0${sender}`;
  }
  return `unscoped\0${sender}\0${recipient}`;
};

export const boundMessageState = (messages: Message[]): Message[] => {
  if (messages.length === 0) return messages;
  const conversationCounts = new Map<string, number>();
  const retained = new Uint8Array(messages.length);
  let retainedCount = 0;

  // Message arrays are kept in chronological/insertion order
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (retainedCount >= MAX_UI_MESSAGES_TOTAL) break;
    const key = conversationKey(messages[index]);
    const count = conversationCounts.get(key) || 0;
    if (count >= MAX_UI_MESSAGES_PER_CONVERSATION) continue;
    conversationCounts.set(key, count + 1);
    retained[index] = 1;
    retainedCount += 1;
  }

  if (retainedCount === messages.length) return messages;
  return messages.filter((_message, index) => retained[index] === 1);
};

export const releaseUnretainedVaultEntries = (
  previous: readonly Message[],
  candidate: readonly Message[],
  retained: readonly Message[],
): void => {
  void previous;
  void candidate;
  void retained;
};
