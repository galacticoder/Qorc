import { syncEncryptedStorage } from '../database/encrypted-storage';
import { STORAGE_KEYS } from '../database/storage-keys';
import { hasPrototypePollutionKeys, isCanonicalAuthUsername, isPlainObject } from '../sanitizers';

export interface NotificationMutes {
  messages: boolean;
  calls: boolean;
}

export interface NotificationPreferences {
  doNotDisturb: NotificationMutes;
  conversations: Array<NotificationMutes & { username: string }>;
}

const listeners = new Set<() => void>();

function validMutes(value: unknown): value is NotificationMutes {
  return isPlainObject(value) && typeof value.messages === 'boolean' && typeof value.calls === 'boolean';
}

export function parseNotificationPreferences(raw: string | null): NotificationPreferences {
  if (raw === null) return { doNotDisturb: { messages: false, calls: false }, conversations: [] };
  if (raw.length > 128 * 1024) throw new Error('Notification preferences are too large');
  const value: unknown = JSON.parse(raw);
  if (
    !isPlainObject(value) || hasPrototypePollutionKeys(value) ||
    Object.keys(value).sort().join(',') !== 'conversations,doNotDisturb' ||
    !validMutes(value.doNotDisturb) || Object.keys(value.doNotDisturb).length !== 2 ||
    !Array.isArray(value.conversations)
  ) throw new Error('Invalid notification preferences');
  const usernames = new Set<string>();
  for (const entry of value.conversations) {
    if (
      !validMutes(entry) || Object.keys(entry).sort().join(',') !== 'calls,messages,username' ||
      !('username' in entry) || !isCanonicalAuthUsername(entry.username) || usernames.has(entry.username)
    ) throw new Error('Invalid conversation notification preferences');
    usernames.add(entry.username);
  }
  return value as unknown as NotificationPreferences;
}

export function notificationPreferencesSnapshot(): string | null {
  return syncEncryptedStorage.getItem(STORAGE_KEYS.NOTIFICATION_PREFERENCES);
}

export function readNotificationPreferences(): NotificationPreferences {
  return parseNotificationPreferences(notificationPreferencesSnapshot());
}

export function subscribeNotificationPreferences(listener: () => void): () => void {
  listeners.add(listener);
  const unsubscribe = syncEncryptedStorage.subscribe(listener);
  return () => { listeners.delete(listener); unsubscribe(); };
}

function saveNotificationPreferences(preferences: NotificationPreferences): void {
  const serialized = JSON.stringify(preferences);
  parseNotificationPreferences(serialized);
  syncEncryptedStorage.setItem(STORAGE_KEYS.NOTIFICATION_PREFERENCES, serialized);
  for (const listener of listeners) {
    try { listener(); } catch (error) { console.error('[Notifications] Settings observer failed', error); }
  }
}

export function setDoNotDisturb(type: keyof NotificationMutes, muted: boolean): void {
  const preferences = readNotificationPreferences();
  saveNotificationPreferences({ ...preferences, doNotDisturb: { ...preferences.doNotDisturb, [type]: muted } });
}

export function setConversationNotificationMutes(username: string, mutes: NotificationMutes): void {
  if (!isCanonicalAuthUsername(username)) throw new Error('Invalid conversation username');
  const preferences = readNotificationPreferences();
  const conversations = preferences.conversations.filter(entry => entry.username !== username);
  if (mutes.messages || mutes.calls) conversations.push({ username, ...mutes });
  saveNotificationPreferences({ ...preferences, conversations });
}

export function getNotificationMutes(username: string, preferences = readNotificationPreferences()): NotificationMutes {
  const conversation = preferences.conversations.find(entry => entry.username === username);
  return {
    messages: preferences.doNotDisturb.messages || conversation?.messages === true,
    calls: preferences.doNotDisturb.calls || conversation?.calls === true,
  };
}
