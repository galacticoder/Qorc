import React, { useEffect, useCallback, useRef } from 'react';
import { Message } from '../components/chat/messaging/types';
import { isPlainObject, hasPrototypePollutionKeys, sanitizeNonEmptyText, isUnsafeObjectKey } from '../lib/sanitizers';
import { sanitizeHybridKeys, isValidKyberPublicKeyBase64 } from '../lib/validators';
import { SecurityAuditLogger } from '../lib/post-quantum-crypto';
import { secureMessageQueue } from '../lib/secure-message-queue';
import { blockingSystem } from '../lib/blocking-system';
import { EventType } from '../lib/event-types';
import type { User } from '../components/chat/messaging/UserList';

const LOCAL_EVENT_RATE_LIMIT_WINDOW_MS = 10_000;
const LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS = 120;
const MAX_LOCAL_MESSAGE_ID_LENGTH = 160;
const MAX_LOCAL_USERNAME_LENGTH = 256;
const MAX_LOCAL_EMOJI_LENGTH = 32;
const MAX_INLINE_BASE64_BYTES = 10 * 1024 * 1024;

interface UseEventHandlersProps {
  allowEvent: (eventType: string) => boolean;
  users: User[];
  setUsers: React.Dispatch<React.SetStateAction<User[]>>;
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  messageSender: any;
  Authentication: any;
  Database: any;
}

export function useEventHandlers({
  allowEvent,
  users,
  setUsers,
  setMessages,
  messageSender,
  Authentication,
  Database,
}: UseEventHandlersProps) {
  // Handle user keys becoming available
  useEffect(() => {
    const processedKeysAvailableRef = new Map<string, number>();

    const handleUserKeysAvailable = async (event: CustomEvent) => {
      try {
        if (!allowEvent('user-keys-available')) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeNonEmptyText((detail as any).username, MAX_LOCAL_USERNAME_LENGTH, false);
        if (!username || isUnsafeObjectKey(username)) return;

        if (processedKeysAvailableRef.size > 512) processedKeysAvailableRef.clear();
        const now = Date.now();
        const last = processedKeysAvailableRef.get(username) || 0;
        if (now - last < 2000) return;
        processedKeysAvailableRef.set(username, now);

        const hybridKeysRaw = (detail as any).hybridKeys;
        if (!isPlainObject(hybridKeysRaw) || hasPrototypePollutionKeys(hybridKeysRaw)) return;

        const maybeKyber = (hybridKeysRaw as any).kyberPublicBase64;
        const maybeDilithium = (hybridKeysRaw as any).dilithiumPublicBase64;
        const maybeX25519 = (hybridKeysRaw as any).x25519PublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) || 
            (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) return;
        if (typeof maybeX25519 === 'string' && maybeX25519.length > 1_000) return;

        const hybridKeys = sanitizeHybridKeys(hybridKeysRaw as any) as any;
        if (!hybridKeys?.kyberPublicBase64 || !hybridKeys?.dilithiumPublicBase64) return;

        SecurityAuditLogger.log('info', 'user-keys-available', { hasKeys: true });

        let targetUser = users.find(user => user.username === username);
        if (!targetUser) {
          targetUser = { id: crypto.randomUUID(), username, isOnline: true, hybridPublicKeys: hybridKeys };
          setUsers(prev => [...prev, targetUser!]);
          SecurityAuditLogger.log('info', 'user-added-with-keys', {});
        } else if (!targetUser.hybridPublicKeys) {
          setUsers(prev => prev.map(user =>
            user.username === username ? { ...user, hybridPublicKeys: hybridKeys, isOnline: true } : user
          ));
          targetUser = { ...targetUser, hybridPublicKeys: hybridKeys, isOnline: true };
          SecurityAuditLogger.log('info', 'user-keys-updated', {});
        }

        const queuedMessages = await secureMessageQueue.processQueueForUser(username);
        if (queuedMessages.length === 0) return;

        targetUser = users.find(user => user.username === username) || targetUser;

        const sentIds: string[] = [];
        for (const queuedMsg of queuedMessages) {
          try {
            await messageSender.handleSendMessage(
              targetUser, queuedMsg.content, queuedMsg.replyTo, queuedMsg.fileData,
              queuedMsg.messageSignalType, queuedMsg.originalMessageId, queuedMsg.editMessageId
            );
            sentIds.push(queuedMsg.id);
            await new Promise<void>((r) => setTimeout(r, 0));
          } catch (_error) {
            SecurityAuditLogger.log('error', 'queued-message-send-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
          }
        }

        if (sentIds.length) {
          setMessages(prev => prev.map(msg => (
            sentIds.includes(msg.id) ? { ...msg, pending: false, receipt: { delivered: true, read: false } } : msg
          )));
        }
      } catch { }
    };

    window.addEventListener(EventType.USER_KEYS_AVAILABLE, handleUserKeysAvailable as EventListener);
    return () => window.removeEventListener(EventType.USER_KEYS_AVAILABLE, handleUserKeysAvailable as EventListener);
  }, [users, messageSender, allowEvent]);

  // Handle user-exists-response
  useEffect(() => {
    const lastHandled = new Map<string, number>();

    const handleUserExistsResponse = async (event: Event) => {
      try {
        if (!allowEvent(EventType.USER_EXISTS_RESPONSE)) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeNonEmptyText((detail as any).username, MAX_LOCAL_USERNAME_LENGTH, false);
        if (!username || isUnsafeObjectKey(username)) return;

        if (lastHandled.size > 512) lastHandled.clear();
        const now = Date.now();
        const last = lastHandled.get(username) || 0;
        if (now - last < 2000) return;
        lastHandled.set(username, now);

        await new Promise((r) => setTimeout(r, 0));

        const exists = (detail as any).exists === true;
        const hybridPublicKeys = (detail as any).hybridPublicKeys;

        if (!exists || !hybridPublicKeys) return;
        if (!isPlainObject(hybridPublicKeys) || hasPrototypePollutionKeys(hybridPublicKeys)) return;

        const maybeKyber = (hybridPublicKeys as any).kyberPublicBase64;
        const maybeDilithium = (hybridPublicKeys as any).dilithiumPublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) || 
            (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) return;

        const sanitized = sanitizeHybridKeys(hybridPublicKeys as any);
        if (!sanitized?.kyberPublicBase64 || !sanitized?.dilithiumPublicBase64) return;

        if (sanitized?.kyberPublicBase64 && isValidKyberPublicKeyBase64(sanitized.kyberPublicBase64)) {
          try {
            if (typeof (window as any).edgeApi?.storePQKeys === 'function') {
              await (window as any).edgeApi.storePQKeys({
                username,
                kyberPublicKey: sanitized.kyberPublicBase64,
                dilithiumPublicKey: sanitized.dilithiumPublicBase64,
                x25519PublicKey: sanitized.x25519PublicBase64
              });
            }
          } catch { }
        }

        setTimeout(() => {
          try {
            window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, { detail: { username, hybridKeys: sanitized } }));
          } catch { }
        }, 0);
      } catch { }
    };

    window.addEventListener(EventType.USER_EXISTS_RESPONSE, handleUserExistsResponse as EventListener);
    return () => window.removeEventListener(EventType.USER_EXISTS_RESPONSE, handleUserExistsResponse as EventListener);
  }, [allowEvent]);

  // Handle block list response
  useEffect(() => {
    const onBlockListResponse = async (e: Event) => {
      try {
        if (!allowEvent('block-list-response')) return;
        const detail = (e as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const passphrase = Authentication.passphrasePlaintextRef?.current || '';
        const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
        const key = passphrase ? passphrase : (kyberSecret ? { kyberSecret } : null);
        if (!key || !Database.dbInitialized) return;

        const encryptedDataRaw = typeof (detail as any).encryptedBlockList === 'string' ? (detail as any).encryptedBlockList : null;
        const saltRaw = typeof (detail as any).salt === 'string' ? (detail as any).salt : null;
        if (!encryptedDataRaw || !saltRaw) return;

        const maxChars = Math.ceil((MAX_INLINE_BASE64_BYTES * 4) / 3) + 128;
        const encryptedData = encryptedDataRaw.trim();
        if (!encryptedData || encryptedData.length > maxChars) return;
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encryptedData)) return;

        const pad = encryptedData.endsWith('==') ? 2 : encryptedData.endsWith('=') ? 1 : 0;
        const estimatedBytes = Math.floor((encryptedData.length * 3) / 4) - pad;
        if (estimatedBytes <= 0 || estimatedBytes > MAX_INLINE_BASE64_BYTES) return;

        const salt = saltRaw.trim();
        if (!salt || salt.length > 256) return;
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(salt)) return;

        const lastUpdated = typeof (detail as any).lastUpdated === 'number' && Number.isFinite((detail as any).lastUpdated)
          ? (detail as any).lastUpdated : null;
        const versionRaw = typeof (detail as any).version === 'number' && Number.isFinite((detail as any).version)
          ? (detail as any).version : 3;
        const version = versionRaw >= 3 ? Math.floor(versionRaw) : 3;

        await new Promise((r) => setTimeout(r, 0));
        await blockingSystem.handleServerBlockListData(encryptedData, salt, lastUpdated, version, key as any);
      } catch { }
    };

    window.addEventListener(EventType.BLOCK_LIST_RESPONSE, onBlockListResponse as EventListener);
    return () => window.removeEventListener(EventType.BLOCK_LIST_RESPONSE, onBlockListResponse as EventListener);
  }, [Authentication.passphrasePlaintextRef?.current, allowEvent]);

  // Handle P2P reactions
  useEffect(() => {
    const rateRef = { windowStart: Date.now(), count: 0 };

    const onP2PReaction = (e: Event) => {
      try {
        const now = Date.now();
        if (now - rateRef.windowStart > LOCAL_EVENT_RATE_LIMIT_WINDOW_MS) {
          rateRef.windowStart = now;
          rateRef.count = 0;
        }
        rateRef.count += 1;
        if (rateRef.count > LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS) return;

        const detail = (e as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
        const reaction = sanitizeNonEmptyText(detail.reaction, MAX_LOCAL_EMOJI_LENGTH, false);
        const sender = sanitizeNonEmptyText(detail.sender, MAX_LOCAL_USERNAME_LENGTH, false);
        const action = typeof detail.action === 'string' ? detail.action : '';
        if (!messageId || !reaction || !sender) return;
        if (isUnsafeObjectKey(reaction)) return;
        if (action !== 'add' && action !== 'remove') return;

        setMessages(prev => prev.map(msg => {
          if (msg.id !== messageId) return msg;

          const reactions: Record<string, string[]> = Object.create(null);
          if (msg.reactions && typeof msg.reactions === 'object') {
            for (const [k, v] of Object.entries(msg.reactions as Record<string, unknown>)) {
              if (typeof k !== 'string' || isUnsafeObjectKey(k)) continue;
              if (!Array.isArray(v)) continue;
              const safeUsers: string[] = [];
              const seen = new Set<string>();
              for (const candidate of v as unknown[]) {
                if (safeUsers.length >= 250) break;
                const cleaned = sanitizeNonEmptyText(candidate, MAX_LOCAL_USERNAME_LENGTH, false);
                if (!cleaned || seen.has(cleaned)) continue;
                seen.add(cleaned);
                safeUsers.push(cleaned);
              }
              if (safeUsers.length > 0) reactions[k] = safeUsers;
            }
          }

          for (const key of Object.keys(reactions)) {
            reactions[key] = reactions[key].filter(u => u !== sender);
            if (reactions[key].length === 0) delete reactions[key];
          }

          if (action === 'add') {
            const arr = Array.isArray(reactions[reaction]) ? [...reactions[reaction]] : [];
            if (!arr.includes(sender) && arr.length < 250) arr.push(sender);
            if (arr.length > 0) reactions[reaction] = arr;
          }

          return { ...msg, reactions };
        }));
      } catch { }
    };

    window.addEventListener(EventType.MESSAGE_REACTION, onP2PReaction as EventListener);
    return () => window.removeEventListener(EventType.MESSAGE_REACTION, onP2PReaction as EventListener);
  }, []);

  // Handle clear conversation messages
  useEffect(() => {
    const lastHandled = new Map<string, number>();

    const handleClearConversationMessages = (event: CustomEvent) => {
      try {
        if (!allowEvent('clear-conversation-messages')) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeNonEmptyText((detail as any).username, MAX_LOCAL_USERNAME_LENGTH, false);
        if (!username || isUnsafeObjectKey(username)) return;

        if (lastHandled.size > 512) lastHandled.clear();
        const now = Date.now();
        const last = lastHandled.get(username) || 0;
        if (now - last < 2000) return;
        lastHandled.set(username, now);

        setMessages(prev => prev.filter(msg => !(msg.sender === username || msg.recipient === username)));
      } catch { }
    };

    window.addEventListener(EventType.CLEAR_CONVERSATION_MESSAGES, handleClearConversationMessages as EventListener);
    return () => window.removeEventListener(EventType.CLEAR_CONVERSATION_MESSAGES, handleClearConversationMessages as EventListener);
  }, [allowEvent]);

  // Handle settings events
  useEffect(() => {
    const handleOpenSettings = () => window.dispatchEvent(new CustomEvent(EventType.SETTINGS_OPEN));
    const handleCloseSettings = () => window.dispatchEvent(new CustomEvent(EventType.SETTINGS_CLOSE));

    window.addEventListener(EventType.OPEN_SETTINGS, handleOpenSettings);
    window.addEventListener(EventType.CLOSE_SETTINGS, handleCloseSettings);

    return () => {
      window.removeEventListener(EventType.OPEN_SETTINGS, handleOpenSettings);
      window.removeEventListener(EventType.CLOSE_SETTINGS, handleCloseSettings);
    };
  }, []);
}
