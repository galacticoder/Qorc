import React, { useEffect } from 'react';
import { Message } from '../components/chat/messaging/types';
import { isPlainObject, hasPrototypePollutionKeys, sanitizeNonEmptyText, isUnsafeObjectKey } from '../lib/sanitizers';
import { sanitizeHybridKeys } from '../lib/utils/messaging-validators';
import { SecurityAuditLogger } from '../lib/cryptography/audit-logger';
import { secureMessageQueue } from '../lib/database/secure-message-queue';
import { blockingSystem } from '../lib/blocking/blocking-system';
import { EventType } from '../lib/types/event-types';
import {
  MAX_LOCAL_USERNAME_LENGTH,
  MAX_INLINE_BASE64_BYTES,
  BASE64_STANDARD_REGEX
} from '../lib/constants';
import type { User } from '../components/chat/messaging/UserList';
import { SignalType } from '../lib/types/signal-types';
import { quicTransport } from '../lib/transport/quic-transport';

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
        if (!allowEvent(EventType.USER_KEYS_AVAILABLE)) return;
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
        const inboxId = (detail as any).inboxId;
        if (!isPlainObject(hybridKeysRaw) || hasPrototypePollutionKeys(hybridKeysRaw)) return;

        const maybeKyber = (hybridKeysRaw as any).kyberPublicBase64;
        const maybeDilithium = (hybridKeysRaw as any).dilithiumPublicBase64;
        const maybeX25519 = (hybridKeysRaw as any).x25519PublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) ||
          (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) return;
        if (typeof maybeX25519 === 'string' && maybeX25519.length > 1_000) return;

        const hybridKeys = sanitizeHybridKeys(hybridKeysRaw as any) as any;
        if (!hybridKeys?.kyberPublicBase64 || !hybridKeys?.dilithiumPublicBase64) return;
        if (inboxId && typeof inboxId === 'string') {
          try { quicTransport.registerUsernameAlias(username, inboxId); } catch { }
        }

        let targetUser = users.find(user => user.username === username);
        if (!targetUser) {
          targetUser = { id: crypto.randomUUID(), username, isOnline: true, hybridPublicKeys: hybridKeys, inboxId };
          setUsers(prev => [...prev, targetUser!]);
        } else if (!targetUser.hybridPublicKeys || targetUser.inboxId !== inboxId) {
          setUsers(prev => prev.map(user =>
            user.username === username ? { ...user, hybridPublicKeys: hybridKeys, isOnline: true, inboxId } : user
          ));
          targetUser = { ...targetUser, hybridPublicKeys: hybridKeys, isOnline: true, inboxId };
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
            SecurityAuditLogger.log(SignalType.ERROR, 'queued-message-send-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
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

  // Handle block list response
  useEffect(() => {
    const onBlockListResponse = async (e: Event) => {
      try {
        if (!allowEvent(EventType.BLOCK_LIST_RESPONSE)) return;
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
        if (!BASE64_STANDARD_REGEX.test(encryptedData)) return;

        const pad = encryptedData.endsWith('==') ? 2 : encryptedData.endsWith('=') ? 1 : 0;
        const estimatedBytes = Math.floor((encryptedData.length * 3) / 4) - pad;
        if (estimatedBytes <= 0 || estimatedBytes > MAX_INLINE_BASE64_BYTES) return;

        const salt = saltRaw.trim();
        if (!salt || salt.length > 256) return;
        if (!BASE64_STANDARD_REGEX.test(salt)) return;

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

  // Handle clear conversation messages
  useEffect(() => {
    const lastHandled = new Map<string, number>();

    const handleClearConversationMessages = (event: CustomEvent) => {
      try {
        if (!allowEvent(EventType.CLEAR_CONVERSATION_MESSAGES)) return;
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
