import React, { useEffect } from 'react';
import { Message } from '../components/chat/messaging/types';
import { isPlainObject, hasPrototypePollutionKeys, sanitizeNonEmptyText, isUnsafeObjectKey } from '../lib/sanitizers';
import { sanitizeHybridKeys } from '../lib/utils/messaging-validators';
import { areHybridPublicKeysEquivalent } from '../lib/utils/peer-certificate-utils';
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
import { p2pTransport } from '../lib/transport/p2p-transport';
import { isRendezvousRouteId } from '../lib/transport/rendezvous-routing';

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
        const routeId = isRendezvousRouteId((detail as any).routeId) ? (detail as any).routeId : undefined;
        const mailboxLookupId = isRendezvousRouteId((detail as any).mailboxLookupId) ? (detail as any).mailboxLookupId : undefined;
        const bundleLookupId = isRendezvousRouteId((detail as any).bundleLookupId) ? (detail as any).bundleLookupId : undefined;
        if (!isPlainObject(hybridKeysRaw) || hasPrototypePollutionKeys(hybridKeysRaw)) return;

        const maybeKyber = (hybridKeysRaw as any).kyberPublicBase64;
        const maybeDilithium = (hybridKeysRaw as any).dilithiumPublicBase64;
        const maybeX25519 = (hybridKeysRaw as any).x25519PublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) ||
          (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) return;
        if (typeof maybeX25519 === 'string' && maybeX25519.length > 1_000) return;

        const hybridKeys = sanitizeHybridKeys(hybridKeysRaw as any) as any;
        if (!hybridKeys?.kyberPublicBase64 || !hybridKeys?.dilithiumPublicBase64) return;
        const incomingPeerCertificateFingerprint = typeof (detail as any).peerCertificateFingerprint === 'string'
          ? (detail as any).peerCertificateFingerprint.trim().toLowerCase()
          : '';
        const incomingIdentityRootFingerprint = typeof (detail as any).identityRootFingerprint === 'string'
          ? (detail as any).identityRootFingerprint.trim().toLowerCase()
          : '';
        const incomingIdentityBundleFingerprint = typeof (detail as any).identityBundleFingerprint === 'string'
          ? (detail as any).identityBundleFingerprint.trim().toLowerCase()
          : '';
        if (!incomingPeerCertificateFingerprint || !incomingIdentityRootFingerprint) return;
        if (!/^[a-f0-9]{64}$/i.test(incomingPeerCertificateFingerprint)) return;
        if (!/^[a-f0-9]{64}$/i.test(incomingIdentityRootFingerprint)) return;
        if (incomingIdentityBundleFingerprint && !/^[a-f0-9]{64}$/i.test(incomingIdentityBundleFingerprint)) return;
        const incomingPeerCertificatePinnedAt = Number.isFinite((detail as any).peerCertificatePinnedAt)
          ? Math.trunc((detail as any).peerCertificatePinnedAt)
          : now;
        if (inboxId && typeof inboxId === 'string') {
          try { p2pTransport.registerUsernameAlias(username, inboxId); } catch { }
        }

        let targetUser = users.find(user => user.username === username);
        const nextHybridKeys = { ...hybridKeys, inboxId, routeId, mailboxLookupId, bundleLookupId };
        const existingPeerCertificateFingerprint = targetUser?.peerCertificateFingerprint?.trim().toLowerCase() || '';
        const existingIdentityRootFingerprint = targetUser?.identityRootFingerprint?.trim().toLowerCase() || '';
        const hasPinnedPeerCertificate = existingPeerCertificateFingerprint.length > 0;
        const incomingFingerprintMismatch = !!(
          hasPinnedPeerCertificate &&
          incomingPeerCertificateFingerprint &&
          incomingPeerCertificateFingerprint !== existingPeerCertificateFingerprint
        );
        const incomingIdentityRootMismatch = !!(
          existingIdentityRootFingerprint &&
          incomingIdentityRootFingerprint &&
          incomingIdentityRootFingerprint !== existingIdentityRootFingerprint
        );
        const unpinnedMutationAgainstPinnedPeer = !!(
          hasPinnedPeerCertificate &&
          !incomingPeerCertificateFingerprint &&
          targetUser &&
          !areHybridPublicKeysEquivalent(
            {
              ...targetUser.hybridPublicKeys,
              inboxId: targetUser.inboxId || targetUser.hybridPublicKeys?.inboxId,
              routeId: targetUser.routeId || targetUser.hybridPublicKeys?.routeId,
              mailboxLookupId: targetUser.mailboxLookupId || targetUser.hybridPublicKeys?.mailboxLookupId
            },
            nextHybridKeys
          )
        );

        if (incomingFingerprintMismatch || incomingIdentityRootMismatch || unpinnedMutationAgainstPinnedPeer) {
          console.warn('[UserKeys] Rejected key update that conflicts with pinned peer certificate', {
            hasPinnedPeerCertificate,
            incomingFingerprintPresent: !!incomingPeerCertificateFingerprint,
            incomingIdentityRootPresent: !!incomingIdentityRootFingerprint
          });
          return;
        }

        if (!targetUser) {
          targetUser = {
            id: crypto.randomUUID(),
            username,
            isOnline: true,
            hybridPublicKeys: nextHybridKeys,
            inboxId,
            routeId,
            mailboxLookupId,
            bundleLookupId,
            peerCertificateFingerprint: incomingPeerCertificateFingerprint || undefined,
            peerCertificatePinnedAt: incomingPeerCertificateFingerprint ? incomingPeerCertificatePinnedAt : undefined,
            identityRootFingerprint: incomingIdentityRootFingerprint || undefined,
            identityBundleFingerprint: incomingIdentityBundleFingerprint || undefined
          };
          setUsers(prev => [...prev, targetUser!]);
        } else if (
          !targetUser.hybridPublicKeys ||
          targetUser.inboxId !== inboxId ||
          !areHybridPublicKeysEquivalent(
            {
              ...targetUser.hybridPublicKeys,
              inboxId: targetUser.inboxId || targetUser.hybridPublicKeys?.inboxId,
              routeId: targetUser.routeId || targetUser.hybridPublicKeys?.routeId,
              mailboxLookupId: targetUser.mailboxLookupId || targetUser.hybridPublicKeys?.mailboxLookupId
            },
            nextHybridKeys
          ) ||
          (!existingPeerCertificateFingerprint && !!incomingPeerCertificateFingerprint)
        ) {
          setUsers(prev => prev.map(user =>
            user.username === username ? {
              ...user,
              hybridPublicKeys: nextHybridKeys,
              isOnline: true,
              inboxId,
              routeId,
              mailboxLookupId,
              bundleLookupId,
              peerCertificateFingerprint: user.peerCertificateFingerprint || incomingPeerCertificateFingerprint || undefined,
              peerCertificatePinnedAt: user.peerCertificatePinnedAt || (incomingPeerCertificateFingerprint ? incomingPeerCertificatePinnedAt : undefined),
              identityRootFingerprint: user.identityRootFingerprint || incomingIdentityRootFingerprint || undefined,
              identityBundleFingerprint: incomingIdentityBundleFingerprint || user.identityBundleFingerprint || undefined
            } : user
          ));
          targetUser = {
            ...targetUser,
            hybridPublicKeys: nextHybridKeys,
            isOnline: true,
            inboxId,
            routeId,
            mailboxLookupId,
            bundleLookupId,
            peerCertificateFingerprint: targetUser.peerCertificateFingerprint || incomingPeerCertificateFingerprint || undefined,
            peerCertificatePinnedAt: targetUser.peerCertificatePinnedAt || (incomingPeerCertificateFingerprint ? incomingPeerCertificatePinnedAt : undefined),
            identityRootFingerprint: targetUser.identityRootFingerprint || incomingIdentityRootFingerprint || undefined,
            identityBundleFingerprint: incomingIdentityBundleFingerprint || targetUser.identityBundleFingerprint || undefined
          };
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
