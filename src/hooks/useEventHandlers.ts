import React, { useEffect } from 'react';
import { isCanonicalAuthUsername, isPlainObject, hasPrototypePollutionKeys } from '../lib/sanitizers';
import { sanitizeHybridKeys } from '../lib/utils/messaging-validators';
import { EventType } from '../lib/types/event-types';
import type { User } from '../components/chat/messaging/UserList';
import {
  isKeyTransparencyAuthorizedPeerKeySet,
  isKeyTransparencyPeerRevoked,
} from '../lib/key-transparency/verified-material';
import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  isKeyTransparencyHash,
} from '../../shared/key-transparency-protocol.js';

interface UseEventHandlersProps {
  allowEvent: (eventType: string) => boolean;
  setUsers: React.Dispatch<React.SetStateAction<User[]>>;
  currentUsername: string;
}

export function useEventHandlers({
  allowEvent,
  setUsers,
  currentUsername,
}: UseEventHandlersProps) {
  // Handle user keys becoming available
  useEffect(() => {
    const processedKeysAvailableRef = new Map<string, number>();

    const handleUserKeysAvailable = async (event: CustomEvent) => {
      try {
        if (!allowEvent(EventType.USER_KEYS_AVAILABLE)) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        const detailKeys = Object.keys(detail).sort().join(',');
        if (detailKeys !== [
          'account',
          'hybridKeys',
          'identityBundleFingerprint',
          'identityRootFingerprint',
          'peerCertificateFingerprint',
          'username',
        ].sort().join(',')) return;
        if ((detail as any).account !== currentUsername || !currentUsername) return;

        const username = (detail as any).username;
        if (!isCanonicalAuthUsername(username)) return;

        const now = Date.now();

        const hybridKeysRaw = (detail as any).hybridKeys;
        if (!isPlainObject(hybridKeysRaw) || hasPrototypePollutionKeys(hybridKeysRaw)) return;

        const maybeKyber = (hybridKeysRaw as any).kyberPublicBase64;
        const maybeDilithium = (hybridKeysRaw as any).dilithiumPublicBase64;
        const maybeX25519 = (hybridKeysRaw as any).x25519PublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) ||
          (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) return;
        if (typeof maybeX25519 === 'string' && maybeX25519.length > 1_000) return;

        const hybridKeys = sanitizeHybridKeys(hybridKeysRaw as any) as any;
        if (
          !hybridKeys?.kyberPublicBase64 ||
          !hybridKeys?.dilithiumPublicBase64 ||
          !hybridKeys?.x25519PublicBase64
        ) return;
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
        if (!/^[a-f0-9]{64}$/i.test(incomingIdentityBundleFingerprint)) return;
        if (!isKeyTransparencyAuthorizedPeerKeySet({
          account: currentUsername,
          peer: username,
          kyberPublicBase64: hybridKeys.kyberPublicBase64,
          dilithiumPublicBase64: hybridKeys.dilithiumPublicBase64,
          x25519PublicBase64: hybridKeys.x25519PublicBase64,
          peerCertificateFingerprint: incomingPeerCertificateFingerprint,
          identityRootFingerprint: incomingIdentityRootFingerprint,
          identityBundleFingerprint: incomingIdentityBundleFingerprint,
        })) return;

        const eventId = `${username}\0${incomingPeerCertificateFingerprint}\0${incomingIdentityRootFingerprint}\0${incomingIdentityBundleFingerprint}`;
        const last = processedKeysAvailableRef.get(eventId) || 0;
        if (now - last < 2000) return;
        processedKeysAvailableRef.delete(eventId);
        processedKeysAvailableRef.set(eventId, now);
        while (processedKeysAvailableRef.size > 512) {
          const oldest = processedKeysAvailableRef.keys().next().value as string | undefined;
          if (!oldest) break;
          processedKeysAvailableRef.delete(oldest);
        }

        setUsers(prev => {
          const index = prev.findIndex(user => user.username === username);
          const nextUser: User = {
            ...(index >= 0 ? prev[index] : { id: crypto.randomUUID(), username }),
            hybridPublicKeys: { ...hybridKeys },
            peerCertificateFingerprint: incomingPeerCertificateFingerprint,
            peerCertificateVerifiedAt: now,
            identityRootFingerprint: incomingIdentityRootFingerprint,
            identityBundleFingerprint: incomingIdentityBundleFingerprint,
          };
          if (index < 0) return [...prev, nextUser];
          const next = [...prev];
          next[index] = nextUser;
          return next;
        });
      } catch { }
    };

    window.addEventListener(EventType.USER_KEYS_AVAILABLE, handleUserKeysAvailable as EventListener);
    return () => window.removeEventListener(EventType.USER_KEYS_AVAILABLE, handleUserKeysAvailable as EventListener);
  }, [allowEvent, currentUsername, setUsers]);

  useEffect(() => {
    const handleTransparencyRootChanged = (event: Event) => {
      try {
        if (!allowEvent(EventType.KEY_TRANSPARENCY_ROOT_CHANGED)) return;
        if (!(event instanceof CustomEvent)) return;
        const detail = event.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        if (Object.keys(detail).sort().join(',') !== 'account,peer,rootCommitment,version') return;
        const { account, peer, rootCommitment, version } = detail as Record<string, unknown>;
        if (account !== currentUsername || !currentUsername) return;
        if (!isCanonicalAuthUsername(peer) || peer === currentUsername) return;
        if (!isKeyTransparencyHash(rootCommitment)) return;
        if (
          !Number.isSafeInteger(version) ||
          (version as number) < 1 ||
          (version as number) > KEY_TRANSPARENCY_MAX_LOG_SIZE
        ) return;
        if (!isKeyTransparencyPeerRevoked(currentUsername, peer)) return;

        setUsers((previous) => previous.map((user) => user.username === peer ? {
          ...user,
          hybridPublicKeys: undefined,
          peerCertificateFingerprint: undefined,
          peerCertificateVerifiedAt: undefined,
          identityRootFingerprint: undefined,
          identityBundleFingerprint: undefined,
        } : user));
      } catch { }
    };

    window.addEventListener(
      EventType.KEY_TRANSPARENCY_ROOT_CHANGED,
      handleTransparencyRootChanged as EventListener,
    );
    return () => window.removeEventListener(
      EventType.KEY_TRANSPARENCY_ROOT_CHANGED,
      handleTransparencyRootChanged as EventListener,
    );
  }, [allowEvent, currentUsername, setUsers]);

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
