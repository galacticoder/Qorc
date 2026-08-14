import { useRef, useEffect, useLayoutEffect, useCallback, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { SecureDB } from '../../lib/database/secureDB';
import type { Message } from '../../components/chat/messaging/types';
import type { User } from '../../components/chat/messaging/UserList';
import { DB_MAX_PENDING_MESSAGES, DB_SAVE_DEBOUNCE_MS } from '../../lib/constants';
import type { UseSecureDBProps, UseSecureDBReturn } from '../../lib/types/database-types';
import {
  initializeSecureDB,
  initializeBlockingSystem,
  storeAuthMetadata,
  initializeEncryptedStorage,
} from './initialization';
import {
  loadRecentMessages,
  loadConversationMessages,
  mergeMessages,
  flushPendingMessages,
  saveMessageBatch,
  addToPendingQueue,
  projectMessageForUi,
} from './message-persistence';
import { loadUsers, saveUsers } from './user-persistence';
import { database, signal } from '../../lib/tauri-bindings';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { blockStatusCache } from '../../lib/blocking/block-status-cache';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { deliveryReceiptOutbox } from '../../lib/signals/delivery-receipt-outbox';
import { normalizeKnownUsers } from '../../lib/database/known-users';
import { isCanonicalAuthUsername } from '../../lib/sanitizers';
import { STORAGE_KEYS, STORAGE_STORES } from '../../lib/database/storage-keys';

export const useSecureDB = ({ Authentication, setMessages }: UseSecureDBProps): UseSecureDBReturn => {
  const secureDBRef = useRef<SecureDB | null>(null);
  const [dbInitialized, setDbInitialized] = useState(false);
  const [dbInitError, setDbInitError] = useState<string | null>(null);
  const [dbInitAttempt, setDbInitAttempt] = useState(0);
  const [users, setUsersState] = useState<User[]>([]);
  const initializingDbRef = useRef(false);
  const dbGenerationRef = useRef(0);
  const activeAccountRef = useRef<string | null>(null);
  const initializationChainRef = useRef<Promise<void>>(Promise.resolve());

  const pendingMessagesRef = useRef<Message[]>([]);
  const debouncedSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingSaveMessagesRef = useRef<Map<string, Message>>(new Map());
  const pendingSaveActivePeersRef = useRef<Map<string, string | undefined>>(new Map());
  const pendingSaveVersionsRef = useRef<Map<string, number>>(new Map());
  const pendingSaveWaitersRef = useRef<Map<string, Array<{
    version: number;
    resolve: () => void;
    reject: (error: Error) => void;
  }>>>(new Map());
  const nextSaveVersionRef = useRef(0);
  const saveFlushInFlightRef = useRef<Promise<void> | null>(null);
  const inflightDbOpRef = useRef<Promise<void>>(Promise.resolve());
  const userSaveChainRef = useRef<Promise<void>>(Promise.resolve());
  const usersLoadedGenerationRef = useRef<number | null>(null);

  const setUsers = useCallback<Dispatch<SetStateAction<User[]>>>((action) => {
    setUsersState((previous) => {
      const candidate = typeof action === 'function' ? action(previous) : action;
      const owner = activeAccountRef.current;
      if (!owner && candidate.length === 0) return [];
      try {
        return normalizeKnownUsers(candidate, owner || '', 'merge');
      } catch {
        return previous;
      }
    });
  }, []);

  const loadedAccountRef = useRef<string | null>(null);

  // Reset on logout
  useLayoutEffect(() => {
    const account = Authentication?.isLoggedIn
      ? (Authentication?.loginUsernameRef?.current || Authentication?.username || null)
      : null;
    const accountChanged = activeAccountRef.current !== account;
    if (accountChanged) dbGenerationRef.current += 1;
    activeAccountRef.current = account;

    if (!Authentication?.isLoggedIn || accountChanged) {
      unifiedSignalTransport.resetForAccountTransition();
      deliveryReceiptOutbox.setPersistence(null, null);
      syncEncryptedStorage.reset();
      blockingSystem.setSecureDB(null);
      blockStatusCache.clear();
      profilePictureSystem.setSecureDB(null);
      const transitionError = new Error('Secure database account changed before save completed');
      for (const waiters of pendingSaveWaitersRef.current.values()) {
        for (const waiter of waiters) waiter.reject(transitionError);
      }
      pendingSaveWaitersRef.current.clear();
      pendingSaveVersionsRef.current.clear();
      pendingSaveActivePeersRef.current.clear();
      if (debouncedSaveRef.current) clearTimeout(debouncedSaveRef.current);
      debouncedSaveRef.current = null;
      saveFlushInFlightRef.current = null;
      setDbInitialized(false);
      setDbInitError(null);
      initializingDbRef.current = false;
      secureDBRef.current?.dispose();
      secureDBRef.current = null;

      // Wipe previous accounts in memory data
      loadedAccountRef.current = null;
      usersLoadedGenerationRef.current = null;
      pendingMessagesRef.current = [];
      pendingSaveMessagesRef.current.clear();
      setUsers([]);
      setMessages([]);
    }
  }, [Authentication?.isLoggedIn, Authentication?.username, setMessages]);

  // Initialize database
  useEffect(() => {
    if (!Authentication?.isLoggedIn || dbInitialized || secureDBRef.current) return;
    if (!Authentication.vaultReady) return;
    if (!Authentication.loginUsernameRef.current) return;

    const generation = dbGenerationRef.current;
    const authOperation = Authentication.authLifecycle?.capture?.();
    const username = Authentication.loginUsernameRef.current;
    const isCurrent = () => (
      dbGenerationRef.current === generation &&
      activeAccountRef.current === username &&
      (!authOperation || Authentication.authLifecycle?.isCurrent?.(authOperation)) &&
      Authentication?.isLoggedIn
    );

    const initializeDB = async () => {
      if (!isCurrent() || dbInitialized || secureDBRef.current) return;
      initializingDbRef.current = true;
      setDbInitError(null);
      let initializedDb: SecureDB | null = null;
      try {
        const db = await initializeSecureDB(username);
        initializedDb = db;
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }
        secureDBRef.current = db;

        await signal.initStorage(username);
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }

        const accountKeys = await Authentication.getKeysOnDemand?.();
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }
        if (!accountKeys?.native || !accountKeys.kyber?.publicKeyBase64) {
          throw new Error('Native account public keys unavailable');
        }
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }

        await initializeBlockingSystem(db);
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }

        await storeAuthMetadata(
          db,
          Authentication.pseudonym || username,
          Authentication.originalUsernameRef?.current || null
        );
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }

        await initializeEncryptedStorage(db);
        if (!isCurrent()) {
          db.dispose();
          secureDBRef.current = null;
          await database.lock(db.getAccountScope()).catch(() => false);
          return;
        }

        unifiedSignalTransport.setDeliveryAckPersistence({
          load: async () => (await db.retrieve(STORAGE_STORES.TRANSPORT_DELIVERY, STORAGE_KEYS.DELIVERY_ACKS)) ?? [],
          save: async (entries) => {
            if (entries.length === 0) {
              await db.delete(STORAGE_STORES.TRANSPORT_DELIVERY, STORAGE_KEYS.DELIVERY_ACKS);
            } else {
              await db.store(STORAGE_STORES.TRANSPORT_DELIVERY, STORAGE_KEYS.DELIVERY_ACKS, entries);
            }
          },
          clearRecovery: async (peer, messageIds) => {
            await db.clearUnacknowledgedMessages(peer, messageIds);
          },
        });
        deliveryReceiptOutbox.setPersistence(username, {
          load: async () => (await db.retrieve(STORAGE_STORES.DELIVERY_RECEIPTS, STORAGE_KEYS.DELIVERY_RECEIPT_OUTBOX)) ?? [],
          save: async (entries) => {
            if (entries.length === 0) {
              await db.delete(STORAGE_STORES.DELIVERY_RECEIPTS, STORAGE_KEYS.DELIVERY_RECEIPT_OUTBOX);
            } else {
              await db.store(STORAGE_STORES.DELIVERY_RECEIPTS, STORAGE_KEYS.DELIVERY_RECEIPT_OUTBOX, entries);
            }
          }
        });

        setDbInitialized(true);
        Authentication.setVaultReady?.(true);
      } catch (err) {
        if (initializedDb) {
          initializedDb.dispose();
          await database.lock(initializedDb.getAccountScope()).catch(() => false);
        }
        if (!isCurrent()) return;
        console.error('[useSecureDB] Failed to initialize SecureDB', err);
        const message = err instanceof Error ? err.message : String(err);
        secureDBRef.current = null;
        setDbInitialized(false);
        setDbInitError(message || 'Failed to initialize secure storage');
        Authentication.setLoginError?.(`Failed to initialize secure storage: ${message || 'unknown error'}`);
      } finally {
        if (dbGenerationRef.current === generation) {
          initializingDbRef.current = false;
        }
      }
    };

    const queued = initializationChainRef.current
      .catch(() => undefined)
      .then(initializeDB);
    initializationChainRef.current = queued;
    void queued;
  }, [Authentication?.isLoggedIn, Authentication?.username, dbInitialized, Authentication?.vaultReady, dbInitAttempt]);

  const retryInitializeDB = useCallback(() => {
    initializingDbRef.current = false;
    secureDBRef.current?.dispose();
    secureDBRef.current = null;
    setDbInitialized(false);
    setDbInitError(null);
    setDbInitAttempt((attempt) => attempt + 1);
  }, []);

  // Load data after initialization
  useEffect(() => {
    if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;

    const generation = dbGenerationRef.current;
    const db = secureDBRef.current;
    const currentUser = Authentication?.loginUsernameRef?.current;
    if (!currentUser) return;
    let cancelled = false;
    const isCurrent = () => (
      !cancelled &&
      dbGenerationRef.current === generation &&
      activeAccountRef.current === currentUser &&
      secureDBRef.current === db &&
      Authentication?.isLoggedIn
    );

    const loadData = async () => {
      if (!isCurrent()) return;

      if (loadedAccountRef.current !== null && loadedAccountRef.current !== currentUser) {
        pendingMessagesRef.current = [];
        pendingSaveMessagesRef.current.clear();
        pendingSaveVersionsRef.current.clear();
        pendingSaveActivePeersRef.current.clear();
        setUsers([]);
        setMessages([]);
      }
      usersLoadedGenerationRef.current = null;
      loadedAccountRef.current = currentUser;

      // Load only conversation previews
      try {
        const recentMessages = await loadRecentMessages(db, currentUser);
        if (isCurrent() && recentMessages.length > 0) {
          setMessages(prev => isCurrent() ? mergeMessages(prev, recentMessages, currentUser) : prev);
        }
      } catch (err) {
        console.error('[useSecureDB] Failed to load messages', err);
      }

      // Load users
      try {
        const savedUsers = await loadUsers(db);
        if (isCurrent()) {
          setUsers(savedUsers);
          usersLoadedGenerationRef.current = generation;
        }
      } catch (err) {
        console.error('[useSecureDB] Failed to load users', err);
      }
    };

    void loadData();
    return () => {
      cancelled = true;
    };
  }, [Authentication?.isLoggedIn, Authentication?.username, dbInitialized, setMessages]);


  // Flush pending messages
  useEffect(() => {
    if (!dbInitialized || !secureDBRef.current || pendingMessagesRef.current.length === 0) return;

    const generation = dbGenerationRef.current;
    const db = secureDBRef.current;
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let failedAttempts = 0;
    const isCurrent = () => (
      !cancelled &&
      generation === dbGenerationRef.current &&
      secureDBRef.current === db
    );
    const flush = async () => {
      const snapshot = [...pendingMessagesRef.current];
      if (!isCurrent() || snapshot.length === 0) return;
      let operation: Promise<void> | null = null;
      try {
        await inflightDbOpRef.current.catch(() => undefined);
        if (!isCurrent()) return;
        operation = flushPendingMessages(db, snapshot);
        inflightDbOpRef.current = operation;
        await operation;
        if (!isCurrent()) return;
        const saved = new Set(snapshot);
        pendingMessagesRef.current = pendingMessagesRef.current.filter(message => !saved.has(message));
        failedAttempts = 0;
      } catch {
        if (!isCurrent()) return;
        failedAttempts += 1;
        const delay = Math.min(1_000 * (2 ** Math.min(failedAttempts - 1, 5)), 30_000);
        retryTimer = setTimeout(() => {
          retryTimer = null;
          void flush();
        }, delay);
      } finally {
        if (operation && inflightDbOpRef.current === operation) {
          inflightDbOpRef.current = Promise.resolve();
        }
      }
    };

    void flush();
    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [dbInitialized]);

  // Save users on change
  useEffect(() => {
    if (
      !Authentication?.isLoggedIn ||
      !dbInitialized ||
      !secureDBRef.current ||
      usersLoadedGenerationRef.current !== dbGenerationRef.current
    ) return;
    const account = activeAccountRef.current;
    const generation = dbGenerationRef.current;
    const db = secureDBRef.current;
    const snapshot = users.map((user) => ({ ...user }));
    const isCurrent = () => (
      !!account &&
      Authentication?.isLoggedIn &&
      activeAccountRef.current === account &&
      dbGenerationRef.current === generation &&
      secureDBRef.current === db
    );

    const operation = userSaveChainRef.current
      .catch(() => undefined)
      .then(async () => {
        if (!isCurrent()) return;
        await saveUsers(db, snapshot);
        if (!isCurrent()) throw new Error('Secure database account changed during user save');
      });
    userSaveChainRef.current = operation;
    void operation.catch(err => console.error('[useSecureDB] saveUsers error:', err));
  }, [users, Authentication?.isLoggedIn, dbInitialized]);

  const settleSaveWaiters = useCallback((messageId: string, throughVersion: number, error?: Error) => {
    const waiters = pendingSaveWaitersRef.current.get(messageId) || [];
    const remaining = [] as typeof waiters;
    for (const waiter of waiters) {
      if (waiter.version > throughVersion) {
        remaining.push(waiter);
      } else if (error) {
        waiter.reject(error);
      } else {
        waiter.resolve();
      }
    }
    if (remaining.length > 0) pendingSaveWaitersRef.current.set(messageId, remaining);
    else pendingSaveWaitersRef.current.delete(messageId);
  }, []);

  const schedulePendingSaveFlush = useCallback(() => {
    if (debouncedSaveRef.current) return;
    debouncedSaveRef.current = setTimeout(() => {
      debouncedSaveRef.current = null;
      void runPendingSaveFlush().catch(() => { });
    }, DB_SAVE_DEBOUNCE_MS);
  }, []);

  async function runPendingSaveFlush(): Promise<void> {
    if (saveFlushInFlightRef.current) return saveFlushInFlightRef.current;
    if (pendingSaveMessagesRef.current.size === 0) return;

    const db = secureDBRef.current;
    if (!db) throw new Error('Secure database is not ready');
    const generation = dbGenerationRef.current;
    const snapshot = new Map(pendingSaveMessagesRef.current);
    const activePeers = new Map<string, string | undefined>();
    const versions = new Map<string, number>();
    for (const messageId of snapshot.keys()) {
      versions.set(messageId, pendingSaveVersionsRef.current.get(messageId) || 0);
      activePeers.set(messageId, pendingSaveActivePeersRef.current.get(messageId));
    }

    const operation = (async () => {
      try {
        const grouped = new Map<string | undefined, Map<string, Message>>();
        for (const [messageId, message] of snapshot) {
          const activePeer = activePeers.get(messageId);
          const group = grouped.get(activePeer) || new Map<string, Message>();
          group.set(messageId, message);
          grouped.set(activePeer, group);
        }
        for (const [activePeer, messages] of grouped) {
          await saveMessageBatch(db, messages, activePeer);
        }
        if (dbGenerationRef.current !== generation || secureDBRef.current !== db) {
          throw new Error('Secure database account changed during save');
        }

        for (const [messageId, version] of versions) {
          settleSaveWaiters(messageId, version);
          if (pendingSaveVersionsRef.current.get(messageId) === version) {
            pendingSaveVersionsRef.current.delete(messageId);
            pendingSaveMessagesRef.current.delete(messageId);
            pendingSaveActivePeersRef.current.delete(messageId);
          }
        }
      } catch (cause) {
        const error = cause instanceof Error ? cause : new Error(String(cause));
        throw error;
      }
    })();

    saveFlushInFlightRef.current = operation;
    try {
      await operation;
    } finally {
      if (saveFlushInFlightRef.current === operation) saveFlushInFlightRef.current = null;
      if (
        dbGenerationRef.current === generation &&
        secureDBRef.current === db &&
        pendingSaveMessagesRef.current.size > 0
      ) {
        schedulePendingSaveFlush();
      }
    }
  }

  const saveMessageToLocalDB = useCallback(
    async (message: Message, activeConversationPeer?: string) => {
      if (!message.id) throw new Error('Message id is required');
      const account = activeAccountRef.current;
      const generation = dbGenerationRef.current;
      const db = secureDBRef.current;
      const isCurrent = () => (
        !!account &&
        generation === dbGenerationRef.current &&
        activeAccountRef.current === account &&
        secureDBRef.current === db
      );
      if (!account || (message.sender !== account && message.recipient !== account)) {
        throw new Error('Message does not belong to the active account');
      }
      if (
        activeConversationPeer !== undefined &&
        (!isCanonicalAuthUsername(activeConversationPeer) || activeConversationPeer === account)
      ) {
        throw new Error('Invalid active conversation peer');
      }
      if (
        !pendingSaveMessagesRef.current.has(message.id) &&
        pendingSaveMessagesRef.current.size >= DB_MAX_PENDING_MESSAGES
      ) {
        throw new Error('Pending database save limit exceeded');
      }

      const uiMessage = projectMessageForUi(message);
      setMessages(prev => {
        if (!isCurrent()) return prev;
        const idx = prev.findIndex(m => m.id === message.id);
        if (idx !== -1) {
          const updated = [...prev];
          updated[idx] = uiMessage;
          return updated;
        }
        return [...prev, uiMessage];
      });
      if (!isCurrent()) throw new Error('Secure database account changed before save');

      if (!dbInitialized || !db) {
        pendingMessagesRef.current = addToPendingQueue(pendingMessagesRef.current, message);
        throw new Error('Secure database is not ready');
      }

      const version = ++nextSaveVersionRef.current;
      pendingSaveMessagesRef.current.set(message.id, message);
      pendingSaveVersionsRef.current.set(message.id, version);
      if (activeConversationPeer !== undefined || !pendingSaveActivePeersRef.current.has(message.id)) {
        pendingSaveActivePeersRef.current.set(message.id, activeConversationPeer);
      }

      const persisted = new Promise<void>((resolve, reject) => {
        const waiters = pendingSaveWaitersRef.current.get(message.id!) || [];
        waiters.push({ version, resolve, reject });
        pendingSaveWaitersRef.current.set(message.id!, waiters);
      });
      schedulePendingSaveFlush();
      return persisted;
    },
    [dbInitialized, setMessages, schedulePendingSaveFlush]
  );

  const loadMoreConversationMessages = useCallback(
    async (peerUsername: string, currentOffset: number, limit: number = 50) => {
      if (!secureDBRef.current || !Authentication?.loginUsernameRef?.current) {
        console.error('[useSecureDB] Cannot load more messages: DB or username not available');
        return [];
      }

      const generation = dbGenerationRef.current;
      const db = secureDBRef.current;
      const currentUser = Authentication.loginUsernameRef.current;
      const isCurrent = () => (
        dbGenerationRef.current === generation &&
        activeAccountRef.current === currentUser &&
        secureDBRef.current === db
      );

      try {
        const moreMessages = await loadConversationMessages(
          db,
          peerUsername,
          currentUser,
          limit,
          currentOffset
        );

        if (!isCurrent() || moreMessages.length === 0) return [];

        setMessages(prevMessages => {
          if (!isCurrent()) return prevMessages;
          const existingIds = new Set(prevMessages.map(msg => msg.id));
          const newMessages = moreMessages.filter(msg => !existingIds.has(msg.id));
          const merged = [...prevMessages, ...newMessages];
          merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
          return merged;
        });

        return moreMessages;
      } catch (err) {
        console.error('[useSecureDB] Failed to load more messages', err);
        return [];
      }
    },
    [Authentication?.loginUsernameRef?.current, setMessages]
  );

  const flushPendingSaves = useCallback(async () => {
    const db = secureDBRef.current;
    if (!db) return;

    if (debouncedSaveRef.current) {
      clearTimeout(debouncedSaveRef.current);
      debouncedSaveRef.current = null;
    }

    if (pendingSaveMessagesRef.current.size > 0) {
      await runPendingSaveFlush();
    }
    if (pendingMessagesRef.current.length > 0) {
      const snapshot = [...pendingMessagesRef.current];
      await flushPendingMessages(db, snapshot);
      const saved = new Set(snapshot);
      pendingMessagesRef.current = pendingMessagesRef.current.filter((message) => !saved.has(message));
    }
  }, [runPendingSaveFlush]);

  return {
    users,
    setUsers,
    dbInitialized,
    dbInitError,
    retryInitializeDB,
    secureDBRef,
    saveMessageToLocalDB,
    loadMoreConversationMessages,
    flushPendingSaves,
  };
};
