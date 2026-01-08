import React, { useRef, useEffect, useCallback, useState } from 'react';
import { SecureDB } from '../../lib/database/secureDB';
import type { Message } from '../../components/chat/messaging/types';
import type { User } from '../../components/chat/messaging/UserList';
import { EventType } from '../../lib/types/event-types';
import { DB_SAVE_DEBOUNCE_MS } from '../../lib/constants';
import { prewarmUsernameCache } from '../../lib/utils/database-utils';
import type { UseSecureDBProps, UseSecureDBReturn, MappingPayload, RateLimitBucket } from '../../lib/types/database-types';
import {
  isValidCryptoKey,
  initializeSecureDB,
  initializeBlockingSystem,
  storeAuthMetadata,
  initializeEncryptedStorage,
} from './initialization';
import {
  loadRecentMessages,
  loadAllMessages,
  loadConversationMessages,
  mergeMessages,
  flushPendingMessages,
  saveMessageBatch,
  addToPendingQueue,
} from './message-persistence';
import { loadUsers, saveUsers } from './user-persistence';
import {
  handleMappingReceived,
  handleUserKeysAvailable,
  queuePendingMapping,
  flushPendingMappings,
} from './mapping-handlers';

export const useSecureDB = ({ Authentication, setMessages }: UseSecureDBProps): UseSecureDBReturn => {
  const secureDBRef = useRef<SecureDB | null>(null);
  const [dbInitialized, setDbInitialized] = useState(false);
  const [users, setUsers] = useState<User[]>([]);

  const pendingMessagesRef = useRef<Message[]>([]);
  const pendingMappingsRef = useRef<MappingPayload[]>([]);
  const debouncedSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingSavesRef = useRef<Set<string>>(new Set());
  const pendingSaveMessagesRef = useRef<Map<string, Message>>(new Map());
  const messageMapRef = useRef<Map<string, Message>>(new Map());
  const inflightDbOpRef = useRef<Promise<void>>(Promise.resolve());
  const eventRateLimitRef = useRef<RateLimitBucket>({ windowStart: Date.now(), count: 0 });
  const keysEventRateLimitRef = useRef<RateLimitBucket>({ windowStart: Date.now(), count: 0 });

  // Reset on logout
  useEffect(() => {
    if (!Authentication?.isLoggedIn) {
      setDbInitialized(false);
      secureDBRef.current = null;
    }
  }, [Authentication?.isLoggedIn]);

  // Initialize database
  useEffect(() => {
    if (!Authentication?.isLoggedIn || dbInitialized || secureDBRef.current) return;
    if (!Authentication.loginUsernameRef.current || !Authentication.aesKeyRef?.current) return;

    const initializeDB = async () => {
      try {
        const key = Authentication.aesKeyRef.current;
        if (!isValidCryptoKey(key)) {
          console.error('[useSecureDB] Invalid CryptoKey');
          Authentication.setLoginError?.('Invalid stored key, cannot initialize secure storage');
          secureDBRef.current = null;
          Authentication.logout(secureDBRef).catch(console.error);
          return;
        }

        const db = await initializeSecureDB(Authentication.loginUsernameRef.current, key);
        secureDBRef.current = db;

        await initializeBlockingSystem(
          db,
          Authentication.passphrasePlaintextRef?.current || null,
          Authentication.hybridKeysRef?.current?.kyber?.secretKey || null
        );

        await storeAuthMetadata(
          db,
          Authentication.loginUsernameRef.current,
          Authentication.originalUsernameRef?.current || null
        );

        await initializeEncryptedStorage(db);

        setDbInitialized(true);
        Authentication.passphraseRef.current = '';
      } catch (err) {
        console.error('[useSecureDB] Failed to initialize SecureDB', err);
        Authentication.setLoginError?.('Failed to initialize secure storage');
      }
    };

    initializeDB();
  }, [Authentication?.isLoggedIn, Authentication?.username, dbInitialized]);

  // Load data after initialization
  useEffect(() => {
    if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;

    const loadData = async () => {
      if (!secureDBRef.current) return;

      // Prewarm username cache
      try {
        const mappings = await secureDBRef.current.getAllUsernameMappings();
        if (Array.isArray(mappings) && mappings.length > 0) {
          prewarmUsernameCache(mappings);
        }
      } catch { }

      const currentUser = Authentication?.loginUsernameRef?.current;
      if (!currentUser) return;

      // Load recent messages first
      try {
        const recentMessages = await loadRecentMessages(secureDBRef.current!, currentUser);
        if (recentMessages.length > 0) {
          setMessages(prev => mergeMessages(prev, recentMessages, currentUser));
        }

        // Background full load
        setTimeout(async () => {
          if (!secureDBRef.current) return;
          try {
            const allMessages = await loadAllMessages(secureDBRef.current, currentUser);
            if (allMessages.length > 0) {
              setMessages(prev => mergeMessages(prev, allMessages, currentUser));
            }
          } catch (err) {
            console.error('[useSecureDB] Background history load failed', err);
          }
        }, 500);
      } catch (err) {
        console.error('[useSecureDB] Failed to load messages', err);
      }

      // Load users
      try {
        const savedUsers = await loadUsers(secureDBRef.current!);
        if (savedUsers.length > 0) {
          setUsers(savedUsers);
        }
      } catch (err) {
        console.error('[useSecureDB] Failed to load users', err);
      }
    };

    loadData();
  }, [Authentication?.isLoggedIn, dbInitialized, setMessages]);

  // Username mapping listener
  useEffect(() => {
    if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;

    const mappingListener = async (e: Event) => {
      try {
        await handleMappingReceived(
          (e as CustomEvent).detail,
          secureDBRef.current!,
          eventRateLimitRef.current
        );
      } catch (err) {
        console.error('[useSecureDB] Failed to store username mapping', err);
      }
    };

    const keysListener = (e: Event) => {
      try {
        const newUsers = handleUserKeysAvailable(
          (e as CustomEvent).detail,
          users,
          keysEventRateLimitRef.current
        );
        if (newUsers) setUsers(newUsers);
      } catch { }
    };

    window.addEventListener(EventType.USERNAME_MAPPING_RECEIVED, mappingListener as EventListener);
    window.addEventListener(EventType.USER_KEYS_AVAILABLE, keysListener as EventListener);
    return () => {
      window.removeEventListener(EventType.USERNAME_MAPPING_RECEIVED, mappingListener as EventListener);
      window.removeEventListener(EventType.USER_KEYS_AVAILABLE, keysListener as EventListener);
    };
  }, [Authentication?.isLoggedIn, dbInitialized, users]);

  // Pre initialize mapping queue
  useEffect(() => {
    if (dbInitialized) return;

    const preInitListener = (e: Event) => {
      const result = queuePendingMapping((e as CustomEvent).detail, pendingMappingsRef.current);
      if (result) pendingMappingsRef.current = result;
    };

    window.addEventListener(EventType.USERNAME_MAPPING_RECEIVED, preInitListener as EventListener);
    return () => window.removeEventListener(EventType.USERNAME_MAPPING_RECEIVED, preInitListener as EventListener);
  }, [dbInitialized]);

  // Flush pending mappings
  useEffect(() => {
    if (!dbInitialized || !secureDBRef.current || pendingMappingsRef.current.length === 0) return;
    
    const toFlush = [...pendingMappingsRef.current];
    pendingMappingsRef.current = [];
    flushPendingMappings(secureDBRef.current, toFlush);
  }, [dbInitialized]);

  // Trigger mapping update on init
  useEffect(() => {
    if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;
    try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: '__all__' } })); } catch { }
  }, [Authentication?.isLoggedIn, dbInitialized]);

  // Flush pending messages
  useEffect(() => {
    if (!dbInitialized || !secureDBRef.current || pendingMessagesRef.current.length === 0) return;

    const flush = async () => {
      try {
        await inflightDbOpRef.current;
        inflightDbOpRef.current = flushPendingMessages(secureDBRef.current!, pendingMessagesRef.current);
        await inflightDbOpRef.current;
        pendingMessagesRef.current = [];
      } catch (err) {
        console.error('[useSecureDB] Failed to flush pending messages', err);
      }
    };

    flush();
  }, [dbInitialized]);

  // Save users on change
  useEffect(() => {
    if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current || users.length === 0) return;
    saveUsers(secureDBRef.current, users).catch(err => console.error('[useSecureDB] saveUsers error:', err));
  }, [users, Authentication?.isLoggedIn, dbInitialized]);

  const saveMessageToLocalDB = useCallback(
    async (message: Message, activeConversationPeer?: string) => {
      if (!message.id) {
        console.error('[useSecureDB] No message id provided');
        return;
      }

      setMessages(prev => {
        const idx = prev.findIndex(m => m.id === message.id);
        if (idx !== -1) {
          const updated = [...prev];
          updated[idx] = message;
          messageMapRef.current.set(message.id, message);
          return updated;
        } else {
          messageMapRef.current.set(message.id, message);
          return [...prev, message];
        }
      });

      const saveToPending = () => {
        pendingMessagesRef.current = addToPendingQueue(pendingMessagesRef.current, message);
      };

      if (!dbInitialized || !secureDBRef.current) {
        return saveToPending();
      }

      if (pendingSavesRef.current.has(message.id)) {
        pendingSaveMessagesRef.current.set(message.id, message);
        return;
      }

      pendingSavesRef.current.add(message.id);
      pendingSaveMessagesRef.current.set(message.id, message);

      if (debouncedSaveRef.current) {
        clearTimeout(debouncedSaveRef.current);
      }

      debouncedSaveRef.current = setTimeout(async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 0));
          await saveMessageBatch(secureDBRef.current!, pendingSaveMessagesRef.current, activeConversationPeer);
          pendingSavesRef.current.clear();
          pendingSaveMessagesRef.current.clear();
        } catch (err) {
          console.error('[useSecureDB] DB save failed', err);
          pendingSavesRef.current.clear();
          saveToPending();
        }
      }, DB_SAVE_DEBOUNCE_MS);
    },
    [dbInitialized, setMessages]
  );

  const loadMoreConversationMessages = useCallback(
    async (peerUsername: string, currentOffset: number, limit: number = 50) => {
      if (!secureDBRef.current || !Authentication?.loginUsernameRef?.current) {
        console.error('[useSecureDB] Cannot load more messages: DB or username not available');
        return [];
      }

      try {
        const moreMessages = await loadConversationMessages(
          secureDBRef.current,
          peerUsername,
          Authentication.loginUsernameRef.current,
          limit,
          currentOffset
        );

        if (moreMessages.length === 0) return [];

        setMessages(prevMessages => {
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
    if (!secureDBRef.current) return;

    if (debouncedSaveRef.current) {
      clearTimeout(debouncedSaveRef.current);
      debouncedSaveRef.current = null;
    }

    if (pendingSaveMessagesRef.current.size > 0 || pendingMessagesRef.current.length > 0) {
      try {
        const msgs = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
        let hasChanges = false;

        for (const [msgId, pendingMsg] of pendingSaveMessagesRef.current.entries()) {
          const idx = msgs.findIndex((m: Message) => m.id === msgId);
          if (idx !== -1) {
            msgs[idx] = pendingMsg;
          } else {
            msgs.push(pendingMsg);
          }
          hasChanges = true;
        }

        for (const pendingMsg of pendingMessagesRef.current) {
          const idx = msgs.findIndex((m: Message) => m.id === pendingMsg.id);
          if (idx !== -1) {
            msgs[idx] = pendingMsg;
          } else {
            msgs.push(pendingMsg);
          }
          hasChanges = true;
        }

        if (hasChanges) {
          await secureDBRef.current.saveMessages(msgs);
        }

        pendingSavesRef.current.clear();
        pendingSaveMessagesRef.current.clear();
        pendingMessagesRef.current = [];
      } catch (err) {
        console.error('[useSecureDB] Failed to flush pending saves:', err);
      }
    }
  }, []);

  return {
    users,
    setUsers,
    dbInitialized,
    secureDBRef,
    saveMessageToLocalDB,
    loadMoreConversationMessages,
    flushPendingSaves,
  };
};

export default useSecureDB;
