import { useState, useCallback, useEffect, useRef } from "react";
import { Conversation } from "../../components/chat/messaging/ConversationList";
import { Message } from "../../components/chat/messaging/types";
import { User } from "../../components/chat/messaging/UserList";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import { computeBlindUserId } from "../../lib/utils/auth-utils";
import { shouldAttemptDiscovery } from "../../lib/utils/discovery-utils";
import { SecureDB } from "../../lib/database/secureDB";
import { MAX_CONVERSATIONS, CONVERSATION_RATE_LIMIT_WINDOW_MS, CONVERSATION_RATE_LIMIT_MAX } from "../../lib/constants";
import {
  dispatchSafeEvent,
  getConversationPreview,
  isValidConversationUsername,
  isPseudonymHash,
  createConversation
} from "./conversations";

export const useConversations = (
  currentUsername: string,
  users: User[],
  messages: Message[],
  secureDB: SecureDB | null,
  findUser: (handle: string) => Promise<any>
) => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [removedConversations, setRemovedConversations] = useState<Set<string>>(new Set());
  const [lastReadByConversation, setLastReadByConversation] = useState<Map<string, number>>(new Map());
  const [pinStateByConversation, setPinStateByConversation] = useState<Map<string, { isPinned: boolean; pinnedAt: number }>>(new Map());

  // Rate limiting state
  const rateStateRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });
  const pendingAddsRef = useRef<Map<string, Promise<Conversation | null>>>(new Map());
  const eventCleanupRef = useRef<Map<string, () => void>>(new Map());

  const addConversation = useCallback(async (username: string, autoSelect: boolean = true): Promise<Conversation | null> => {
    if (!secureDB) {
      throw new Error('[useConversations] SecureDB is required - cannot add conversation');
    }
    const trimmed = username?.trim();
    if (!trimmed) {
      throw new Error('Username cannot be empty');
    }

    if (isPseudonymHash(trimmed)) {
      throw new Error('Please enter a handle, not a pseudonym hash');
    }

    if (!isValidConversationUsername(trimmed)) {
      throw new Error('Invalid name format');
    }

    if (conversations.length >= MAX_CONVERSATIONS) {
      throw new Error('Maximum conversation limit reached');
    }

    const conversationUsername = trimmed;
    const discoveryId = computeBlindUserId(trimmed);

    const currentDiscoveryId = currentUsername ? computeBlindUserId(currentUsername) : '';
    if (conversationUsername === currentUsername || (currentDiscoveryId && discoveryId === currentDiscoveryId)) {
      throw new Error('Cannot create conversation with yourself');
    }

    const pendingMap = pendingAddsRef.current;
    if (pendingMap.has(discoveryId)) {
      return pendingMap.get(discoveryId)!;
    }

    const now = Date.now();
    const rateState = rateStateRef.current;
    if (now - rateState.windowStart > CONVERSATION_RATE_LIMIT_WINDOW_MS) {
      rateState.windowStart = now;
      rateState.count = 0;
    }
    if (rateState.count >= CONVERSATION_RATE_LIMIT_MAX) {
      throw new Error('Rate limit exceeded - too many conversation requests');
    }
    rateState.count += 1;

    const operation = (async (): Promise<Conversation | null> => {
      try {
        if (removedConversations.has(conversationUsername)) {
          setRemovedConversations(prev => {
            const newSet = new Set(prev);
            newSet.delete(conversationUsername);
            return newSet;
          });
        }

        const existingConversation = conversations.find(conv => conv.username === conversationUsername);
        if (existingConversation) {
          if (autoSelect) {
            setSelectedConversation(conversationUsername);
          }
          return existingConversation;
        }

        return await new Promise<Conversation | null>(async (resolve, reject) => {
          let timeoutId: number | null = null;
          const cleanup = () => {
            if (timeoutId !== null) {
              clearTimeout(timeoutId);
              timeoutId = null;
            }
            eventCleanupRef.current.delete(conversationUsername);
          };

          // Blind discovery
          try {
            if (!shouldAttemptDiscovery(conversationUsername, users.map(u => u.username).filter(Boolean))) {
              reject(new Error('User not eligible for discovery'));
              cleanup();
              return;
            }
            const material = await findUser(conversationUsername);
            if (material) {
              const { inboxId, publicKeys } = material;
              dispatchSafeEvent(EventType.USER_KEYS_AVAILABLE, {
                username: conversationUsername,
                hybridKeys: {
                  ...publicKeys,
                  inboxId,
                  routeId: material.routeId,
                  mailboxLookupId: material.mailboxLookupId,
                  bundleLookupId: material.bundleLookupId
                },
                inboxId,
                routeId: material.routeId,
                mailboxLookupId: material.mailboxLookupId,
                bundleLookupId: material.bundleLookupId,
                peerCertificateFingerprint: material.peerCertificateFingerprint,
                identityRootFingerprint: material.identityRootFingerprint,
                identityBundleFingerprint: material.identityBundleFingerprint
              }, ['username', 'hybridKeys', 'inboxId', 'routeId', 'mailboxLookupId', 'bundleLookupId', 'peerCertificateFingerprint', 'identityRootFingerprint', 'identityBundleFingerprint']);

              const newConversation = createConversation(conversationUsername, inboxId);

              setConversations(prev => [...prev, newConversation]);
              if (autoSelect && selectedConversation !== conversationUsername) {
                setSelectedConversation(conversationUsername);
              }
              resolve(newConversation);
              cleanup();
              return;
            } else {
              reject(new Error('User not found in discovery billboard'));
              cleanup();
              return;
            }
          } catch (discoveryErr) {
            console.error('[useConversations] Discovery error:', discoveryErr);
            reject(new Error('Discovery service error'));
            cleanup();
            return;
          }
        });
      } catch (_error) {
        rateState.count = Math.max(rateState.count - 1, 0);
        throw _error;
      }
    })();

    const wrapped = operation.finally(() => {
      pendingMap.delete(discoveryId);
    });
    pendingMap.set(discoveryId, wrapped);
    return wrapped;
  }, [conversations, currentUsername, removedConversations, selectedConversation, users, secureDB, findUser]);

  const getLatestConversationTimestamp = useCallback((username: string) => {
    if (!username) return 0;
    let latest = 0;
    for (const msg of messages) {
      if (!msg?.sender || !msg?.recipient) continue;
      const other = msg.sender === currentUsername ? msg.recipient : msg.sender;
      if (other !== username) continue;
      const ts = msg.timestamp instanceof Date ? msg.timestamp.getTime() : new Date(msg.timestamp).getTime();
      if (!Number.isNaN(ts) && ts > latest) latest = ts;
    }
    return latest;
  }, [messages, currentUsername]);

  const persistConversationReadState = useCallback(async (username: string, lastReadTimestamp: number) => {
    if (!secureDB || !username || !lastReadTimestamp) return;
    try {
      let metadata = await secureDB.loadConversationMetadata().catch(() => []);
      if (!metadata || metadata.length === 0) {
        metadata = await secureDB.rebuildConversationMetadata().catch(() => []);
      }
      if (!metadata || metadata.length === 0) return;

      let changed = false;
      const next = metadata.map((entry) => {
        if (entry.peerUsername !== username) return entry;
        const nextRead = Math.max(entry.lastReadTimestamp || 0, lastReadTimestamp);
        if (nextRead !== entry.lastReadTimestamp || (entry.unreadCount || 0) !== 0) {
          changed = true;
          return { ...entry, lastReadTimestamp: nextRead, unreadCount: 0 };
        }
        return entry;
      });

      if (changed) {
        await secureDB.saveConversationMetadata(next);
      }
    } catch (err) {
      console.error('[useConversations] Failed to persist conversation read state', err);
    }
  }, [secureDB]);

  const markConversationAsRead = useCallback((username: string) => {
    if (!username) return;
    const latest = getLatestConversationTimestamp(username);
    if (!latest) return;
    setLastReadByConversation(prev => {
      const next = new Map(prev);
      const current = next.get(username) || 0;
      if (latest > current) {
        next.set(username, latest);
      }
      return next;
    });
    void persistConversationReadState(username, latest);
  }, [getLatestConversationTimestamp, persistConversationReadState]);

  const selectConversation = useCallback((username: string) => {
    if (!username || typeof username !== 'string') {
      return;
    }

    if (selectedConversation !== username) {
      setSelectedConversation(username);
      setConversations(prev => prev.map(conv =>
        conv.username === username ? { ...conv, unreadCount: 0 } : conv
      ));
      markConversationAsRead(username);
    }
  }, [selectedConversation, markConversationAsRead]);

  useEffect(() => {
    return () => {
      eventCleanupRef.current.forEach(cleanup => cleanup());
      eventCleanupRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (!secureDB) return;
    let cancelled = false;
    const loadReadState = async () => {
      try {
        let metadata = await secureDB.loadConversationMetadata().catch(() => []);
        if (!metadata || metadata.length === 0) {
          metadata = await secureDB.rebuildConversationMetadata().catch(() => []);
        }
        if (cancelled || !metadata) return;
        const nextReads = new Map<string, number>();
        const nextPins = new Map<string, { isPinned: boolean; pinnedAt: number }>();
        for (const entry of metadata) {
          if (entry?.peerUsername) {
            nextReads.set(entry.peerUsername, entry.lastReadTimestamp || 0);
            if (entry.isPinned && entry.pinnedAt) {
              nextPins.set(entry.peerUsername, { isPinned: entry.isPinned, pinnedAt: entry.pinnedAt });
            }
          }
        }
        setLastReadByConversation(nextReads);
        setPinStateByConversation(nextPins);
      } catch (err) {
        console.error('[useConversations] Failed to load read state', err);
      }
    };
    loadReadState();
    return () => { cancelled = true; };
  }, [secureDB]);

  const getConversationMessages = useCallback((conversationUsername?: string) => {
    if (!conversationUsername) return [];

    const filtered = messages.filter(msg =>
      (msg.sender === conversationUsername && msg.recipient === currentUsername) ||
      (msg.sender === currentUsername && msg.recipient === conversationUsername)
    );

    return filtered;
  }, [messages, currentUsername]);

  useEffect(() => {
    if (!messages || messages.length === 0 || !currentUsername) {
      return;
    }

    const convMap = new Map<string, Conversation>();

    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i];
      if (!msg.sender || !msg.recipient) continue;

      const content = msg.content;
      if (content && (content.includes('"type":"typing-') ||
        content.includes(SignalType.DELIVERY_RECEIPT) ||
        content.includes(SignalType.READ_RECEIPT))) {
        continue;
      }

      const other = msg.sender === currentUsername ? msg.recipient : msg.sender;
      if (!other || other === currentUsername || other === 'System') continue;
      const msgTime = new Date(msg.timestamp);
      const lastReadTs = lastReadByConversation.get(other) || 0;
      const isIncoming = msg.sender !== currentUsername;
      const msgTimeMs = msgTime.getTime();
      const isUnread = isIncoming && !msg.receipt?.read && (lastReadTs === 0 || msgTimeMs > lastReadTs);
      const unreadIncrement = isUnread ? 1 : 0;

      const conv = convMap.get(other);
      if (!conv) {
        convMap.set(other, {
          id: crypto.randomUUID(),
          username: other,
          lastMessage: getConversationPreview(msg, currentUsername),
          lastMessageTime: msgTime,
          unreadCount: unreadIncrement,
          secureContentId: msg.secureContentId || msg.id,
        });
      } else {
        const updated = { ...conv };
        
        if (msgTime.getTime() > (conv.lastMessageTime?.getTime() || 0)) {
          updated.lastMessage = getConversationPreview(msg, currentUsername);
          updated.lastMessageTime = msgTime;
          updated.secureContentId = msg.secureContentId || msg.id;
        }
        if (unreadIncrement > 0) {
          updated.unreadCount = (conv.unreadCount || 0) + unreadIncrement;
        }
        convMap.set(other, updated);
      }
    }

    const toRestore: string[] = [];
    for (const username of convMap.keys()) {
      if (removedConversations.has(username)) {
        toRestore.push(username);
      }
    }

    if (toRestore.length > 0) {
      setRemovedConversations(prevRemoved => {
        const newSet = new Set(prevRemoved);
        for (const u of toRestore) newSet.delete(u);
        return newSet;
      });
    }

    setConversations(prev => {
      const merged = new Map<string, Conversation>();
      for (const c of prev) {
        if (c.username !== currentUsername) {
          merged.set(c.username, c);
        }
      }

      for (const [username, conv] of convMap.entries()) {
        const exists = merged.get(username);
        const pinState = pinStateByConversation.get(username);
        if (exists) {
          merged.set(username, {
            ...exists,
            lastMessage: conv.lastMessage,
            lastMessageTime: conv.lastMessageTime,
            unreadCount: username === selectedConversation ? 0 : conv.unreadCount,
            secureContentId: conv.secureContentId,
            displayName: exists.displayName || conv.displayName,
            isPinned: pinState?.isPinned,
            pinnedAt: pinState?.pinnedAt
          });
        } else {
          merged.set(username, {
            ...conv,
            isPinned: pinState?.isPinned,
            pinnedAt: pinState?.pinnedAt
          });
        }
      }

      const next = Array.from(merged.values());
      next.sort((a, b) => {
        const timeA = a.lastMessageTime?.getTime() || 0;
        const timeB = b.lastMessageTime?.getTime() || 0;
        return timeB - timeA;
      });

      if (prev.length === next.length) {
        const prevByUser = new Map(prev.map((c) => [c.username, c] as const));
        let equal = true;
        for (const c of next) {
          const p = prevByUser.get(c.username);
          if (!p) { equal = false; break; }
          const pTime = p.lastMessageTime?.getTime() || 0;
          const cTime = c.lastMessageTime?.getTime() || 0;
          if (
            (p.lastMessage || '') !== (c.lastMessage || '') ||
            (p.secureContentId || '') !== (c.secureContentId || '') ||
            pTime !== cTime ||
            (p.unreadCount || 0) !== (c.unreadCount || 0) ||
            (p.displayName || '') !== (c.displayName || '') ||
            p.isPinned !== c.isPinned ||
            p.pinnedAt !== c.pinnedAt
          ) {
            equal = false;
            break;
          }
        }
        if (equal) {
          return prev;
        }
      }

      return next;
    });
  }, [messages, currentUsername, selectedConversation, removedConversations, lastReadByConversation, pinStateByConversation]);

  useEffect(() => {
    if (!selectedConversation) return;
    markConversationAsRead(selectedConversation);
  }, [selectedConversation, messages, markConversationAsRead]);

  const removeConversation = useCallback((username: string, clearMessages: boolean = true) => {
    if (!username || typeof username !== 'string') {
      return;
    }

    setConversations(prev => prev.filter(conv => conv.username !== username));
    setRemovedConversations(prev => new Set(prev).add(username));

    if (selectedConversation === username) {
      setSelectedConversation(null);
    }

    if (clearMessages) {
      dispatchSafeEvent(EventType.CLEAR_CONVERSATION_MESSAGES, { username }, ['username']);
    }

    try {
      if (secureDB) {
        void secureDB.deleteConversationMessages(username, currentUsername)
          .catch((e) => console.error('[useConversations] Failed to delete conversation messages from DB:', e));
      }
    } catch { }
  }, [selectedConversation, secureDB, currentUsername]);

  const toggleConversationPin = useCallback(async (username: string) => {
    if (!username || !secureDB) return;
    
    setPinStateByConversation(prev => {
        const next = new Map(prev);
        const current = next.get(username);
        const isPinned = !current?.isPinned;
        
        if (isPinned) {
            next.set(username, { isPinned: true, pinnedAt: Date.now() });
        } else {
            next.delete(username);
        }
        
        secureDB.toggleConversationPin(username, isPinned).catch(e => {
            console.error('[useConversations] Failed to persist pin state', e);
        });
        
        return next;
    });
  }, [secureDB]);

  return {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    removeConversation,
    getConversationMessages,
    toggleConversationPin,
  };
};
