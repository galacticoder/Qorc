import { useState, useCallback, useEffect, useLayoutEffect, useRef } from "react";
import { Conversation } from "../../components/chat/messaging/ConversationList";
import { Message } from "../../components/chat/messaging/types";
import { User } from "../../components/chat/messaging/UserList";
import { EventType } from "../../lib/types/event-types";
import { computeBlindUserId } from "../../lib/utils/auth-utils";
import { shouldAttemptDiscovery } from "../../lib/utils/discovery-utils";
import { SecureDB } from "../../lib/database/secureDB";
import { keyTransparencyClient } from "../../lib/key-transparency/client";
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
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  secureDB: SecureDB | null,
  findUser: (handle: string) => Promise<any>
) => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [lastReadByConversation, setLastReadByConversation] = useState<Map<string, number>>(new Map());
  const [pinStateByConversation, setPinStateByConversation] = useState<Map<string, { isPinned: boolean; pinnedAt: number }>>(new Map());

  // Rate limiting state
  const rateStateRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });
  const pendingAddsRef = useRef<Map<string, Promise<Conversation | null>>>(new Map());
  const activeAccountRef = useRef(currentUsername);
  const activeDbRef = useRef(secureDB);
  activeDbRef.current = secureDB;
  const accountGenerationRef = useRef(0);

  // Clear the previous accounts derived UI state before paint
  useLayoutEffect(() => {
    if (activeAccountRef.current === currentUsername) return;
    activeAccountRef.current = currentUsername;
    accountGenerationRef.current += 1;
    pendingAddsRef.current.clear();
    rateStateRef.current = { windowStart: 0, count: 0 };
    setConversations([]);
    setSelectedConversation(null);
    setLastReadByConversation(new Map());
    setPinStateByConversation(new Map());
  }, [currentUsername]);

  const addConversation = useCallback(async (username: string, autoSelect: boolean = true): Promise<Conversation | null> => {
    const owner = currentUsername;
    const generation = accountGenerationRef.current;
    const db = secureDB;
    const isCurrent = () => (
      !!owner &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === owner &&
      activeDbRef.current === db
    );
    if (!db || !isCurrent()) {
      throw new Error('[useConversations] SecureDB is required, cannot add conversation');
    }
    const trimmed = username?.trim();
    if (!trimmed) {
      throw new Error('Username cannot be empty');
    }

    if (isPseudonymHash(trimmed)) {
      throw new Error('Please enter a handle,');
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
      throw new Error('Rate limit exceeded, too many conversation requests');
    }
    rateState.count += 1;

    const operation = (async (): Promise<Conversation | null> => {
      try {
        if (!isCurrent()) throw new Error('Account changed during conversation discovery');
        const existingConversation = conversations.find(conv => conv.username === conversationUsername);
        if (existingConversation) {
          if (autoSelect && isCurrent()) {
            setSelectedConversation(conversationUsername);
          }
          return existingConversation;
        }

        if (!shouldAttemptDiscovery(conversationUsername)) {
          throw new Error('User not eligible for discovery');
        }
        const material = await findUser(conversationUsername);
        if (!isCurrent()) throw new Error('Account changed during conversation discovery');
        if (!material) throw new Error('User not found in discovery billboard');

        const { publicKeys } = material;
        dispatchSafeEvent(EventType.USER_KEYS_AVAILABLE, {
          account: owner,
          username: conversationUsername,
          hybridKeys: { ...publicKeys },
          peerCertificateFingerprint: material.peerCertificateFingerprint,
          identityRootFingerprint: material.identityRootFingerprint,
          identityBundleFingerprint: material.identityBundleFingerprint
        }, ['account', 'username', 'hybridKeys', 'peerCertificateFingerprint', 'identityRootFingerprint', 'identityBundleFingerprint']);

        const newConversation = createConversation(conversationUsername);
        setConversations(prev => isCurrent() && !prev.some((entry) => entry.username === conversationUsername)
          ? [...prev, newConversation]
          : prev);
        if (autoSelect && selectedConversation !== conversationUsername && isCurrent()) {
          setSelectedConversation(conversationUsername);
        }
        return newConversation;
      } catch (_error) {
        if (isCurrent()) rateState.count = Math.max(rateState.count - 1, 0);
        throw _error;
      }
    })();

    let wrapped!: Promise<Conversation | null>;
    wrapped = operation.finally(() => {
      if (pendingMap.get(discoveryId) === wrapped) pendingMap.delete(discoveryId);
    });
    pendingMap.set(discoveryId, wrapped);
    return wrapped;
  }, [conversations, currentUsername, selectedConversation, users, secureDB, findUser]);

  const getLatestConversationTimestamp = useCallback((username: string) => {
    if (!username) return 0;
    let latest = 0;
    for (const msg of messages) {
      if (!msg?.sender || !msg?.recipient) continue;
      if (msg.sender !== currentUsername && msg.recipient !== currentUsername) continue;
      const other = msg.sender === currentUsername ? msg.recipient : msg.sender;
      if (other !== username) continue;
      const ts = msg.timestamp instanceof Date ? msg.timestamp.getTime() : new Date(msg.timestamp).getTime();
      if (!Number.isNaN(ts) && ts > latest) latest = ts;
    }
    return latest;
  }, [messages, currentUsername]);

  const persistConversationReadState = useCallback(async (username: string, lastReadTimestamp: number) => {
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    const db = secureDB;
    const isCurrent = () => (
      !!account &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      activeDbRef.current === db
    );
    if (!db || !username || !lastReadTimestamp || !isCurrent()) return;
    try {
      await db.markConversationRead(username, lastReadTimestamp);
    } catch (err) {
      if (isCurrent()) console.error('[useConversations] Failed to persist conversation read state', err);
    }
  }, [secureDB, currentUsername]);

  const markConversationAsRead = useCallback((username: string) => {
    if (!username || !currentUsername || activeAccountRef.current !== currentUsername) return;
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
  }, [getLatestConversationTimestamp, persistConversationReadState, currentUsername]);

  const selectConversation = useCallback((username: string) => {
    if (!username || typeof username !== 'string' || activeAccountRef.current !== currentUsername) {
      return;
    }

    if (selectedConversation !== username) {
      setSelectedConversation(username);
      setConversations(prev => prev.map(conv =>
        conv.username === username ? { ...conv, unreadCount: 0 } : conv
      ));
      markConversationAsRead(username);
    }
  }, [selectedConversation, markConversationAsRead, currentUsername]);

  useEffect(() => {
    if (!secureDB) return;
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    const db = secureDB;
    let cancelled = false;
    const isCurrent = () => (
      !cancelled &&
      !!account &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      activeDbRef.current === db
    );
    const loadReadState = async () => {
      try {
        const metadata = await db.loadConversationMetadata();
        if (!isCurrent()) return;
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
        if (isCurrent()) {
          setLastReadByConversation(nextReads);
          setPinStateByConversation(nextPins);
        }
      } catch (err) {
        if (isCurrent()) console.error('[useConversations] Failed to load read state', err);
      }
    };
    loadReadState();
    return () => { cancelled = true; };
  }, [secureDB, currentUsername]);

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
      if (msg.sender !== currentUsername && msg.recipient !== currentUsername) continue;

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
          secureContentId: msg.secureContentId,
        });
      } else {
        const updated = { ...conv };
        
        if (msgTime.getTime() > (conv.lastMessageTime?.getTime() || 0)) {
          updated.lastMessage = getConversationPreview(msg, currentUsername);
          updated.lastMessageTime = msgTime;
          updated.secureContentId = msg.secureContentId;
        }
        if (unreadIncrement > 0) {
          updated.unreadCount = (conv.unreadCount || 0) + unreadIncrement;
        }
        convMap.set(other, updated);
      }
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
      if (next.length > MAX_CONVERSATIONS) next.length = MAX_CONVERSATIONS;

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
  }, [messages, currentUsername, selectedConversation, lastReadByConversation, pinStateByConversation]);

  useEffect(() => {
    if (!selectedConversation) return;
    markConversationAsRead(selectedConversation);
  }, [selectedConversation, messages, markConversationAsRead]);

  const removeConversation = useCallback(async (username: string) => {
    if (!username || typeof username !== 'string' || !currentUsername || activeAccountRef.current !== currentUsername) {
      return;
    }

    const db = secureDB;
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    if (!db) return;
    try {
      await keyTransparencyClient.removeMonitoredPeer(account, username);
    } catch (error) {
      if (generation === accountGenerationRef.current && activeAccountRef.current === account) {
        console.error('[useConversations] Failed to remove contact transparency monitor', error);
      }
      return;
    }
    if (generation !== accountGenerationRef.current || activeAccountRef.current !== account) return;
    try {
      await db.deleteConversationMessages(username);
    } catch (error) {
      if (generation === accountGenerationRef.current && activeAccountRef.current === account) {
        console.error('[useConversations] Failed to delete conversation from DB', error);
      }
      return;
    }
    if (generation !== accountGenerationRef.current || activeAccountRef.current !== account) return;

    setConversations(prev => prev.filter(conv => conv.username !== username));
    setMessages(prev => prev.filter(msg => !(
      (msg.sender === username && msg.recipient === account) ||
      (msg.sender === account && msg.recipient === username)
    )));
    if (selectedConversation === username) setSelectedConversation(null);
  }, [selectedConversation, secureDB, currentUsername, setMessages]);

  const toggleConversationPin = useCallback(async (username: string) => {
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    const db = secureDB;
    const isCurrent = () => (
      !!account &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      activeDbRef.current === db
    );
    if (!username || !db || !isCurrent()) return;

    const current = pinStateByConversation.get(username);
    const isPinned = !current?.isPinned;
    const next = new Map(pinStateByConversation);
    if (isPinned) next.set(username, { isPinned: true, pinnedAt: Date.now() });
    else next.delete(username);
    setPinStateByConversation(next);

    try {
      await db.toggleConversationPin(username, isPinned);
    } catch (error) {
      if (isCurrent()) {
        setPinStateByConversation(pinStateByConversation);
        console.error('[useConversations] Failed to persist pin state', error);
      }
    }
  }, [secureDB, currentUsername, pinStateByConversation]);

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
