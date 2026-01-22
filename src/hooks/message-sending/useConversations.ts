import { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { Conversation } from "../../components/chat/messaging/ConversationList";
import { Message } from "../../components/chat/messaging/types";
import { User } from "../../components/chat/messaging/UserList";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import { pseudonymizeUsernameWithCache } from "../../lib/database/username-hash";
import { SecureDB } from "../../lib/database/secureDB";
import { MAX_CONVERSATIONS, CONVERSATION_RATE_LIMIT_WINDOW_MS, CONVERSATION_RATE_LIMIT_MAX, VALIDATION_TIMEOUT_MS } from "../../lib/constants";
import { unifiedSignalTransport } from "../../lib/transport/unified-signal-transport";
import {
  dispatchSafeEvent,
  getConversationPreview,
  isValidConversationUsername,
  isPseudonymHash,
  createConversation
} from "./conversations";

export const useConversations = (currentUsername: string, users: User[], messages: Message[], secureDB: SecureDB | null) => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [removedConversations, setRemovedConversations] = useState<Set<string>>(new Set());

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
      throw new Error('[useConversations] Username cannot be empty');
    }

    // Check if it looks like a pseudonym or validate as username
    const looksLikePseudonym = isPseudonymHash(trimmed);
    if (!looksLikePseudonym && !isValidConversationUsername(trimmed)) {
      throw new Error('[useConversations] Invalid username format (2-64 chars, alphanumeric/._- only)');
    }

    if (conversations.length >= MAX_CONVERSATIONS) {
      throw new Error('[useConversations] Maximum conversation limit reached');
    }

    const pseudonym = looksLikePseudonym ? trimmed.toLowerCase() : await pseudonymizeUsernameWithCache(trimmed, secureDB || undefined);

    if (pseudonym === currentUsername) {
      throw new Error('[useConversations] Cannot create conversation with yourself');
    }

    const pendingMap = pendingAddsRef.current;
    if (pendingMap.has(pseudonym)) {
      return pendingMap.get(pseudonym)!;
    }

    const now = Date.now();
    const rateState = rateStateRef.current;
    if (now - rateState.windowStart > CONVERSATION_RATE_LIMIT_WINDOW_MS) {
      rateState.windowStart = now;
      rateState.count = 0;
    }
    if (rateState.count >= CONVERSATION_RATE_LIMIT_MAX) {
      throw new Error('[useConversations] Rate limit exceeded - too many conversation requests');
    }
    rateState.count += 1;

    const operation = (async (): Promise<Conversation | null> => {
      try {
        if (!looksLikePseudonym && trimmed !== pseudonym) {
          try {
            await secureDB.storeUsernameMapping(pseudonym, trimmed);
            dispatchSafeEvent(EventType.USERNAME_MAPPING_UPDATED, { username: pseudonym, original: trimmed }, ['username', 'original']);
          } catch (_error) {
            console.error('[useConversations] Failed to store username mapping:', _error);
            throw new Error('[useConversations] Failed to store username mapping');
          }
        }

        if (removedConversations.has(pseudonym)) {
          setRemovedConversations(prev => {
            const newSet = new Set(prev);
            newSet.delete(pseudonym);
            return newSet;
          });
        }

        const existingConversation = conversations.find(conv => conv.username === pseudonym);
        if (existingConversation) {
          if (autoSelect) {
            setSelectedConversation(pseudonym);
          }
          return existingConversation;
        }

        return await new Promise<Conversation | null>(async (resolve, reject) => {
          let timeoutId: number | null = null;
          let resolved = false;

          const cleanup = () => {
            if (timeoutId !== null) {
              clearTimeout(timeoutId);
              timeoutId = null;
            }
            window.removeEventListener(EventType.USER_EXISTS_RESPONSE, handleUserExistsResponse as EventListener);
            eventCleanupRef.current.delete(pseudonym);
          };

          const handleUserExistsResponse = (event: Event) => {
            if (resolved) return;

            const customEvent = event as CustomEvent;
            const detail = typeof customEvent.detail === 'object' && customEvent.detail !== null ? customEvent.detail : {};
            const { username: responseUsername, exists, error, hybridPublicKeys } = detail as { username?: string; exists?: boolean; error?: string; hybridPublicKeys?: any };

            if ((responseUsername || '').toLowerCase() !== pseudonym.toLowerCase()) {
              return;
            }

            resolved = true;
            cleanup();

            if (error) {
              reject(new Error(`User validation failed: ${error}`));
              return;
            }

            if (!exists) {
              reject(new Error('User does not exist'));
              return;
            }

            if (hybridPublicKeys) {
              try {
                dispatchSafeEvent(EventType.USER_KEYS_AVAILABLE, { username: pseudonym, hybridKeys: hybridPublicKeys }, ['username', 'hybridKeys']);
              } catch (dispatchError) {
                console.error('Failed to dispatch user-keys-available:', dispatchError);
              }
            }

            const isOnline = users.some(user => user.username === pseudonym && user.isOnline);
            const newConversation = createConversation(pseudonym, isOnline);

            setConversations(prev => {
              return [...prev, newConversation];
            });
            if (autoSelect && selectedConversation !== pseudonym) {
              setSelectedConversation(pseudonym);
            }
            resolve(newConversation);
          };

          window.addEventListener(EventType.USER_EXISTS_RESPONSE, handleUserExistsResponse as EventListener);

          try {
            await unifiedSignalTransport.send('SERVER', { username: pseudonym }, SignalType.CHECK_USER_EXISTS);
          } catch (_error) {
            resolved = true;
            cleanup();
            console.error('Failed to send check-user-exists:', _error);
            reject(new Error('Failed to validate user'));
            return;
          }

          timeoutId = window.setTimeout(() => {
            if (resolved) return;
            resolved = true;
            cleanup();
            reject(new Error('User validation timeout'));
          }, VALIDATION_TIMEOUT_MS);

          eventCleanupRef.current.set(pseudonym, cleanup);
        });
      } catch (_error) {
        rateState.count = Math.max(rateState.count - 1, 0);
        throw _error;
      }
    })();

    const wrapped = operation.finally(() => {
      pendingMap.delete(pseudonym);
    });
    pendingMap.set(pseudonym, wrapped);
    return wrapped;
  }, [conversations, currentUsername, removedConversations, selectedConversation, users, secureDB]);

  const selectConversation = useCallback((username: string) => {
    if (!username || typeof username !== 'string') {
      return;
    }

    if (selectedConversation !== username) {
      setSelectedConversation(username);
      setConversations(prev => prev.map(conv =>
        conv.username === username ? { ...conv, unreadCount: 0 } : conv
      ));
    }
  }, [selectedConversation]);

  useEffect(() => {
    return () => {
      eventCleanupRef.current.forEach(cleanup => cleanup());
      eventCleanupRef.current.clear();
    };
  }, []);

  const getConversationMessages = useCallback((conversationUsername?: string) => {
    if (!conversationUsername) return [];

    const filtered = messages.filter(msg =>
      (msg.sender === conversationUsername && msg.recipient === currentUsername) ||
      (msg.sender === currentUsername && msg.recipient === conversationUsername)
    );

    return filtered;
  }, [messages, currentUsername]);

  const userLookup = useMemo(() => {
    const lookup = new Map<string, boolean>();
    for (const user of users) {
      lookup.set(user.username, user.isOnline);
    }
    return lookup;
  }, [users]);

  useEffect(() => {
    setConversations(prev => {
      let hasChanges = false;
      const updated = prev.map(conv => {
        const isOnline = userLookup.get(conv.username) ?? false;
        if (conv.isOnline !== isOnline) {
          hasChanges = true;
          return { ...conv, isOnline };
        }
        return conv;
      });
      return hasChanges ? updated : prev;
    });
  }, [userLookup]);

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
      const isOnline = userLookup.get(other) ?? false;
      const msgTime = new Date(msg.timestamp);
      const unreadIncrement = (msg.sender !== currentUsername && (!msg.receipt || !msg.receipt.read)) ? 1 : 0;

      let conv = convMap.get(other);
      if (!conv) {
        const displayName = (msg.sender === other && msg.fromOriginal) ? msg.fromOriginal : undefined;
        conv = {
          id: crypto.randomUUID(),
          username: other,
          isOnline,
          lastMessage: getConversationPreview(msg, currentUsername),
          lastMessageTime: msgTime,
          unreadCount: unreadIncrement,
          secureContentId: msg.secureContentId || msg.id,
          displayName
        };
        convMap.set(other, conv);
      } else {
        if (unreadIncrement > 0) {
          convMap.set(other, {
            ...conv,
            unreadCount: (conv.unreadCount || 0) + unreadIncrement
          });
        }
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
        if (exists) {
          merged.set(username, {
            ...exists,
            isOnline: conv.isOnline,
            lastMessage: conv.lastMessage,
            lastMessageTime: conv.lastMessageTime,
            unreadCount: username === selectedConversation ? 0 : conv.unreadCount,
            secureContentId: conv.secureContentId,
            displayName: exists.displayName || conv.displayName
          });
        } else {
          merged.set(username, conv);
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
            p.isOnline !== c.isOnline ||
            (p.lastMessage || '') !== (c.lastMessage || '') ||
            pTime !== cTime ||
            (p.unreadCount || 0) !== (c.unreadCount || 0) ||
            (p.displayName || '') !== (c.displayName || '')
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

    if (secureDB) {
      const usernames = Array.from(convMap.keys());
      Promise.allSettled(
        usernames.map(async (u) => {
          try {
            const original = await secureDB.getOriginalUsername(u);
            return original && typeof original === 'string' ? { username: u, displayName: original } : null;
          } catch {
            return null;
          }
        })
      ).then(results => {
        const resolvedMap = new Map<string, string>();
        for (const result of results) {
          if (result.status === 'fulfilled' && result.value) {
            resolvedMap.set(result.value.username, result.value.displayName);
          }
        }

        if (resolvedMap.size > 0) {
          setConversations(prev =>
            prev.map(c => {
              const resolved = resolvedMap.get(c.username);
              return resolved ? { ...c, displayName: resolved } : c;
            })
          );
        }
      });
    }
  }, [messages, currentUsername, selectedConversation, removedConversations, userLookup, secureDB]);

  // Auto-selection of first conversation removed as per user request
  /*
  useEffect(() => {
    if (!selectedConversation && conversations.length > 0) {
      const firstConversationUsername = conversations[0].username;
      if (selectedConversation !== firstConversationUsername) {
        setSelectedConversation(firstConversationUsername);
      }
    }
  }, [conversations, selectedConversation]);
  */

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

  return {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    removeConversation,
    getConversationMessages,
  };
}
