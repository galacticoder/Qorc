/**
 * useConversations Hook
 */

import { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { Conversation } from "../components/chat/ConversationList";
import { Message } from "../components/chat/types";
import { User } from "../components/chat/UserList";
import { SignalType } from "../lib/signal-types";
import websocketClient from "../lib/websocket";
import { pseudonymizeUsernameWithCache } from "../lib/username-hash";
import { SecureDB } from "../lib/secureDB";
import { sanitizeEventPayload, sanitizeTextInput } from "../lib/sanitizers";

// Constants for validation
const MAX_PREVIEW_LENGTH = 80;
const MIN_USERNAME_LENGTH = 2;
const MAX_USERNAME_LENGTH = 64;
const USERNAME_PATTERN = /^[a-zA-Z0-9._-]{2,64}$/;
const PSEUDONYM_PATTERN = /^[a-f0-9]{32,}$/i;
const MAX_CONVERSATIONS = 1000;

// Rate limiting
const CONVERSATION_RATE_LIMIT_WINDOW_MS = 10_000;
const CONVERSATION_RATE_LIMIT_MAX = 8;
const VALIDATION_TIMEOUT_MS = 15_000;

// Dispatch sanitized events only
const dispatchSafeEvent = (name: string, detail: Record<string, unknown>, allowedKeys?: string[]): void => {
  try {
    const sanitized = sanitizeEventPayload(detail, allowedKeys);
    window.dispatchEvent(new CustomEvent(name, { detail: sanitized }));
  } catch (_error) {
    console.error(`[useConversations] Failed to dispatch event ${name}:`, _error);
  }
};

const sanitizePreviewText = (input: string | undefined | null): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  const clean = sanitizeTextInput(input, { maxLength: MAX_PREVIEW_LENGTH, allowNewlines: false });
  return clean.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
};

// Generate safe preview text from message
const getConversationPreview = (message: Message, currentUsername: string): string => {
  const filename = sanitizePreviewText(message.filename);
  const isMe = message.sender === currentUsername;
  const prefix = isMe ? 'You sent' : `${message.sender} sent`;

  if (message.type === 'file' || message.type === 'file-message' || filename) {
    if (filename && filename.match(/\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff)$/i)) {
      return `${prefix} an image`;
    }
    if (filename && filename.match(/\.(mp4|webm|ogg|avi|mov|wmv|flv|mkv)$/i)) {
      return `${prefix} a video`;
    }
    if (filename && (filename.toLowerCase().includes('voice-note') || filename.match(/\.(mp3|wav|ogg|webm|m4a|aac|flac)$/i))) {
      return `${prefix} a voice message`;
    }
    return `${prefix} a file`;
  }

  return sanitizePreviewText(message.content);
};

// Validate username format
const isValidUsername = (username: string): boolean => {
  if (!username || typeof username !== 'string') return false;
  if (username.length < MIN_USERNAME_LENGTH || username.length > MAX_USERNAME_LENGTH) return false;
  return USERNAME_PATTERN.test(username);
};

// Check if string looks like a pseudonym hash
const isPseudonymHash = (value: string): boolean => {
  return PSEUDONYM_PATTERN.test(value);
};

const createConversation = (username: string, isOnline: boolean): Conversation => ({
  id: crypto.randomUUID(),
  username,
  isOnline,
  lastMessage: undefined,
  lastMessageTime: undefined,
  unreadCount: 0
});

export const useConversations = (currentUsername: string, users: User[], messages: Message[], secureDB: SecureDB | null) => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [removedConversations, setRemovedConversations] = useState<Set<string>>(new Set());

  // Rate limiting state
  const rateStateRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });
  const pendingAddsRef = useRef<Map<string, Promise<Conversation | null>>>(new Map());

  const eventCleanupRef = useRef<Map<string, () => void>>(new Map());

  const addConversation = useCallback(async (username: string, autoSelect: boolean = true): Promise<Conversation | null> => {
    // Require SecureDB for operations 
    if (!secureDB) {
      throw new Error('[useConversations] SecureDB is required - cannot add conversation');
    }
    const trimmed = username?.trim();
    if (!trimmed) {
      throw new Error('[useConversations] Username cannot be empty');
    }

    // Check if it looks like a pseudonym or validate as username
    const looksLikePseudonym = isPseudonymHash(trimmed);
    if (!looksLikePseudonym && !isValidUsername(trimmed)) {
      throw new Error('[useConversations] Invalid username format (2-64 chars, alphanumeric/._- only)');
    }

    // Prevent adding too many conversations
    if (conversations.length >= MAX_CONVERSATIONS) {
      throw new Error('[useConversations] Maximum conversation limit reached');
    }

    const pseudonym = looksLikePseudonym ? trimmed.toLowerCase() : await pseudonymizeUsernameWithCache(trimmed, secureDB || undefined);

    // Prevent self-conversation
    if (pseudonym === currentUsername) {
      throw new Error('[useConversations] Cannot create conversation with yourself');
    }

    const pendingMap = pendingAddsRef.current;
    if (pendingMap.has(pseudonym)) {
      return pendingMap.get(pseudonym)!;
    }

    // Rate limiting to prevent DoS
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
        // Store username mapping in encrypted database
        if (!looksLikePseudonym && trimmed !== pseudonym) {
          try {
            await secureDB.storeUsernameMapping(pseudonym, trimmed);
            dispatchSafeEvent('username-mapping-updated', { username: pseudonym, original: trimmed }, ['username', 'original']);
          } catch (_error) {
            console.error('[useConversations] Failed to store username mapping:', _error);
            throw new Error('[useConversations] Failed to store username mapping');
          }
        }

        // Restore conversation if it was removed
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

        // Validate user existence with server
        return await new Promise<Conversation | null>((resolve, reject) => {
          let timeoutId: number | null = null;
          let resolved = false;

          // Cleanup function to prevent memory leaks
          const cleanup = () => {
            if (timeoutId !== null) {
              clearTimeout(timeoutId);
              timeoutId = null;
            }
            window.removeEventListener('user-exists-response', handleUserExistsResponse as EventListener);
            eventCleanupRef.current.delete(pseudonym);
          };

          const handleUserExistsResponse = (event: Event) => {
            if (resolved) return;

            const customEvent = event as CustomEvent;
            const detail = typeof customEvent.detail === 'object' && customEvent.detail !== null ? customEvent.detail : {};
            const { username: responseUsername, exists, error, hybridPublicKeys } = detail as { username?: string; exists?: boolean; error?: string; hybridPublicKeys?: any };

            // Case-insensitive username comparison
            if ((responseUsername || '').toLowerCase() !== pseudonym.toLowerCase()) {
              return;
            }

            resolved = true;
            cleanup();

            // Handle errors
            if (error) {
              reject(new Error(`User validation failed: ${error}`));
              return;
            }

            if (!exists) {
              reject(new Error('User does not exist'));
              return;
            }

            // Dispatch key availability event
            if (hybridPublicKeys) {
              try {
                dispatchSafeEvent('user-keys-available', { username: pseudonym, hybridKeys: hybridPublicKeys }, ['username', 'hybridKeys']);
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

          // Register event listener
          window.addEventListener('user-exists-response', handleUserExistsResponse as EventListener);

          // Send validation request
          try {
            websocketClient.send(
              JSON.stringify({
                type: SignalType.CHECK_USER_EXISTS,
                username: pseudonym
              })
            );
          } catch (_error) {
            resolved = true;
            cleanup();
            console.error('Failed to send check-user-exists:', _error);
            reject(new Error('Failed to validate user'));
            return;
          }

          // Timeout for validation
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
    // Validate username
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

  // Cleanup event listeners on unmount
  useEffect(() => {
    return () => {
      // Clean up all pending event listeners
      eventCleanupRef.current.forEach(cleanup => cleanup());
      eventCleanupRef.current.clear();
    };
  }, []);

  // Get messages for the selected conversation
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
    if (!messages || messages.length === 0) {
      return;
    }

    const convMap = new Map<string, Conversation>();

    // Optimization: Iterate backwards to find latest messages first
    // This avoids updating the 'lastMessage' repeatedly for every message in the history
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i];
      // Validate message structure
      if (!msg.sender || !msg.recipient) continue;

      const content = msg.content;
      if (content && (content.includes('"type":"typing-') ||
        content.includes('delivery-receipt') ||
        content.includes('read-receipt'))) {
        continue;
      }

      const other = msg.sender === currentUsername ? msg.recipient : msg.sender;
      const isOnline = userLookup.get(other) ?? false;
      const msgTime = new Date(msg.timestamp);
      const unreadIncrement = (msg.sender !== currentUsername && (!msg.receipt || !msg.receipt.read)) ? 1 : 0;

      let conv = convMap.get(other);
      if (!conv) {
        // First time seeing this peer (scanning from newest), so this is the latest message
        conv = {
          id: crypto.randomUUID(), // Will be overwritten by existing ID in merge step
          username: other,
          isOnline,
          lastMessage: getConversationPreview(msg, currentUsername),
          lastMessageTime: msgTime,
          unreadCount: unreadIncrement
        };
        convMap.set(other, conv);
      } else {
        // Already have the latest message, just update unread count
        if (unreadIncrement > 0) {
          convMap.set(other, {
            ...conv,
            unreadCount: (conv.unreadCount || 0) + unreadIncrement
          });
        }
      }
    }

    // Determine which removed conversations should be restored based on new activity
    const toRestore: string[] = [];
    for (const username of convMap.keys()) {
      if (removedConversations.has(username)) {
        toRestore.push(username);
      }
    }

    // First, restore removed conversations
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
        merged.set(c.username, c);
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

  useEffect(() => {
    if (!selectedConversation && conversations.length > 0) {
      const firstConversationUsername = conversations[0].username;
      if (selectedConversation !== firstConversationUsername) {
        setSelectedConversation(firstConversationUsername);
      }
    }
  }, [conversations, selectedConversation]);

  // Remove conversation with validation
  const removeConversation = useCallback((username: string, clearMessages: boolean = true) => {
    if (!username || typeof username !== 'string') {
      return;
    }

    setConversations(prev => prev.filter(conv => conv.username !== username));
    setRemovedConversations(prev => new Set(prev).add(username));

    if (selectedConversation === username) {
      setSelectedConversation(null);
    }

    // Clear messages from UI
    if (clearMessages) {
      dispatchSafeEvent('clear-conversation-messages', { username }, ['username']);
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