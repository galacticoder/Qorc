import { useState, useCallback, useEffect, useMemo } from "react";
import { Conversation } from "../components/chat/ConversationList";
import { Message } from "../components/chat/types";
import { User } from "../components/chat/UserList";
import { SignalType } from "../lib/signals";
import websocketClient from "../lib/websocket";
import { pseudonymizeUsernameWithCache } from "../lib/username-hash";
import { SecureDB } from "../lib/secureDB";
import { formatFileSize } from "../components/chat/ChatMessage/FileMessage";

// Helper function to generate appropriate conversation preview for different message types
const getConversationPreview = (message: Message): string => {
  const MAX_PREVIEW_LENGTH = 40; // Maximum characters for preview

  // Handle file messages
  if (message.type === 'file' || message.type === 'file-message' || message.filename) {
    let preview = '';

    // For images
    if (message.filename && /\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff)$/i.test(message.filename)) {
      preview = `📷 ${message.filename}`;
    }
    // For videos
    else if (message.filename && /\.(mp4|webm|ogg|avi|mov|wmv|flv|mkv)$/i.test(message.filename)) {
      preview = `🎬 ${message.filename}`;
    }
    // For voice notes
    else if (message.filename && (message.filename.toLowerCase().includes('voice-note') || /\.(mp3|wav|ogg|webm|m4a|aac|flac)$/i.test(message.filename))) {
      preview = `🎤 Voice message`;
    }
    // For other files
    else {
      const filename = message.filename || 'File';
      preview = `📎 ${filename}`;
    }

    // Truncate if too long
    return preview.length > MAX_PREVIEW_LENGTH
      ? preview.substring(0, MAX_PREVIEW_LENGTH - 3) + '...'
      : preview;
  }

  // For regular text messages, truncate if needed
  const content = message.content || '';
  return content.length > MAX_PREVIEW_LENGTH
    ? content.substring(0, MAX_PREVIEW_LENGTH - 3) + '...'
    : content;
};

export const useConversations = (currentUsername: string, users: User[], messages: Message[], secureDB?: SecureDB) => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [removedConversations, setRemovedConversations] = useState<Set<string>>(new Set());

  // Add a new conversation with user validation (use pseudonymized username for server)
  const addConversation = useCallback((username: string, autoSelect: boolean = true): Promise<Conversation | null> => {
    return new Promise(async (resolve, reject) => {
      try {
        if (!username) {
          resolve(null);
          return;
        }

        // Compute pseudonym for this username; server must never see original
        const pseudonym = await pseudonymizeUsernameWithCache(username);

        if (pseudonym === currentUsername) {
          resolve(null);
          return;
        }

        // Store username mapping for display purposes if we have secureDB
        if (secureDB && username !== pseudonym) {
          try {
            console.log(`[useConversations] Storing username mapping: ${pseudonym} -> ${username}`);
            await secureDB.storeUsernameMapping(pseudonym, username);
          } catch (error) {
            console.error('[useConversations] Failed to store username mapping:', error);
          }
        }

        // If this conversation was previously removed, allow re-adding it
        if (removedConversations.has(pseudonym)) {
          setRemovedConversations(prev => {
            const newSet = new Set(prev);
            newSet.delete(pseudonym);
            return newSet;
          });
        }

        // Check if conversation already exists by pseudonym
        const existingConversation = conversations.find(conv => conv.username === pseudonym);
        if (existingConversation) {
          if (autoSelect) {
            setSelectedConversation(pseudonym);
          }
          resolve(existingConversation);
          return;
        }

        let timeoutId: number | null = null;

        // Validate user exists before creating conversation
        const handleUserExistsResponse = (event: CustomEvent) => {
          const { username: responseUsername, exists, error } = event.detail;

          if (responseUsername !== pseudonym) return; // Not for this request

          // Remove event listener and clear timeout
          window.removeEventListener('user-exists-response', handleUserExistsResponse as EventListener);
          if (timeoutId !== null) {
            clearTimeout(timeoutId);
            timeoutId = null;
          }

          if (error) {
            console.error('[useConversations] Error checking user existence:', error);
            reject(new Error(`Failed to validate user: ${error}`));
            return;
          }

          if (!exists) {
            console.warn('[useConversations] User does not exist (pseudonym):', pseudonym);
            reject(new Error(`User does not exist. Please check the username and try again.`));
            return;
          }

          // User exists, create conversation (store pseudonym as the key)
          const newConversation: Conversation = {
            id: crypto.randomUUID(),
            username: pseudonym,
            isOnline: users.some(user => user.username === pseudonym && user.isOnline),
            lastMessage: undefined,
            lastMessageTime: undefined,
            unreadCount: 0
          };

          setConversations(prev => [...prev, newConversation]);
          if (autoSelect && selectedConversation !== pseudonym) {
            setSelectedConversation(pseudonym);
          }
          resolve(newConversation);
        };

        // Listen for response
        window.addEventListener('user-exists-response', handleUserExistsResponse as EventListener);

        // Send request to check if user exists (send only pseudonym)
        try {
          websocketClient.send(JSON.stringify({
            type: SignalType.CHECK_USER_EXISTS,
            username: pseudonym
          }));
        } catch (error) {
          window.removeEventListener('user-exists-response', handleUserExistsResponse as EventListener);
          if (timeoutId !== null) {
            clearTimeout(timeoutId);
            timeoutId = null;
          }
          console.error('[useConversations] Failed to send user existence check:', error);
          reject(new Error('Failed to validate user existence. Please try again.'));
          return;
        }

        // Set timeout to prevent hanging
        timeoutId = window.setTimeout(() => {
          window.removeEventListener('user-exists-response', handleUserExistsResponse as EventListener);
          timeoutId = null;
          reject(new Error('User validation timed out. Please try again.'));
        }, 10000); // 10 second timeout
      } catch (err) {
        console.error('[useConversations] Failed to pseudonymize username:', err);
        reject(new Error('Failed to prepare conversation. Please try again.'));
      }
    });
  }, [conversations, users, currentUsername, selectedConversation, removedConversations]);

  // Select a conversation
  const selectConversation = useCallback((username: string) => {
    // Only update state if the conversation is actually changing
    if (selectedConversation !== username) {
      setSelectedConversation(username);
      // Mark messages as read for this conversation
      setConversations(prev => prev.map(conv => 
        conv.username === username ? { ...conv, unreadCount: 0 } : conv
      ));
    }
  }, [selectedConversation]);

  // Get messages for the selected conversation
  const getConversationMessages = useCallback((conversationUsername?: string) => {
    if (!conversationUsername) return [];
    
    return messages.filter(msg => 
      (msg.sender === conversationUsername && msg.recipient === currentUsername) ||
      (msg.sender === currentUsername && msg.recipient === conversationUsername)
    );
  }, [messages, currentUsername]);

  // Memoize user lookup for better performance
  const userLookup = useMemo(() => {
    const lookup = new Map<string, boolean>();
    users.forEach(user => lookup.set(user.username, user.isOnline));
    return lookup;
  }, [users]);

  // Update conversations when users change (online status) - optimized
  useEffect(() => {
    setConversations(prev => {
      let hasChanges = false;
      const updated = prev.map(conv => {
        const isOnline = userLookup.get(conv.username) || false;
        if (conv.isOnline !== isOnline) {
          hasChanges = true;
          return { ...conv, isOnline };
        }
        return conv;
      });
      return hasChanges ? updated : prev;
    });
  }, [userLookup]);

  // Rebuild/merge conversations when messages change (keep manually added ones)
  useEffect(() => {
    if (!messages || messages.length === 0) {
      // Do not clear manually added conversations when there are no messages yet
      setConversations(prev => prev);
      return;
    }

    // Build conversation map from all messages so existing conversations appear after relogin
    const convMap = new Map<string, Conversation>();

    for (const msg of messages) {
      if (!msg.sender || !msg.recipient) continue;
      
      // Skip typing indicators and receipts for conversation creation
      if (msg.content?.includes('"type":"typing-') || 
          msg.content?.includes('delivery-receipt') || 
          msg.content?.includes('read-receipt')) {
        continue;
      }

      const other = msg.sender === currentUsername ? msg.recipient : msg.sender;
      const isOnline = users.some(user => user.username === other && user.isOnline);
      const msgTime = new Date(msg.timestamp);
      const unreadIncrement = (msg.sender !== currentUsername && (!msg.receipt || !msg.receipt.read)) ? 1 : 0;

      const existing = convMap.get(other);
      if (!existing) {
        convMap.set(other, {
          id: crypto.randomUUID(),
          username: other,
          isOnline,
          lastMessage: getConversationPreview(msg),
          lastMessageTime: msgTime,
          unreadCount: unreadIncrement
        });
      } else {
        // Update last message info if this message is newer
        if (!existing.lastMessageTime || msgTime > existing.lastMessageTime) {
          existing.lastMessage = getConversationPreview(msg);
          existing.lastMessageTime = msgTime;
        }
        existing.unreadCount = (existing.unreadCount || 0) + unreadIncrement;
        existing.isOnline = isOnline;
      }
    }

    // Merge rebuilt map with existing conversations, preserving manually added ones
    setConversations(prev => {
      const merged = new Map<string, Conversation>(prev.map(c => [c.username, c]));

      for (const [username, conv] of convMap.entries()) {
        // For conversations that were manually removed, restore them when receiving new messages
        if (removedConversations.has(username)) {
          // Always restore if there's any message activity (like modern chat apps)
          setRemovedConversations(prevRemoved => {
            const newSet = new Set(prevRemoved);
            newSet.delete(username);
            return newSet;
          });
          merged.set(username, conv);
          continue;
        }
        
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

      const arr = Array.from(merged.values());
      // Sort by latest activity; manual conversations without messages come last
      arr.sort((a, b) => (b.lastMessageTime?.getTime() || 0) - (a.lastMessageTime?.getTime() || 0));
      return arr;
    });
  }, [messages, users, currentUsername, selectedConversation, removedConversations]);

  // Auto-select the most recent conversation on initial rebuild if none selected
  useEffect(() => {
    if (!selectedConversation && conversations.length > 0) {
      const firstConversationUsername = conversations[0].username;
      if (selectedConversation !== firstConversationUsername) {
        setSelectedConversation(firstConversationUsername);
      }
    }
  }, [conversations, selectedConversation]);

  // Debug conversation state
  const debugConversationState = useCallback(() => {
    console.log('[useConversations] Current state:', {
      conversationsCount: conversations.length,
      conversations: conversations.map(c => ({
        username: c.username,
        lastMessage: c.lastMessage?.substring(0, 50),
        unreadCount: c.unreadCount,
        isOnline: c.isOnline
      })),
      selectedConversation,
      currentUsername,
      usersCount: users.length,
      messagesCount: messages.length
    });
  }, [conversations, selectedConversation, currentUsername, users.length, messages.length]);

  // Remove a conversation (like hiding/archiving in modern chat apps)
  const removeConversation = useCallback((username: string, clearMessages: boolean = true) => {
    setConversations(prev => prev.filter(conv => conv.username !== username));
    // Track that this conversation was manually removed (soft delete)
    setRemovedConversations(prev => new Set(prev).add(username));
    // If we're removing the currently selected conversation, clear selection
    if (selectedConversation === username) {
      setSelectedConversation(null);
    }
    
    // Clear messages for this conversation if requested
    if (clearMessages) {
      // Dispatch event to clear messages for this conversation
      window.dispatchEvent(new CustomEvent('clear-conversation-messages', { 
        detail: { username } 
      }));
    }
  }, [selectedConversation]);

  // Clear conversation removal status (for when user wants to unarchive)
  const clearConversationRemoval = useCallback((username: string) => {
    setRemovedConversations(prev => {
      const newSet = new Set(prev);
      newSet.delete(username);
      return newSet;
    });
  }, []);

  return {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    removeConversation,
    getConversationMessages,
    debugConversationState,
  };
}