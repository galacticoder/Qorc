import { useState, useCallback, useEffect, useMemo } from "react";
import { Conversation } from "@/components/chat/ConversationList";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";

export function useConversations(currentUsername: string, users: User[], messages: Message[]) {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);

  // Add a new conversation
  const addConversation = useCallback((username: string, autoSelect: boolean = true) => {
    if (!username || username === currentUsername) return;
    
    // Check if conversation already exists
    const existingConversation = conversations.find(conv => conv.username === username);
    if (existingConversation) {
      if (autoSelect && selectedConversation !== username) {
        setSelectedConversation(username);
      }
      return existingConversation;
    }

    // Create new conversation
    const newConversation: Conversation = {
      id: crypto.randomUUID(),
      username,
      isOnline: users.some(user => user.username === username && user.isOnline),
      lastMessage: undefined,
      lastMessageTime: undefined,
      unreadCount: 0
    };

    setConversations(prev => [...prev, newConversation]);
    if (autoSelect && selectedConversation !== username) {
      setSelectedConversation(username);
    }
    return newConversation;
  }, [conversations, users, currentUsername, selectedConversation]);

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
          lastMessage: msg.content,
          lastMessageTime: msgTime,
          unreadCount: unreadIncrement
        });
      } else {
        // Update last message info if this message is newer
        if (!existing.lastMessageTime || msgTime > existing.lastMessageTime) {
          existing.lastMessage = msg.content;
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
  }, [messages, users, currentUsername, selectedConversation]);

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

  return {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    getConversationMessages,
    debugConversationState,
  };
}
