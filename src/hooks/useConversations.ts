import { useState, useCallback, useEffect, useMemo } from "react";
import { Conversation } from "@/components/chat/ConversationList";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";

export function useConversations(currentUsername: string, users: User[], messages: Message[]) {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);

  // Add a new conversation
  const addConversation = useCallback((username: string) => {
    if (!username || username === currentUsername) return;
    
    // Check if conversation already exists
    const existingConversation = conversations.find(conv => conv.username === username);
    if (existingConversation) {
      setSelectedConversation(username);
      return;
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
    setSelectedConversation(username);
  }, [conversations, users, currentUsername]);

  // Select a conversation
  const selectConversation = useCallback((username: string) => {
    setSelectedConversation(username);
    // Mark messages as read for this conversation
    setConversations(prev => prev.map(conv => 
      conv.username === username ? { ...conv, unreadCount: 0 } : conv
    ));
  }, []);

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

  // Rebuild conversations when messages change (handles initial load and subsequent updates)
  useEffect(() => {
    if (!messages || messages.length === 0) {
      setConversations(prev => prev.length ? [] : prev);
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
        existing.unreadCount += unreadIncrement;
        existing.isOnline = isOnline;
      }
    }

    // Convert to array and normalize unread for selected conversation
    let rebuilt = Array.from(convMap.values()).map(conv => (
      conv.username === selectedConversation ? { ...conv, unreadCount: 0 } : conv
    ));

    // Sort by latest activity
    rebuilt.sort((a, b) => (b.lastMessageTime?.getTime() || 0) - (a.lastMessageTime?.getTime() || 0));

    setConversations(rebuilt);
  }, [messages, users, currentUsername, selectedConversation]);

  // Auto-select the most recent conversation on initial rebuild if none selected
  useEffect(() => {
    if (!selectedConversation && conversations.length > 0) {
      setSelectedConversation(conversations[0].username);
    }
  }, [conversations, selectedConversation]);

  return {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    getConversationMessages,
  };
}
