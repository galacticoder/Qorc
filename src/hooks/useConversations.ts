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

  // Update conversations when messages change
  useEffect(() => {
    if (messages.length === 0) return;

    const latestMessage = messages[messages.length - 1];
    if (!latestMessage.sender || !latestMessage.recipient) return;

    const conversationUsername = latestMessage.sender === currentUsername 
      ? latestMessage.recipient 
      : latestMessage.sender;

    setConversations(prev => {
      const existingIndex = prev.findIndex(conv => conv.username === conversationUsername);
      
      if (existingIndex >= 0) {
        const updated = [...prev];
        updated[existingIndex] = {
          ...updated[existingIndex],
          lastMessage: latestMessage.content,
          lastMessageTime: new Date(latestMessage.timestamp),
          unreadCount: selectedConversation === conversationUsername ? 0 : (updated[existingIndex].unreadCount || 0) + 1
        };
        return updated;
      } else {
        // Create new conversation if it doesn't exist
        const newConversation: Conversation = {
          id: crypto.randomUUID(),
          username: conversationUsername,
          isOnline: users.some(user => user.username === conversationUsername && user.isOnline),
          lastMessage: latestMessage.content,
          lastMessageTime: new Date(latestMessage.timestamp),
          unreadCount: selectedConversation === conversationUsername ? 0 : 1
        };
        return [...prev, newConversation];
      }
    });
  }, [messages, selectedConversation, users, currentUsername]);

  return {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    getConversationMessages,
  };
}
