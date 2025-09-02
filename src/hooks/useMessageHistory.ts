import { useEffect, useCallback, useRef } from 'react';
import { Message } from '@/components/chat/types';
import { SignalType } from '@/lib/signals';
import websocketClient from '@/lib/websocket';

export function useMessageHistory(
  currentUsername: string,
  isLoggedIn: boolean,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
  const hasRequestedHistory = useRef(false);
  const isProcessingHistory = useRef(false);

  // Request message history from server after successful authentication
  const requestMessageHistory = useCallback((limit: number = 50, since?: number) => {
    if (!isLoggedIn || !currentUsername) {
      console.log('[MessageHistory] Cannot request history - not logged in');
      return;
    }

    if (hasRequestedHistory.current && !since) {
      console.log('[MessageHistory] History already requested for this session');
      return;
    }

    try {
      console.log(`[MessageHistory] Requesting message history for user: ${currentUsername}`);
      
      const request = {
        type: SignalType.REQUEST_MESSAGE_HISTORY,
        limit,
        ...(since ? { since } : {})
      };

      websocketClient.send(JSON.stringify(request));
      
      if (!since) {
        hasRequestedHistory.current = true;
      }
      
      console.log(`[MessageHistory] History request sent - limit: ${limit}${since ? `, since: ${since}` : ''}`);
    } catch (error) {
      console.error('[MessageHistory] Failed to request message history:', error);
    }
  }, [isLoggedIn, currentUsername]);

  // Handle message history response from server
  const handleMessageHistory = useCallback(async (data: any) => {
    if (isProcessingHistory.current) {
      console.log('[MessageHistory] Already processing history, skipping duplicate');
      return;
    }

    isProcessingHistory.current = true;

    try {
      const { messages: serverMessages, hasMore, timestamp } = data;
      
      if (!Array.isArray(serverMessages)) {
        console.error('[MessageHistory] Invalid message history format');
        return;
      }

      console.log(`[MessageHistory] Processing ${serverMessages.length} historical messages`);

      // Convert server messages to UI format
      const processedMessages: Message[] = serverMessages.map((serverMsg: any) => {
        // Parse the nested payload if it's a string
        let payload = serverMsg.payload;
        if (typeof payload === 'string') {
          try {
            payload = JSON.parse(payload);
          } catch (error) {
            console.error('[MessageHistory] Failed to parse message payload:', error);
            return null;
          }
        }

        // Validate and extract ID
        const id = serverMsg.messageId || payload?.messageId;
        if (!id) {
          console.warn('[MessageHistory] Skipping message with missing ID');
          return null;
        }

        // Validate and parse timestamp
        const timestampValue = serverMsg.timestamp || payload?.timestamp;
        if (!timestampValue) {
          console.warn('[MessageHistory] Skipping message with missing timestamp');
          return null;
        }
        const timestamp = new Date(timestampValue);
        if (isNaN(timestamp.getTime())) {
          console.warn('[MessageHistory] Skipping message with invalid timestamp:', timestampValue);
          return null;
        }

        // Validate content
        const content = payload?.encryptedContent || payload?.content;
        if (!content || (typeof content === 'string' && content.trim() === '')) {
          console.warn('[MessageHistory] Skipping message with empty/invalid content');
          return null;
        }

        return {
          id,
          content,
          sender: serverMsg.fromUsername || payload.fromUsername,
          recipient: serverMsg.toUsername || payload.toUsername,
          timestamp,
          type: payload.messageType || 'text',
          isCurrentUser: (serverMsg.fromUsername || payload.fromUsername) === currentUsername,
          encrypted: true,
          transport: 'websocket',
          p2p: false,
          // Restore receipt information if available
          receipt: payload.receipt ? {
            ...payload.receipt,
            deliveredAt: payload.receipt.deliveredAt ? new Date(payload.receipt.deliveredAt) : undefined,
            readAt: payload.receipt.readAt ? new Date(payload.receipt.readAt) : undefined,
          } : undefined,
          // Restore reply information if available
          replyTo: payload.replyTo ? {
            id: payload.replyTo.id,
            content: payload.replyTo.content,
            sender: payload.replyTo.sender
          } : undefined
        };
      }).filter(Boolean); // Remove any null entries from validation failures

      // Get current messages to check for duplicates
      setMessages(currentMessages => {
        // Create a map of existing message IDs for fast lookup
        const existingIds = new Set(currentMessages.map(msg => msg.id));
        
        // Filter out messages that already exist
        const newMessages = processedMessages.filter(msg => !existingIds.has(msg.id));
        
        if (newMessages.length === 0) {
          console.log('[MessageHistory] No new messages to add (all duplicates)');
          return currentMessages;
        }

        console.log(`[MessageHistory] Adding ${newMessages.length} new historical messages`);

        // Sort all messages by timestamp to maintain chronological order
        const allMessages = [...currentMessages, ...newMessages].sort(
          (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
        );

        // Save new messages to local DB
        newMessages.forEach(async (msg) => {
          try {
            await saveMessageToLocalDB(msg);
          } catch (error) {
            console.error('[MessageHistory] Failed to save historical message to local DB:', error);
          }
        });

        return allMessages;
      });

      console.log(`[MessageHistory] Message history processing complete. Has more: ${hasMore}`);
      
      // TODO: Implement pagination if hasMore is true and user requests it
      
    } catch (error) {
      console.error('[MessageHistory] Error processing message history:', error);
    } finally {
      isProcessingHistory.current = false;
    }
  }, [currentUsername, setMessages, saveMessageToLocalDB]);

  // Auto-request message history on login
  useEffect(() => {
    if (isLoggedIn && currentUsername && !hasRequestedHistory.current) {
      // Small delay to ensure authentication is fully complete
      const timer = setTimeout(() => {
        requestMessageHistory(50); // Request last 50 messages
      }, 1000);

      return () => clearTimeout(timer);
    }
  }, [isLoggedIn, currentUsername, requestMessageHistory]);

  // Reset flag when user logs out
  useEffect(() => {
    if (!isLoggedIn) {
      hasRequestedHistory.current = false;
      isProcessingHistory.current = false;
    }
  }, [isLoggedIn]);

  return {
    requestMessageHistory,
    handleMessageHistory
  };
}