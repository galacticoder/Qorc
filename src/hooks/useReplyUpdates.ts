import { useCallback, useEffect, useRef } from 'react';
import { Message } from '@/components/chat/types';

/**
 * Hook for managing efficient reply field updates when messages are edited
 * Maintains a reverse mapping of messageId -> [replyingMessageIds] for O(1) lookups
 */
export const useReplyUpdates = (
  messages: Message[],
  onMessagesUpdate: (updatedMessages: Message[]) => void
) => {
  // Reverse mapping: original message ID -> array of message IDs that reply to it
  const replyMappingRef = useRef<Map<string, string[]>>(new Map());
  
  // Index of messages by ID for fast lookup
  const messageIndexRef = useRef<Map<string, number>>(new Map());

  // Build and maintain the reply mapping whenever messages change
  useEffect(() => {
    const replyMapping = new Map<string, string[]>();
    const messageIndex = new Map<string, number>();

    messages.forEach((message, index) => {
      // Build message index for fast lookup
      messageIndex.set(message.id, index);

      // Build reply mapping
      if (message.replyTo?.id) {
        const replyToId = message.replyTo.id;
        if (!replyMapping.has(replyToId)) {
          replyMapping.set(replyToId, []);
        }
        replyMapping.get(replyToId)!.push(message.id);
      }
    });

    replyMappingRef.current = replyMapping;
    messageIndexRef.current = messageIndex;
  }, [messages]);

  // Function to update reply fields when a message is edited
  const updateReplyFields = useCallback((editedMessageId: string, newContent: string) => {
    const replyingMessageIds = replyMappingRef.current.get(editedMessageId);
    
    if (!replyingMessageIds || replyingMessageIds.length === 0) {
      // No messages reply to this one, nothing to update
      return;
    }

    // Use the callback to get fresh message state and update reply fields
    onMessagesUpdate(currentMessages => {
      // Find the edited message in the current (fresh) message state
      const editedMessage = currentMessages.find(msg => msg.id === editedMessageId);
      if (!editedMessage) {
        console.warn('[ReplyUpdates] Could not find edited message in current state:', editedMessageId);
        return currentMessages; // Return unchanged if message not found
      }

      // Create updated messages array with efficient updates
      let hasUpdates = false;
      const updatedMessages = currentMessages.map(msg => {
        // Check if this message replies to the edited message
        if (replyingMessageIds.includes(msg.id) && msg.replyTo?.id === editedMessageId) {
          hasUpdates = true;
          console.log(`[ReplyUpdates] Updated reply field for message ${msg.id} -> references ${editedMessageId}`);
          return {
            ...msg,
            replyTo: {
              ...msg.replyTo,
              content: newContent, // Use the new content passed to the function
              sender: editedMessage.sender // Get sender from the current edited message
            }
          };
        }
        return msg;
      });

      if (hasUpdates) {
        console.log(`[ReplyUpdates] Updated ${replyingMessageIds.length} messages that reply to ${editedMessageId}`);
        return updatedMessages;
      } else {
        return currentMessages;
      }
    });
  }, [onMessagesUpdate]);

  // Function to update reply fields when a message is deleted
  const handleMessageDeleted = useCallback((deletedMessageId: string) => {
    const replyingMessageIds = replyMappingRef.current.get(deletedMessageId);
    
    if (!replyingMessageIds || replyingMessageIds.length === 0) {
      return;
    }

    // Use the callback to get fresh message state and update reply fields
    onMessagesUpdate(currentMessages => {
      let hasUpdates = false;
      const updatedMessages = currentMessages.map(msg => {
        // Check if this message replies to the deleted message
        if (replyingMessageIds.includes(msg.id) && msg.replyTo?.id === deletedMessageId) {
          hasUpdates = true;
          return {
            ...msg,
            replyTo: {
              ...msg.replyTo,
              content: '[Message deleted]',
              sender: msg.replyTo.sender || '[Unknown]'
            }
          };
        }
        return msg;
      });

      if (hasUpdates) {
        console.log(`[ReplyUpdates] Updated ${replyingMessageIds.length} messages that replied to deleted message ${deletedMessageId}`);
        return updatedMessages;
      } else {
        return currentMessages;
      }
    });
  }, [onMessagesUpdate]);

  // Set up event listeners for message edits and deletions
  useEffect(() => {
    const handleMessageEdit = (event: CustomEvent) => {
      try {
        const { messageId, newContent } = event.detail;
        if (!messageId || !newContent) {
          console.warn('[ReplyUpdates] Invalid edit event detail:', event.detail);
          return;
        }
        updateReplyFields(messageId, newContent);
      } catch (error) {
        console.error('[ReplyUpdates] Error handling message edit event:', error);
      }
    };

    const handleMessageDelete = (event: CustomEvent) => {
      try {
        const { messageId } = event.detail;
        if (!messageId) {
          console.warn('[ReplyUpdates] Invalid delete event detail:', event.detail);
          return;
        }
        handleMessageDeleted(messageId);
      } catch (error) {
        console.error('[ReplyUpdates] Error handling message delete event:', error);
      }
    };

    // Listen for local message edits (from the sender's perspective)
    // These should fire AFTER the original message has been updated in Index.tsx
    window.addEventListener('local-message-edit', handleMessageEdit as EventListener);
    window.addEventListener('local-message-delete', handleMessageDelete as EventListener);

    // Listen for remote message edits (from encrypted message handler)
    // These should fire AFTER the original message has been updated in useEncryptedMessageHandler
    window.addEventListener('remote-message-edit', handleMessageEdit as EventListener);
    window.addEventListener('remote-message-delete', handleMessageDelete as EventListener);

    return () => {
      window.removeEventListener('local-message-edit', handleMessageEdit as EventListener);
      window.removeEventListener('local-message-delete', handleMessageDelete as EventListener);
      window.removeEventListener('remote-message-edit', handleMessageEdit as EventListener);
      window.removeEventListener('remote-message-delete', handleMessageDelete as EventListener);
    };
  }, [updateReplyFields, handleMessageDeleted]);

  return {
    updateReplyFields,
    handleMessageDeleted,
    // Statistics for debugging
    getStats: () => ({
      totalMappings: replyMappingRef.current.size,
      totalMessages: messageIndexRef.current.size,
      replyCount: Array.from(replyMappingRef.current.values()).reduce((sum, arr) => sum + arr.length, 0)
    })
  };
};
