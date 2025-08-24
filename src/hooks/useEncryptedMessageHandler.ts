import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";
import websocketClient from "@/lib/websocket";

export function useEncryptedMessageHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  keyManagerRef: React.MutableRefObject<any>,
  loginUsernameRef: React.MutableRefObject<string>,
  setUsers: React.Dispatch<React.SetStateAction<any[]>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
  // Helper function to handle read receipts
  const handleReadReceipt = useCallback((payload: any) => {
    console.log('[EncryptedMessageHandler] handleReadReceipt called with payload:', {
      type: payload?.type,
      messageId: payload?.messageId,
      content: payload?.content,
      contentPreview: payload?.content ? payload.content.substring(0, 100) : 'no content'
    });

    // Check if the payload itself is a read receipt
    if (payload?.type === 'read-receipt' && payload?.messageId) {
      try {
        console.log('[EncryptedMessageHandler] Processing read receipt (direct):', {
          messageId: payload.messageId,
          from: payload.from,
          timestamp: payload.timestamp
        });
        
        const event = new CustomEvent('message-read', {
          detail: {
            messageId: payload.messageId,
            from: payload.from
          }
        });
        window.dispatchEvent(event);
        return true; // Indicates this was a read receipt that should not be processed as a message
      } catch (error) {
        console.error('[EncryptedMessageHandler] Error processing read receipt:', error);
        return true; // Return true to prevent processing as message even if processing fails
      }
    }
    
    // Check for read receipts embedded in message content (current issue)
    if (payload?.type === 'message' && payload?.content) {
      try {
        // Try to parse the content to see if it's a read receipt
        const contentData = JSON.parse(payload.content);
        console.log('[EncryptedMessageHandler] Parsed message content:', contentData);
        
        if (contentData.type === 'read-receipt' && contentData.messageId) {
          console.log('[EncryptedMessageHandler] Processing read receipt from message content:', {
            messageId: contentData.messageId,
            from: payload.from,
            timestamp: contentData.timestamp
          });
          
          const event = new CustomEvent('message-read', {
            detail: {
              messageId: contentData.messageId,
              from: payload.from
            }
          });
          window.dispatchEvent(event);
          return true; // Indicates this was a read receipt that should not be processed as a message
        }
      } catch (error) {
        console.log('[EncryptedMessageHandler] Content is not JSON, continuing as regular message');
        // Content is not JSON, continue processing as regular message
      }
    }
    
    // Also check for legacy read receipts embedded in content
    if (payload?.typeInside === 'read-receipt' && payload?.content) {
      try {
        // Parse the content to extract the read receipt data
        const receiptData = JSON.parse(payload.content);
        if (receiptData.type === 'read-receipt' && receiptData.messageId) {
          console.log('[EncryptedMessageHandler] Processing legacy read receipt from typeInside:', {
            messageId: receiptData.messageId,
            from: payload.from,
            timestamp: receiptData.timestamp
          });
          
          const event = new CustomEvent('message-read', {
            detail: {
              messageId: receiptData.messageId,
              from: payload.from
            }
          });
          window.dispatchEvent(event);
          return true; // Indicates this was a read receipt that should not be processed as a message
        }
      } catch (error) {
        console.log('[EncryptedMessageHandler] Legacy read receipt parsing failed, preventing message processing');
        return true; // Return true to prevent processing as message even if parsing fails
      }
    }
    
    console.log('[EncryptedMessageHandler] Not a read receipt, can process as normal message');
    return false; // Not a read receipt, can process as normal message
  }, []);

  return useCallback(
    async (encryptedMessage: any) => {
      try {
        // Skip non-object stuff like raw strings from old server messages
        if (typeof encryptedMessage !== "object" || encryptedMessage === null) {
          return;
        }

        let payload: any;
        
        // Handle Signal Protocol encrypted messages
        if (encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE && encryptedMessage?.encryptedPayload?.content) {
          try {
            const currentUser = loginUsernameRef.current;
            const fromUser = encryptedMessage.encryptedPayload.from;
            const ctB64 = encryptedMessage.encryptedPayload.content;
            
            console.log('[EncryptedMessageHandler] Processing Signal Protocol message:', {
              from: fromUser,
              to: currentUser,
              hasContent: !!ctB64,
              messageType: encryptedMessage.encryptedPayload.type,
              sessionId: encryptedMessage.encryptedPayload.sessionId
            });
            
            const dec = await (window as any).edgeApi.decrypt({ 
              selfUsername: currentUser, 
              fromUsername: fromUser, 
              ciphertextBase64: ctB64 
            });
            
            if (dec && dec.plaintext) {
              payload = JSON.parse(dec.plaintext);
              console.log('[EncryptedMessageHandler] Message decrypted successfully:', {
                hasPayload: !!payload,
                payloadType: payload?.type,
                contentLength: payload?.content?.length
              });
            } else {
              console.error('[EncryptedMessageHandler] Decryption returned no plaintext');
              return;
            }
          } catch (err) {
            console.error('[EncryptedMessageHandler] Signal Protocol decryption failed:', err);
            return;
          }
        } else if (encryptedMessage?.type === SignalType.DR_SEND) {
          // Legacy double ratchet message - skip processing
          return;
        } else if (encryptedMessage?.type === SignalType.LIBSIGNAL_DELIVER_BUNDLE) {
          // Handle Signal Protocol bundle delivery
          try {
            const currentUser = loginUsernameRef.current;
            const bundle = encryptedMessage.bundle;
            const peerUsername = encryptedMessage.username;
            
            await (window as any).edgeApi.processPreKeyBundle({
              selfUsername: currentUser,
              peerUsername,
              bundle
            });
          } catch (error) {
            console.error('[EncryptedMessageHandler] Bundle processing failed:', error);
            return;
          }
          return;
        } else {
          // Unknown message type
          console.warn('[EncryptedMessageHandler] Unknown message type:', encryptedMessage?.type);
          return;
        }

        // Process the decrypted payload
        if (payload && typeof payload === 'object') {
          console.log('[EncryptedMessageHandler] Processing decrypted payload:', {
            type: payload.type,
            messageId: payload.messageId,
            from: payload.from,
            content: payload.content,
            isReadReceipt: payload.type === 'read-receipt',
            contentPreview: payload.content ? payload.content.substring(0, 100) : 'no content'
          });
          
          // Handle read receipts
          if (handleReadReceipt(payload)) {
            console.log('[EncryptedMessageHandler] Read receipt handled, skipping message processing');
            return;
          } else {
            console.log('[EncryptedMessageHandler] Not a read receipt, processing as regular message');
          }

          // Handle regular messages
          if ((payload.type === 'message' || payload.type === 'text') && payload.content) {
            const message: Message = {
              id: payload.messageId || uuidv4(),
              content: payload.content,
              sender: payload.from,  // Use 'sender' to match Message interface
              recipient: loginUsernameRef.current,  // Add recipient field for proper filtering
              timestamp: new Date(payload.timestamp || Date.now()),  // Convert to Date object
              type: 'text',
              isCurrentUser: false  // Received messages are not from current user
            };

            console.log('[EncryptedMessageHandler] Adding message to state:', {
              id: message.id,
              sender: message.sender,
              recipient: message.recipient,
              contentLength: message.content.length,
              timestamp: message.timestamp,
              isCurrentUser: message.isCurrentUser
            });

            setMessages(prev => [...prev, message]);
            await saveMessageToLocalDB(message);

            // Send delivery receipt to the sender
            try {
              const deliveryReceiptPayload = {
                type: SignalType.MESSAGE_DELIVERED,
                messageId: message.id,
                to: payload.from
              };
              
              websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              console.log('[EncryptedMessageHandler] Delivery receipt sent for message:', message.id);
            } catch (error) {
              console.error('[EncryptedMessageHandler] Failed to send delivery receipt:', error);
            }
          }

          // Handle file messages
          if (payload.type === 'file-message' && payload.fileData) {
            const message: Message = {
              id: payload.messageId || uuidv4(),
              content: payload.fileName || 'File',
              sender: payload.from,  // Use 'sender' to match Message interface
              recipient: loginUsernameRef.current,  // Add recipient field for proper filtering
              timestamp: new Date(payload.timestamp || Date.now()),  // Convert to Date object
              type: 'file',
              isCurrentUser: false,  // Received messages are not from current user
              fileInfo: {
                name: payload.fileName || 'File',
                type: payload.fileType || 'application/octet-stream',
                size: payload.fileSize || 0,
                data: new ArrayBuffer(0)  // Placeholder - actual file data would be handled separately
              }
            };

            setMessages(prev => [...prev, message]);
            await saveMessageToLocalDB(message);

            // Send delivery receipt to the sender
            try {
              const deliveryReceiptPayload = {
                type: SignalType.MESSAGE_DELIVERED,
                messageId: message.id,
                to: payload.from
              };
              
              websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              console.log('[EncryptedMessageHandler] Delivery receipt sent for file message:', message.id);
            } catch (error) {
              console.error('[EncryptedMessageHandler] Failed to send delivery receipt for file message:', error);
            }
          }

          // Handle delivery receipts
          if (payload.type === 'delivery-receipt' && payload.messageId) {
            const event = new CustomEvent('message-delivered', {
              detail: {
                messageId: payload.messageId,
                from: payload.from
              }
            });
            window.dispatchEvent(event);
          }

          // Handle typing indicators
          if (payload.type === 'typing-start' || payload.type === 'typing-stop') {
            const event = new CustomEvent('typing-indicator', {
              detail: {
                from: payload.from,
                isTyping: payload.type === 'typing-start'
              }
            });
            window.dispatchEvent(event);
          }
        } else {
          console.warn('[EncryptedMessageHandler] No valid payload after decryption');
        }
      } catch (error) {
        console.error('[EncryptedMessageHandler] Error processing encrypted message:', error);
      }
    },
    [handleReadReceipt, setMessages, saveMessageToLocalDB]
  );
}