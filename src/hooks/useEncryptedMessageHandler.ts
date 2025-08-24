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
          
          // Handle system messages first (these should not appear in chat)
          
          // Handle read receipts
          if (payload.type === 'read-receipt' && payload.messageId) {
            console.log('[EncryptedMessageHandler] Processing read receipt:', payload);
            const event = new CustomEvent('message-read', {
              detail: {
                messageId: payload.messageId,
                from: payload.from
              }
            });
            window.dispatchEvent(event);
            return; // Don't process as regular message
          }

          // Handle delivery receipts
          if (payload.type === 'delivery-receipt' && payload.messageId) {
            console.log('[EncryptedMessageHandler] Processing delivery receipt:', payload);
            const event = new CustomEvent('message-delivered', {
              detail: {
                messageId: payload.messageId,
                from: payload.from
              }
            });
            window.dispatchEvent(event);
            return; // Don't process as regular message
          }

          // Handle typing indicators (only if not already processed as a system message)
          if (payload.type === 'typing-start' || payload.type === 'typing-stop' || payload.type === 'typing-indicator') {
            console.log('[EncryptedMessageHandler] Processing typing indicator:', payload);
            
            // For typing-indicator type, we need to parse the content to get the actual indicator type
            let indicatorType = payload.type;
            if (payload.type === 'typing-indicator' && payload.content) {
              try {
                const contentData = JSON.parse(payload.content);
                indicatorType = contentData.type;
                console.log('[EncryptedMessageHandler] Extracted indicator type from content:', indicatorType);
              } catch (error) {
                console.warn('[EncryptedMessageHandler] Failed to parse typing indicator content:', error);
                // Fallback to a default type if parsing fails
                indicatorType = 'typing-start';
              }
            }
            
            const event = new CustomEvent('typing-indicator', {
              detail: {
                from: payload.from,
                indicatorType: indicatorType
              }
            });
            window.dispatchEvent(event);
            console.log('[EncryptedMessageHandler] Dispatched typing indicator event:', { from: payload.from, indicatorType });
            return; // Don't process as regular message
          }

          // Check if the content contains typing indicator data (for backward compatibility)
          // This handles cases where typing indicators might be sent with generic message types
          if (payload.content && typeof payload.content === 'string') {
            try {
              const contentData = JSON.parse(payload.content);
              if (contentData.type === 'typing-start' || contentData.type === 'typing-stop') {
                console.log('[EncryptedMessageHandler] Processing typing indicator from content (backward compatibility):', contentData);
                const event = new CustomEvent('typing-indicator', {
                  detail: {
                    from: payload.from,
                    indicatorType: contentData.type
                  }
                });
                window.dispatchEvent(event);
                return; // Don't process as regular message
              }
            } catch (error) {
              // Content is not JSON, continue processing as regular message
            }
          }

          // Handle regular messages (only if not a system message)
          // Additional check to ensure typing indicator messages are not processed as regular messages
          if ((payload.type === 'message' || payload.type === 'text' || !payload.type) && payload.content) {
            // Double-check that this is not a typing indicator message
            try {
              const contentData = JSON.parse(payload.content);
              if (contentData.type === 'typing-start' || contentData.type === 'typing-stop') {
                console.log('[EncryptedMessageHandler] Skipping typing indicator message that was already processed:', contentData);
                return; // Don't process as regular message
              }
            } catch (error) {
              // Content is not JSON, continue processing as regular message
            }
            const messageId = payload.messageId || uuidv4();
            
            // Check if message already exists to prevent duplicates
            setMessages(prev => {
              const messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                console.log('[EncryptedMessageHandler] Message already exists, skipping duplicate:', messageId);
                return prev;
              }
              
              const message: Message = {
                id: messageId,
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

              return [...prev, message];
            });
            
            // Save to database
            const message: Message = {
              id: messageId,
              content: payload.content,
              sender: payload.from,
              recipient: loginUsernameRef.current,
              timestamp: new Date(payload.timestamp || Date.now()),
              type: 'text',
              isCurrentUser: false
            };
            await saveMessageToLocalDB(message);

            // Send delivery receipt to the sender as encrypted message
            try {
              const deliveryReceiptData = {
                type: 'delivery-receipt',
                messageId: message.id,
                timestamp: Date.now()
              };
              
              const deliveryReceiptPayload = {
                type: SignalType.ENCRYPTED_MESSAGE,
                to: payload.from,
                encryptedPayload: {
                  type: 1, // Signal Protocol message type
                  from: loginUsernameRef.current,
                  to: payload.from,
                  content: JSON.stringify(deliveryReceiptData),
                  sessionId: crypto.randomUUID() // Generate unique session ID for receipt
                }
              };
              
              websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              console.log('[EncryptedMessageHandler] Delivery receipt sent for message:', message.id);
            } catch (error) {
              console.error('[EncryptedMessageHandler] Failed to send delivery receipt:', error);
            }
          }

          // Handle file messages
          if (payload.type === 'file-message' && payload.fileData) {
            const messageId = payload.messageId || uuidv4();
            
            // Check if message already exists to prevent duplicates
            setMessages(prev => {
              const messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                console.log('[EncryptedMessageHandler] File message already exists, skipping duplicate:', messageId);
                return prev;
              }
              
              const message: Message = {
                id: messageId,
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

              return [...prev, message];
            });
            
            // Save to database
            const message: Message = {
              id: messageId,
              content: payload.fileName || 'File',
              sender: payload.from,
              recipient: loginUsernameRef.current,
              timestamp: new Date(payload.timestamp || Date.now()),
              type: 'file',
              isCurrentUser: false,
              fileInfo: {
                name: payload.fileName || 'File',
                type: payload.fileType || 'application/octet-stream',
                size: payload.fileSize || 0,
                data: new ArrayBuffer(0)
              }
            };
            await saveMessageToLocalDB(message);

            // Send delivery receipt to the sender as encrypted message
            try {
              const deliveryReceiptData = {
                type: 'delivery-receipt',
                messageId: message.id,
                timestamp: Date.now()
              };
              
              const deliveryReceiptPayload = {
                type: SignalType.ENCRYPTED_MESSAGE,
                to: payload.from,
                encryptedPayload: {
                  type: 1, // Signal Protocol message type
                  from: loginUsernameRef.current,
                  to: payload.from,
                  content: JSON.stringify(deliveryReceiptData),
                  sessionId: crypto.randomUUID() // Generate unique session ID for receipt
                }
              };
              
              websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              console.log('[EncryptedMessageHandler] Delivery receipt sent for file message:', message.id);
            } catch (error) {
              console.error('[EncryptedMessageHandler] Failed to send delivery receipt for file message:', error);
            }
          }

          // Note: System messages (read receipts, delivery receipts, typing indicators) are handled above
        } else {
          console.warn('[EncryptedMessageHandler] No valid payload after decryption');
        }
      } catch (error) {
        console.error('[EncryptedMessageHandler] Error processing encrypted message:', error);
      }
    },
    [setMessages, saveMessageToLocalDB]
  );
}