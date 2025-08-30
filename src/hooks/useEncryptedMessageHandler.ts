import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";
import websocketClient from "@/lib/websocket";

// SECURITY: Safe JSON parsing with size and structure validation
function safeJsonParse(jsonString: string, maxSize: number = 10000): any {
  if (!jsonString || typeof jsonString !== 'string') return null;
  if (jsonString.length > maxSize) {
    console.error('[Security] JSON string too large, rejecting');
    return null;
  }
  try {
    return JSON.parse(jsonString);
  } catch (error) {
    console.error('[Security] JSON parse failed:', error);
    return null;
  }
}

export function useEncryptedMessageHandler(
  loginUsernameRef: React.MutableRefObject<string>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
  

  return useCallback(
    async (encryptedMessage: any) => {
      try {
        // SECURITY: Comprehensive type validation to prevent type confusion attacks
        if (typeof encryptedMessage !== "object" ||
            encryptedMessage === null ||
            Array.isArray(encryptedMessage) ||
            encryptedMessage instanceof Date ||
            encryptedMessage instanceof RegExp ||
            typeof encryptedMessage === 'function') {
          console.warn('[EncryptedMessageHandler] Invalid message type:', typeof encryptedMessage);
          return;
        }

        // SECURITY: Prevent prototype pollution through message object
        if (encryptedMessage.hasOwnProperty('__proto__') ||
            encryptedMessage.hasOwnProperty('constructor') ||
            encryptedMessage.hasOwnProperty('prototype')) {
          console.error('[EncryptedMessageHandler] Prototype pollution attempt detected');
          return;
        }

        let payload: any;

        // Handle P2P encrypted messages (highest priority)
        if (encryptedMessage?.p2p === true && encryptedMessage?.encrypted === true) {
          try {
            // SECURITY: Validate P2P message structure and content with strict type checking
            if (!encryptedMessage.from || !encryptedMessage.to || !encryptedMessage.id ||
                typeof encryptedMessage.from !== 'string' ||
                typeof encryptedMessage.to !== 'string' ||
                typeof encryptedMessage.id !== 'string') {
              console.error('[EncryptedMessageHandler] Invalid P2P message structure');
              return;
            }

            // SECURITY: Validate username format to prevent injection attacks
            const usernameRegex = /^[a-zA-Z0-9_-]{1,32}$/;
            if (!usernameRegex.test(encryptedMessage.from) || !usernameRegex.test(encryptedMessage.to)) {
              console.error('[EncryptedMessageHandler] Invalid username format in P2P message');
              return;
            }

            // SECURITY: Validate message ID format (UUID)
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(encryptedMessage.id)) {
              console.error('[EncryptedMessageHandler] Invalid message ID format');
              return;
            }

            // SECURITY: Validate message is intended for current user
            if (encryptedMessage.to !== loginUsernameRef.current) {
              console.error('[EncryptedMessageHandler] P2P message not intended for current user');
              return;
            }

            // SECURITY: Validate content length, type, and sanitize for XSS prevention
            if (typeof encryptedMessage.content !== 'string' ||
                encryptedMessage.content.length === 0 ||
                encryptedMessage.content.length > 10000) {
              console.error('[EncryptedMessageHandler] Invalid P2P message content length');
              return;
            }

            // SECURITY: Check for potential XSS and injection attacks in content
            const dangerousPatterns = [
              /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
              /javascript:/gi,
              /vbscript:/gi,
              /data:text\/html/gi,
              /on\w+\s*=/gi,
              /<iframe\b/gi,
              /<object\b/gi,
              /<embed\b/gi,
              /<link\b/gi,
              /<meta\b/gi
            ];

            const hasDangerousContent = dangerousPatterns.some(pattern => pattern.test(encryptedMessage.content));
            if (hasDangerousContent) {
              console.error('[EncryptedMessageHandler] Potentially dangerous content detected in P2P message');
              return;
            }

            // SECURITY: Check for null bytes and control characters
            if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(encryptedMessage.content)) {
              console.error('[EncryptedMessageHandler] Invalid control characters in P2P message content');
              return;
            }

            // SECURITY: Validate timestamp is reasonable (not too old or future)
            const now = Date.now();
            const messageTime = new Date(encryptedMessage.timestamp).getTime();
            const maxAge = 24 * 60 * 60 * 1000; // 24 hours
            const maxFuture = 5 * 60 * 1000; // 5 minutes

            if (isNaN(messageTime) || messageTime < (now - maxAge) || messageTime > (now + maxFuture)) {
              console.error('[EncryptedMessageHandler] Invalid P2P message timestamp');
              return;
            }

            console.log('[EncryptedMessageHandler] Processing validated P2P message:', {
              from: encryptedMessage.from,
              to: encryptedMessage.to,
              timestamp: encryptedMessage.timestamp,
              hasContent: !!encryptedMessage.content
            });

            // P2P messages are already decrypted by the P2P service
            payload = {
              id: encryptedMessage.id,
              content: encryptedMessage.content,
              timestamp: encryptedMessage.timestamp,
              from: encryptedMessage.from,
              to: encryptedMessage.to,
              type: 'message',
              p2p: true
            };

            console.log('[EncryptedMessageHandler] P2P message processed successfully');
          } catch (error) {
            console.error('[EncryptedMessageHandler] Failed to process P2P message:', error);
            return;
          }
        }
        // Handle Signal Protocol encrypted messages
        else if (encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE && encryptedMessage?.encryptedPayload?.content) {
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
            }).catch(() => ({ plaintext: atob(ctB64) }));
            
            if (dec && dec.plaintext) {
              payload = safeJsonParse(dec.plaintext, 50000); // Allow larger size for encrypted payloads
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
            isDeliveryReceipt: payload.type === 'delivery-receipt',
            contentPreview: payload.content ? payload.content.substring(0, 100) : 'no content',
            payloadKeys: Object.keys(payload),
            hasReplyTo: !!payload.replyTo,
            replyToKeys: payload.replyTo ? Object.keys(payload.replyTo) : null
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
            console.log('[EncryptedMessageHandler] Read receipt event dispatched for message:', payload.messageId);
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
            console.log('[EncryptedMessageHandler] Delivery receipt event dispatched for message:', payload.messageId);
            return; // Don't process as regular message
          }

          // Handle typing indicators (only if not already processed as a system message)
          if (payload.type === 'typing-start' || payload.type === 'typing-stop' || payload.type === 'typing-indicator') {
            console.log('[EncryptedMessageHandler] Processing typing indicator:', payload);
            
            // For typing-indicator type, we need to parse the content to get the actual indicator type
            let indicatorType = payload.type;
            if (payload.type === 'typing-indicator' && payload.content) {
              const contentData = safeJsonParse(payload.content);
              if (contentData && contentData.type) {
                indicatorType = contentData.type;
                console.log('[EncryptedMessageHandler] Extracted indicator type from content:', indicatorType);
              } else {
                console.warn('[EncryptedMessageHandler] Failed to parse typing indicator content');
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

          // Check if the content contains system message data (typing indicators, receipts, etc.)
          // This handles cases where system messages might be sent with generic message types
          if (payload.content && typeof payload.content === 'string') {
            const contentData = safeJsonParse(payload.content);
            if (contentData) {
              // Handle typing indicators
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
              
              // Handle read receipts
              if (contentData.type === 'read-receipt' && contentData.messageId) {
                console.log('[EncryptedMessageHandler] Processing read receipt from content:', contentData);
                const event = new CustomEvent('message-read', {
                  detail: {
                    messageId: contentData.messageId,
                    from: payload.from
                  }
                });
                window.dispatchEvent(event);
                return; // Don't process as regular message
              }
              
              // Handle delivery receipts
              if (contentData.type === 'delivery-receipt' && contentData.messageId) {
                console.log('[EncryptedMessageHandler] Processing delivery receipt from content:', contentData);
                const event = new CustomEvent('message-delivered', {
                  detail: {
                    messageId: contentData.messageId,
                    from: payload.from
                  }
                });
                window.dispatchEvent(event);
                return; // Don't process as regular message
              }
            }
          }

          // Before showing a regular message, ensure typing indicator for this sender is cleared
          try {
            const typingClearEvent = new CustomEvent('typing-indicator', {
              detail: { from: payload.from, indicatorType: 'typing-stop' }
            });
            window.dispatchEvent(typingClearEvent);
          } catch {}

          // Handle regular messages (only if not a system message)
          // Additional check to ensure typing indicator messages are not processed as regular messages
          if ((payload.type === 'message' || payload.type === 'text' || !payload.type) && payload.content) {
            // Double-check that this is not a typing indicator message
            const typingCheckData = safeJsonParse(payload.content);
            if (typingCheckData && (typingCheckData.type === 'typing-start' || typingCheckData.type === 'typing-stop')) {
              console.log('[EncryptedMessageHandler] Skipping typing indicator message that was already processed:', typingCheckData);
              return; // Don't process as regular message
            }
            
            // Extract message ID from the payload content since it's encrypted along with the content
            let messageId = payload.messageId;
            let messageContent = payload.content;
            
            // Try to parse the content to get the actual message data
            const contentData = safeJsonParse(payload.content);
            if (contentData && contentData.messageId) {
              messageId = contentData.messageId;
              messageContent = contentData.content || contentData.message || payload.content;
              if (contentData.replyTo) {
                payload.replyTo = contentData.replyTo;
              }
              console.log('[EncryptedMessageHandler] Extracted message ID from content:', messageId);
            } else {
              // Content is not valid JSON or no messageId, use fallback
              messageId = messageId || uuidv4();
              console.log('[EncryptedMessageHandler] Using fallback message ID:', messageId);
            }
            
            // SECURITY: Atomic check and add to prevent race conditions
            let messageExists = false;
            let messageAdded = false;

            setMessages(prev => {
              messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                console.log('[EncryptedMessageHandler] Message already exists, skipping duplicate:', messageId);
                return prev;
              }

              // Mark that we're adding the message atomically
              messageAdded = true;
              
              // Fill replyTo from payload, falling back to existing message content if missing
              let replyToFilled: { id: string; sender: string; content: string } | undefined = undefined;
              if (payload.replyTo && typeof payload.replyTo === 'object' && payload.replyTo.id) {
                let replyContent = payload.replyTo.content || '';
                if (!replyContent) {
                  const ref = prev.find(m => m.id === payload.replyTo.id);
                  if (ref?.content) replyContent = ref.content;
                }
                replyToFilled = {
                  id: payload.replyTo.id,
                  sender: payload.replyTo.sender || payload.from,
                  content: replyContent
                };
                console.log('[EncryptedMessageHandler] Reply data found and filled:', replyToFilled);
              } else {
                console.log('[EncryptedMessageHandler] No replyTo in payload or invalid format:', payload.replyTo);
              }

              const message: Message = {
                id: messageId,
                content: messageContent,
                sender: payload.from,  // Use 'sender' to match Message interface
                recipient: loginUsernameRef.current,  // Add recipient field for proper filtering
                timestamp: new Date(payload.timestamp || Date.now()),  // Convert to Date object
                type: 'text',
                isCurrentUser: false,  // Received messages are not from current user
                p2p: payload.p2p || false,  // Mark P2P messages
                encrypted: true,  // All messages are encrypted
                ...(replyToFilled && { replyTo: replyToFilled })
              };

              console.log('[EncryptedMessageHandler] Final message object:', {
                id: message.id,
                content: message.content,
                sender: message.sender,
                hasReplyTo: !!message.replyTo,
                replyToData: message.replyTo,
                messageKeys: Object.keys(message),
                fullMessage: message
              });

              console.log('[EncryptedMessageHandler] Adding message to state:', {
                id: message.id,
                sender: message.sender,
                recipient: message.recipient,
                contentLength: message.content.length,
                timestamp: message.timestamp,
                isCurrentUser: message.isCurrentUser
              });

              const newMessages = [...prev, message];
              console.log('[EncryptedMessageHandler] Updated messages state:', {
                totalMessages: newMessages.length,
                lastMessage: newMessages[newMessages.length - 1],
                lastMessageHasReplyTo: !!newMessages[newMessages.length - 1].replyTo,
                lastMessageReplyTo: newMessages[newMessages.length - 1].replyTo
              });
              return newMessages;
            });

            // SECURITY: Only save to database if message was actually added to prevent race conditions
            if (!messageExists && messageAdded) {
              try {
                await saveMessageToLocalDB({
                  id: messageId,
                  content: messageContent,
                  sender: payload.from,
                  recipient: loginUsernameRef.current,
                  p2p: payload.p2p || false,
                  encrypted: true,
                  transport: payload.p2p ? 'p2p' : 'websocket',
                  timestamp: new Date(payload.timestamp || Date.now()),
                  type: 'text',
                  isCurrentUser: false
                });
              } catch (dbError) {
                console.error('[EncryptedMessageHandler] Failed to save message to database:', dbError);
                // Don't throw - message is already in UI state
              }
            }
            
            // Send delivery receipt to the sender as encrypted message
            try {
              // First, ensure we have a session with the sender for delivery receipts
              const currentUser = loginUsernameRef.current;
              const senderUsername = payload.from;
              
              // Check if we have a session with the sender
              const sessionCheck = await (window as any).edgeApi?.hasSession?.({ 
                selfUsername: currentUser, 
                peerUsername: senderUsername, 
                deviceId: 1 
              });
              
              if (!sessionCheck?.hasSession) {
                console.log('[EncryptedMessageHandler] No session with sender, requesting bundle for delivery receipt');
                // Request the sender's bundle so we can send delivery receipts
                websocketClient.send(JSON.stringify({ 
                  type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, 
                  username: senderUsername 
                }));
                
                // Wait a bit for the bundle to be processed
                await new Promise(resolve => setTimeout(resolve, 500));
              }
              
              const deliveryReceiptData = {
                messageId: `delivery-receipt-${messageId}`,
                from: loginUsernameRef.current,
                to: payload.from,
                content: 'delivery-receipt',
                timestamp: Date.now(),
                messageType: 'signal-protocol',
                signalType: 'signal-protocol',
                protocolType: 'signal',
                type: 'delivery-receipt'
              };
              
              console.log('[EncryptedMessageHandler] Sending delivery receipt for message:', {
                messageId: messageId,
                originalMessageId: payload.messageId,
                extractedMessageId: messageId,
                deliveryReceiptData,
                sender: payload.from,
                recipient: loginUsernameRef.current
              });
              
              // Use the proper Signal Protocol encryption flow through edgeApi
              const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
                fromUsername: loginUsernameRef.current,
                toUsername: payload.from,
                plaintext: JSON.stringify(deliveryReceiptData)
              });
              
              if (!encryptedMessage?.ciphertextBase64) {
                console.error('[EncryptedMessageHandler] Failed to encrypt delivery receipt');
                return;
              }
              
              const deliveryReceiptPayload = {
                type: SignalType.ENCRYPTED_MESSAGE,
                to: payload.from,
                encryptedPayload: {
                  from: loginUsernameRef.current,
                  to: payload.from,
                  content: encryptedMessage.ciphertextBase64,
                  messageId: `delivery-receipt-${messageId}`,
                  type: encryptedMessage.type,
                  sessionId: encryptedMessage.sessionId
                }
              };
              
              websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              console.log('[EncryptedMessageHandler] Delivery receipt sent for message:', messageId);
            } catch (error) {
              console.error('[EncryptedMessageHandler] Failed to send delivery receipt:', error);
            }
          }

          // Handle file messages
          if (payload.type === 'file-message' && payload.fileData) {
            // Extract message ID from the payload content since it's encrypted along with the content
            let messageId = payload.messageId;
            let fileName = payload.fileName;
            
            // Try to parse the content to get the actual message data
            const fileContentData = safeJsonParse(payload.content);
            if (fileContentData && fileContentData.messageId) {
              messageId = fileContentData.messageId;
              fileName = fileContentData.fileName || fileContentData.fileData || payload.fileName;
              console.log('[EncryptedMessageHandler] Extracted file message ID from content:', messageId);
            } else {
              // Content is not valid JSON or no messageId, use fallback
              messageId = messageId || uuidv4();
              console.log('[EncryptedMessageHandler] Using fallback file message ID:', messageId);
            }
            
            // Check if message already exists to prevent duplicates
            let messageExists = false;
            setMessages(prev => {
              messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                console.log('[EncryptedMessageHandler] File message already exists, skipping duplicate:', messageId);
                return prev;
              }
              
              const message: Message = {
                id: messageId,
                content: fileName || 'File',
                sender: payload.from,  // Use 'sender' to match Message interface
                recipient: loginUsernameRef.current,  // Add recipient field for proper filtering
                timestamp: new Date(payload.timestamp || Date.now()),  // Convert to Date object
                type: 'file',
                isCurrentUser: false,  // Received messages are not from current user
                fileInfo: {
                  name: fileName || 'File',
                  type: payload.fileType || 'application/octet-stream',
                  size: payload.fileSize || 0,
                  data: new ArrayBuffer(0)  // SECURITY: Zero-length buffer to prevent memory leaks
                }
              };

              return [...prev, message];
            });

            if (!messageExists) {
              // Save to database (this will also add to state)
              await saveMessageToLocalDB({
                id: messageId,
                content: fileName || 'File',
                sender: payload.from,
                recipient: loginUsernameRef.current,
                timestamp: new Date(payload.timestamp || Date.now()),
                type: 'file',
                isCurrentUser: false,
                fileInfo: {
                  name: fileName || 'File',
                  type: payload.fileType || 'application/octet-stream',
                  size: payload.fileSize || 0,
                  data: new ArrayBuffer(0)  // SECURITY: Zero-length buffer to prevent memory leaks
                }
              });
            }

            // Send delivery receipt to the sender as encrypted message
            try {
              // First, ensure we have a session with the sender for delivery receipts
              const currentUser = loginUsernameRef.current;
              const senderUsername = payload.from;
              
              // Check if we have a session with the sender
              const sessionCheck = await (window as any).edgeApi?.hasSession?.({ 
                selfUsername: currentUser, 
                peerUsername: senderUsername, 
                deviceId: 1 
              });
              
              if (!sessionCheck?.hasSession) {
                console.log('[EncryptedMessageHandler] No session with sender, requesting bundle for file message delivery receipt');
                // Request the sender's bundle so we can send delivery receipts
                websocketClient.send(JSON.stringify({ 
                  type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, 
                  username: senderUsername 
                }));
                
                // Wait a bit for the bundle to be processed
                await new Promise(resolve => setTimeout(resolve, 500));
              }
              
              const deliveryReceiptData = {
                messageId: `delivery-receipt-${messageId}`,
                from: loginUsernameRef.current,
                to: payload.from,
                content: 'delivery-receipt',
                timestamp: Date.now(),
                messageType: 'signal-protocol',
                signalType: 'signal-protocol',
                protocolType: 'signal',
                type: 'delivery-receipt'
              };
              
              console.log('[EncryptedMessageHandler] Sending delivery receipt for file message:', {
                messageId: messageId,
                originalMessageId: payload.messageId,
                extractedMessageId: messageId,
                deliveryReceiptData,
                sender: payload.from,
                recipient: loginUsernameRef.current
              });
              
              // Use the proper Signal Protocol encryption flow through edgeApi
              const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
                fromUsername: loginUsernameRef.current,
                toUsername: payload.from,
                plaintext: JSON.stringify(deliveryReceiptData)
              });
              
              if (!encryptedMessage?.ciphertextBase64) {
                console.error('[EncryptedMessageHandler] Failed to encrypt delivery receipt');
                return;
              }
              
              const deliveryReceiptPayload = {
                type: SignalType.ENCRYPTED_MESSAGE,
                to: payload.from,
                encryptedPayload: {
                  from: loginUsernameRef.current,
                  to: payload.from,
                  content: encryptedMessage.ciphertextBase64,
                  messageId: `delivery-receipt-${messageId}`,
                  type: encryptedMessage.type,
                  sessionId: encryptedMessage.sessionId
                }
              };
              
              websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              console.log('[EncryptedMessageHandler] Delivery receipt sent for file message:', messageId);
            } catch (error) {
              console.error('[EncryptedMessageHandler] Failed to send delivery receipt for file message:', error);
            }
          }

          // Handle call signals
          if (payload.type === 'call-signal') {
            console.log('[EncryptedMessageHandler] Received call signal:', payload);
            
            // Dispatch call signal event for calling service
            const callSignalEvent = new CustomEvent('call-signal', {
              detail: JSON.parse(payload.content)
            });
            window.dispatchEvent(callSignalEvent);
            return; // Don't save call signals as regular messages
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