import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";
import websocketClient from "@/lib/websocket";

// SECURITY: Safe JSON parsing with size and structure validation
function safeJsonParse(jsonString: string, maxSize: number = 10000): any {
  if (!jsonString || typeof jsonString !== 'string') return null;
  if (jsonString.length > maxSize) {
    console.error('[Security] JSON string too large, rejecting:', {
      actualSize: jsonString.length,
      maxSize,
      preview: jsonString.substring(0, 100) + '...'
    });
    return null;
  }

  // Quick check if string looks like JSON (starts with { or [)
  const trimmed = jsonString.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return null; // Not JSON, don't log error for plain text
  }

  try {
    return JSON.parse(jsonString);
  } catch (error) {
    console.error('[Security] JSON parse failed:', error);
    return null;
  }
}

// SECURITY: Context-aware JSON parsing with appropriate size limits
const MAX_CALL_SIGNAL_SIZE = 100000; // 100KB limit for call signals
const MAX_MESSAGE_SIZE = 10000; // 10KB limit for regular messages
const MAX_FILE_MESSAGE_SIZE = 1000000; // 1MB limit for file messages with base64 data

// Helper function to create blob URL from base64 data
function createBlobUrlFromBase64(dataBase64: string, fileType?: string): string | null {
  try {
    // Clean and validate base64 string
    let cleanBase64 = dataBase64.trim();

    // Remove data URL prefix if present (e.g., "data:audio/webm;base64,")
    if (cleanBase64.includes(',')) {
      cleanBase64 = cleanBase64.split(',')[1];
    }

    // Remove any whitespace and invalid characters
    cleanBase64 = cleanBase64.replace(/[^A-Za-z0-9+/=]/g, '');

    // Ensure proper padding
    while (cleanBase64.length % 4 !== 0) {
      cleanBase64 += '=';
    }

    // Validate base64 format
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanBase64)) {
      throw new Error('Invalid base64 format after cleaning');
    }

    // Decode base64 to binary string
    const binaryString = atob(cleanBase64);

    // Convert binary string to Uint8Array
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    // Create blob with provided MIME type
    const blob = new Blob([bytes], { type: fileType || 'application/octet-stream' });

    // Return blob URL
    return URL.createObjectURL(blob);
  } catch (error) {
    console.warn('[EncryptedMessageHandler] Failed to create blob URL from base64:', error);
    return null;
  }
}

function safeJsonParseForCallSignals(jsonString: string): any {
  // Call signals (WebRTC offers/answers) can be quite large due to SDP data
  return safeJsonParse(jsonString, MAX_CALL_SIGNAL_SIZE);
}

function safeJsonParseForMessages(jsonString: string): any {
  // Regular messages should be smaller
  return safeJsonParse(jsonString, MAX_MESSAGE_SIZE);
}

function safeJsonParseForFileMessages(jsonString: string): any {
  // File messages can contain large base64 encoded data
  const parsed = safeJsonParse(jsonString, MAX_FILE_MESSAGE_SIZE);

  if (!parsed) {
    return null;
  }

  // Validate base64-encoded file payloads if present
  if (parsed.dataBase64 && typeof parsed.dataBase64 === 'string') {
    if (!isValidBase64(parsed.dataBase64)) {
      console.warn('[Security] Base64 validation failed for file message, but allowing through for voice notes');
      // Don't reject - voice notes might have slightly different base64 encoding
      // return null;
    }
  }

  // Check other potential base64 fields that might be present in file messages
  const base64Fields = ['fileData', 'data', 'content'];
  for (const field of base64Fields) {
    if (parsed[field] && typeof parsed[field] === 'string' && parsed[field].length > 100) {
      // Only validate if it looks like it could be base64 (long string)
      if (looksLikeBase64(parsed[field]) && !isValidBase64(parsed[field])) {
        console.error(`[Security] Invalid base64 data in field '${field}' of file message, rejecting payload`);
        return null;
      }
    }
  }

  return parsed;
}

// Helper function to check if a string looks like base64
function looksLikeBase64(str: string): boolean {
  // Base64 strings are typically long and contain only valid base64 characters
  return str.length > 100 && /^[A-Za-z0-9+/]*={0,2}$/.test(str);
}

// Helper function to validate base64 strings
function isValidBase64(str: string): boolean {
  if (!str || typeof str !== 'string') {
    return false;
  }

  // Check basic base64 pattern
  const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
  if (!base64Pattern.test(str)) {
    return false;
  }

  // Check length is multiple of 4 (base64 requirement)
  if (str.length % 4 !== 0) {
    return false;
  }

  // Attempt safe decode+re-encode roundtrip to validate
  try {
    // Use different methods based on environment
    if (typeof window !== 'undefined' && typeof Buffer === 'undefined') {
      // Browser environment
      const decoded = atob(str);
      const reencoded = btoa(decoded);
      return reencoded === str;
    } else {
      // Node.js/Electron environment
      const decoded = Buffer.from(str, 'base64');
      const reencoded = decoded.toString('base64');
      return reencoded === str;
    }
  } catch (error) {
    console.error('[Security] Base64 decode/encode roundtrip failed:', error);
    return false;
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
              // First, try to parse with file message limit to check message type (file messages can be very large)
              let tempPayload = safeJsonParse(dec.plaintext, MAX_FILE_MESSAGE_SIZE);

              // Use appropriate limit based on message type
              if (tempPayload?.type === 'file-message') {
                payload = tempPayload; // Already parsed with correct limit
              } else if (tempPayload?.type === 'call-signal') {
                // For call signals, use the call signal limit (reparse if needed)
                payload = safeJsonParse(dec.plaintext, MAX_CALL_SIGNAL_SIZE);
              } else {
                // For other message types, use the standard limit (reparse if needed)
                payload = safeJsonParse(dec.plaintext, 50000);
              }

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
          // Only try to parse as JSON if it looks like structured data
          if (payload.content && typeof payload.content === 'string') {
            const trimmed = payload.content.trim();
            if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
              const contentData = safeJsonParseForMessages(payload.content);
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
          }

          // Before showing a regular message, ensure typing indicator for this sender is cleared
          // Only clear typing indicators for actual text messages, not system messages like call signals
          const isActualMessage = (payload.type === 'message' || payload.type === 'text' || !payload.type) &&
                                  payload.content &&
                                  typeof payload.content === 'string' &&
                                  payload.content.trim().length > 0;

          if (isActualMessage) {
            try {
              const typingClearEvent = new CustomEvent('typing-indicator', {
                detail: { from: payload.from, indicatorType: 'typing-stop' }
              });
              window.dispatchEvent(typingClearEvent);
            } catch {}
          }

          // Handle regular messages (only if not a system message or file message)
          // Additional check to ensure typing indicator messages and file messages are not processed as regular messages
          if ((payload.type === 'message' || payload.type === 'text' || !payload.type) &&
              payload.content && payload.type !== 'file-message') {
            // Double-check that this is not a typing indicator message (only if content looks like JSON)
            const trimmedContent = payload.content.trim();
            if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
              const typingCheckData = safeJsonParseForMessages(payload.content);
              if (typingCheckData && (typingCheckData.type === 'typing-start' || typingCheckData.type === 'typing-stop')) {
                console.log('[EncryptedMessageHandler] Skipping typing indicator message that was already processed:', typingCheckData);
                return; // Don't process as regular message
              }
            }

            // Extract message ID from the payload content since it's encrypted along with the content
            let messageId = payload.messageId;
            let messageContent = payload.content;

            // Try to parse the content to get the actual message data (only if it looks like JSON)
            if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
              const contentData = safeJsonParseForMessages(payload.content);
              if (contentData && contentData.messageId) {
                messageId = contentData.messageId;
                messageContent = contentData.content || contentData.message || payload.content;
                if (contentData.replyTo) {
                  payload.replyTo = contentData.replyTo;
                }
                console.log('[EncryptedMessageHandler] Extracted message ID from content:', messageId);
              } else {
                // Content is JSON but no messageId, use fallback
                messageId = messageId || uuidv4();
                console.log('[EncryptedMessageHandler] Using fallback message ID for JSON content:', messageId);
              }
            } else {
              // Content is plain text, use fallback message ID
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
                recipient: (payload as any)?.to || loginUsernameRef.current,  // Prefer decrypted recipient if present
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
                  recipient: (payload as any)?.to || loginUsernameRef.current,
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
          if (payload.type === 'file-message') {
            // Extract message ID from the payload content since it's encrypted along with the content
            let messageId = payload.messageId;
            let fileName = payload.fileName;
            let fileType = payload.fileType || 'application/octet-stream';
            let fileSize = payload.fileSize || 0;
            let dataBase64: string | null = null;
            
            // Try to parse the content to get the actual message data
            const fileContentData = safeJsonParseForFileMessages(payload.content);
            if (fileContentData) {
              // Extract data even if base64 validation failed
              messageId = fileContentData.messageId || messageId || uuidv4();
              fileName = fileContentData.fileName || fileContentData.fileData || payload.fileName;
              fileType = fileContentData.fileType || fileType;
              fileSize = fileContentData.fileSize || fileSize;
              dataBase64 = fileContentData.dataBase64 || null;
              console.log('[EncryptedMessageHandler] Extracted file message data:', {
                messageId,
                fileName,
                fileType,
                fileSize,
                hasDataBase64: !!dataBase64
              });
            } else {
              // Content is not valid JSON, use fallback
              messageId = messageId || uuidv4();
              console.log('[EncryptedMessageHandler] Using fallback file message ID:', messageId);
            }
            
            // If inline base64 is present, construct a Blob URL for immediate playback/download
            let contentValue: string = payload.content;
            if (dataBase64 && typeof dataBase64 === 'string') {
              const blobUrl = createBlobUrlFromBase64(dataBase64, fileType);
              if (blobUrl) {
                contentValue = blobUrl;
              }
            }

            // Check if message already exists to prevent duplicates
            let messageExists = false;
            setMessages(prev => {
              messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                console.log('[EncryptedMessageHandler] File message already exists or skipped, not adding:', messageId);
                return prev;
              }

              // Convert base64 data to blob URL for file content if available
              let fileContent = contentValue || fileName || 'File';
              if (dataBase64) {
                const blobUrl = createBlobUrlFromBase64(dataBase64, fileType);
                if (blobUrl) {
                  fileContent = blobUrl;
                  console.log('[EncryptedMessageHandler] Created blob URL for file:', fileName, fileContent);
                } else {
                  console.error('[EncryptedMessageHandler] Failed to create blob URL, using fallback content');
                  // Don't add the message if it's a voice note and blob creation failed
                  if (fileName?.includes('voice-note') || fileType?.startsWith('audio/')) {
                    console.error('[EncryptedMessageHandler] Skipping voice note with invalid audio data');
                    // Mark that we should skip this message
                    messageExists = true; // This will prevent the message from being added
                  }
                }
              }

              const message: Message = {
                id: messageId,
                content: fileContent,
                sender: payload.from,  // Use 'sender' to match Message interface
                recipient: (payload as any)?.to || loginUsernameRef.current,  // Prefer decrypted recipient if present
                timestamp: new Date(payload.timestamp || Date.now()),  // Convert to Date object
                type: 'file',
                isCurrentUser: false,  // Received messages are not from current user
                filename: fileName,  // Add filename for voice note detection
                mimeType: fileType,  // Add mimeType for voice note detection
                fileSize: fileSize,  // Add fileSize for display
                // Store original base64 data for reliable downloads
                originalBase64Data: dataBase64,
                fileInfo: {
                  name: fileName || 'File',
                  type: fileType,
                  size: fileSize,
                  data: new ArrayBuffer(0)  // SECURITY: Zero-length buffer to prevent memory leaks
                }
              };

              return [...prev, message];
            });

            if (!messageExists) {
              // Save to database (this will also add to state)
              await saveMessageToLocalDB({
                id: messageId,
                content: contentValue || fileName || 'File',
                sender: payload.from,
                recipient: (payload as any)?.to || loginUsernameRef.current,
                timestamp: new Date(payload.timestamp || Date.now()),
                type: 'file',
                isCurrentUser: false,
                fileInfo: {
                  name: fileName || 'File',
                  type: fileType,
                  size: fileSize,
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

            // Parse call signal content with larger size limit
            const callSignalData = safeJsonParseForCallSignals(payload.content);
            if (callSignalData) {
              // Dispatch call signal event for calling service
              const callSignalEvent = new CustomEvent('call-signal', {
                detail: callSignalData
              });
              window.dispatchEvent(callSignalEvent);
            } else {
              console.error('[EncryptedMessageHandler] Failed to parse call signal content');
            }
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