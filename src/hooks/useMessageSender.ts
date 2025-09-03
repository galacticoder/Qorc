import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";
import websocketClient from "@/lib/websocket";
import { User } from "@/components/chat/types";
import { CryptoUtils } from "@/lib/unified-crypto";
import { ServerDatabase } from "./useSecureDB";

export function useMessageSender(
  users: User[],
  loginUsernameRef: React.MutableRefObject<string>,
  onNewMessage: (message: Message) => void,
  serverHybridPublic: { x25519PublicBase64: string; kyberPublicBase64: string } | null,
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  aesKeyRef: React.MutableRefObject<CryptoKey | null>,
  keyManagerRef?: React.MutableRefObject<any>,
  passphraseRef?: React.MutableRefObject<string>,
  isLoggedIn?: boolean
) {
  const pendingSendsRef = { current: [] as Array<() => Promise<void>> } as any;
  let flushTimer: any = null;

  function scheduleFlush(delayMs: number) {
    if (flushTimer) return;
    flushTimer = setTimeout(async () => {
      flushTimer = null;
      const tasks = pendingSendsRef.current.splice(0, pendingSendsRef.current.length);

      // SECURITY: Handle all promises properly to prevent unhandled rejections
      const taskPromises = tasks.map(async (task) => {
        try {
          await task();
        } catch (error) {
          console.error('[MessageSender] Task execution failed:', error);
          // Don't rethrow to prevent unhandled rejection
        }
      });

      try {
        await Promise.allSettled(taskPromises);
      } catch (error) {
        console.error('[MessageSender] Batch task execution failed:', error);
      }
    }, delayMs);
  }

  async function waitForSessionAvailability(currentUser: string, peer: string, totalMs = 5000, intervalMs = 100): Promise<boolean> {
    const start = Date.now();
    let attempt = 0;

    // SECURITY: Add mutex to prevent concurrent session checks for same peer
    const sessionKey = `${currentUser}-${peer}`;
    if (waitForSessionAvailability._pending?.has?.(sessionKey)) {
      console.log('[MessageSender] Session check already in progress for', sessionKey);
      return waitForSessionAvailability._pending.get(sessionKey);
    }

    // Initialize pending map if not exists
    if (!waitForSessionAvailability._pending) {
      waitForSessionAvailability._pending = new Map();
    }

    const sessionPromise = (async () => {
      try {
        // First check if session already exists
        try {
          const sessionCheck = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername: peer, deviceId: 1 });
          if (sessionCheck?.hasSession) {
            return true;
          }
        } catch (e) {
          console.error('[MessageSender] Initial session check failed:', e);
        }
    
    // Listen for session ready event
    return new Promise((resolve) => {
      const eventListener = (event: any) => {
        if (event.detail?.peer === peer) {
          window.removeEventListener('libsignal-session-ready', eventListener);
          resolve(true);
        }
      };
      
      window.addEventListener('libsignal-session-ready', eventListener);
      
      // Fallback polling mechanism with timeout
      const pollForSession = async () => {
        while (Date.now() - start < totalMs) {
          try {
            const sessionCheck = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername: peer, deviceId: 1 });
            if (sessionCheck?.hasSession) {
              window.removeEventListener('libsignal-session-ready', eventListener);
              resolve(true);
              return;
            }
          } catch (e) {
            console.error('[MessageSender] Session polling failed:', e);
          }
          attempt++;
          await new Promise(res => setTimeout(res, intervalMs));
        }
        
        window.removeEventListener('libsignal-session-ready', eventListener);
        resolve(false);
      };
      
      pollForSession().catch(error => {
        console.error('[MessageSender] Session polling error:', error);
        window.removeEventListener('libsignal-session-ready', eventListener);
        resolve(false);
      });
    });
      } finally {
        // SECURITY: Clean up pending session check
        waitForSessionAvailability._pending?.delete?.(sessionKey);
      }
    })();

    // Store the promise to prevent concurrent checks
    waitForSessionAvailability._pending.set(sessionKey, sessionPromise);
    return sessionPromise;
  }

  async function getDeterministicMessageId(message: {
    content: string;
    timestamp: number;
    sender: string;
    replyToId?: string;
  }): Promise<string> {
    // Use a more stable timestamp (round to nearest second) to prevent ID changes
    const stableTimestamp = Math.floor(message.timestamp / 1000) * 1000;
    const normalized = `${message.sender}:${message.content}:${stableTimestamp}${message.replyToId ? `:${message.replyToId}` : ''}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(normalized);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const idHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const messageId = idHex.slice(0, 16);
    
    console.log('[MessageSender] Generated message ID:', {
      originalTimestamp: message.timestamp,
      stableTimestamp,
      normalized,
      messageId
    });
    
    return messageId;
  }

  const handleSendMessage = useCallback(async (user: User, content: string, replyTo?: string | { id: string; sender?: string; content?: string }, fileData?: string, messageSignalType?: string, originalMessageId?: string, editMessageId?: string) => {
    if (!isLoggedIn || !loginUsernameRef.current) return;

    const currentUser = loginUsernameRef.current;
    const replyToId = typeof replyTo === 'string' ? replyTo : replyTo?.id;
    const replyToData = replyToId ? {
      id: replyToId,
      ...(typeof replyTo === 'object' ? { sender: replyTo.sender, content: replyTo.content } : {})
    } : undefined;

    console.log('[MessageSender] Reply processing:', {
      replyToParam: replyTo,
      replyToType: typeof replyTo,
      replyToId,
      replyToData,
      hasReplyToData: !!replyToData
    });

    // For edit messages, use the editMessageId parameter (original message ID)
    // For other messages, generate a new deterministic ID
    let actualMessageId;
    if (messageSignalType === 'edit-message' && editMessageId) {
      actualMessageId = editMessageId;
      console.log('[MessageSender] Using original message ID for edit:', actualMessageId);
    } else {
      actualMessageId = await getDeterministicMessageId({
        content,
        timestamp: Date.now(),
        sender: currentUser,
        replyToId
      });
    }

    // Check if we have a session with this user
    try {
      // Check existing session
      const sessionCheck = await (window as any).edgeApi?.hasSession?.({ 
        selfUsername: currentUser, 
        peerUsername: user.username, 
        deviceId: 1 
      });
      if (!sessionCheck?.hasSession) {
        // Request prekey bundle from server for this specific peer
        websocketClient.send(JSON.stringify({ 
          type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, 
          username: user.username 
        }));
        // Wait for session to become available after bundle is delivered
        const sessionAvailable = await waitForSessionAvailability(currentUser, user.username);
        if (!sessionAvailable) {
          console.error('[MessageSender] Session not available after waiting');
          return;
        }
      }
    } catch (error) {
      console.error('[MessageSender] Session check failed:', error);
      return;
    }

    // Encrypt the message using Signal Protocol
    try {
      console.log('[MessageSender] Attempting to encrypt message:', {
        fromUsername: currentUser,
        toUsername: user.username,
        contentLength: content.length,
        messageId: actualMessageId
      });

      const messageType = messageSignalType === 'typing-start' || messageSignalType === 'typing-stop' ? 'typing-indicator' : 
                          messageSignalType === 'delete-message' ? 'delete-message' :
                          messageSignalType === 'edit-message' ? 'edit-message' :
                          (fileData ? 'file-message' : 'message');
      
      console.log('[MessageSender] Preparing message with type:', { messageType, messageSignalType, content: content.substring(0, 100) });
      
      const encryptedMessage = await (window as any).edgeApi.encrypt({
        fromUsername: currentUser,
        toUsername: user.username,
        plaintext: JSON.stringify({
          messageId: actualMessageId,  // Use 'messageId' to match receiver expectations
          from: currentUser,
          to: user.username,
          content: content,
          timestamp: Date.now(),
          messageType: 'signal-protocol',  // Add message type identifier
          signalType: 'signal-protocol',   // Add signal type for server validation
          protocolType: 'signal',          // Add protocol type identifier
          type: messageType,  // Use special type for typing indicators
          ...(messageSignalType === 'delete-message' && originalMessageId && { deleteMessageId: originalMessageId }),
          ...(replyToData && { replyTo: replyToData }),
          ...(fileData && { fileData })
        })
      });

      // SECURITY: Log only non-sensitive metadata
      console.log('[MessageSender] Encryption result details:', {
        hasResult: !!encryptedMessage,
        resultType: typeof encryptedMessage,
        resultKeys: encryptedMessage ? Object.keys(encryptedMessage) : [],
        hasCiphertext: !!encryptedMessage?.ciphertextBase64,
        ciphertextLength: encryptedMessage?.ciphertextBase64?.length || 0,
        hasType: !!encryptedMessage?.type,
        typeValue: encryptedMessage?.type,
        hasSessionId: !!encryptedMessage?.sessionId
        // SECURITY: No actual ciphertext or session ID values logged
      });

      // Check for encryption errors
      if (encryptedMessage?.error) {
        console.error('[MessageSender] Encryption failed:', encryptedMessage.message || 'Unknown error');
        // Try to handle specific error types
        if (encryptedMessage.code === 'EBADF') {
          console.error('[MessageSender] File descriptor error - this should not happen with the new error handling');
        }
        return;
      }

      if (!encryptedMessage?.ciphertextBase64) {
        console.error('[MessageSender] Encryption returned no ciphertext');
        return;
      }

      // Create the message payload
      const messagePayload = {
        type: SignalType.ENCRYPTED_MESSAGE,
        to: user.username,  // Add 'to' field at root level for server parsing
        encryptedPayload: {
          from: currentUser,
          to: user.username,
          content: encryptedMessage.ciphertextBase64,
          messageId: actualMessageId,
          type: encryptedMessage.type,  // Use the actual Signal Protocol message type (1 or 3)
          sessionId: encryptedMessage.sessionId  // Add session ID for server validation
        }
      };

      // Send the encrypted message
      websocketClient.send(JSON.stringify(messagePayload));

      // Handle delete messages locally for sender
      if (messageSignalType === 'delete-message' && originalMessageId) {
        console.log('[MessageSender] Processing local delete for sender:', { originalMessageId });
        // Create a custom event to trigger local message deletion
        const deleteEvent = new CustomEvent('local-message-delete', {
          detail: { messageId: originalMessageId }
        });
        window.dispatchEvent(deleteEvent);
        return; // Don't create a new message for delete signals
      }

      // Handle edit messages locally for sender
      if (messageSignalType === 'edit-message') {
        console.log('[MessageSender] Processing local edit for sender:', { messageId: actualMessageId, content: content.substring(0, 100) });
        // For edit messages, use the messageId passed from the UI (which is the original message ID)
        // Don't generate a new ID for edits
        const editEvent = new CustomEvent('local-message-edit', {
          detail: { messageId: actualMessageId, newContent: content }
        });
        window.dispatchEvent(editEvent);
        return; // Don't create a new message for edit signals
      }

      // Create local message for UI (only for non-typing indicator messages, non-delete messages, and non-edit messages)
      if (messageSignalType !== 'typing-start' && messageSignalType !== 'typing-stop' && messageSignalType !== 'delete-message' && messageSignalType !== 'edit-message') {
        console.log('[MessageSender] Creating local message for UI:', { messageId: actualMessageId, content: content.substring(0, 100) });
        const localMessage: Message = {
          id: actualMessageId,
          content: content,
          sender: currentUser,
          recipient: user.username,  // Add recipient field for proper filtering
          timestamp: new Date(),
          type: fileData ? 'file' : 'text',
          isCurrentUser: true,  // Sent messages are from current user
          receipt: {
            delivered: false,
            read: false
          },
          ...(replyToData && { replyTo: replyToData }),
          ...(fileData && { fileInfo: { name: fileData, type: 'text/plain', size: 0, data: new ArrayBuffer(0) } })
        };

        onNewMessage(localMessage);
      } else {
        console.log('[MessageSender] Skipping local message creation for:', { messageSignalType, messageId: actualMessageId });
      }

      // Note: Delivery receipt should be sent by the recipient when they receive the message
      // Not by the sender immediately after sending
      // This will be implemented when proper delivery receipt handling is added

    } catch (error) {
      // Encryption failed
      return;
    }
  }, [isLoggedIn, onNewMessage, getKeysOnDemand]);

  return { handleSendMessage };
}