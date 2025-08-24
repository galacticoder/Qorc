import { useCallback } from "react";
import { Message } from "@/components/chat/types";
import { SignalType } from "@/lib/signals";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
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
      for (const task of tasks) {
        try { await task(); } catch { /* keep quiet */ }
      }
    }, delayMs);
  }

  async function waitForSessionAvailability(currentUser: string, peer: string, totalMs = 5000, intervalMs = 100): Promise<boolean> {
    const start = Date.now();
    let attempt = 0;
    
    // First check if session already exists
    try {
      const sessionCheck = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername: peer, deviceId: 1 });
      if (sessionCheck?.hasSession) {
        return true;
      }
    } catch (e) {
      // Session check failed
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
            // Session check failed
          }
          attempt++;
          await new Promise(res => setTimeout(res, intervalMs));
        }
        
        window.removeEventListener('libsignal-session-ready', eventListener);
        resolve(false);
      };
      
      pollForSession();
    });
  }

  async function getDeterministicMessageId(message: {
    content: string;
    timestamp: number;
    sender: string;
    replyToId?: string;
  }): Promise<string> {
    const normalized = `${message.sender}:${message.content}:${message.timestamp}${message.replyToId ? `:${message.replyToId}` : ''}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(normalized);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const idHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return idHex.slice(0, 16);
  }

  const handleSendMessage = useCallback(async (user: User, content: string, replyToId?: string, fileData?: string, messageSignalType?: string) => {
    if (!isLoggedIn || !loginUsernameRef.current) return;

    const currentUser = loginUsernameRef.current;
    const messageId = await getDeterministicMessageId({
      content,
      timestamp: Date.now(),
      sender: currentUser,
      replyToId
    });

    // Check if we have a session with this user
    try {
      console.log('[MessageSender] Checking session availability for:', {
        selfUsername: currentUser,
        peerUsername: user.username,
        deviceId: 1
      });
      
      const sessionCheck = await (window as any).edgeApi?.hasSession?.({ 
        selfUsername: currentUser, 
        peerUsername: user.username, 
        deviceId: 1 
      });
      
      console.log('[MessageSender] Session check result:', sessionCheck);
      
      if (!sessionCheck?.hasSession) {
        console.log('[MessageSender] No session exists, requesting prekey bundle');
        // No session exists, request a prekey bundle
        websocketClient.send(JSON.stringify({ 
          type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, 
          username: user.username 
        }));
        
        // Wait for session to become available
        const sessionAvailable = await waitForSessionAvailability(currentUser, user.username);
        console.log('[MessageSender] Session availability wait result:', sessionAvailable);
        if (!sessionAvailable) {
          console.error('[MessageSender] Session not available after waiting');
          return;
        }
      } else {
        console.log('[MessageSender] Session already exists, proceeding with encryption');
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
        messageId
      });

      const messageType = messageSignalType === 'typing-start' || messageSignalType === 'typing-stop' ? 'typing-indicator' : (fileData ? 'file-message' : 'message');
      
      console.log('[MessageSender] Preparing message with type:', { messageType, messageSignalType, content: content.substring(0, 100) });
      
      const encryptedMessage = await (window as any).edgeApi.encrypt({
        fromUsername: currentUser,
        toUsername: user.username,
        plaintext: JSON.stringify({
          messageId: messageId,  // Use 'messageId' to match receiver expectations
          from: currentUser,
          to: user.username,
          content: content,
          timestamp: Date.now(),
          messageType: 'signal-protocol',  // Add message type identifier
          signalType: 'signal-protocol',   // Add signal type for server validation
          protocolType: 'signal',          // Add protocol type identifier
          type: messageType,  // Use special type for typing indicators
          ...(replyToId && { replyTo: { id: replyToId } }),
          ...(fileData && { fileData })
        })
      });

      console.log('[MessageSender] Raw encryption result from edgeApi:', encryptedMessage);
      console.log('[MessageSender] Encryption result details:', {
        hasResult: !!encryptedMessage,
        resultType: typeof encryptedMessage,
        resultKeys: encryptedMessage ? Object.keys(encryptedMessage) : [],
        hasCiphertext: !!encryptedMessage?.ciphertextBase64,
        ciphertextLength: encryptedMessage?.ciphertextBase64?.length || 0,
        hasType: !!encryptedMessage?.type,
        typeValue: encryptedMessage?.type,
        hasSessionId: !!encryptedMessage?.sessionId,
        sessionIdValue: encryptedMessage?.sessionId
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
          messageId: messageId,
          type: encryptedMessage.type,  // Use the actual Signal Protocol message type (1 or 3)
          sessionId: encryptedMessage.sessionId  // Add session ID for server validation
        }
      };

      // Send the encrypted message
      websocketClient.send(JSON.stringify(messagePayload));

      // Create local message for UI (only for non-typing indicator messages)
      if (messageSignalType !== 'typing-start' && messageSignalType !== 'typing-stop') {
        console.log('[MessageSender] Creating local message for UI:', { messageId, content: content.substring(0, 100) });
        const localMessage: Message = {
          id: messageId,
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
          ...(fileData && { fileInfo: { name: fileData, type: 'text/plain', size: 0, data: new ArrayBuffer(0) } })
        };

        onNewMessage(localMessage);
      } else {
        console.log('[MessageSender] Skipping local message creation for typing indicator:', { messageSignalType, messageId });
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