import { useCallback } from "react";
import { v4 as uuidv4 } from "uuid";
import websocketClient from "@/lib/websocket";
import { Message } from "@/components/chat/types";
import { SignalType } from "@/lib/signals";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";

export function useMessageSender(
  isLoggedIn: boolean,
  users: User[],
  loginUsernameRef: React.MutableRefObject<string>,
  onNewMessage: (message: Message) => void,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  aesKey: CryptoKey | null,
  serverPublicKey: string
) {
  async function getDeterministicMessageId(message: {
    content: string;
    timestamp: number;
    sender: string;
    replyToId?: string;
  }): Promise<string> {
    const encoder = new TextEncoder();

    const replyPart = message.replyToId ? `:${message.replyToId}` : '';
    const normalized = `${message.content.trim()}:${message.timestamp}:${message.sender.trim().toLowerCase()}${replyPart}`;
    
    const hashBuffer = await crypto.subtle.digest("SHA-512", encoder.encode(normalized));
    
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  const handleSendMessage = useCallback(
    async (content: string, replyTo?: Message | null) => {
      if (!isLoggedIn || !content.trim()) return;
      
      try {
        const time = Date.now();
        
        const messageId = await getDeterministicMessageId({
          content: content,
          timestamp: time,
          sender: loginUsernameRef.current,
          replyToId: replyTo?.id
        });
        
        console.log(`Message ID sent: `, messageId)
        
        const newMessage: Message = {
          id: messageId,
          content,
          sender: loginUsernameRef.current,
          timestamp: new Date(),
          isCurrentUser: true,
          ...(replyTo ? { replyTo } : {}),
        };
                
        onNewMessage(newMessage);

        //send message for server db update
        const ciphertext = await CryptoUtils.Encrypt.encryptWithAES(content, aesKey);
        const serializedCiphertext = CryptoUtils.Encrypt.serializeEncryptedData(
          ciphertext.iv,
          ciphertext.authTag,
          ciphertext.encrypted
        );

        console.log(`Server db update serialized ciphertext: ${serializedCiphertext}`)
          
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;
            
            const serverPayloadDBUpdate = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              id: messageId,
              recipientPEM: serverPublicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.UPDATE_DB,
              content: serializedCiphertext,
              timestamp: time,
              typeInside: "chat",
              ...(replyTo && {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: serializedCiphertext, //when decrypting message history send back from the server later after decrypting payload decyrpt this seperately and re-set this var
                },
              }),
            });
            
            console.log("DB update payload to server sent: ", serverPayloadDBUpdate);
            websocketClient.send(JSON.stringify(serverPayloadDBUpdate));
          })
        );

        //message to users
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;
            
            const payload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              id: messageId,
              recipientPEM: user.publicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.ENCRYPTED_MESSAGE,
              content,
              timestamp: time,
              typeInside: "chat",
              ...(replyTo && {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: replyTo.content,
                },
              }),
            });
            
            console.log("Message payload sent: ", payload);
            websocketClient.send(JSON.stringify(payload));
          })
        );
      } catch (error) {
        console.error("E2EE send error:", error);

        onNewMessage({
          id: uuidv4(),
          content: `Failed to send message: ${error instanceof Error ? error.message : "Unknown error"}`,
          sender: "System",
          timestamp: new Date(),
          isCurrentUser: false,
          isSystemMessage: true,
        });
      }
    },
    [isLoggedIn, users, loginUsernameRef, onNewMessage]
  );

  const handleDeleteMessage = useCallback(
    async (messageId: string, replyTo?: Message | null) => {
      if (!isLoggedIn) return;

      try {
        console.log("messGEW deleted")

        const ciphertext = await CryptoUtils.Encrypt.encryptWithAES("", aesKey);
        const serializedCiphertext = CryptoUtils.Encrypt.serializeEncryptedData(
          ciphertext.iv,
          ciphertext.authTag,
          ciphertext.encrypted
        );
        
        console.log(`Server db update serialized ciphertext: ${serializedCiphertext}`)
        const time = Date.now();
        
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;
            
            const serverPayloadDBUpdate = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              id: messageId,
              recipientPEM: serverPublicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.UPDATE_DB,
              content: serializedCiphertext,
              timestamp: time,
              typeInside: SignalType.DELETE_MESSAGE,
            });
            
            console.log("DB update payload to server sent (Delete message): ", serverPayloadDBUpdate);
            websocketClient.send(JSON.stringify(serverPayloadDBUpdate));
          })
        );
          
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;
            
            const payload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              recipientPEM: user.publicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.ENCRYPTED_MESSAGE,
              typeInside: SignalType.DELETE_MESSAGE,
              id: messageId,
              timestamp: time,
            });
            
            websocketClient.send(JSON.stringify(payload));

            setMessages(prev => prev.map(msg => 
             msg.id === messageId 
               ? { ...msg, isDeleted: true, content: "Message deleted" } 
               : msg
           ));
          })
        );
      } catch (error) {
        console.error("Delete failed:", error);
      }
    },
    [isLoggedIn, users, loginUsernameRef]
  );

   const handleEditMessage = useCallback(
    async (messageId: string, newContent: string, replyTo?: Message | null) => {
      if (!isLoggedIn || !newContent.trim()) return;
      
      
      try {
      //___________________________
      
      
      const ciphertext = await CryptoUtils.Encrypt.encryptWithAES(newContent, aesKey);
      const serializedCiphertext = CryptoUtils.Encrypt.serializeEncryptedData(
        ciphertext.iv,
        ciphertext.authTag,
        ciphertext.encrypted
      );
      
      console.log(`Server db update serialized ciphertext: ${serializedCiphertext}`)
      const time = Date.now();
      
      await Promise.all(
        users.map(async (user) => {
          if (user.username === loginUsernameRef.current || !user.publicKey) return;
          
          const serverPayloadDBUpdate = await CryptoUtils.Encrypt.encryptAndFormatPayload({
            id: messageId,
            recipientPEM: serverPublicKey,
            from: loginUsernameRef.current,
            to: user.username,
            type: SignalType.UPDATE_DB,
            content: serializedCiphertext,
            timestamp: time,
            typeInside: SignalType.EDIT_MESSAGE,
            ...(replyTo && {
              replyTo: {
                id: replyTo.id,
                sender: replyTo.sender,
                content: replyTo.content,
              },
            }),
          });
          
          console.log("DB update payload to server sent (Edit message): ", serverPayloadDBUpdate);
          websocketClient.send(JSON.stringify(serverPayloadDBUpdate));
        })
      );
      //___________________________
      
      
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;
            
            const payload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              recipientPEM: user.publicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.ENCRYPTED_MESSAGE,
              messageId,
              typeInside: SignalType.EDIT_MESSAGE,
              content: newContent,
              timestamp: time,
            });

            websocketClient.send(JSON.stringify(payload));

            setMessages(prev => prev.map(msg => 
              msg.id === messageId 
                ? { ...msg, content: newContent, isEdited: true } 
                : msg
            ));
          })
        );
      } catch (error) {
        console.error("Failed to edit message:", error);
      }
    },
    [isLoggedIn, users, loginUsernameRef]
  );

  return { handleSendMessage, handleDeleteMessage, handleEditMessage };
}