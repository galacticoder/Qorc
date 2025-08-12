import { useCallback } from "react";
import { v4 as uuidv4 } from "uuid";
import websocketClient from "@/lib/websocket";
import { Message } from "@/components/chat/ChatMessage";
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
        
        //_____________________________________SERVER DB UPDATE
        // if (!aesKey) {
        //   console.log("No AES key for updating db. Re-login again or else your message history wont be saved");
        //   return;
        // }

        // const txtTest = "test text";

        // const decryptedText = await CryptoUtils.Decrypt.decryptMessage(encryptedPayload, aesKey); //decrypt like this when receiving back
        
          // { //local scope so isnt accessable from anywhere else
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
                    content: replyTo.content,
                  },
                }),
              });
              
              console.log("DB update payload to server sent: ", serverPayloadDBUpdate);
              websocketClient.send(JSON.stringify(serverPayloadDBUpdate));
            })
          );
          // }
          //_____________________________________________________________
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
              typeInside: "chat", //forgot to adapt the delete and edit buttons
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
    async (messageId: string) => {
      if (!isLoggedIn) return;

      try {
        console.log("messGEW deleted")
        
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;
            
            const payload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              recipientPEM: user.publicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.ENCRYPTED_MESSAGE,
              typeInside: SignalType.DELETE_MESSAGE,
              messageId,
              timestamp: Date.now(),
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
    async (messageId: string, newContent: string) => {
      if (!isLoggedIn || !newContent.trim()) return;

      console.log("message eddited")

      const time = Date.now();

      try {
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

            /*
            
            {
              "from": "loginUsernameHere",
              "to": "userUsernameHere",
              "type": "ENCRYPTED_MESSAGE",       // from SignalType.ENCRYPTED_MESSAGE
              "encryptedAESKey": "<base64 string>", // RSA encrypted AES key (base64)
              "encryptedMessage": "<string>"        // AES encrypted and serialized JSON of:
              // {
              //   "messageId": "...",
              //   "typeInside": "EDIT_MESSAGE",
              //   "content": "...",
              //   "timestamp": "..."
              // }
            }

            
            */
            
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