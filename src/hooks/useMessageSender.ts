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
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>
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
        
        setMessages(prev => [...prev, newMessage]);

        
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

        setMessages(prev => [
          ...prev,
          {
            id: uuidv4(),
            content: `Failed to send message: ${error instanceof Error ? error.message : "Unknown error"}`,
            sender: "System",
            timestamp: new Date(),
            isCurrentUser: false,
            isSystemMessage: true,
          },
        ]);
      }
    },
    [isLoggedIn, users, loginUsernameRef, setMessages]
  );

  return { handleSendMessage };
}
