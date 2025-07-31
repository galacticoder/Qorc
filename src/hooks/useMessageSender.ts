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
  const handleSendMessage = useCallback(
    async (content: string) => {
      if (!isLoggedIn || !content.trim()) return;

      try {
        const newMessage: Message = {
          id: uuidv4(),
          content,
          sender: loginUsernameRef.current,
          timestamp: new Date(),
          isCurrentUser: true,
        };

        setMessages(prev => [...prev, newMessage]);

        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;

            const payload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              recipientPEM: user.publicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: SignalType.ENCRYPTED_MESSAGE,
              content,
              timestamp: Date.now(),
              typeInside: "chat",
            });

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
