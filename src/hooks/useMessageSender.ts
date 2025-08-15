import { useCallback } from "react";
import websocketClient from "@/lib/websocket";
import { Message } from "@/components/chat/types";
import { SignalType } from "@/lib/signals";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import { ServerDatabase } from "./useSecureDB";

export function useMessageSender(
  users: User[],
  loginUsernameRef: React.MutableRefObject<string>,
  onNewMessage: (message: Message) => void,
  aesKey: CryptoKey | null,
  serverPublicKey: string,
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

  const handleMessage = useCallback(
    async ({
      messageId,
      replyTo,
      type,
      typeInside,
      content,
      aesKey
    }: {
      messageId?: string,
      replyTo?: Message | null,
      type?: string,
      typeInside?: string,
      content?: string,
      aesKey?: CryptoKey | null
    }) => {

      const time = Date.now();

      const id = messageId || await getDeterministicMessageId({ //make new message id for normal chat messages
        content: content,
        timestamp: time,
        sender: loginUsernameRef.current,
        replyToId: replyTo?.id
      });

      try {
        await Promise.all(
          users.map(async (user) => {
            if (user.username === loginUsernameRef.current || !user.publicKey) return;

            // send to server DB
            await ServerDatabase.sendDataToServerDb({
              messageId: id,
              serverPemKey: serverPublicKey,
              fromUsername: loginUsernameRef.current,
              toUsername: user.username,
              content: "",
              timestamp: time,
              typeInside: "chat",
              aesKey: aesKey,
              ...(replyTo && {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: replyTo.content,
                },
              }),
            });

            // send to other users
            const payload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
              id: id,
              recipientPEM: user.publicKey,
              from: loginUsernameRef.current,
              to: user.username,
              type: type,
              content: content,
              timestamp: time,
              typeInside: typeInside,
              ...(replyTo && {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: replyTo.content,
                },
              }),
            });

            websocketClient.send(JSON.stringify(payload));
          })
        );

        onNewMessage({ //save to localdb
          id: id,
          content: content,
          sender: loginUsernameRef.current,
          timestamp: new Date(),
          isCurrentUser: true,
          isDeleted: typeInside == SignalType.DELETE_MESSAGE,
          ...(replyTo ? { replyTo } : {})
        });
      } catch (error) {
        console.error("handleMessage failed:", error);
      }
    },
    [users, loginUsernameRef, serverPublicKey, aesKey, onNewMessage]
  );

  const handleSendMessageType = useCallback(
    async (messageId: string, content: string, messageSignalType: string, replyTo?: Message | null) => {
      if (messageSignalType === "chat") {
        await handleMessage({
          replyTo: replyTo,
          type: SignalType.ENCRYPTED_MESSAGE,
          typeInside: "chat",
          content: content,
          aesKey: aesKey
        }
        )
      } else {
        await handleMessage({ //if message typeInside isnt "chat"
          messageId: messageId,
          replyTo: replyTo,
          type: SignalType.ENCRYPTED_MESSAGE,
          typeInside: messageSignalType,
          content: content,
          aesKey: aesKey
        })
      }
    },
    [handleMessage]
  );

  return { handleMessage, handleSendMessageType };
}