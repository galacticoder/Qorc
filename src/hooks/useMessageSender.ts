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
  serverHybridPublic: { x25519PublicBase64: string; kyberPublicBase64: string } | null,
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  aesKeyRef: React.MutableRefObject<CryptoKey | null>,
  keyManagerRef?: React.MutableRefObject<any>,
  passphraseRef?: React.MutableRefObject<string>,
  isLoggedIn?: boolean
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
    async ({
      messageId,
      replyTo,
      type,
      typeInside,
      content,
    }: {
      messageId?: string;
      replyTo?: Message | null;
      type?: string;
      typeInside?: string;
      content?: string;
    }) => {
      if (!serverHybridPublic) {
        console.error("Server keys not available");
        return;
      }

      const hybridKeys = await getKeysOnDemand();
      if (!hybridKeys) {
        console.error("Client keys not available");
        return;
      }

      const time = Date.now();
      const id = messageId || await getDeterministicMessageId({
        content: content || "",
        timestamp: time,
        sender: loginUsernameRef.current,
        replyToId: replyTo?.id
      });

      try {
        await Promise.all(
          users.map(async (user) => {
            if (!user.hybridPublicKeys) return;

            const messagePayload = {
              id: id,
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
            };

            const userEncrypted = await CryptoUtils.Hybrid.encryptHybridPayload(
              messagePayload,
              user.hybridPublicKeys
            );

            const finalUserPayload = {
              type: SignalType.ENCRYPTED_MESSAGE,
              from: loginUsernameRef.current,
              to: user.username,
              encryptedPayload: userEncrypted
            };

            websocketClient.send(JSON.stringify(finalUserPayload));

            console.log(`Sent to user ${user.username}: `, finalUserPayload);

            //send to server db for storage
            if (serverHybridPublic && aesKeyRef.current) {
              const { iv, authTag, encrypted } = await CryptoUtils.AES.encryptWithAesGcmRaw(
                content,
                aesKeyRef.current
              );
              const encryptedContent = CryptoUtils.AES.serializeEncryptedData(iv, authTag, encrypted);

              let encryptedReplyContent = "";
              if (replyTo) {
                const replyContent = replyTo.content || "";
                const { iv: replyIv, authTag: replyAuthTag, encrypted: replyEncrypted } = await CryptoUtils.AES.encryptWithAesGcmRaw(
                  replyContent,
                  aesKeyRef.current
                );
                encryptedReplyContent = CryptoUtils.AES.serializeEncryptedData(replyIv, replyAuthTag, replyEncrypted);
              }

              const serverPayload = {
                messageId: id,
                fromUsername: loginUsernameRef.current,
                toUsername: user.username,
                encryptedContent: encryptedContent,
                timestamp: time,
                typeInside: typeInside,
                ...(replyTo && {
                  replyTo: {
                    id: replyTo.id,
                    sender: replyTo.sender,
                    encryptedContent: encryptedReplyContent,
                  },
                }),
              };

              const serverEncrypted = await CryptoUtils.Hybrid.encryptHybridPayload(
                serverPayload,
                serverHybridPublic
              );

              const dbPayload = {
                type: SignalType.UPDATE_DB,
                ...serverEncrypted
              };

              websocketClient.send(JSON.stringify(dbPayload));

              console.log(`Sent to server database:`, serverPayload.messageId);
            }
          })
        );

        //save to local db
        onNewMessage({
          id: id,
          content: content || "",
          sender: loginUsernameRef.current,
          timestamp: new Date(),
          isCurrentUser: true,
          isDeleted: typeInside === SignalType.DELETE_MESSAGE,
          ...(replyTo ? { replyTo } : {})
        });
      } catch (error) {
        console.error("handleMessage failed:", error);
      }
    },
    [users, loginUsernameRef, serverHybridPublic, getKeysOnDemand, aesKeyRef, onNewMessage]
  );

  const handleSendMessageType = useCallback(
    async (messageId: string, content: string, messageSignalType: string, replyTo?: Message | null) => {
      if (messageSignalType === "chat") {
        await handleSendMessage({
          replyTo: replyTo,
          type: SignalType.ENCRYPTED_MESSAGE,
          typeInside: "chat",
          content: content,
        });
      } else {
        await handleSendMessage({
          messageId: messageId,
          replyTo: replyTo,
          type: SignalType.ENCRYPTED_MESSAGE,
          typeInside: messageSignalType,
          content: content,
        });
      }
    },
    [handleSendMessage]
  );

  return { handleMessage: handleSendMessage, handleSendMessageType };
}