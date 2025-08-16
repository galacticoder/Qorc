import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";

export function useEncryptedMessageHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  loginUsernameRef: React.MutableRefObject<string>,
  setUsers: React.Dispatch<React.SetStateAction<any[]>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
  return useCallback(
    async (encryptedMessage: any) => {
      try {
        const hybridKeys = await getKeysOnDemand();
        if (!hybridKeys) {
          console.error("Client hybrid keys not available for decryption");
          return;
        }

        const payload = await CryptoUtils.Hybrid.decryptHybridPayload(
          encryptedMessage,
          {
            x25519: { private: hybridKeys.x25519.private },
            kyber: { secretKey: hybridKeys.kyber.secretKey }
          }
        );

        if (payload.type === SignalType.USER_DISCONNECT) {
          const username = payload.content?.split(" ")[0];
          if (username) {
            setUsers(prevUsers =>
              prevUsers.filter(user => user.username !== username)
            );
          }
          return;
        }

        const isJoinLeave = payload.content?.includes("joined") ||
          payload.content?.includes("left");

        const messageId = payload.typeInside === "system"
          ? uuidv4()
          : payload.id ?? uuidv4();

        const payloadFull: Message = {
          id: messageId,
          content: payload.content || "",
          sender: payload.from || "system",
          timestamp: new Date(payload.timestamp || Date.now()),
          isCurrentUser: payload.from === loginUsernameRef.current,
          isSystemMessage: payload.typeInside === "system",
          isDeleted: payload.typeInside === SignalType.DELETE_MESSAGE,
          isEdited: payload.typeInside === SignalType.EDIT_MESSAGE,
          shouldPersist: isJoinLeave,
          ...(payload.replyTo && {
            replyTo: {
              id: payload.replyTo.id,
              sender: payload.replyTo.sender,
              content: payload.replyTo.content,
            },
          }),
        };

        await saveMessageToLocalDB(payloadFull);

        console.log("Received payload: ", payload)

        setMessages(prev => {
          const exists = prev.some(msg => msg.id === payloadFull.id);
          if (exists) {
            return prev;
          }
          return [...prev, payloadFull];
        });

        if (payloadFull.isEdited || payloadFull.isDeleted) {
          setMessages(prev => prev.map(msg => {
            const updated = { ...msg };
            const content = payloadFull.isEdited
              ? payload.content
              : "Message Deleted";

            if (msg.replyTo?.id === payload.id) {
              updated.replyTo = { ...updated.replyTo, content: content };
              saveMessageToLocalDB(updated);
            }

            return updated;
          }));
        }
      } catch (error) {
        console.error("Error handling encrypted message:", error);
      }
    },
    [saveMessageToLocalDB, getKeysOnDemand, setUsers, setMessages]
  );
}