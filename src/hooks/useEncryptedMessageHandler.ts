import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";

export function useEncryptedMessageHandler(
  privateKeyRef: React.RefObject<CryptoKey>,
  setUsers: React.Dispatch<React.SetStateAction<any[]>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
) {
  return useCallback(
    async (message: any) => {
      try {
        console.log("Message received. Starting decryption...");
        const payload = await CryptoUtils.Decrypt.decryptAndFormatPayload(
          message,
          privateKeyRef.current
        );
        console.log("Payload decrypted. Message type: ", payload.type);

        if (message.type == SignalType.USER_DISCONNECT) {
          setUsers(prevUsers =>
            prevUsers.filter(
              user => user.username !== payload.content.split(" ")[0]
            )
          );
        }

        if (payload.typeInside === SignalType.DELETE_MESSAGE) {//SAVE THIS AND THE EDIT MESSAGE TO DB LATER TOO
          console.log("payload delete: ", payload);
          setMessages(prev =>
            prev.map(msg =>
              msg.id === payload.id
                ? { ...msg, isDeleted: true, content: "Message deleted" }
                : msg
            )
          );
          return;
        }

        if (payload.typeInside === SignalType.EDIT_MESSAGE) {
          console.log("payload edit: ", payload);
          setMessages(prev =>
            prev.map(msg =>
              msg.id === payload.id
                ? {
                  ...msg,
                  content: payload.content,
                  isEdited: true,
                  timestamp: new Date(payload.timestamp),
                }
                : msg
            )
          );
          return;
        }

        const isJoinLeave = payload.content.includes("joined") || payload.content.includes("left");

        console.log("Message ID received: ", payload.id);

        const payloadFull: Message = {
          id:
            payload.typeInside === "system"
              ? uuidv4()
              : payload.id ?? uuidv4(),
          content: payload.content,
          sender: message.from,
          timestamp: new Date(payload.timestamp),
          isCurrentUser: false,
          isSystemMessage: payload.typeInside === "system",
          shouldPersist: isJoinLeave,
          ...(payload.replyTo && {
            replyTo: {
              id: payload.replyTo.id,
              sender: payload.replyTo.sender,
              content: payload.replyTo.content,
            },
          }),
        };

        //send to server db when done saving the user message

        await saveMessageToLocalDB(payloadFull);
      } catch (error) {
        console.error("Error handling encrypted message:", error);
      }
    },
    [saveMessageToLocalDB, privateKeyRef, setUsers, setMessages]
  );
}
