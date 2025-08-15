import { v4 as uuidv4 } from "uuid";
import { useCallback } from "react";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";

export function useEncryptedMessageHandler(
  privateKeyRef: React.RefObject<CryptoKey>,
  loginUsernameRef: React.MutableRefObject<string>,
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
          isCurrentUser: payload.from == loginUsernameRef.current,
          isSystemMessage: payload.typeInside === "system",
          isDeleted: payload.typeInside == SignalType.DELETE_MESSAGE,
          isEdited: payload.typeInside == SignalType.EDIT_MESSAGE,
          shouldPersist: isJoinLeave,
          ...(payload.replyTo && {
            replyTo: {
              id: payload.replyTo.id,
              sender: payload.replyTo.sender,
              content: payload.replyTo.content,
            },
          }),
        };

        //send to server db when done saving the user message to local db later
        await saveMessageToLocalDB(payloadFull);

        //started handling after saving edited or deleted message to db since before wasnt working for hours
        if (payloadFull.isEdited || payloadFull.isDeleted) {
          setMessages(prev =>
            prev.map(msg => {
              const updated = { ...msg };
              const content = payload.isEdited ? payload.content : "Message Deleted";

              //update reply fields of messages replying to the edited message
              if (msg.replyTo?.id === payload.id) {
                console.log("Updating message reply fields")
                updated.replyTo = { ...updated.replyTo, content: content };
                saveMessageToLocalDB(updated);
              }

              console.log("Updated all reply fields to new edited or deleted message")
              return updated;
            })
          );
          return;
        }
      } catch (error) {
        console.error("Error handling encrypted message:", error);
      }
    },
    [saveMessageToLocalDB, privateKeyRef, setUsers, setMessages]
  );
}
