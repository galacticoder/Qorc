import { useRef, useCallback } from "react";
import { v4 as uuidv4 } from "uuid";
import * as pako from "pako";
import { SignalType } from "@/lib/signals";
import { IncomingFileChunks } from "@/pages/types";
import { Message } from "@/components/chat/types";
import { CryptoUtils } from "@/lib/unified-crypto";
import { User } from "@/components/chat/UserList";

export function useFileHandler(
  privateKeyRef: React.MutableRefObject<CryptoKey | null>,
  onNewMessage: (message: Message) => void,
  setLoginError: (err: string) => void
) {
  const incomingFileChunksRef = useRef<IncomingFileChunks>({});

  const handleFileMessageChunk = useCallback(
    async (payload: any, message: any) => {
      try {
        const { from } = message;
        const { chunkIndex, totalChunks, chunkData, encryptedAESKey, filename } = payload;
        const fileKey = `${from}-${filename}`;

        let fileEntry = incomingFileChunksRef.current[fileKey];
        if (!fileEntry) {
          fileEntry = {
            decryptedChunks: new Array(totalChunks),
            totalChunks,
            encryptedAESKey,
            filename,
            receivedCount: 0
          };
          incomingFileChunksRef.current[fileKey] = fileEntry;
        }

        const encryptedBytes = Uint8Array.from(atob(chunkData), c => c.charCodeAt(0));
        const { iv, authTag, encrypted } = CryptoUtils.Decrypt.deserializeEncryptedDataFromUint8Array(encryptedBytes);

        if (!fileEntry.aesKey) {
          const decryptedAESKeyBytes = await CryptoUtils.Decrypt.decryptWithRSA(
            CryptoUtils.Base64.base64ToArrayBuffer(fileEntry.encryptedAESKey),
            privateKeyRef.current
          );
          fileEntry.aesKey = await CryptoUtils.Keys.importAESKey(decryptedAESKeyBytes);
        }

        const decryptedChunk = await CryptoUtils.Decrypt.decryptWithAESRaw(
          new Uint8Array(encrypted),
          new Uint8Array(iv),
          new Uint8Array(authTag),
          fileEntry.aesKey
        );

        const decompressedChunk = pako.inflate(new Uint8Array(decryptedChunk));
        fileEntry.decryptedChunks[chunkIndex] = new Blob([decompressedChunk]);
        fileEntry.receivedCount++;

        if (fileEntry.receivedCount === totalChunks) {
          const fileBlob = new Blob(fileEntry.decryptedChunks, { type: "application/octet-stream" });
          const fileUrl = URL.createObjectURL(fileBlob);

          onNewMessage({
            id: uuidv4(),
            content: fileUrl,
            sender: from,
            timestamp: new Date(),
            isCurrentUser: false,
            isSystemMessage: false,
            type: SignalType.FILE_MESSAGE,
            filename,
            fileSize: fileBlob.size
          });

          delete incomingFileChunksRef.current[fileKey];
        }
      } catch (err) {
        console.error("Error handling FILE_MESSAGE_CHUNK:", err);
        setLoginError("Failed to process file chunk");
      }
    },
    [privateKeyRef, onNewMessage, setLoginError]
  );

  const handleSendFile = async (
    fileMessage: Message,
    loginUsernameRef: string,
    onNewMessage: (message: Message) => void,
  ) => {
    const userFileMessage: Message = { 
      ...fileMessage, 
      isCurrentUser: true, 
      sender: loginUsernameRef,
      shouldPersist: false
    };
    
    onNewMessage(userFileMessage);
  }

  return { handleFileMessageChunk, handleSendFile };
}
