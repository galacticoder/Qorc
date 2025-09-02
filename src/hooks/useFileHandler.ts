import { useRef, useCallback } from "react";
import { v4 as uuidv4 } from "uuid";
import * as pako from "pako";
import { SignalType } from "@/lib/signals";
import { IncomingFileChunks } from "@/pages/types";
import { Message } from "@/components/chat/types";
import { CryptoUtils } from "@/lib/unified-crypto";
import { User } from "@/components/chat/UserList";

export function useFileHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  onNewMessage: (message: Message) => void,
  setLoginError: (err: string) => void
) {
  const incomingFileChunksRef = useRef<IncomingFileChunks>({});

  const handleFileMessageChunk = useCallback(
    async (payload: any, message: any) => {
      try {
        const { from } = message;
        const { chunkIndex, totalChunks, chunkData, encryptedAESKey, ephemeralX25519Public, kyberCiphertext, filename } = payload;
        const fileKey = `${from}-${filename}`;

        let fileEntry = incomingFileChunksRef.current[fileKey];
        if (!fileEntry) {
          fileEntry = {
            decryptedChunks: new Array(totalChunks),
            totalChunks,
            encryptedAESKey,
            ephemeralX25519Public: payload.ephemeralX25519Public,
            kyberCiphertext: payload.kyberCiphertext,
            filename,
            receivedCount: 0
          };
          incomingFileChunksRef.current[fileKey] = fileEntry;
        }

        const encryptedBytes = Uint8Array.from(atob(chunkData), c => c.charCodeAt(0));
        const { iv, authTag, encrypted } = CryptoUtils.Decrypt.deserializeEncryptedDataFromUint8Array(encryptedBytes);

        if (!fileEntry.aesKey) {
          const hybridKeys = await getKeysOnDemand();
          if (!hybridKeys) {
            throw new Error("Hybrid keys not available for file decryption");
          }

          const hybridPayload = {
            version: "hybrid-v1",
            ephemeralX25519Public: fileEntry.ephemeralX25519Public,
            kyberCiphertext: fileEntry.kyberCiphertext,
            encryptedMessage: fileEntry.encryptedAESKey
          };

          const decryptedPayload = await CryptoUtils.Hybrid.decryptHybridPayload(
            hybridPayload,
            hybridKeys
          );

          const aesKeyBytes = CryptoUtils.Base64.base64ToUint8Array(decryptedPayload.aesKey as string);
          fileEntry.aesKey = await CryptoUtils.Keys.importAESKey(aesKeyBytes);
        }

        const decryptedChunk = await CryptoUtils.Decrypt.decryptWithAESRaw(
          new Uint8Array(iv),
          new Uint8Array(authTag),
          new Uint8Array(encrypted),
          fileEntry.aesKey
        );

        const decompressedChunk = pako.inflate(new Uint8Array(decryptedChunk));
        fileEntry.decryptedChunks[chunkIndex] = new Blob([decompressedChunk]);
        fileEntry.receivedCount++;

        if (fileEntry.receivedCount === totalChunks) {
          // Infer MIME type for better handling on the UI (especially voice notes)
          const lowerName = String(filename || '').toLowerCase();
          let detectedMime = 'application/octet-stream';
          if (lowerName.endsWith('.webm')) detectedMime = 'audio/webm';
          else if (lowerName.endsWith('.mp3')) detectedMime = 'audio/mpeg';
          else if (lowerName.endsWith('.wav')) detectedMime = 'audio/wav';
          else if (lowerName.endsWith('.ogg')) detectedMime = 'audio/ogg';
          else if (lowerName.endsWith('.m4a')) detectedMime = 'audio/mp4';

          const fileBlob = new Blob(fileEntry.decryptedChunks, { type: detectedMime });
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
            fileSize: fileBlob.size,
            mimeType: detectedMime
          });

          delete incomingFileChunksRef.current[fileKey];
        }
      } catch (err) {
        console.error("Error handling FILE_MESSAGE_CHUNK:", err);
        setLoginError("Failed to process file chunk");
      }
    },
    [getKeysOnDemand, onNewMessage, setLoginError]
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