import { useState } from "react";
import * as pako from "pako";
import { CryptoUtils } from "@/lib/unified-crypto";
import wsClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";

const CHUNK_SIZE = 256 * 1024;

interface User {
  username: string;
  publicKey?: string;
}

export function useFileSender(currentUsername: string, users: User[]) {
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);

  async function sendFile(file: File) {
    if (!users || users.length === 0) return;

    setIsSendingFile(true);
    setProgress(0);

    try {
      const rawBytes = new Uint8Array(await file.arrayBuffer());

      const aesKey = await CryptoUtils.Keys.generateAESKey();
      const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);

      const userKeys = await Promise.all(
        users
          .filter((user) => user.username !== currentUsername && user.publicKey)
          .map(async (user) => {
            const recipientKey = await CryptoUtils.Keys.importPublicKeyFromPEM(user.publicKey!);
            const encryptedAes = await CryptoUtils.Encrypt.encryptWithRSA(rawAes, recipientKey);
            return {
              username: user.username,
              encryptedAESKeyBase64: btoa(String.fromCharCode(...new Uint8Array(encryptedAes))),
            };
          })
      );

      const totalChunks = Math.ceil(rawBytes.length / CHUNK_SIZE);
      const totalBytes = rawBytes.length * userKeys.length;
      let bytesSent = 0;

      for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, rawBytes.length);
        const chunk = rawBytes.slice(start, end);

        const compressedChunk = pako.deflate(chunk);

        const { iv, authTag, encrypted } = await CryptoUtils.Encrypt.encryptBinaryWithAES(
          compressedChunk.buffer,
          aesKey
        );

        const serializedChunk = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);
        const chunkDataBase64 = btoa(serializedChunk);

        for (const userKey of userKeys) {
          const payload = {
            type: SignalType.FILE_MESSAGE_CHUNK,
            from: currentUsername,
            to: userKey.username,
            encryptedAESKey: userKey.encryptedAESKeyBase64,
            chunkIndex,
            totalChunks,
            chunkData: chunkDataBase64,
            filename: file.name,
            isLastChunk: chunkIndex === totalChunks - 1,
          };

          wsClient.send(JSON.stringify(payload));
        }

        bytesSent += chunk.length * userKeys.length;
        setProgress(bytesSent / totalBytes);
      }

      setProgress(1);
    } catch (error) {
      console.error("Failed to process and send file:", error);
      throw error; // rethrow so caller can handle if needed
    } finally {
      setIsSendingFile(false);
    }
  }

  return { sendFile, progress, isSendingFile };
}
