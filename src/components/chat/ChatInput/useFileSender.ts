import { useState } from "react";
import * as pako from "pako";
import { CryptoUtils } from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";

const CHUNK_SIZE = 256 * 1024;

interface User {
  username: string;
  hybridPublicKeys?: {
    x25519PublicBase64: string;
    kyberPublicBase64: string;
  };
}

export function useFileSender(currentUsername: string, targetUsername: string, users: User[]) {
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);

  async function sendFile(file: File) {
    console.log('[useFileSender] Starting file send:', {
      filename: file.name,
      size: file.size,
      targetUsername,
      currentUsername,
      usersCount: users.length,
      users: users.map(u => u.username)
    });

    if (users.length === 0) {
      console.error('[useFileSender] No users provided for file sending');
      throw new Error('No users available for file sending');
    }

    setIsSendingFile(true);
    setProgress(0);

    try {
      const rawBytes = new Uint8Array(await file.arrayBuffer());

      const aesKey = await CryptoUtils.Keys.generateAESKey();
      if (!window?.crypto?.subtle) {
        throw new Error('WebCrypto API not available');
      }
      const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
      const aesKeyBase64 = CryptoUtils.Base64.arrayBufferToBase64(rawAes);

      // Filter users to only include the target user for one-on-one conversation
      const filteredUsers = users.filter((user) =>
        user.username === targetUsername &&
        user.username !== currentUsername &&
        user.hybridPublicKeys
      );

      console.log('[useFileSender] Filtered users for encryption:', {
        targetUsername,
        totalUsers: users.length,
        filteredCount: filteredUsers.length,
        filteredUsers: filteredUsers.map(u => ({ username: u.username, hasKeys: !!u.hybridPublicKeys }))
      });

      if (filteredUsers.length === 0) {
        console.error('[useFileSender] No valid target user with hybrid keys found for:', targetUsername);
        throw new Error(`No valid recipient found for user: ${targetUsername}`);
      }

      const userKeys = await Promise.all(
        filteredUsers.map(async (user) => {

            const aesKeyPayload = { aesKey: aesKeyBase64 };

            const encryptedPayload = await CryptoUtils.Hybrid.encryptHybridPayload(
              aesKeyPayload,
              user.hybridPublicKeys!
            );

            return {
              username: user.username,
              encryptedAESKey: encryptedPayload.encryptedMessage,
              ephemeralX25519Public: encryptedPayload.ephemeralX25519Public,
              kyberCiphertext: encryptedPayload.kyberCiphertext,
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
            encryptedAESKey: userKey.encryptedAESKey,
            ephemeralX25519Public: userKey.ephemeralX25519Public,
            kyberCiphertext: userKey.kyberCiphertext,
            chunkIndex,
            totalChunks,
            chunkData: chunkDataBase64,
            filename: file.name,
            isLastChunk: chunkIndex === totalChunks - 1,
          };

          websocketClient.send(JSON.stringify(payload));
        }

        bytesSent += chunk.length * userKeys.length;
        setProgress(bytesSent / totalBytes);
      }

      setProgress(1);
      console.log('[useFileSender] File sending completed successfully');
    } catch (error) {
      console.error("[useFileSender] Failed to process and send file:", error);
      setProgress(0);
      throw error; // Re-throw so the caller can handle it
    } finally {
      setIsSendingFile(false);
    }
  }

  return { sendFile, progress, isSendingFile };
}
