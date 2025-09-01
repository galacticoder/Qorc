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
        console.warn('[useFileSender] No hybrid keys for target; attempting Signal Protocol fallback');

        // Signal Protocol fallback: embed small files directly into encrypted message
        // For larger files, still error out to avoid huge messages
        const maxInlineBytes = 5 * 1024 * 1024; // 5MB inline limit
        if (rawBytes.length > maxInlineBytes) {
          console.error('[useFileSender] File too large for inline Signal message');
          throw new Error(`No valid recipient found for user: ${targetUsername}`);
        }

        try {
          // Ensure we have a libsignal session with the peer
          const sessionCheck = await (window as any).edgeApi?.hasSession?.({
            selfUsername: currentUsername,
            peerUsername: targetUsername,
            deviceId: 1
          });

          if (!sessionCheck?.hasSession) {
            websocketClient.send(JSON.stringify({
              type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
              username: targetUsername
            }));
            // Wait briefly for session establishment
            await new Promise((resolve) => setTimeout(resolve, 500));
          }

          // Safe base64 encoding for large binary arrays
          let b64: string;
          if (typeof window !== 'undefined' && typeof Buffer === 'undefined') {
            // Browser environment - use chunked conversion to avoid stack overflow
            if (rawBytes.length > 65536) { // 64KB threshold
              // Use Blob and FileReader for large files to avoid stack overflow
              const blob = new Blob([rawBytes]);
              const reader = new FileReader();
              b64 = await new Promise<string>((resolve, reject) => {
                reader.onload = () => {
                  const dataUrl = reader.result as string;
                  // Strip the data URL prefix (e.g., "data:application/octet-stream;base64,")
                  const base64 = dataUrl.split(',')[1];
                  resolve(base64);
                };
                reader.onerror = reject;
                reader.readAsDataURL(blob);
              });
            } else {
              // Small files can use btoa safely with chunked conversion
              let result = '';
              const chunkSize = 8192; // 8KB chunks
              for (let i = 0; i < rawBytes.length; i += chunkSize) {
                const chunk = rawBytes.slice(i, i + chunkSize);
                result += btoa(String.fromCharCode(...chunk));
              }
              b64 = result;
            }
          } else {
            // Node.js/Electron environment
            b64 = Buffer.from(rawBytes).toString('base64');
          }
          const payload = {
            type: 'file-message',
            messageId: crypto.randomUUID(),
            from: currentUsername,
            to: targetUsername,
            timestamp: Date.now(),
            fileName: file.name,
            fileType: file.type || 'application/octet-stream',
            fileSize: file.size,
            // Put base64 in content to be parsed on recipient side
            content: JSON.stringify({
              messageId: crypto.randomUUID(),
              fileName: file.name,
              fileType: file.type || 'application/octet-stream',
              fileSize: file.size,
              dataBase64: b64
            })
          };

          const encrypted = await (window as any).edgeApi?.encrypt?.({
            fromUsername: currentUsername,
            toUsername: targetUsername,
            plaintext: JSON.stringify(payload)
          });

          if (!encrypted?.ciphertextBase64) {
            throw new Error('Failed to encrypt inline file');
          }

          websocketClient.send(JSON.stringify({
            type: SignalType.ENCRYPTED_MESSAGE,
            to: targetUsername,
            encryptedPayload: {
              from: currentUsername,
              to: targetUsername,
              content: encrypted.ciphertextBase64,
              messageId: payload.messageId,
              type: encrypted.type,
              sessionId: encrypted.sessionId
            }
          }));

          setProgress(1);
          setIsSendingFile(false);
          return;
        } catch (fallbackError) {
          console.error('[useFileSender] Signal Protocol inline fallback failed:', fallbackError);
          throw new Error(`No valid recipient found for user: ${targetUsername}`);
        }
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