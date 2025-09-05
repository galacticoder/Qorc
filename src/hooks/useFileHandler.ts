import { useRef, useCallback, useEffect } from "react";
import { v4 as uuidv4 } from "uuid";
import * as pako from "pako";
import { SignalType } from "@/lib/signals";
import { IncomingFileChunks } from "@/pages/types";
import { Message } from "@/components/chat/types";
import { CryptoUtils } from "@/lib/unified-crypto";
import { User } from "@/components/chat/UserList";

// Security and performance constants
const MAX_FILE_SIZE_BYTES = Number.MAX_SAFE_INTEGER; // No file size limit
const INACTIVITY_TIMEOUT_MS = 120 * 1000; // 2 minutes per transfer inactivity timeout
const MAX_TOTAL_CHUNKS = Number.MAX_SAFE_INTEGER; // No chunk limit

// Extended per-file transfer state (augmenting IncomingFileChunks items at runtime)
interface ExtendedFileState {
  // inherited fields (runtime augmentation, not enforced by TS on the external type)
  decryptedChunks: Blob[];
  totalChunks: number;
  encryptedAESKey: string;
  ephemeralX25519Public?: string;
  kyberCiphertext?: string;
  filename: string;
  aesKey?: CryptoKey;
  receivedCount: number;
  // extended fields
  chunkSize?: number;
  fileSize?: number;
  startedAt?: number;
  lastUpdated?: number;
  paused?: boolean;
  bytesReceivedApprox?: number; // approximate based on number of chunks
  receivedSet?: Set<number>;
}

function dispatchProgressEvent(detail: any) {
  try {
    const evt = new CustomEvent('file-transfer-progress', { detail });
    window.dispatchEvent(evt);
  } catch {}
}

function dispatchCompleteEvent(detail: any) {
  try {
    const evt = new CustomEvent('file-transfer-complete', { detail });
    window.dispatchEvent(evt);
  } catch {}
}

function dispatchCanceledEvent(detail: any) {
  try {
    const evt = new CustomEvent('file-transfer-canceled', { detail });
    window.dispatchEvent(evt);
  } catch {}
}

export function useFileHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  onNewMessage: (message: Message) => void,
  setLoginError: (err: string) => void
) {
  const incomingFileChunksRef = useRef<IncomingFileChunks>({});
  // Maintain per-file MAC key and metadata
  const macStateRef = useRef<Map<string, { macKey: Uint8Array; fileSize: number }>>(new Map());
  const cleanupTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // Exposed cleanup for consumers to cancel timers and clear refs
  const cleanup = useCallback(() => {
    // Clear all inactivity timers
    for (const [, t] of cleanupTimersRef.current) {
      try { clearTimeout(t); } catch {}
    }
    cleanupTimersRef.current.clear();
    // Clear per-file states
    macStateRef.current.clear();
    // Remove all in-progress entries
    for (const key of Object.keys(incomingFileChunksRef.current as any)) {
      delete (incomingFileChunksRef.current as any)[key];
    }
  }, []);

  // Auto-cleanup on unmount as a safety net
  useEffect(() => {
    return () => cleanup();
  }, [cleanup]);

  const clearTimer = (fileKey: string) => {
    const t = cleanupTimersRef.current.get(fileKey);
    if (t) {
      clearTimeout(t);
      cleanupTimersRef.current.delete(fileKey);
    }
  };

  const scheduleInactivityTimer = (fileKey: string, from: string, filename: string) => {
    clearTimer(fileKey);
    const timeout = setTimeout(() => {
      // Abort inactive transfer
      delete (incomingFileChunksRef.current as any)[fileKey];
      macStateRef.current.delete(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'inactivity-timeout' });
      console.warn('[useFileHandler] Inactivity timeout - aborted transfer:', { from, filename });
    }, INACTIVITY_TIMEOUT_MS);
    cleanupTimersRef.current.set(fileKey, timeout);
  };

  const handleFileMessageChunk = useCallback(
    async (payload: any, message: any) => {
      try {
        const { from } = message;
        const { chunkIndex, totalChunks, chunkData, encryptedAESKey, ephemeralX25519Public, kyberCiphertext, filename } = payload || {};
        if (!filename || typeof chunkIndex !== 'number' || typeof totalChunks !== 'number' || !chunkData) {
          console.warn('[useFileHandler] Malformed FILE_MESSAGE_CHUNK payload - ignoring');
          return;
        }

        const fileKey = `${from}-${filename}`;
        let fileEntry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;

        // Initialize state for first chunk
        if (!fileEntry) {
          if (totalChunks <= 0 || totalChunks > MAX_TOTAL_CHUNKS) {
            console.error('[useFileHandler] totalChunks out of bounds - aborting transfer:', { totalChunks, filename });
            setLoginError('File transfer rejected (invalid metadata)');
            return;
          }

          const fileSize = Number(payload.fileSize || 0);
          if (!Number.isFinite(fileSize) || fileSize < 0 || fileSize > MAX_FILE_SIZE_BYTES) {
            console.error('[useFileHandler] fileSize invalid or exceeds limit - aborting transfer:', { fileSize, filename });
            setLoginError('File too large or invalid');
            return;
          }

          const chunkSize = Number(payload.chunkSize || 0);
          if (!Number.isFinite(chunkSize) || chunkSize <= 0) {
            console.error('[useFileHandler] chunkSize invalid - aborting transfer:', { chunkSize, filename });
            setLoginError('Invalid file transfer metadata');
            return;
          }

          // Sanity: expected total bytes heuristic (allow variance for compression/last chunk)
          const expectedMaxBytes = chunkSize * totalChunks;
          if (expectedMaxBytes > MAX_FILE_SIZE_BYTES * 4) {
            console.error('[useFileHandler] Transfer heuristic exceeds safety cap - aborting:', { expectedMaxBytes, filename });
            setLoginError('File transfer rejected (unsafe size)');
            return;
          }

          fileEntry = {
            decryptedChunks: new Array(totalChunks),
            totalChunks,
            encryptedAESKey,
            ephemeralX25519Public,
            kyberCiphertext,
            filename,
            receivedCount: 0,
            fileSize,
            chunkSize,
            startedAt: Date.now(),
            lastUpdated: Date.now(),
            paused: false,
            bytesReceivedApprox: 0,
            receivedSet: new Set<number>()
          };
          ;(incomingFileChunksRef.current as any)[fileKey] = fileEntry;
          scheduleInactivityTimer(fileKey, from, filename);
        } else {
          // Validate immutables for consistency
          if (fileEntry.totalChunks !== totalChunks) {
            console.error('[useFileHandler] totalChunks changed mid-transfer - abort:', { filename });
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            setLoginError('File transfer corrupted (metadata mismatch)');
            return;
          }
        }

        // If paused, ignore chunks but keep timer refreshed
        if (fileEntry.paused) {
          scheduleInactivityTimer(fileKey, from, filename);
          return;
        }

        fileEntry.lastUpdated = Date.now();
        scheduleInactivityTimer(fileKey, from, filename);

        // Validate chunkIndex
        if (chunkIndex < 0 || chunkIndex >= fileEntry.totalChunks) {
          console.warn('[useFileHandler] Invalid chunk index - ignoring:', { chunkIndex, total: fileEntry.totalChunks });
          return;
        }

        // Avoid double-counting duplicates
        if (fileEntry.receivedSet?.has(chunkIndex)) {
          // Duplicate or retransmit; ignore silently but refresh timer
          return;
        }

        // Deserialize encrypted chunk
        const encryptedBytes = Uint8Array.from(atob(chunkData), c => c.charCodeAt(0));
        const { iv, authTag, encrypted } = CryptoUtils.Decrypt.deserializeEncryptedDataFromUint8Array(encryptedBytes);

        // Decrypt per-file AES key once
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

        // Derive per-file MAC key on first use and store
        let macEntry = macStateRef.current.get(fileKey);
        if (!macEntry && fileEntry.aesKey) {
          const rawAes = await CryptoUtils.Keys.exportAESKey(fileEntry.aesKey);
          const macSalt = new TextEncoder().encode('ft-mac-salt-v1');
          const macInfo = new TextEncoder().encode(`ft:${filename}:${fileEntry.fileSize || 0}`);
          const macKey = await CryptoUtils.Hash.blake3Hkdf(new Uint8Array(rawAes), macSalt, macInfo, 32);
          macEntry = { macKey, fileSize: fileEntry.fileSize || 0 };
          macStateRef.current.set(fileKey, macEntry);
        }

        // Verify per-chunk MAC if provided before decrypting
        if (payload.chunkMac && macEntry) {
          const macInput = new Uint8Array(iv.length + authTag.length + encrypted.length);
          macInput.set(iv, 0);
          macInput.set(authTag, iv.length);
          macInput.set(encrypted, iv.length + authTag.length);
          const computedMac = await CryptoUtils.Hash.generateBlake3Mac(macInput, new Uint8Array(macEntry.macKey));
          const computedMacB64 = CryptoUtils.Base64.arrayBufferToBase64(computedMac);
          if (computedMacB64 !== payload.chunkMac) {
            // Integrity failure: abort this file transfer
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            console.error('[useFileHandler] Chunk MAC verification failed, aborting file transfer:', {
              from,
              filename,
              chunkIndex,
              totalChunks
            });
            setLoginError('File integrity check failed');
            dispatchCanceledEvent({ from, filename, reason: 'chunk-mac-failed' });
            return;
          }
        }

        // Decrypt then inflate
        let decryptedChunk: ArrayBuffer;
        try {
          decryptedChunk = await CryptoUtils.Decrypt.decryptWithAESRaw(
            new Uint8Array(iv),
            new Uint8Array(authTag),
            new Uint8Array(encrypted),
            fileEntry.aesKey!
          );
        } catch (e) {
          console.error('[useFileHandler] AES decryption failed, aborting transfer', e);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          setLoginError('Failed to decrypt file chunk');
          dispatchCanceledEvent({ from, filename, reason: 'decrypt-failed' });
          return;
        }

        let decompressedChunk: Uint8Array;
        try {
          decompressedChunk = pako.inflate(new Uint8Array(decryptedChunk));
        } catch (e) {
          console.error('[useFileHandler] Decompression failed, aborting transfer', e);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          setLoginError('Failed to decompress file chunk');
          dispatchCanceledEvent({ from, filename, reason: 'decompress-failed' });
          return;
        }

        // Commit chunk if not duplicate
        if (!fileEntry.receivedSet!.has(chunkIndex)) {
          fileEntry.decryptedChunks[chunkIndex] = new Blob([decompressedChunk]);
          fileEntry.receivedSet!.add(chunkIndex);
          fileEntry.receivedCount++;
        }

        // Dispatch progress (approximate by count)
        const percent = Math.min(1, fileEntry.receivedCount / fileEntry.totalChunks);
        dispatchProgressEvent({ from, filename, percent, received: fileEntry.receivedCount, total: fileEntry.totalChunks });

        // Complete
        if (fileEntry.receivedCount === fileEntry.totalChunks) {
          clearTimer(fileKey);
          macStateRef.current.delete(fileKey);

          // Infer MIME type for better handling on the UI (especially voice notes)
          const lowerName = String(filename || '').toLowerCase();
          let detectedMime = 'application/octet-stream';
          if (lowerName.endsWith('.webm')) detectedMime = 'audio/webm';
          else if (lowerName.endsWith('.mp3')) detectedMime = 'audio/mpeg';
          else if (lowerName.endsWith('.wav')) detectedMime = 'audio/wav';
          else if (lowerName.endsWith('.ogg')) detectedMime = 'audio/ogg';
          else if (lowerName.endsWith('.m4a')) detectedMime = 'audio/mp4';

          let fileBlob: Blob;
          try {
            fileBlob = new Blob(fileEntry.decryptedChunks, { type: detectedMime });
          } catch (e) {
            console.error('[useFileHandler] Failed to assemble file blob', e);
            setLoginError('Failed to assemble received file');
            delete (incomingFileChunksRef.current as any)[fileKey];
            dispatchCanceledEvent({ from, filename, reason: 'assemble-failed' });
            return;
          }

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

          dispatchCompleteEvent({ from, filename, size: fileBlob.size, mimeType: detectedMime });

          delete (incomingFileChunksRef.current as any)[fileKey];
        }
      } catch (err) {
        console.error("Error handling FILE_MESSAGE_CHUNK:", err);
        setLoginError("Failed to process file chunk");
      }
    },
    [getKeysOnDemand, onNewMessage, setLoginError]
  );

  // Cancel a specific incoming transfer
  const cancelIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    if ((incomingFileChunksRef.current as any)[fileKey]) {
      delete (incomingFileChunksRef.current as any)[fileKey];
      macStateRef.current.delete(fileKey);
      clearTimer(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'user-canceled' });
      console.log('[useFileHandler] Canceled incoming file transfer:', { from, filename });
    }
  }, []);

  // Pause receiving (ignores chunks but keeps timer refreshed)
  const pauseIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    const entry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;
    if (entry) {
      entry.paused = true;
      scheduleInactivityTimer(fileKey, from, filename);
      console.log('[useFileHandler] Paused incoming file transfer:', { from, filename });
    }
  }, []);

  const resumeIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    const entry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;
    if (entry) {
      entry.paused = false;
      scheduleInactivityTimer(fileKey, from, filename);
      console.log('[useFileHandler] Resumed incoming file transfer:', { from, filename });
    }
  }, []);

  // Sending-side stub (kept for compatibility with existing callers)
  const handleSendFile = async (
    fileMessage: Message,
    loginUsernameRef: string,
    onNewMessageImmediate: (message: Message) => void,
  ) => {
    const userFileMessage: Message = {
      ...fileMessage,
      isCurrentUser: true,
      sender: loginUsernameRef,
      shouldPersist: false
    };

    onNewMessageImmediate(userFileMessage);
  };

  return { handleFileMessageChunk, handleSendFile, cancelIncomingFile, pauseIncomingFile, resumeIncomingFile, cleanup };
}