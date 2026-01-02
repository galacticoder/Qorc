import React, { useRef, useCallback, useEffect } from "react";
import { IncomingFileChunks } from "../../pages/types";
import { Message } from '../../components/chat/messaging/types';
import { INACTIVITY_TIMEOUT_MS, RATE_LIMIT_MAX_EVENTS, RATE_LIMIT_WINDOW_MS, MAX_FILE_SIZE_BYTES, MAX_CHUNK_SIZE_BYTES } from "../../lib/constants";
import { createBlobCache, releaseFileEntry, dispatchProgressEvent, dispatchCanceledEvent } from "../../lib/utils/file-utils";
import type { ExtendedFileState } from "../../lib/types/file-types";
import { extractChunkData, validateNewTransfer, createFileEntry, isValidChunkIndex } from "./chunk-validation";
import { parseEncryptedChunk, decryptEnvelope, verifyChunkMac, decryptChunk, decompressChunk, cleanupFailedTransfer } from "./chunk-decryption";
import { completeFileTransfer, handleAssemblyFailure } from "./file-assembly";

export function useFileHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  onNewMessage: (message: Message) => void,
  setLoginError: (err: string) => void,
  secureDBRef?: React.RefObject<any | null>
) {
  const incomingFileChunksRef = useRef<IncomingFileChunks>({});
  const macStateRef = useRef<Map<string, { macKey: Uint8Array; fileSize: number }>>(new Map());
  const cleanupTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const blobCacheRef = useRef(createBlobCache());

  const cleanup = useCallback(() => {
    for (const [, t] of cleanupTimersRef.current) {
      try { clearTimeout(t); } catch { }
    }
    cleanupTimersRef.current.clear();
    macStateRef.current.clear();
    blobCacheRef.current.clear();
    for (const key of Object.keys(incomingFileChunksRef.current as any)) {
      delete (incomingFileChunksRef.current as any)[key];
    }
  }, []);

  useEffect(() => cleanup, [cleanup]);

  const clearTimer = useCallback((fileKey: string) => {
    const t = cleanupTimersRef.current.get(fileKey);
    if (t) {
      clearTimeout(t);
      cleanupTimersRef.current.delete(fileKey);
    }
  }, []);

  const scheduleInactivityTimer = useCallback((fileKey: string, from: string, filename: string) => {
    clearTimer(fileKey);
    const timeout = setTimeout(() => {
      delete (incomingFileChunksRef.current as any)[fileKey];
      macStateRef.current.delete(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'inactivity-timeout' });
    }, INACTIVITY_TIMEOUT_MS);
    cleanupTimersRef.current.set(fileKey, timeout);
  }, [clearTimer]);

  const handleFileMessageChunk = useCallback(
    async (payload: any, message: any) => {
      try {
        const data = extractChunkData(payload, message);
        if (!data) return;

        const { from, toUser, safeFilename, fileKey, chunkIndex, totalChunks, chunkData, envelope } = data;
        const store = incomingFileChunksRef.current as any;
        let fileEntry = store[fileKey] as ExtendedFileState | undefined;

        if (!fileEntry) {
          if (!validateNewTransfer(data, incomingFileChunksRef.current, setLoginError)) return;
          fileEntry = createFileEntry(data);
          store[fileKey] = fileEntry;
          scheduleInactivityTimer(fileKey, from, safeFilename);
        } else if (fileEntry.totalChunks !== totalChunks) {
          cleanupFailedTransfer(fileEntry, fileKey, store, macStateRef.current, cleanupTimersRef.current, blobCacheRef.current, from, safeFilename, 'metadata-mismatch', setLoginError, 'File transfer corrupted (metadata mismatch)');
          return;
        }

        if (fileEntry.paused) {
          scheduleInactivityTimer(fileKey, from, safeFilename);
          return;
        }

        fileEntry.lastUpdated = Date.now();
        scheduleInactivityTimer(fileKey, from, safeFilename);

        if (!isValidChunkIndex(chunkIndex, fileEntry.totalChunks) || fileEntry.receivedSet?.has(chunkIndex)) {
          return;
        }

        const parsed = parseEncryptedChunk(chunkData);
        if (!parsed) {
          cleanupFailedTransfer(fileEntry, fileKey, store, macStateRef.current, cleanupTimersRef.current, blobCacheRef.current, from, safeFilename, 'deserialize-failed', setLoginError, 'Invalid file chunk format');
          return;
        }

        const { iv, authTag, encrypted } = parsed;

        if (!fileEntry.aesKey) {
          const hybridKeys = await getKeysOnDemand();
          if (!hybridKeys) {
            throw new Error(`Hybrid keys not available for file decryption (${safeFilename})`);
          }

          const keys = await decryptEnvelope(envelope, hybridKeys);
          if (!keys) {
            cleanupFailedTransfer(fileEntry, fileKey, store, macStateRef.current, cleanupTimersRef.current, blobCacheRef.current, from, safeFilename, 'envelope-decrypt-failed', setLoginError, 'File transfer rejected (key envelope invalid)');
            return;
          }

          fileEntry.aesKey = keys.aesKey;
          macStateRef.current.set(fileKey, { macKey: keys.macKey, fileSize: fileEntry.fileSize || 0 });
        }

        const macEntry = macStateRef.current.get(fileKey);
        if (payload.chunkMac && macEntry) {
          const ctx = { fileEntry, fileKey, from, safeFilename, chunkIndex, iv, authTag, encrypted };
          const valid = await verifyChunkMac(ctx, payload.chunkMac, macEntry.macKey, totalChunks);
          if (!valid) {
            cleanupFailedTransfer(fileEntry, fileKey, store, macStateRef.current, cleanupTimersRef.current, blobCacheRef.current, from, safeFilename, 'chunk-mac-failed', setLoginError, 'File integrity check failed');
            return;
          }
        }

        const decryptedBytes = await decryptChunk(iv, authTag, encrypted, fileEntry.aesKey!);
        if (!decryptedBytes) {
          cleanupFailedTransfer(fileEntry, fileKey, store, macStateRef.current, cleanupTimersRef.current, blobCacheRef.current, from, safeFilename, 'decrypt-failed', setLoginError, 'Failed to decrypt file chunk');
          return;
        }

        const decompressedChunk = decompressChunk(decryptedBytes);

        const nowTs = Date.now();
        const bucket = fileEntry.rateBucket ?? { windowStart: nowTs, count: 0 };
        if (nowTs - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = nowTs;
          bucket.count = 0;
        }
        bucket.count += 1;
        fileEntry.rateBucket = bucket;
        if (bucket.count > RATE_LIMIT_MAX_EVENTS) {
          scheduleInactivityTimer(fileKey, from, safeFilename);
          return;
        }

        if (!fileEntry.receivedSet!.has(chunkIndex)) {
          fileEntry.decryptedChunks[chunkIndex] = new Blob([new Uint8Array(decompressedChunk)]);
          fileEntry.receivedSet!.add(chunkIndex);
          fileEntry.receivedCount++;
          fileEntry.bytesReceivedApprox = (fileEntry.bytesReceivedApprox || 0) + decompressedChunk.length;

          if ((fileEntry.fileSize && fileEntry.bytesReceivedApprox > fileEntry.fileSize + MAX_CHUNK_SIZE_BYTES) ||
            fileEntry.bytesReceivedApprox > MAX_FILE_SIZE_BYTES) {
            cleanupFailedTransfer(fileEntry, fileKey, store, macStateRef.current, cleanupTimersRef.current, blobCacheRef.current, from, safeFilename, 'size-exceeded', setLoginError, 'File transfer rejected (size exceeded)');
            return;
          }
        }

        dispatchProgressEvent({ from, filename: safeFilename, percent: Math.min(1, fileEntry.receivedCount / fileEntry.totalChunks), received: fileEntry.receivedCount, total: fileEntry.totalChunks });

        if (fileEntry.receivedCount === fileEntry.totalChunks) {
          clearTimer(fileKey);
          macStateRef.current.delete(fileKey);

          const success = await completeFileTransfer(fileEntry, fileKey, from, toUser, store, blobCacheRef.current, secureDBRef, onNewMessage);
          if (!success) {
            handleAssemblyFailure(fileEntry, fileKey, store, blobCacheRef.current, from, 'assembly-failed', setLoginError, 'File transfer incomplete');
          }
        }
      } catch (err) {
        console.error('[useFileHandler] Error handling FILE_MESSAGE_CHUNK', err);
        setLoginError('Failed to process file chunk');
      }
    },
    [getKeysOnDemand, onNewMessage, setLoginError, scheduleInactivityTimer, clearTimer, secureDBRef]
  );

  const cancelIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    const store = incomingFileChunksRef.current as any;
    if (store[fileKey]) {
      delete store[fileKey];
      macStateRef.current.delete(fileKey);
      clearTimer(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'user-canceled' });
    }
  }, [clearTimer]);

  const pauseIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    const entry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;
    if (entry) {
      entry.paused = true;
      scheduleInactivityTimer(fileKey, from, filename);
    }
  }, [scheduleInactivityTimer]);

  const resumeIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    const entry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;
    if (entry) {
      entry.paused = false;
      scheduleInactivityTimer(fileKey, from, filename);
    }
  }, [scheduleInactivityTimer]);

  return { handleFileMessageChunk, cancelIncomingFile, pauseIncomingFile, resumeIncomingFile, cleanup };
}
