import { useRef, useCallback, useEffect } from "react";
import { v4 as uuidv4 } from "uuid";
import * as pako from "pako";
import { toast } from "sonner";
import { SignalType } from "@/lib/signal-types";
import { IncomingFileChunks } from "@/pages/types";
import { Message } from '@/components/chat/types';
import { CryptoUtils } from "@/lib/unified-crypto";
import { sanitizeTextInput } from "@/lib/sanitizers";

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const INACTIVITY_TIMEOUT_MS = 120 * 1000;
const MAX_TOTAL_CHUNKS = 10_000;
const MAX_CHUNK_SIZE_BYTES = 384 * 1024;
const MAX_CONCURRENT_TRANSFERS = 16;
const MAX_BASE64_CHARS = MAX_CHUNK_SIZE_BYTES * 2;
const MAX_FILENAME_LENGTH = 256;
const RATE_LIMIT_WINDOW_MS = 5_000;
const RATE_LIMIT_MAX_EVENTS = 6_000;
const BASE64_STANDARD_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64_URLSAFE_REGEX = /^[A-Za-z0-9_-]*={0,2}$/;

interface ExtendedFileState {
  decryptedChunks: Blob[];
  totalChunks: number;
  encryptedAESKey: string;
  ephemeralX25519Public?: string;
  kyberCiphertext?: string;
  filename: string;
  aesKey?: CryptoKey;
  receivedCount: number;
  chunkSize?: number;
  fileSize?: number;
  startedAt?: number;
  lastUpdated?: number;
  paused?: boolean;
  bytesReceivedApprox?: number;
  receivedSet?: Set<number>;
  rateBucket?: { windowStart: number; count: number };
  safeFilename: string;
  originalFilename: string;
  messageId?: string;
}

interface FileChunkPayload {
  chunkIndex: number;
  totalChunks: number;
  chunkData: string;
  envelope?: any;
  encryptedAESKey?: string;
  ephemeralX25519Public?: string;
  kyberCiphertext?: string;
  filename?: string;
  fileSize?: number;
  chunkSize?: number;
  chunkMac?: string;
  messageId?: string;
}

const sanitizeEventDetail = (detail: Record<string, unknown>) => {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(detail)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeTextInput(value, { maxLength: 256, allowNewlines: false });
    } else if (typeof value === 'number') {
      sanitized[key] = Number.isFinite(value) ? value : 0;
    } else if (typeof value === 'boolean') {
      sanitized[key] = value;
    }
  }
  return sanitized;
};

function dispatchProgressEvent(detail: Record<string, unknown>) {
  try {
    const evt = new CustomEvent('file-transfer-progress', { detail: sanitizeEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
}

function dispatchCompleteEvent(detail: Record<string, unknown>) {
  try {
    const evt = new CustomEvent('file-transfer-complete', { detail: sanitizeEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
}

function dispatchCanceledEvent(detail: Record<string, unknown>) {
  try {
    const evt = new CustomEvent('file-transfer-canceled', { detail: sanitizeEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
}

const sanitizeFilename = (value: string | undefined) => {
  const normalized = sanitizeTextInput(value ?? 'file.bin', { maxLength: MAX_FILENAME_LENGTH, allowNewlines: false });
  const cleaned = normalized.replace(/[^A-Za-z0-9._()\-\s]/g, '_').trim();
  return cleaned || 'file.bin';
};

const normalizeBase64 = (input: string) => input.replace(/\s+/g, '');

const decodeBase64Chunk = (data: string): Uint8Array | null => {
  if (typeof data !== 'string' || data.length === 0 || data.length > MAX_BASE64_CHARS) {
    return null;
  }
  const normalized = normalizeBase64(data);
  const isUrlSafe = BASE64_URLSAFE_REGEX.test(normalized.replace(/=*$/, ''));
  const pattern = isUrlSafe ? BASE64_URLSAFE_REGEX : BASE64_STANDARD_REGEX;
  if (!pattern.test(normalized)) {
    return null;
  }
  let working = isUrlSafe ? normalized.replace(/-/g, '+').replace(/_/g, '/') : normalized;
  while (working.length % 4 !== 0) {
    working += '=';
  }
  try {
    if (typeof Buffer !== 'undefined') {
      return Uint8Array.from(Buffer.from(working, 'base64'));
    }
    const binary = atob(working);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (value: Record<string, unknown>): boolean => {
  return ['__proto__', 'prototype', 'constructor'].some((key) => Object.prototype.hasOwnProperty.call(value, key));
};

const validateEnvelope = (envelope: unknown): envelope is Record<string, unknown> => {
  if (!isPlainObject(envelope) || hasPrototypePollutionKeys(envelope)) {
    return false;
  }
  return true;
};

const enforceConcurrentLimit = (store: IncomingFileChunks) => {
  const active = Object.keys(store as Record<string, unknown>).length;
  return active < MAX_CONCURRENT_TRANSFERS;
};

const createBlobCache = () => {
  const entries: Array<{ url: string; source: string }> = [];
  const enqueue = (url: string, source: string) => {
    entries.push({ url, source });
    if (entries.length > MAX_TOTAL_CHUNKS) {
      const stale = entries.shift();
      if (stale) {
        try { URL.revokeObjectURL(stale.url); } catch { }
      }
    }
  };
  const clear = () => {
    while (entries.length) {
      const stale = entries.shift();
      if (stale) {
        try { URL.revokeObjectURL(stale.url); } catch { }
      }
    }
  };
  return { enqueue, clear };
};

const releaseFileEntry = (entry?: ExtendedFileState) => {
  if (!entry) return;
  entry.decryptedChunks.length = 0;
  entry.receivedSet?.clear();
  entry.bytesReceivedApprox = 0;
  entry.aesKey = undefined;
};

export function useFileHandler(
  getKeysOnDemand: () => Promise<{ x25519: { private: any; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  onNewMessage: (message: Message) => void,
  setLoginError: (err: string) => void,
  secureDBRef?: React.MutableRefObject<any | null>
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

  useEffect(() => {
    return () => cleanup();
  }, [cleanup]);

  const clearTimer = useCallback((fileKey: string) => {
    const t = cleanupTimersRef.current.get(fileKey);
    if (t) {
      clearTimeout(t);
      cleanupTimersRef.current.delete(fileKey);
    }
  }, []);

  const scheduleInactivityTimer = useCallback((fileKey: string, from: string, filename: string) => {
    const t = cleanupTimersRef.current.get(fileKey);
    if (t) {
      clearTimeout(t);
      cleanupTimersRef.current.delete(fileKey);
    }
    const timeout = setTimeout(() => {
      delete (incomingFileChunksRef.current as any)[fileKey];
      macStateRef.current.delete(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'inactivity-timeout' });
    }, INACTIVITY_TIMEOUT_MS);
    cleanupTimersRef.current.set(fileKey, timeout);
  }, []);

  const handleFileMessageChunk = useCallback(
    async (payload: any, message: any) => {
      try {
        if (!isPlainObject(payload) || hasPrototypePollutionKeys(payload)) {
          return;
        }

        const { chunkIndex, totalChunks, chunkData, envelope, encryptedAESKey, ephemeralX25519Public, kyberCiphertext, filename, messageId } = payload as unknown as FileChunkPayload;
        const from = sanitizeTextInput(String(message?.from ?? ''), { maxLength: 96, allowNewlines: false }) || 'unknown';
        const toUser = sanitizeTextInput(String((message as any)?.to ?? (payload as any)?.to ?? ''), { maxLength: 96, allowNewlines: false }) || undefined;
        const safeFilename = sanitizeFilename(filename);

        if (typeof chunkIndex !== 'number' || typeof totalChunks !== 'number' || typeof chunkData !== 'string') {
          return;
        }

        const fileKey = `${from}-${safeFilename}`;
        let fileEntry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;

        if (!fileEntry) {
          if (!enforceConcurrentLimit(incomingFileChunksRef.current)) {
            setLoginError('Too many simultaneous file transfers');
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'concurrency-limit' });
            return;
          }
          if (totalChunks <= 0 || totalChunks > MAX_TOTAL_CHUNKS) {
            console.error('[useFileHandler] totalChunks out of bounds - aborting transfer:', { totalChunks, filename: safeFilename });
            setLoginError('File transfer rejected (invalid metadata)');
            return;
          }

          const fileSize = Number(payload.fileSize || 0);
          if (!Number.isFinite(fileSize) || fileSize < 0 || fileSize > MAX_FILE_SIZE_BYTES) {
            console.error('[useFileHandler] fileSize invalid or exceeds limit - aborting transfer:', { fileSize, filename: safeFilename });
            setLoginError('File too large or invalid');
            return;
          }

          const chunkSize = Number(payload.chunkSize || 0);
          if (!Number.isFinite(chunkSize) || chunkSize <= 0 || chunkSize > MAX_CHUNK_SIZE_BYTES) {
            console.error('[useFileHandler] chunkSize invalid - aborting transfer:', { chunkSize, filename: safeFilename });
            setLoginError('Invalid file transfer metadata');
            return;
          }

          const expectedMaxBytes = chunkSize * totalChunks;
          if (expectedMaxBytes > MAX_FILE_SIZE_BYTES * 4) {
            console.error('[useFileHandler] Transfer heuristic exceeds safety cap - aborting:', { expectedMaxBytes, filename: safeFilename });
            setLoginError('File transfer rejected (unsafe size)');
            return;
          }

          fileEntry = {
            decryptedChunks: Array(totalChunks).fill(null),
            totalChunks,
            encryptedAESKey,
            ephemeralX25519Public,
            kyberCiphertext,
            filename: safeFilename,
            receivedCount: 0,
            fileSize,
            chunkSize,
            startedAt: Date.now(),
            lastUpdated: Date.now(),
            paused: false,
            bytesReceivedApprox: 0,
            receivedSet: new Set<number>(),
            rateBucket: { windowStart: Date.now(), count: 0 },
            safeFilename,
            originalFilename: filename ?? 'file.bin',
            messageId: typeof messageId === 'string' ? sanitizeTextInput(messageId, { maxLength: 256, allowNewlines: false }) : undefined,
          };
          (incomingFileChunksRef.current as any)[fileKey] = fileEntry;
          scheduleInactivityTimer(fileKey, from, safeFilename);
        } else {
          if (fileEntry.totalChunks !== totalChunks) {
            console.error('[useFileHandler] totalChunks changed mid-transfer - abort:', { filename: safeFilename });
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            blobCacheRef.current.clear();
            setLoginError('File transfer corrupted (metadata mismatch)');
            return;
          }
        }

        if (fileEntry.paused) {
          scheduleInactivityTimer(fileKey, from, safeFilename);
          return;
        }

        fileEntry.lastUpdated = Date.now();
        scheduleInactivityTimer(fileKey, from, safeFilename);

        if (chunkIndex < 0 || chunkIndex >= fileEntry.totalChunks) {
          return;
        }

        if (fileEntry.receivedSet?.has(chunkIndex)) {
          return;
        }

        const encryptedBytes = decodeBase64Chunk(chunkData);
        if (!encryptedBytes) {
          return;
        }

        let parsed;
        try {
          parsed = CryptoUtils.Decrypt.deserializeEncryptedDataFromUint8Array(encryptedBytes);
        } catch (e) {
          console.error('[useFileHandler] Failed to deserialize encrypted chunk', { error: e, from, filename: safeFilename, chunkIndex });
          releaseFileEntry(fileEntry);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          blobCacheRef.current.clear();
          setLoginError('Invalid file chunk format');
          dispatchCanceledEvent({ from, filename: safeFilename, reason: 'deserialize-failed' });
          return;
        }

        const iv = parsed?.iv as Uint8Array | undefined;
        const authTag = parsed?.authTag as Uint8Array | undefined;
        const encrypted = parsed?.encrypted as Uint8Array | undefined;
        if (!(iv instanceof Uint8Array && authTag instanceof Uint8Array && encrypted instanceof Uint8Array) ||
          iv.length === 0 || authTag.length === 0 || encrypted.length === 0) {
          console.error('[useFileHandler] Invalid chunk wrapper (missing fields)', { from, filename: safeFilename, chunkIndex });
          releaseFileEntry(fileEntry);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          blobCacheRef.current.clear();
          setLoginError('Invalid file chunk wrapper');
          dispatchCanceledEvent({ from, filename: safeFilename, reason: 'invalid-wrapper' });
          return;
        }

        if (!fileEntry.aesKey) {
          const hybridKeys = await getKeysOnDemand();
          if (!hybridKeys) {
            throw new Error(`Hybrid keys not available for file decryption (${safeFilename})`);
          }

          try {
          } catch { }

          if (!envelope || !validateEnvelope(envelope)) {
            // Missing or invalid envelope => reject transfer
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            blobCacheRef.current.clear();
            console.error('[useFileHandler] File transfer rejected: invalid/missing envelope', { from, filename: safeFilename });
            setLoginError('File transfer rejected: invalid metadata');
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'invalid-envelope' });
            return;
          }

          // Decrypt per-file AES/MAC keys from hybrid envelope
          try {
            const senderDilithiumPk = (envelope as any)?.metadata?.sender?.dilithiumPublicKey;
            const decrypted = await (CryptoUtils as any).Hybrid.decryptIncoming(
              envelope as any,
              {
                kyberSecretKey: hybridKeys.kyber?.secretKey,
                x25519SecretKey: hybridKeys.x25519?.private,
                senderDilithiumPublicKey: senderDilithiumPk
              }
            );

            const aesPayload = (decrypted?.payloadJson ?? null) as { aesKey?: string; macKey?: string } | null;
            if (!aesPayload || typeof aesPayload.aesKey !== 'string' || typeof aesPayload.macKey !== 'string') {
              throw new Error('Invalid decrypted envelope payload');
            }

            const aesKeyBytes = CryptoUtils.Base64.base64ToUint8Array(aesPayload.aesKey);
            fileEntry.aesKey = await CryptoUtils.Keys.importAESKey(aesKeyBytes);
            const macKeyBytes = CryptoUtils.Base64.base64ToUint8Array(aesPayload.macKey);
            macStateRef.current.set(fileKey, { macKey: macKeyBytes, fileSize: fileEntry.fileSize || 0 });
          } catch (_e) {
            console.error('[useFileHandler] Failed to decrypt file key envelope', { error: _e, from, filename: safeFilename });
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            blobCacheRef.current.clear();
            setLoginError('File transfer rejected (key envelope invalid)');
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'envelope-decrypt-failed' });
            return;
          }
        }

        let macEntry = macStateRef.current.get(fileKey);

        if (payload.chunkMac && macEntry) {
          const idxBuf = new Uint8Array(8);
          const dv = new DataView(idxBuf.buffer);
          dv.setUint32(0, chunkIndex >>> 0, false);
          dv.setUint32(4, totalChunks >>> 0, false);
          const msgIdBytes = fileEntry.messageId ? new TextEncoder().encode(fileEntry.messageId) : new Uint8Array(0);
          const nameBytes = new TextEncoder().encode(safeFilename);
          const macInput = new Uint8Array(iv.length + authTag.length + encrypted.length + idxBuf.length + msgIdBytes.length + nameBytes.length);
          let mo = 0;
          macInput.set(iv, mo); mo += iv.length;
          macInput.set(authTag, mo); mo += authTag.length;
          macInput.set(encrypted, mo); mo += encrypted.length;
          macInput.set(idxBuf, mo); mo += idxBuf.length;
          macInput.set(msgIdBytes, mo); mo += msgIdBytes.length;
          macInput.set(nameBytes, mo);
          const computedMac = await CryptoUtils.Hash.generateBlake3Mac(macInput, new Uint8Array(macEntry.macKey));
          const computedMacB64 = CryptoUtils.Base64.arrayBufferToBase64(computedMac);
          if (computedMacB64 !== payload.chunkMac) {
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            blobCacheRef.current.clear();
            setLoginError('File integrity check failed');
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'chunk-mac-failed' });
            return;
          }
        }

        let decryptedBytes: Uint8Array;
        try {
          decryptedBytes = await CryptoUtils.AES.decryptBinaryWithAES(
            new Uint8Array(iv),
            new Uint8Array(authTag),
            new Uint8Array(encrypted),
            fileEntry.aesKey!
          );
        } catch (e) {
          console.error('[useFileHandler] AES decryption failed, aborting transfer', { error: e, from, filename: safeFilename, chunkIndex });
          releaseFileEntry(fileEntry);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          blobCacheRef.current.clear();
          setLoginError('Failed to decrypt file chunk');
          dispatchCanceledEvent({ from, filename: safeFilename, reason: 'decrypt-failed' });
          return;
        }

        if (!(decryptedBytes instanceof Uint8Array) || decryptedBytes.length === 0) {
          console.error('[useFileHandler] Decryption returned empty/invalid buffer', { from, filename: safeFilename, chunkIndex });
          releaseFileEntry(fileEntry);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          blobCacheRef.current.clear();
          setLoginError('Invalid decrypted chunk');
          dispatchCanceledEvent({ from, filename: safeFilename, reason: 'invalid-decrypted-buffer' });
          return;
        }

        let decompressedChunk: Uint8Array;
        try {
          try {
            decompressedChunk = pako.inflate(decryptedBytes);
          } catch {
            decompressedChunk = decryptedBytes;
          }
        } catch (e) {
          console.error('[useFileHandler] Decompression failed, aborting transfer', { error: e, from, filename: safeFilename, chunkIndex });
          releaseFileEntry(fileEntry);
          delete (incomingFileChunksRef.current as any)[fileKey];
          macStateRef.current.delete(fileKey);
          clearTimer(fileKey);
          blobCacheRef.current.clear();
          setLoginError('Failed to decompress file chunk');
          dispatchCanceledEvent({ from, filename: safeFilename, reason: 'decompress-failed' });
          return;
        }

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
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            macStateRef.current.delete(fileKey);
            clearTimer(fileKey);
            blobCacheRef.current.clear();
            setLoginError('File transfer rejected (size exceeded)');
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'size-exceeded' });
            return;
          }
        }

        const percent = Math.min(1, fileEntry.receivedCount / fileEntry.totalChunks);
        dispatchProgressEvent({ from, filename: safeFilename, percent, received: fileEntry.receivedCount, total: fileEntry.totalChunks });

        if (fileEntry.receivedCount === fileEntry.totalChunks) {
          clearTimer(fileKey);
          macStateRef.current.delete(fileKey);

          // Validate all chunks are present (no null/undefined holes in the array)
          let hasAllChunks = true;
          for (let i = 0; i < fileEntry.totalChunks; i++) {
            if (fileEntry.decryptedChunks[i] === null || fileEntry.decryptedChunks[i] === undefined) {
              hasAllChunks = false;
              console.error('[useFileHandler] Missing chunk', { chunkIndex: i, filename: safeFilename });
              break;
            }
          }

          if (!hasAllChunks) {
            console.error('[useFileHandler] Transfer incomplete - missing chunks despite count match', {
              from,
              filename: safeFilename,
              receivedCount: fileEntry.receivedCount,
              totalChunks: fileEntry.totalChunks
            });
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            blobCacheRef.current.clear();
            setLoginError('File transfer incomplete - missing chunks');
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'missing-chunks' });
            return;
          }

          const lowerName = safeFilename.toLowerCase();
          let detectedMime = 'application/octet-stream';
          if (lowerName.endsWith('.webm')) detectedMime = 'audio/webm';
          else if (lowerName.endsWith('.mp3')) detectedMime = 'audio/mpeg';
          else if (lowerName.endsWith('.wav')) detectedMime = 'audio/wav';
          else if (lowerName.endsWith('.ogg')) detectedMime = 'audio/ogg';
          else if (lowerName.endsWith('.m4a')) detectedMime = 'audio/mp4';

          let fileBlob: Blob;
          try {
            const parts = (fileEntry.decryptedChunks || []).filter((p) => p != null) as Blob[];
            fileBlob = new Blob(parts, { type: detectedMime });
          } catch (e) {
            console.error('[useFileHandler] Failed to assemble file blob', { error: e, from, filename: safeFilename });
            setLoginError('Failed to assemble received file');
            releaseFileEntry(fileEntry);
            delete (incomingFileChunksRef.current as any)[fileKey];
            blobCacheRef.current.clear();
            dispatchCanceledEvent({ from, filename: safeFilename, reason: 'assemble-failed' });
            return;
          }

          const fileUrl = URL.createObjectURL(fileBlob);
          blobCacheRef.current.enqueue(fileUrl, safeFilename);

          const messageId = fileEntry.messageId || uuidv4();
          if (secureDBRef?.current) {
            try {
              const saveResult = await secureDBRef.current.saveFile(messageId, fileBlob);
              if (!saveResult.success && saveResult.quotaExceeded) {
                toast.warning('Storage limit reached. This file will not persist after restart.', {
                  duration: 5000
                });
              }
            } catch (saveErr) {
              console.error('[useFileHandler] Failed to save file to SecureDB:', saveErr);
            }
          }

          let originalBase64Data: string | undefined;
          try {
            originalBase64Data = await new Promise<string>((resolve, reject) => {
              const reader = new FileReader();
              reader.onloadend = () => {
                const result = reader.result as string;
                const base64 = result.split(',')[1];
                resolve(base64);
              };
              reader.onerror = reject;
              reader.readAsDataURL(fileBlob);
            });
          } catch (e) {
            console.error('[useFileHandler] Failed to convert blob to base64:', e);
          }

          onNewMessage({
            id: fileEntry.messageId || uuidv4(),
            content: fileUrl,
            sender: from,
            recipient: toUser,
            timestamp: new Date(),
            isCurrentUser: false,
            isSystemMessage: false,
            type: SignalType.FILE_MESSAGE,
            filename: safeFilename,
            fileSize: fileBlob.size,
            mimeType: detectedMime,
            encrypted: true,
            transport: 'websocket',
            version: '1.0',
            receipt: { delivered: false, read: false },
            originalBase64Data,
          });

          dispatchCompleteEvent({ from, filename: safeFilename, size: fileBlob.size, mimeType: detectedMime, messageId: fileEntry.messageId || '' });

          delete (incomingFileChunksRef.current as any)[fileKey];
          releaseFileEntry(fileEntry);
        }
      } catch (err) {
        const errorObj = err as any;
        const details = {
          name: errorObj?.name,
          message: errorObj?.message,
          stack: errorObj?.stack,
        };
        try {
          console.error('[useFileHandler] Error handling FILE_MESSAGE_CHUNK', details);
        } catch { }
        try {
          console.error('[useFileHandler] FILE_MESSAGE_CHUNK payload summary', {
            hasEnvelope: !!(payload as any)?.envelope,
            from: (payload as any)?.from ?? message?.from,
            filename: (payload as any)?.filename,
            chunkIndex: (payload as any)?.chunkIndex,
            totalChunks: (payload as any)?.totalChunks,
            chunkSize: (payload as any)?.chunkSize,
            fileSize: (payload as any)?.fileSize,
          });
        } catch { }
        setLoginError('Failed to process file chunk');
      }
    },
    [getKeysOnDemand, onNewMessage, setLoginError, scheduleInactivityTimer, clearTimer]
  );

  // Cancel a incoming transfer
  const cancelIncomingFile = useCallback((from: string, filename: string) => {
    const fileKey = `${from}-${filename}`;
    if ((incomingFileChunksRef.current as any)[fileKey]) {
      delete (incomingFileChunksRef.current as any)[fileKey];
      macStateRef.current.delete(fileKey);
      clearTimer(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'user-canceled' });
    }
  }, [clearTimer]);

  // Pause receiving
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