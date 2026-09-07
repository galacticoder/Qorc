import React, { useRef, useCallback, useEffect } from "react";
import { Message } from '../../components/chat/messaging/types';
import { INACTIVITY_TIMEOUT_MS, RATE_LIMIT_MAX_EVENTS, RATE_LIMIT_WINDOW_MS, MAX_FILE_SIZE_BYTES, GLOBAL_INBOUND_FILE_MEMORY_BUDGET, FILE_NACK_STALL_MS, MAX_NACK_ATTEMPTS, MAX_RETRANSMIT_CHUNKS_PER_REQUEST } from "../../lib/constants";
import { dispatchProgressEvent, dispatchCanceledEvent, totalInboundFileBytes, releaseFileEntry } from "../../lib/utils/file-utils";
import type { ExtendedFileState } from "../../lib/types/file-types";
import { shouldQueueFileTransportAck } from './transport-ack';
import { extractChunkData, validateNewTransfer, createFileEntry, isValidChunkIndex } from "./chunk-validation";
import { parseEncryptedChunk, decryptEnvelope, verifyChunkMac, decryptChunk, cleanupFailedTransfer } from "./chunk-decryption";
import { completeFileTransfer, deriveIncomingFileMessageId, handleAssemblyFailure } from "./file-assembly";
import type { User } from "../../components/chat/messaging/UserList";
import { unifiedSignalTransport } from "../../lib/transport/unified-signal-transport";
import { SignalType } from "../../lib/types/signal-types";
import { deliveryReceiptOutbox } from '../../lib/signals/delivery-receipt-outbox';
import type { HybridKeys } from '../../lib/types/auth-types';
import { isCanonicalAuthUsername, sanitizeMessageId } from '../../lib/sanitizers';
import type { SecureDB } from '../../lib/database/secureDB';

const FILE_PERSIST_RETRY_BASE_MS = 1_500;
const FILE_PERSIST_RETRY_MAX_MS = 15_000;
const MAX_CANCELED_FILE_TRANSFERS = 512;

export function useFileHandler(
  getKeysOnDemand: () => Promise<HybridKeys | null>,
  onNewMessage: (message: Message) => void,
  setLoginError: (err: string) => void,
  secureDBRef: React.RefObject<SecureDB | null>,
  usersRef: React.RefObject<User[]>,
  findUser: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>,
  activeAccount: string | null
) {
  const incomingFileChunksRef = useRef<Record<string, ExtendedFileState>>({});
  const macStateRef = useRef<Map<string, { macKey: Uint8Array }>>(new Map());
  const cleanupTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  
  const nackTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const nackAttemptsRef = useRef<Map<string, number>>(new Map());
  const ackRetryTimersRef = useRef<Set<ReturnType<typeof setTimeout>>>(new Set());
  const canceledTransfersRef = useRef<Map<string, number>>(new Map());
  const accountGenerationRef = useRef(0);
  const activeAccountRef = useRef<string | null>(activeAccount || null);

  const clearMacState = useCallback((fileKey: string) => {
    const entry = macStateRef.current.get(fileKey);
    entry?.macKey.fill(0);
    macStateRef.current.delete(fileKey);
  }, []);

  const clearNackTimer = useCallback((fileKey: string) => {
    const t = nackTimersRef.current.get(fileKey);
    if (t) { try { clearTimeout(t); } catch { } nackTimersRef.current.delete(fileKey); }
  }, []);

  const scheduleNackCheck = useCallback((fileKey: string, from: string, fileId: string, filename: string) => {
    clearNackTimer(fileKey);
    const generation = accountGenerationRef.current;
    const timer = setTimeout(() => {
      nackTimersRef.current.delete(fileKey);
      if (generation !== accountGenerationRef.current) return;
      const entry = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;
      if (!entry) return;
      if (entry.receivedCount >= entry.totalChunks) return;

      const attempts = (nackAttemptsRef.current.get(fileKey) || 0) + 1;
      if (attempts > MAX_NACK_ATTEMPTS) return;

      const missingIndices: number[] = [];
      const received = entry.receivedSet;
      for (let i = 0; i < entry.totalChunks && missingIndices.length < MAX_RETRANSMIT_CHUNKS_PER_REQUEST; i++) {
        if (!received?.has(i)) missingIndices.push(i);
      }
      if (missingIndices.length === 0) return;

      nackAttemptsRef.current.set(fileKey, attempts);
      
      const refund = () => {
        if (nackAttemptsRef.current.get(fileKey) === attempts) {
          nackAttemptsRef.current.set(fileKey, attempts - 1);
        }
      };
      void unifiedSignalTransport
        .send(from, { fileId, filename, missingIndices }, SignalType.FILE_CHUNK_NACK)
        .then((r) => { if (!r?.success) refund(); })
        .catch(refund)
        .finally(() => {
          const current = (incomingFileChunksRef.current as any)[fileKey] as ExtendedFileState | undefined;
          if (
            generation === accountGenerationRef.current &&
            current === entry &&
            current.receivedCount < current.totalChunks
          ) {
            scheduleNackCheck(fileKey, from, fileId, filename);
          }
        });
    }, FILE_NACK_STALL_MS);
    nackTimersRef.current.set(fileKey, timer);
  }, [clearNackTimer]);

  const cleanup = useCallback(() => {
    for (const [, t] of cleanupTimersRef.current) {
      try { clearTimeout(t); } catch { }
    }
    cleanupTimersRef.current.clear();
    for (const [, t] of nackTimersRef.current) {
      try { clearTimeout(t); } catch { }
    }
    nackTimersRef.current.clear();
    nackAttemptsRef.current.clear();
    for (const entry of macStateRef.current.values()) entry.macKey.fill(0);
    macStateRef.current.clear();
    for (const timer of ackRetryTimersRef.current) clearTimeout(timer);
    ackRetryTimersRef.current.clear();
    for (const key of Object.keys(incomingFileChunksRef.current as any)) {
      releaseFileEntry((incomingFileChunksRef.current as any)[key]);
      delete (incomingFileChunksRef.current as any)[key];
    }
    canceledTransfersRef.current.clear();
  }, []);

  useEffect(() => cleanup, [cleanup]);

  useEffect(() => {
    const account = activeAccount || null;
    if (activeAccountRef.current === account) return;
    activeAccountRef.current = account;
    accountGenerationRef.current += 1;
    cleanup();
  }, [activeAccount, cleanup]);

  const clearTimer = useCallback((fileKey: string) => {
    const t = cleanupTimersRef.current.get(fileKey);
    if (t) {
      clearTimeout(t);
      cleanupTimersRef.current.delete(fileKey);
    }
  }, []);

  const scheduleInactivityTimer = useCallback((fileKey: string, from: string, filename: string) => {
    clearTimer(fileKey);
    const generation = accountGenerationRef.current;
    const timeout = setTimeout(() => {
      if (cleanupTimersRef.current.get(fileKey) === timeout) {
        cleanupTimersRef.current.delete(fileKey);
      }
      if (generation !== accountGenerationRef.current) return;
      releaseFileEntry((incomingFileChunksRef.current as any)[fileKey]);
      delete (incomingFileChunksRef.current as any)[fileKey];
      clearMacState(fileKey);
      clearNackTimer(fileKey);
      nackAttemptsRef.current.delete(fileKey);
      dispatchCanceledEvent({ from, filename, reason: 'inactivity-timeout' });
    }, INACTIVITY_TIMEOUT_MS);
    cleanupTimersRef.current.set(fileKey, timeout);
  }, [clearTimer, clearNackTimer, clearMacState]);

  const cancelIncomingFileTransfer = useCallback((from: string, fileId: string): boolean => {
    if (!isCanonicalAuthUsername(from) || sanitizeMessageId(fileId) !== fileId) return false;
    const fileKey = `${from}\0${fileId}`;
    const now = Date.now();
    for (const [key, expiresAt] of canceledTransfersRef.current) {
      if (expiresAt <= now) canceledTransfersRef.current.delete(key);
    }
    canceledTransfersRef.current.delete(fileKey);
    while (canceledTransfersRef.current.size >= MAX_CANCELED_FILE_TRANSFERS) {
      const oldest = canceledTransfersRef.current.keys().next().value;
      if (typeof oldest !== 'string') break;
      canceledTransfersRef.current.delete(oldest);
    }
    canceledTransfersRef.current.set(fileKey, now + INACTIVITY_TIMEOUT_MS);

    const entry = incomingFileChunksRef.current[fileKey];
    if (!entry) return true;
    clearTimer(fileKey);
    clearNackTimer(fileKey);
    nackAttemptsRef.current.delete(fileKey);
    clearMacState(fileKey);
    releaseFileEntry(entry);
    delete incomingFileChunksRef.current[fileKey];
    dispatchCanceledEvent({ from, filename: entry.safeFilename, reason: 'sender-canceled' });
    return true;
  }, [clearMacState, clearNackTimer, clearTimer]);

  const handleFileMessageChunk = useCallback(
    async (payload: any, message: any) => {
      const generation = accountGenerationRef.current;
      const account = activeAccountRef.current;
      const secureDB = secureDBRef.current;
      const isCurrent = () => (
        generation === accountGenerationRef.current &&
        account !== null &&
        activeAccountRef.current === account &&
        secureDBRef.current === secureDB
      );
      try {
        if (!account || !secureDB || !isCurrent()) return false;
        const data = extractChunkData(payload, message);
        if (!data) {
          console.error('[FILE-RECV-STAGE] chunk-payload-validation', {
            payloadKeys: payload && typeof payload === 'object'
              ? Object.keys(payload).sort()
              : typeof payload,
            transportMessageId: message?.transportMessageId,
          });
          return;
        }

        const {
          from,
          toUser,
          safeFilename,
          fileKey,
          chunkIndex,
          totalChunks,
          chunkData,
          envelope,
          transportMessageId,
          chunkMac,
          recoveryProbe,
        } = data;
        if (toUser !== account) return;
        const canceledUntil = canceledTransfersRef.current.get(fileKey);
        if (canceledUntil !== undefined) {
          if (canceledUntil > Date.now()) return true;
          canceledTransfersRef.current.delete(fileKey);
        }
        
        if (!isValidChunkIndex(chunkIndex, totalChunks)) return;
        const store = incomingFileChunksRef.current as any;
        let fileEntry = store[fileKey] as ExtendedFileState | undefined;

        const failTransfer = (entry: ExtendedFileState, reason: string, errorMessage: string): void => {
          console.error(`[FILE-RECV-STAGE] ${reason}`);
          clearNackTimer(fileKey);
          nackAttemptsRef.current.delete(fileKey);
          cleanupFailedTransfer(
            entry,
            fileKey,
            store,
            macStateRef.current,
            cleanupTimersRef.current,
            from,
            safeFilename,
            reason,
            setLoginError,
            errorMessage
          );
        };

        const acknowledgeTransport = (force = false) => {
          if (!transportMessageId || !isCurrent()) return;
          const entry = fileEntry!;
          const canAcknowledge = () => (
            isCurrent() &&
            !entry.transportAckCanceled &&
            (store[fileKey] === entry || entry.transportAckDurablyCommitted === true)
          );
          if (!canAcknowledge()) return;
          entry.transportAckedIndices ??= new Set<number>();
          entry.transportAckPending ??= new Map<number, string>();
          if (!shouldQueueFileTransportAck(entry, chunkIndex, Date.now(), force)) return;
          entry.transportAckPending.set(chunkIndex, transportMessageId);

          const startNextAck = () => {
            if (!canAcknowledge()) return;
            if (entry.transportAckInFlight) return;
            const next = entry.transportAckPending?.entries().next().value as [number, string] | undefined;
            if (!next) {
              if (entry.transportAckDurablyCommitted) entry.transportAckedIndices?.clear();
              return;
            }
            const [nextChunkIndex, ackFor] = next;
            entry.transportAckInFlight = { chunkIndex: nextChunkIndex, ackFor };
            const finish = (confirmed: boolean) => {
              const active = entry.transportAckInFlight;
              if (!active || active.chunkIndex !== nextChunkIndex || active.ackFor !== ackFor) return;
              entry.transportAckInFlight = undefined;
              if (confirmed && canAcknowledge()) {
                entry.transportAckedIndices?.add(nextChunkIndex);
              }
              if (entry.transportAckPending?.get(nextChunkIndex) === ackFor) {
                entry.transportAckPending.delete(nextChunkIndex);
              }
              if (canAcknowledge()) startNextAck();
            };
            const scheduleRetry = (attempt: number) => {
              const timer = setTimeout(() => {
                ackRetryTimersRef.current.delete(timer);
                if (canAcknowledge()) sendAck(attempt);
                else finish(false);
              }, 1500);
              ackRetryTimersRef.current.add(timer);
            };
            const sendAck = (attempt: number) => {
              if (!canAcknowledge()) {
                finish(false);
                return;
              }
              unifiedSignalTransport
                .send(from, { ackFor }, SignalType.FILE_TRANSPORT_ACK)
                .then((result) => {
                  if (!canAcknowledge()) {
                    finish(false);
                  } else if (result?.success) {
                    finish(true);
                  } else if (attempt < 2) {
                    scheduleRetry(attempt + 1);
                  } else {
                    finish(false);
                  }
                })
                .catch(() => {
                  if (canAcknowledge() && attempt < 2) scheduleRetry(attempt + 1);
                  else finish(false);
                });
            };
            sendAck(0);
          };
          startNextAck();
        };

        if (!fileEntry) {
          const validation = validateNewTransfer(data, incomingFileChunksRef.current, setLoginError);
          if (validation !== 'valid') return validation === 'busy' ? false : undefined;
          if (recoveryProbe) {
            const persistedMessageId = await deriveIncomingFileMessageId(from, data.messageId);
            if (!isCurrent()) return false;
            if (await secureDB.hasCompleteFileMessage(from, persistedMessageId)) {
              if (!isCurrent()) return false;
              const queued = await deliveryReceiptOutbox.queueDelivery(toUser, from, data.messageId);
              if (!queued || !isCurrent()) return false;
              if (transportMessageId) {
                try {
                  await unifiedSignalTransport.send(
                    from,
                    { ackFor: transportMessageId },
                    SignalType.FILE_TRANSPORT_ACK
                  );
                } catch { }
                if (!isCurrent()) return false;
              }
              return true;
            }
            if (!isCurrent()) return false;
          }
          fileEntry = createFileEntry(data);
          store[fileKey] = fileEntry;
          
          scheduleInactivityTimer(fileKey, from, safeFilename);
        } else if (
          fileEntry.totalChunks !== totalChunks ||
          fileEntry.fileSize !== data.fileSize ||
          fileEntry.chunkSize !== data.chunkSize ||
          fileEntry.messageId !== data.messageId ||
          fileEntry.safeFilename !== safeFilename
        ) {
          failTransfer(fileEntry, 'metadata-mismatch', 'File transfer corrupted (metadata mismatch)');
          return;
        }

        if (fileEntry.transport !== data.transport) fileEntry.transport = 'relay';

        const finalizeCompletedTransfer = async (): Promise<boolean> => {
          if ((fileEntry!.persistenceRetryAt || 0) > Date.now()) return false;
          const result = await completeFileTransfer(
            fileEntry!,
            from,
            toUser,
            secureDB,
            onNewMessage,
            isCurrent
          );
          if (!isCurrent()) return false;
          if (!result.assembled) {
            clearTimer(fileKey);
            clearNackTimer(fileKey);
            nackAttemptsRef.current.delete(fileKey);
            clearMacState(fileKey);
            handleAssemblyFailure(fileEntry!, fileKey, store, from, 'assembly-failed', setLoginError, 'File transfer incomplete');
            return true;
          }
          if (!result.durablySaved) {
            const failures = Math.min((fileEntry!.persistenceFailureCount || 0) + 1, 16);
            fileEntry!.persistenceFailureCount = failures;
            fileEntry!.persistenceRetryAt = Date.now() + Math.min(
              FILE_PERSIST_RETRY_BASE_MS * (2 ** (failures - 1)),
              FILE_PERSIST_RETRY_MAX_MS
            );
            
            return false;
          }

          clearTimer(fileKey);
          clearNackTimer(fileKey);
          nackAttemptsRef.current.delete(fileKey);
          clearMacState(fileKey);
          fileEntry!.transportAckDurablyCommitted = true;
          delete store[fileKey];
          releaseFileEntry(fileEntry!);
          acknowledgeTransport(true);
          return true;
        };

        if (fileEntry.receivedSet?.has(chunkIndex)) {
          if (fileEntry.receivedCount === fileEntry.totalChunks) {
            return finalizeCompletedTransfer();
          }
          acknowledgeTransport(true);
          return true;
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
          return false;
        }

        const parsed = parseEncryptedChunk(chunkData);
        if (!parsed) {
            failTransfer(fileEntry, 'deserialize-failed', 'Invalid file chunk format');
          return;
        }

        const { iv, authTag, encrypted } = parsed;
        try {

          if (!fileEntry.aesKey) {
          const hybridKeys = await getKeysOnDemand();
          if (!isCurrent()) return false;
          if (!hybridKeys) {
            return false;
          }

          const keys = await decryptEnvelope(envelope, account, from, usersRef.current, findUser);
          if (!isCurrent()) {
            keys?.macKey.fill(0);
            return false;
          }
          if (!keys) {
            failTransfer(fileEntry, 'envelope-decrypt-failed', 'File transfer rejected (key envelope invalid)');
            return;
          }

          fileEntry.aesKey = keys.aesKey;
          macStateRef.current.set(fileKey, { macKey: keys.macKey });
        }

          const macEntry = macStateRef.current.get(fileKey);
        if (!macEntry) {
          failTransfer(fileEntry, 'chunk-mac-key-missing', 'File integrity key unavailable');
          return;
        }
          const ctx = { fileEntry, fileKey, from, safeFilename, chunkIndex, iv, authTag, encrypted };
          const valid = await verifyChunkMac(ctx, chunkMac, macEntry.macKey, totalChunks);
        if (!isCurrent()) return false;
        if (!valid) {
          failTransfer(fileEntry, 'chunk-mac-failed', 'File integrity check failed');
          return;
        }

          const decryptedBytes = await decryptChunk(iv, authTag, encrypted, fileEntry.aesKey!);
        if (!isCurrent()) {
          decryptedBytes?.fill(0);
          return false;
        }
        if (!decryptedBytes) {
          failTransfer(fileEntry, 'decrypt-failed', 'Failed to decrypt file chunk');
          return;
        }

        const expectedChunkLength = chunkIndex === fileEntry.totalChunks - 1
          ? fileEntry.fileSize! - (fileEntry.chunkSize! * (fileEntry.totalChunks - 1))
          : fileEntry.chunkSize!;
        if (decryptedBytes.length !== expectedChunkLength) {
          decryptedBytes.fill(0);
          failTransfer(fileEntry, 'chunk-size-mismatch', 'File transfer rejected (chunk size mismatch)');
          return;
        }

        if (!fileEntry.receivedSet!.has(chunkIndex)) {
          const chunkLength = decryptedBytes.length;
          if (totalInboundFileBytes(store) + chunkLength > GLOBAL_INBOUND_FILE_MEMORY_BUDGET) {
            decryptedBytes.fill(0);
            failTransfer(fileEntry, 'global-memory-exceeded', 'File transfer rejected (memory limit)');
            return;
          }
          const ownedChunk = new Uint8Array(decryptedBytes.length);
          ownedChunk.set(decryptedBytes);
          fileEntry.decryptedChunks[chunkIndex] = ownedChunk;
          decryptedBytes.fill(0);
          fileEntry.receivedSet!.add(chunkIndex);
          fileEntry.receivedCount++;
          fileEntry.bytesReceivedApprox = (fileEntry.bytesReceivedApprox || 0) + chunkLength;
          scheduleInactivityTimer(fileKey, from, safeFilename);
          nackAttemptsRef.current.delete(fileKey);

          if (fileEntry.bytesReceivedApprox > fileEntry.fileSize! ||
            fileEntry.bytesReceivedApprox > MAX_FILE_SIZE_BYTES) {
            failTransfer(fileEntry, 'size-exceeded', 'File transfer rejected (size exceeded)');
            return;
          }
        } else {
          decryptedBytes.fill(0);
        }

        dispatchProgressEvent({ from, filename: safeFilename, percent: Math.min(1, fileEntry.receivedCount / fileEntry.totalChunks), received: fileEntry.receivedCount, total: fileEntry.totalChunks });

        if (fileEntry.receivedCount === fileEntry.totalChunks) {
          return finalizeCompletedTransfer();
        } else if (fileEntry.messageId) {
          acknowledgeTransport();
          scheduleNackCheck(fileKey, from, fileEntry.messageId, safeFilename);
        }
          return true;
        } finally {
          iv.fill(0);
          authTag.fill(0);
          encrypted.fill(0);
        }
      } catch (err) {
        if (!isCurrent()) return false;
        console.error('[useFileHandler] Error handling FILE_MESSAGE_CHUNK', err);
        setLoginError('Failed to process file chunk');
        throw err;
      }
    },
    [getKeysOnDemand, onNewMessage, setLoginError, scheduleInactivityTimer, clearTimer, clearNackTimer, clearMacState, secureDBRef, usersRef, findUser]
  );

  return { handleFileMessageChunk, cancelIncomingFileTransfer, cleanup };
}
