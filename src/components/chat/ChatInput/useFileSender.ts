import { useRef, useState, useCallback, useEffect, useLayoutEffect } from "react";
import { CryptoUtils } from "../../../lib/utils/crypto-utils";
import { SignalType } from "../../../lib/types/signal-types";
import { EventType } from "../../../lib/types/event-types";
import { exactEventDetail, sanitizeFilename, sanitizeMessageId } from "../../../lib/sanitizers";
import { AUTH_USERNAME_REGEX, DEFAULT_CHUNK_SIZE_SMALL, DEFAULT_CHUNK_SIZE_LARGE, LARGE_FILE_THRESHOLD, MAX_CHUNKS_PER_SECOND, INACTIVITY_TIMEOUT_MS, RATE_LIMITER_SLEEP_MS, YIELD_INTERVAL, MAC_SALT, SESSION_WAIT_MS, SESSION_POLL_BASE_MS, SESSION_POLL_MAX_MS, SESSION_FRESH_COOLDOWN_MS, FILE_RETRANSMIT_RETENTION_MS, MAX_RETAINED_TRANSFERS, MAX_RETRANSMIT_CHUNKS_PER_REQUEST, RETRANSMIT_MIN_INTERVAL_MS, MAX_FILE_SIZE } from "../../../lib/constants";
import { unifiedSignalTransport } from "../../../lib/transport/unified-signal-transport";
import { account, signal } from "../../../lib/tauri-bindings";
import { stripImageMetadata } from "../../../lib/utils/file-utils";
import { shouldAttemptDiscovery } from "../../../lib/utils/discovery-utils";
import { resolveTrustedPeerHybridPublicKeys } from "../../../lib/utils/signal-bundle-utils";
import { validateHybridKeys } from "../../../hooks/message-sending/validation";
import { blockingSystem } from "../../../lib/blocking/blocking-system";
import { getSessionApi } from '../../../lib/utils/message-sending-utils';
import {
  isKeyTransparencyAuthorizedPeerKeySet,
  isKeyTransparencyPeerRevoked,
} from "../../../lib/key-transparency/verified-material";
import type { HybridKeys as NativeAccountKeys } from "../../../lib/types/auth-types";
import type { HybridPublicKeys, UserWithKeys } from '../../../lib/types/message-sending-types';
import { PROTOCOL_KEYS } from '../../../lib/config/protocol-keys';

interface TransferState {
  readonly fileId: string;
  readonly fileName: string;
  readonly fileSize: number;
  readonly chunkSize: number;
  readonly totalChunks: number;
  lastSentIndex: number;
  canceled: boolean;
  lastActivity: number;
  inactivityTimer?: NodeJS.Timeout;
  readonly ownerUsername: string;
  readonly ownerGeneration: number;
  readonly recipientUsername: string;
}

type LocalKeys = NativeAccountKeys;

interface UserKeyEnvelope {
  readonly username: string;
  readonly envelope: unknown;
}

interface RetainedTransfer {
  readonly fileId: string;
  readonly file: File;
  readonly aesKey: CryptoKey;
  readonly macKey: Uint8Array;
  readonly userKeys: readonly UserKeyEnvelope[];
  readonly totalChunks: number;
  readonly chunkSize: number;
  readonly fileName: string;
  readonly fileSize: number;
  retainedAt: number;
  readonly ownerUsername: string;
  readonly ownerGeneration: number;
}

interface FileSendOperation {
  canceled: boolean;
}

type FileSendPhase = 'idle' | 'preparing' | 'sending';

const MAX_RETAINED_FILE_BYTES = 128 * 1024 * 1024;
const MAX_FILE_SESSION_PEERS = 512;
const FILE_RECOVERY_PROBE_INITIAL_MS = 15_000;
const FILE_RECOVERY_PROBE_MAX_MS = 120_000;

const fileRecoveryRetentionMs = (totalChunks: number): number => Math.max(
  FILE_RETRANSMIT_RETENTION_MS,
  Math.ceil((totalChunks / MAX_CHUNKS_PER_SECOND) * 1000) +
    INACTIVITY_TIMEOUT_MS +
    (FILE_RECOVERY_PROBE_INITIAL_MS * 2)
);

export function useFileSender(
  currentUsername: string,
  targetUsername: string | undefined,
  users: readonly UserWithKeys[],
  getKeysOnDemand?: () => Promise<LocalKeys | null>,
  getPeerHybridKeys?: (peerUsername: string) => Promise<HybridPublicKeys | null>,
  findUser?: (handle: string) => Promise<any>,
  secureDB?: any,
  ensurePeerSession?: (peerUsername: string) => Promise<void>
) {
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);
  const [fileSendPhase, setFileSendPhase] = useState<FileSendPhase>('idle');

  const currentTransferRef = useRef<TransferState | null>(null);
  const currentFileRef = useRef<File | null>(null);
  const currentAesKeyRef = useRef<CryptoKey | null>(null);
  const currentMacKeyRef = useRef<Uint8Array | null>(null);
  const rateTokensRef = useRef<number>(MAX_CHUNKS_PER_SECOND);
  const lastRefillRef = useRef<number>(Date.now());
  const sessionEstablishedAt = useRef<Map<string, number>>(new Map());
  const peersNeedingSessionRefresh = useRef<Set<string>>(new Set());
  // Transfers retained (with their keys + file handle) for a window after sending
  // so we can honour a receiver's retransmit request for chunks it dropped.
  const retainedTransfersRef = useRef<Map<string, RetainedTransfer>>(new Map());
  const activeRetransmitContextRef = useRef<RetainedTransfer | null>(null);
  // Per fileId|peer throttle so a peer can't spam retransmit requests.
  const retransmitRateRef = useRef<Map<string, number>>(new Map());
  const retransmitInFlightRef = useRef<Set<string>>(new Set());
  const retentionTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const recoveryProbeTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const earlyDeliveredTransfersRef = useRef<Set<string>>(new Set());
  const accountGenerationRef = useRef(0);
  const activeUsernameRef = useRef(currentUsername);
  const sendOperationRef = useRef<FileSendOperation | null>(null);

  const rememberSessionEstablished = useCallback((peer: string): void => {
    sessionEstablishedAt.current.delete(peer);
    while (sessionEstablishedAt.current.size >= MAX_FILE_SESSION_PEERS) {
      const oldest = sessionEstablishedAt.current.keys().next().value;
      if (typeof oldest !== 'string') break;
      sessionEstablishedAt.current.delete(oldest);
    }
    sessionEstablishedAt.current.set(peer, Date.now());
  }, []);

  const rememberSessionRefresh = useCallback((peer: string): void => {
    peersNeedingSessionRefresh.current.delete(peer);
    while (peersNeedingSessionRefresh.current.size >= MAX_FILE_SESSION_PEERS) {
      const oldest = peersNeedingSessionRefresh.current.values().next().value;
      if (typeof oldest !== 'string') break;
      peersNeedingSessionRefresh.current.delete(oldest);
    }
    peersNeedingSessionRefresh.current.add(peer);
  }, []);

  const isOwnedByActiveAccount = useCallback((ownerUsername: string, ownerGeneration: number): boolean => (
    ownerUsername === activeUsernameRef.current && ownerGeneration === accountGenerationRef.current
  ), []);

  const isTransferAuthorized = useCallback((
    ownerUsername: string,
    ownerGeneration: number,
    recipientUsername: string,
  ): boolean => (
    isOwnedByActiveAccount(ownerUsername, ownerGeneration) &&
    !isKeyTransparencyPeerRevoked(ownerUsername, recipientUsername)
  ), [isOwnedByActiveAccount]);

  const releaseRetainedTransfer = useCallback((fileId: string, expected?: RetainedTransfer): void => {
    const retained = retainedTransfersRef.current.get(fileId);
    if (!retained || (expected && retained !== expected)) return;
    retained.macKey.fill(0);
    retainedTransfersRef.current.delete(fileId);
    const timer = retentionTimersRef.current.get(fileId);
    if (timer) clearTimeout(timer);
    retentionTimersRef.current.delete(fileId);
    const probeTimer = recoveryProbeTimersRef.current.get(fileId);
    if (probeTimer) clearTimeout(probeTimer);
    recoveryProbeTimersRef.current.delete(fileId);
    for (const key of Array.from(retransmitRateRef.current.keys())) {
      if (key.startsWith(`${fileId}|`)) retransmitRateRef.current.delete(key);
    }
    for (const key of Array.from(retransmitInFlightRef.current)) {
      if (key.startsWith(`${fileId}|`)) retransmitInFlightRef.current.delete(key);
    }
  }, []);

  const clearRetainedTransfers = useCallback(() => {
    for (const fileId of Array.from(retainedTransfersRef.current.keys())) {
      releaseRetainedTransfer(fileId);
    }
    for (const timer of retentionTimersRef.current.values()) clearTimeout(timer);
    retentionTimersRef.current.clear();
    for (const timer of recoveryProbeTimersRef.current.values()) clearTimeout(timer);
    recoveryProbeTimersRef.current.clear();
    retransmitRateRef.current.clear();
    retransmitInFlightRef.current.clear();
    earlyDeliveredTransfersRef.current.clear();
  }, [releaseRetainedTransfer]);

  // Listen for session reset events
  useEffect(() => {
    const handleSessionReset = (event: Event) => {
      try {
        const detail = exactEventDetail(event, ['account', 'failedMessageId', 'peerUsername']);
        if (!detail) return;
        if (detail.account !== activeUsernameRef.current) return;
        const peerUsername = detail.peerUsername;
        if (typeof peerUsername === 'string' && AUTH_USERNAME_REGEX.test(peerUsername)) {
          rememberSessionRefresh(peerUsername);
          sessionEstablishedAt.current.delete(peerUsername);
        }
      } catch { }
    };

    const handleSessionEstablished = (event: Event) => {
      try {
        const detail = exactEventDetail(event, ['account', 'peer']);
        if (!detail) return;
        if (detail.account !== activeUsernameRef.current) return;
        const peerUsername = detail.peer;
        if (typeof peerUsername === 'string' && AUTH_USERNAME_REGEX.test(peerUsername)) {
          peersNeedingSessionRefresh.current.delete(peerUsername);
          rememberSessionEstablished(peerUsername);
        }
      } catch { }
    };

    window.addEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionEstablished as EventListener);

    return () => {
      window.removeEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionEstablished as EventListener);
    };
  }, [rememberSessionEstablished, rememberSessionRefresh]);

  // Refill rate limiter tokens based on elapsed time
  const refillTokens = useCallback((): void => {
    const now = Date.now();
    const elapsed = (now - lastRefillRef.current) / 1000;
    if (elapsed > 0) {
      const refill = elapsed * MAX_CHUNKS_PER_SECOND;
      rateTokensRef.current = Math.min(MAX_CHUNKS_PER_SECOND, rateTokensRef.current + refill);
      lastRefillRef.current = now;
    }
  }, []);

  // Take a token from rate limiter if available
  const takeToken = useCallback((): boolean => {
    refillTokens();
    if (rateTokensRef.current >= 1) {
      rateTokensRef.current -= 1;
      return true;
    }
    return false;
  }, [refillTokens]);

  // Compute MAC for chunk integrity verification
  const computeChunkMacAsync = useCallback(async (
    iv: Uint8Array,
    authTag: Uint8Array,
    encrypted: Uint8Array,
    macKey: Uint8Array,
    chunkIndex: number,
    totalChunks: number,
    messageId: string,
    filename: string
  ): Promise<string> => {
    const idxBuf = new Uint8Array(8);
    const dv = new DataView(idxBuf.buffer);
    dv.setUint32(0, chunkIndex >>> 0, false);
    dv.setUint32(4, totalChunks >>> 0, false);

    const enc = new TextEncoder();
    const msgIdBytes = enc.encode(messageId || '');
    const nameBytes = enc.encode(filename || '');

    const macInput = new Uint8Array(
      iv.length + authTag.length + encrypted.length + idxBuf.length + msgIdBytes.length + nameBytes.length
    );
    let o = 0;
    macInput.set(iv, o); o += iv.length;
    macInput.set(authTag, o); o += authTag.length;
    macInput.set(encrypted, o); o += encrypted.length;
    macInput.set(idxBuf, o); o += idxBuf.length;
    macInput.set(msgIdBytes, o); o += msgIdBytes.length;
    macInput.set(nameBytes, o);

    let macBytes: Uint8Array | null = null;
    try {
      macBytes = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
      return CryptoUtils.Base64.arrayBufferToBase64(macBytes);
    } finally {
      idxBuf.fill(0);
      msgIdBytes.fill(0);
      nameBytes.fill(0);
      macInput.fill(0);
      macBytes?.fill(0);
    }
  }, []);

  // Schedule inactivity timeout for transfer cancellation
  const scheduleInactivityTimer = useCallback((state: TransferState): void => {
    if (state.inactivityTimer) clearTimeout(state.inactivityTimer);
    state.inactivityTimer = setTimeout(() => {
      if (currentTransferRef.current && currentTransferRef.current.fileId === state.fileId) {
        cancelCurrent();
      }
    }, INACTIVITY_TIMEOUT_MS);
  }, []);

  // Ensure Signal session is established
  const ensureSignalSession = useCallback(async (forceReestablish: boolean = false): Promise<boolean> => {
    const generation = accountGenerationRef.current;
    const owner = currentUsername;
    const isCurrent = () => !!targetUsername && isTransferAuthorized(owner, generation, targetUsername);
    try {
      if (!targetUsername || !getKeysOnDemand || !isCurrent()) return false;

      const sessionApi = getSessionApi();
      const needsRefresh = forceReestablish || peersNeedingSessionRefresh.current.has(targetUsername);

      const initial = await sessionApi.hasSession({
        selfUsername: currentUsername,
        peerUsername: targetUsername,
      });
      if (!isCurrent()) return false;

      // If session exists and peer doesn't need refresh, trust it
      if (initial?.hasSession && !needsRefresh) {
        return true;
      }

      const lastEstablished = sessionEstablishedAt.current.get(targetUsername) || 0;
      const sessionIsFresh = (Date.now() - lastEstablished) < SESSION_FRESH_COOLDOWN_MS;

      if (initial?.hasSession && needsRefresh && sessionIsFresh && !forceReestablish) {
        peersNeedingSessionRefresh.current.delete(targetUsername);
        return true;
      }

      let hasUsableSession = initial?.hasSession === true;
      if (needsRefresh && hasUsableSession && (forceReestablish || !sessionIsFresh)) {
        try {
          const deleted = await signal.deleteAllSessions(currentUsername, targetUsername);
          if (!isCurrent()) return false;
          if (!deleted) return false;
          hasUsableSession = false;
          sessionEstablishedAt.current.delete(targetUsername);
        } catch (e) {
          console.warn('[FILE-SENDER] Failed to delete stale session:', e);
          return false;
        }
      }

      if (!hasUsableSession && ensurePeerSession) {
        await ensurePeerSession(targetUsername);
        if (!isCurrent()) return false;
      }

      const deadline = Date.now() + SESSION_WAIT_MS;
      let delay = SESSION_POLL_BASE_MS;

      let sessionReadyFlag = false;
      const readyHandler = (event: Event) => {
        const detail = exactEventDetail(event, ['account', 'peer']);
        if (!detail) return;
        if (
          detail.account === currentUsername &&
          detail.peer === targetUsername
        ) {
          sessionReadyFlag = true;
        }
      };
      window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener);

      try {
        const firstCheck = await sessionApi.hasSession({
          selfUsername: currentUsername,
          peerUsername: targetUsername,
        });
        if (!isCurrent()) return false;
        if (firstCheck?.hasSession) {
          peersNeedingSessionRefresh.current.delete(targetUsername);
          rememberSessionEstablished(targetUsername);
          return true;
        }

        while (Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, delay));
          if (!isCurrent()) return false;

          if (sessionReadyFlag) {
            peersNeedingSessionRefresh.current.delete(targetUsername);
            rememberSessionEstablished(targetUsername);
            return true;
          }

          const check = await sessionApi.hasSession({
            selfUsername: currentUsername,
            peerUsername: targetUsername,
          });
          if (!isCurrent()) return false;
          if (check?.hasSession) {
            peersNeedingSessionRefresh.current.delete(targetUsername);
            rememberSessionEstablished(targetUsername);
            return true;
          }

          const randomSource = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 0xffffffff;
          const poisson = -Math.log(Math.max(1 - randomSource, 1e-6));
          delay = Math.min(delay + poisson * SESSION_POLL_BASE_MS, SESSION_POLL_MAX_MS);
        }
      } finally {
        try { window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener); } catch { }
      }
      return false;
    } catch {
      return false;
    }
  }, [getKeysOnDemand, targetUsername, currentUsername, isTransferAuthorized, rememberSessionEstablished, ensurePeerSession]);

  // Send encrypted file chunks
  const sendChunks = useCallback(async (
    state: TransferState,
    userKeys: readonly UserKeyEnvelope[]
  ): Promise<boolean> => {
    const file = currentFileRef.current!;
    const aesKey = currentAesKeyRef.current!;
    const macKey = currentMacKeyRef.current!;

    const totalChunks = state.totalChunks;
    const chunkSize = state.chunkSize;
    const MAX_RESTARTS = 2;
    let retryCause: 'session-reset' | 'transport' | null = null;

    for (let restartAttempt = 0; restartAttempt <= MAX_RESTARTS; restartAttempt++) {
      if (!isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) return false;
      let resetDetected = false;
      let transportFailed = false;
      const resetHandler = (event: Event) => {
        try {
          const detail = exactEventDetail(event, ['account', 'failedMessageId', 'peerUsername']);
          if (!detail) return;
          if (detail.account !== state.ownerUsername) return;
          const peer = detail.peerUsername;
          const target = userKeys[0]?.username;
          if (peer === target) {
            resetDetected = true;
          }
        } catch { }
      };
      window.addEventListener(EventType.SESSION_RESET_RECEIVED, resetHandler as EventListener);

      try {
        const hasPendingReset = targetUsername && peersNeedingSessionRefresh.current.has(targetUsername);
        if (retryCause === 'session-reset' || hasPendingReset) {
          state.lastSentIndex = -1;
          setProgress(0);
          if (!await ensureSignalSession(true)) {
            retryCause = 'session-reset';
            if (restartAttempt < MAX_RESTARTS) {
              await new Promise(r => setTimeout(r, 1000));
              continue;
            }
            break;
          }
        }
        retryCause = null;

        while (state.lastSentIndex < totalChunks - 1) {
          if (!isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) return false;
          if (resetDetected || (targetUsername && peersNeedingSessionRefresh.current.has(targetUsername))) {
            resetDetected = true;
            break;
          }

          if (state.canceled) {
            return false;
          }
          if (!takeToken()) {
            await new Promise(res => setTimeout(res, RATE_LIMITER_SLEEP_MS));
            continue;
          }

          if (resetDetected || (targetUsername && peersNeedingSessionRefresh.current.has(targetUsername))) {
            resetDetected = true;
            break;
          }

          const nextIndex = state.lastSentIndex + 1;
          const start = nextIndex * chunkSize;
          const end = Math.min(start + chunkSize, file.size);
          const blobSlice = file.slice(start, end);
          const chunk = new Uint8Array(await blobSlice.arrayBuffer());
          if (state.canceled || !isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) {
            chunk.fill(0);
            return false;
          }
          let encryptedChunk;
          try {
            encryptedChunk = await CryptoUtils.Encrypt.encryptBinaryWithAES(chunk, aesKey);
          } finally {
            chunk.fill(0);
          }
          const { iv, authTag, encrypted } = encryptedChunk;
          try {
            if (state.canceled || !isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) return false;
            const chunkMac = await computeChunkMacAsync(
              iv,
              authTag,
              encrypted,
              macKey,
              nextIndex,
              totalChunks,
              state.fileId,
              sanitizeFilename(state.fileName)
            );
            if (state.canceled || !isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) return false;

            for (const uk of userKeys) {
              const chunkMetadata = {
                type: SignalType.FILE_MESSAGE_CHUNK,
                from: currentUsername,
                to: uk.username,
                envelope: uk.envelope,
                chunkIndex: nextIndex,
                totalChunks,
                filename: sanitizeFilename(state.fileName),
                isLastChunk: nextIndex === totalChunks - 1,
                fileSize: state.fileSize,
                chunkSize,
                fileId: state.fileId,
                messageId: state.fileId,
                recoveryProbe: false,
                chunkMac
              };

              if (!uk.envelope) {
                transportFailed = true;
                break;
              }

              const chunkDataBase64 = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);

              const fullChunkMessage = {
                ...chunkMetadata,
                messageId: `${state.fileId}:chunk:${nextIndex}`,
                fileTransferId: state.fileId,
                chunkData: chunkDataBase64
              };

              if (state.canceled || !isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) return false;
              const chunkSendResult = await unifiedSignalTransport.send(uk.username, fullChunkMessage, SignalType.FILE_MESSAGE_CHUNK);
              if (state.canceled || !isTransferAuthorized(state.ownerUsername, state.ownerGeneration, state.recipientUsername)) return false;
              if (!chunkSendResult?.success) {
                transportFailed = true;
                break;
              }
            }
          } finally {
            iv.fill(0);
            authTag.fill(0);
            encrypted.fill(0);
          }

          if (resetDetected || transportFailed) break;

          state.lastSentIndex = nextIndex;
          state.lastActivity = Date.now();
          scheduleInactivityTimer(state);

          const confirmedBytes = Math.min(
            (state.lastSentIndex + 1) * chunkSize,
            state.fileSize,
          );
          const pct = confirmedBytes / state.fileSize;
          setProgress(pct);

          if ((nextIndex & (YIELD_INTERVAL - 1)) === 0) {
            await new Promise(res => setTimeout(res, 0));
          }
        }

        if (!resetDetected && targetUsername && peersNeedingSessionRefresh.current.has(targetUsername)) {
          resetDetected = true;
        }

        retryCause = resetDetected ? 'session-reset' : (transportFailed ? 'transport' : null);
        if (retryCause) {
          if (restartAttempt < MAX_RESTARTS) {
            await new Promise(r => setTimeout(r, 1000));
            continue;
          } else {
            break;
          }
        }

        try {
          if (state.inactivityTimer) {
            clearTimeout(state.inactivityTimer);
            state.inactivityTimer = undefined;
          }
        } catch { }
        setProgress(1);
        return true;

      } finally {
        window.removeEventListener(EventType.SESSION_RESET_RECEIVED, resetHandler as EventListener);
      }
    }

    return false;
  }, [computeChunkMacAsync, currentUsername, ensureSignalSession, scheduleInactivityTimer, targetUsername, takeToken, isTransferAuthorized]);

  const sendSingleChunk = useCallback(async (
    ctx: RetainedTransfer,
    chunkIndex: number,
    recipientUsername: string,
    envelope: unknown,
    recoveryProbe = false
  ): Promise<boolean> => {
    const isCurrentRetainedTransfer = () => (
      isTransferAuthorized(ctx.ownerUsername, ctx.ownerGeneration, recipientUsername) &&
      (
        retainedTransfersRef.current.get(ctx.fileId) === ctx ||
        activeRetransmitContextRef.current === ctx
      )
    );
    if (!isCurrentRetainedTransfer()) return false;
    const start = chunkIndex * ctx.chunkSize;
    const end = Math.min(start + ctx.chunkSize, ctx.file.size);
    const blobSlice = ctx.file.slice(start, end);
    const chunk = new Uint8Array(await blobSlice.arrayBuffer());
    if (!isCurrentRetainedTransfer()) {
      chunk.fill(0);
      return false;
    }
    let encryptedChunk;
    try {
      encryptedChunk = await CryptoUtils.Encrypt.encryptBinaryWithAES(chunk, ctx.aesKey);
    } finally {
      chunk.fill(0);
    }
    const { iv, authTag, encrypted } = encryptedChunk;
    try {
      if (!isCurrentRetainedTransfer()) return false;
      const chunkMac = await computeChunkMacAsync(
        iv, authTag, encrypted,
        ctx.macKey, chunkIndex, ctx.totalChunks, ctx.fileId, sanitizeFilename(ctx.fileName)
      );
      if (!isCurrentRetainedTransfer()) return false;

      const chunkMetadata = {
        type: SignalType.FILE_MESSAGE_CHUNK,
        from: currentUsername,
        to: recipientUsername,
        envelope,
        chunkIndex,
        totalChunks: ctx.totalChunks,
        filename: sanitizeFilename(ctx.fileName),
        isLastChunk: chunkIndex === ctx.totalChunks - 1,
        fileSize: ctx.fileSize,
        chunkSize: ctx.chunkSize,
        fileId: ctx.fileId,
        messageId: ctx.fileId,
        recoveryProbe,
        chunkMac
      };

      const chunkDataBase64 = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);
      const fullChunkMessage = {
        ...chunkMetadata,
        messageId: `${ctx.fileId}:chunk:${chunkIndex}`,
        fileTransferId: ctx.fileId,
        chunkData: chunkDataBase64
      };
      if (!isCurrentRetainedTransfer()) return false;
      const res = await unifiedSignalTransport.send(recipientUsername, fullChunkMessage, SignalType.FILE_MESSAGE_CHUNK);
      return isCurrentRetainedTransfer() && !!res?.success;
    } finally {
      iv.fill(0);
      authTag.fill(0);
      encrypted.fill(0);
    }
  }, [computeChunkMacAsync, currentUsername, isTransferAuthorized]);

  const scheduleRecoveryProbe = useCallback((
    ctx: RetainedTransfer,
    initialDelay = FILE_RECOVERY_PROBE_INITIAL_MS
  ): void => {
    const existing = recoveryProbeTimersRef.current.get(ctx.fileId);
    if (existing) clearTimeout(existing);
    recoveryProbeTimersRef.current.delete(ctx.fileId);

    const isLive = () => (
      !!ctx.userKeys[0] &&
      isTransferAuthorized(ctx.ownerUsername, ctx.ownerGeneration, ctx.userKeys[0].username) &&
      retainedTransfersRef.current.get(ctx.fileId) === ctx
    );
    const arm = (delay: number): void => {
      if (!isLive()) return;
      const timer = setTimeout(() => {
        recoveryProbeTimersRef.current.delete(ctx.fileId);
        void (async () => {
          const recipient = ctx.userKeys[0];
          if (!recipient || !isLive()) return;
          while (isLive() && !takeToken()) {
            await new Promise(resolve => setTimeout(resolve, RATE_LIMITER_SLEEP_MS));
          }
          if (!isLive()) return;
          try {
            await sendSingleChunk(ctx, 0, recipient.username, recipient.envelope, true);
          } catch { }
          if (isLive()) arm(Math.min(delay * 2, FILE_RECOVERY_PROBE_MAX_MS));
        })();
      }, delay);
      recoveryProbeTimersRef.current.set(ctx.fileId, timer);
    };
    arm(initialDelay);
  }, [isTransferAuthorized, sendSingleChunk, takeToken]);

  const handleRetransmit = useCallback(async (
    fileId: string,
    requester: string,
    missingIndices: number[]
  ): Promise<void> => {
    const ctx = retainedTransfersRef.current.get(fileId) || (
      activeRetransmitContextRef.current?.fileId === fileId
        ? activeRetransmitContextRef.current
        : undefined
    );
    if (!ctx) return;
    if (!isTransferAuthorized(ctx.ownerUsername, ctx.ownerGeneration, requester)) {
      releaseRetainedTransfer(fileId, ctx);
      return;
    }
    
    const envelope = ctx.userKeys.find(uk => uk.username === requester)?.envelope;
    if (!envelope) return;

    const probeTimer = recoveryProbeTimersRef.current.get(fileId);
    if (probeTimer) clearTimeout(probeTimer);
    recoveryProbeTimersRef.current.delete(fileId);

    // Throttle repeated requests for the same transfer from the same peer
    const rateKey = `${fileId}|${requester}`;
    const now = Date.now();
    if (retransmitInFlightRef.current.has(rateKey)) return;
    if (now - (retransmitRateRef.current.get(rateKey) || 0) < RETRANSMIT_MIN_INTERVAL_MS) return;
    retransmitRateRef.current.set(rateKey, now);
    retransmitInFlightRef.current.add(rateKey);

    try {
      const indices = Array.from(new Set(missingIndices))
        .filter(i => Number.isInteger(i) && i >= 0 && i < ctx.totalChunks)
        .slice(0, MAX_RETRANSMIT_CHUNKS_PER_REQUEST);

      for (const idx of indices) {
        while (!takeToken()) { await new Promise(r => setTimeout(r, RATE_LIMITER_SLEEP_MS)); }
        if (
          retainedTransfersRef.current.get(fileId) !== ctx &&
          activeRetransmitContextRef.current !== ctx
        ) return;
        try { await sendSingleChunk(ctx, idx, requester, envelope); } catch { }
      }
    } finally {
      retransmitInFlightRef.current.delete(rateKey);
      if (retainedTransfersRef.current.get(fileId) === ctx) {
        scheduleRecoveryProbe(ctx, FILE_RECOVERY_PROBE_MAX_MS);
      }
    }
  }, [sendSingleChunk, takeToken, isTransferAuthorized, releaseRetainedTransfer, scheduleRecoveryProbe]);

  // Listen for retransmit requests routed from the message handler
  useEffect(() => {
    const onRetransmit = (event: Event) => {
      const detail = exactEventDetail(event, ['account', 'fileId', 'from', 'missingIndices']);
      if (!detail) return;
      if (detail.account !== activeUsernameRef.current) return;
      const { from, fileId, missingIndices } = detail;
      if (
        typeof from === 'string' && AUTH_USERNAME_REGEX.test(from) &&
        typeof fileId === 'string' && sanitizeMessageId(fileId) === fileId &&
        Array.isArray(missingIndices)
      ) {
        void handleRetransmit(fileId, from, missingIndices);
      }
    };
    window.addEventListener(EventType.FILE_CHUNK_RETRANSMIT, onRetransmit as EventListener);
    return () => window.removeEventListener(EventType.FILE_CHUNK_RETRANSMIT, onRetransmit as EventListener);
  }, [handleRetransmit]);

  useEffect(() => {
    const onDelivered = (event: Event) => {
      const detail = exactEventDetail(event, ['account', 'from', 'messageId']);
      if (!detail) return;
      if (detail.account !== activeUsernameRef.current) return;
      const fileId = sanitizeMessageId(detail.messageId);
      const from = typeof detail.from === 'string' && AUTH_USERNAME_REGEX.test(detail.from)
        ? detail.from
        : '';
      if (!fileId || !from) return;
      const retained = retainedTransfersRef.current.get(fileId);
      if (retained) {
        if (
          isOwnedByActiveAccount(retained.ownerUsername, retained.ownerGeneration) &&
          retained.userKeys.some((entry) => entry.username === from)
        ) {
          releaseRetainedTransfer(fileId, retained);
        }
        return;
      }

      const active = currentTransferRef.current;
      if (
        active?.fileId === fileId &&
        isOwnedByActiveAccount(active.ownerUsername, active.ownerGeneration) &&
        active.recipientUsername === from
      ) {
        earlyDeliveredTransfersRef.current.clear();
        earlyDeliveredTransfersRef.current.add(fileId);
      }
    };
    window.addEventListener(EventType.MESSAGE_DELIVERED, onDelivered as EventListener);
    return () => window.removeEventListener(EventType.MESSAGE_DELIVERED, onDelivered as EventListener);
  }, [isOwnedByActiveAccount, releaseRetainedTransfer]);

  const retainTransfer = useCallback((ctx: RetainedTransfer): void => {
    const recipient = ctx.userKeys[0]?.username;
    if (!recipient || !isTransferAuthorized(ctx.ownerUsername, ctx.ownerGeneration, recipient)) {
      ctx.macKey.fill(0);
      return;
    }
    if (earlyDeliveredTransfersRef.current.delete(ctx.fileId)) {
      ctx.macKey.fill(0);
      return;
    }
    const now = Date.now();
    for (const [id, rt] of retainedTransfersRef.current) {
      if (now - rt.retainedAt > fileRecoveryRetentionMs(rt.totalChunks)) releaseRetainedTransfer(id, rt);
    }
    const retainedBytes = () => Array.from(retainedTransfersRef.current.values())
      .reduce((sum, retained) => sum + retained.fileSize, 0);
    while (
      retainedTransfersRef.current.size >= MAX_RETAINED_TRANSFERS ||
      retainedBytes() + ctx.fileSize > MAX_RETAINED_FILE_BYTES
    ) {
      const oldest = retainedTransfersRef.current.keys().next().value;
      if (oldest === undefined) break;
      releaseRetainedTransfer(oldest);
    }
    if (ctx.fileSize > MAX_RETAINED_FILE_BYTES) {
      ctx.macKey.fill(0);
      return;
    }
    releaseRetainedTransfer(ctx.fileId);
    ctx.retainedAt = now;
    retainedTransfersRef.current.set(ctx.fileId, ctx);
    const retentionMs = fileRecoveryRetentionMs(ctx.totalChunks);
    const timer = setTimeout(() => {
      releaseRetainedTransfer(ctx.fileId, ctx);
    }, retentionMs);
    retentionTimersRef.current.set(ctx.fileId, timer);
    scheduleRecoveryProbe(ctx);
  }, [isTransferAuthorized, releaseRetainedTransfer, scheduleRecoveryProbe]);

  // Send a file
  const sendFile = useCallback(async (rawFile: File): Promise<void> => {
    const ownerGeneration = accountGenerationRef.current;
    const ownerUsername = currentUsername;
    if (
      !targetUsername ||
      targetUsername !== targetUsername.trim().toLowerCase() ||
      !AUTH_USERNAME_REGEX.test(targetUsername) ||
      targetUsername === ownerUsername
    ) {
      throw new Error('No target username specified');
    }
    if (
      !ownerUsername ||
      ownerUsername !== ownerUsername.trim().toLowerCase() ||
      !AUTH_USERNAME_REGEX.test(ownerUsername) ||
      !isTransferAuthorized(ownerUsername, ownerGeneration, targetUsername)
    ) {
      throw new Error('Account changed before file send');
    }
    if (sendOperationRef.current) {
      throw new Error('A file transfer is already in progress');
    }
    const operation: FileSendOperation = { canceled: false };
    sendOperationRef.current = operation;
    let retransmitContext: RetainedTransfer | null = null;
    const isCurrent = () => (
      sendOperationRef.current === operation &&
      !operation.canceled &&
      isTransferAuthorized(ownerUsername, ownerGeneration, targetUsername)
    );

    try {
      setIsSendingFile(true);
      setFileSendPhase('preparing');
      setProgress(0);

      const recipientBlocked = await blockingSystem.isUserBlocked(targetUsername);
      if (!isCurrent()) throw new Error('File transfer canceled or account changed');
      if (recipientBlocked) throw new Error('recipient-blocked');
      if (!Number.isSafeInteger(rawFile.size) || rawFile.size <= 0 || rawFile.size > MAX_FILE_SIZE) {
        throw new Error('File size is outside the supported encrypted-transfer limit');
      }
      const file = await stripImageMetadata(rawFile);
      if (!isCurrent()) throw new Error('File transfer canceled or account changed');
      
      if (file.size === 0) {
        throw new Error('Cannot send an empty file');
      }
      if (!Number.isSafeInteger(file.size) || file.size > MAX_FILE_SIZE) {
        throw new Error('Metadata-safe file exceeds the encrypted-transfer limit');
      }
      currentFileRef.current = file;

      const chunkSize = file.size > LARGE_FILE_THRESHOLD ? DEFAULT_CHUNK_SIZE_LARGE : DEFAULT_CHUNK_SIZE_SMALL;
      const totalChunks = Math.ceil(file.size / chunkSize);
      const fileId = crypto.randomUUID();

      const safeName = sanitizeFilename(file.name || SignalType.FILE);
      const state: TransferState = {
        fileId,
        fileName: safeName,
        fileSize: file.size,
        chunkSize,
        totalChunks,
        lastSentIndex: -1,
        canceled: false,
        lastActivity: Date.now(),
        ownerUsername,
        ownerGeneration,
        recipientUsername: targetUsername
      };

      currentTransferRef.current = state;
      scheduleInactivityTimer(state);

      const rawAesBytes = crypto.getRandomValues(new Uint8Array(32));
      let aesKeyBase64 = '';
      let macKeyBase64 = '';
      try {
        const aesKey = await crypto.subtle.importKey(
          'raw',
          rawAesBytes,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
        if (!isCurrent()) throw new Error('Account changed during file key generation');
        currentAesKeyRef.current = aesKey;
        aesKeyBase64 = CryptoUtils.Base64.arrayBufferToBase64(rawAesBytes);

        const macInfo = new TextEncoder().encode(`ft:${safeName}:${file.size} `);
        try {
          currentMacKeyRef.current = await CryptoUtils.KDF.blake3Hkdf(
            rawAesBytes,
            MAC_SALT,
            macInfo,
            32
          );
        } finally {
          macInfo.fill(0);
        }
        if (!isCurrent()) throw new Error('Account changed during file key generation');
        macKeyBase64 = CryptoUtils.Base64.arrayBufferToBase64(currentMacKeyRef.current);
      } finally {
        rawAesBytes.fill(0);
      }

      let filteredUsers = users.filter((user) =>
        user.username === targetUsername &&
        user.username !== currentUsername &&
        validateHybridKeys(user.hybridPublicKeys) &&
        !!user.peerCertificateFingerprint &&
        !!user.identityRootFingerprint &&
        !!user.identityBundleFingerprint &&
        isKeyTransparencyAuthorizedPeerKeySet({
          account: currentUsername,
          peer: user.username,
          kyberPublicBase64: user.hybridPublicKeys!.kyberPublicBase64,
          dilithiumPublicBase64: user.hybridPublicKeys!.dilithiumPublicBase64!,
          x25519PublicBase64: user.hybridPublicKeys!.x25519PublicBase64!,
          peerCertificateFingerprint: user.peerCertificateFingerprint,
          identityRootFingerprint: user.identityRootFingerprint,
          identityBundleFingerprint: user.identityBundleFingerprint,
        })
      );

      // If recipient's keys not found, try to fetch them
      if (filteredUsers.length === 0 && getPeerHybridKeys && targetUsername) {
        try {
          const fetchedKeys = await getPeerHybridKeys(targetUsername);
          if (!isCurrent()) throw new Error('Account changed during recipient lookup');
          if (validateHybridKeys(fetchedKeys)) {
            filteredUsers = [{
              username: targetUsername,
              hybridPublicKeys: {
                x25519PublicBase64: fetchedKeys.x25519PublicBase64,
                kyberPublicBase64: fetchedKeys.kyberPublicBase64,
                dilithiumPublicBase64: fetchedKeys.dilithiumPublicBase64
              }
            }] as any;
          }
        } catch {
          console.error('[FILE-SENDER] Failed to fetch recipient keys');
        }
      }

      // Discovery fallback
      if (filteredUsers.length === 0 && findUser && targetUsername && shouldAttemptDiscovery(targetUsername)) {
        try {
          const material = await findUser(targetUsername);
          if (!isCurrent()) throw new Error('Account changed during recipient discovery');
          if (material) {
            const trusted = await resolveTrustedPeerHybridPublicKeys(currentUsername, targetUsername, material);
            const hk = trusted?.valid ? trusted.hybridKeys : null;
            if (validateHybridKeys(hk)) {
              filteredUsers = [{
                username: targetUsername,
                hybridPublicKeys: {
                  x25519PublicBase64: hk.x25519PublicBase64,
                  kyberPublicBase64: hk.kyberPublicBase64,
                  dilithiumPublicBase64: hk.dilithiumPublicBase64
                }
              }] as any;
            }
          }
        } catch {
          console.error('[FILE-SENDER] Discovery key resolution failed');
        }
      }

      if (filteredUsers.length === 0) {
        console.error('[FILE-SENDER] Missing recipient keys');
        throw new Error('Cannot send file: post-quantum hybrid encryption keys are required but not available');
      }

      if (!getKeysOnDemand) {
        console.error('[FILE-SENDER] getKeysOnDemand not provided');
        throw new Error('Encryption keys unavailable');
      }
      const localKeys = await getKeysOnDemand();
      if (!isCurrent()) throw new Error('Account changed during local key lookup');
      if (localKeys?.native !== true || !localKeys.dilithium?.publicKeyBase64) {
        console.error('[FILE-SENDER] Local Dilithium keys unavailable');
        throw new Error('Local Dilithium keys unavailable');
      }

      const sessionOk = await ensureSignalSession();
      if (!isCurrent()) throw new Error('Account changed during session setup');
      if (!sessionOk) {
        console.error('[FILE-SENDER] No Signal session with recipient');
        throw new Error('Secure session not established with recipient');
      }

      let userKeys: readonly UserKeyEnvelope[];
      try {
        userKeys = await Promise.all(
          filteredUsers.map(async (user): Promise<UserKeyEnvelope> => {
            const envelope = await CryptoUtils.Hybrid.encryptForClient(
              { aesKey: aesKeyBase64, macKey: macKeyBase64 },
              {
                kyberPublicBase64: user.hybridPublicKeys!.kyberPublicBase64,
                x25519PublicBase64: user.hybridPublicKeys!.x25519PublicBase64!,
                dilithiumPublicBase64: user.hybridPublicKeys!.dilithiumPublicBase64
              },
              {
                to: user.hybridPublicKeys!.dilithiumPublicBase64,
                from: localKeys.dilithium.publicKeyBase64,
                type: SignalType.FILE_MESSAGE_CHUNK,
                senderDilithiumPublicKey: localKeys.dilithium.publicKeyBase64
                ,signRoutingHeader: (canonicalHeader) =>
                  account.sign(PROTOCOL_KEYS.DEVICE_ENVELOPE_SIGNING, canonicalHeader)
              }
            );
            return { username: user.username, envelope };
          })
        );
      } finally {
        aesKeyBase64 = '';
        macKeyBase64 = '';
      }
      if (!isCurrent()) throw new Error('Account changed during key-envelope encryption');

      const localMessage = {
        id: fileId,
        content: '',
        sender: currentUsername,
        recipient: targetUsername,
        timestamp: Date.now(),
        filename: safeName,
        fileSize: file.size,
        mimeType: file.type || 'application/octet-stream',
        type: SignalType.FILE,
        isCurrentUser: true,
        isDeliberateUserAction: true as const,
        receipt: {
          delivered: false,
          read: false
        }
      };

      if (!secureDB || typeof secureDB.storeFileMessage !== 'function') {
        throw new Error('Secure file storage is unavailable');
      }
      const saveResult = await secureDB.storeFileMessage(
        { ...localMessage, timestamp: localMessage.timestamp },
        file,
        targetUsername,
      );
      if (!isCurrent()) throw new Error('Account changed during local file persistence');
      if (!saveResult?.success || saveResult?.duplicate) {
        throw new Error(saveResult?.quotaExceeded
          ? 'Cannot send file: encrypted local storage is full'
          : saveResult?.duplicate
            ? 'Cannot send file: local file identifier collision'
          : 'Cannot send file: failed to save encrypted local copy');
      }

      window.dispatchEvent(new CustomEvent(EventType.LOCAL_FILE_MESSAGE, {
        detail: { ...localMessage, account: currentUsername }
      }));

      retransmitContext = {
        fileId,
        file,
        aesKey: currentAesKeyRef.current!,
        macKey: currentMacKeyRef.current!.slice(),
        userKeys,
        totalChunks,
        chunkSize,
        fileName: safeName,
        fileSize: file.size,
        retainedAt: 0,
        ownerUsername,
        ownerGeneration
      };
      activeRetransmitContextRef.current = retransmitContext;

      setFileSendPhase('sending');
      setProgress(0);
      const delivered = await sendChunks(state, userKeys);
      if (!isCurrent()) throw new Error('Account changed during file transfer');
      if (!delivered && !state.canceled) {
        throw new Error('File transfer failed: chunks could not be delivered');
      }

      if (delivered && retransmitContext) {
        activeRetransmitContextRef.current = null;
        retainTransfer(retransmitContext);
        retransmitContext = null;
      }

    } catch (error) {
      console.error('[FILE-SENDER] Send failed', { error: (error as Error)?.message });
      setProgress(0);
      throw error;
    } finally {
      try {
        const st = currentTransferRef.current;
        if (st?.inactivityTimer) clearTimeout(st.inactivityTimer);
      } catch { }
      currentTransferRef.current = null;
      currentFileRef.current = null;
      currentAesKeyRef.current = null;
      if (retransmitContext) {
        if (activeRetransmitContextRef.current === retransmitContext) {
          activeRetransmitContextRef.current = null;
        }
        retransmitContext.macKey.fill(0);
      }
      currentMacKeyRef.current?.fill(0);
      currentMacKeyRef.current = null;
      sendOperationRef.current = null;
      setFileSendPhase('idle');
      setIsSendingFile(false);
    }
  }, [
    targetUsername,
    currentUsername,
    users,
    getKeysOnDemand,
    getPeerHybridKeys,
    findUser,
    secureDB,
    retainTransfer,
    scheduleInactivityTimer,
    sendChunks,
    isTransferAuthorized,
  ]);

  // Cancel current file transfer and cleanup resources
  const cancelCurrent = useCallback((): void => {
    const operation = sendOperationRef.current;
    if (operation) operation.canceled = true;
    const st = currentTransferRef.current;
    const activeRetransmit = activeRetransmitContextRef.current;
    if (activeRetransmit && (!st || activeRetransmit.fileId === st.fileId)) {
      activeRetransmitContextRef.current = null;
      activeRetransmit.macKey.fill(0);
    }
    if (st) {
      st.canceled = true;
      if (st.inactivityTimer) clearTimeout(st.inactivityTimer);
      currentTransferRef.current = null;
      currentFileRef.current = null;
      currentAesKeyRef.current = null;
      currentMacKeyRef.current?.fill(0);
      currentMacKeyRef.current = null;
      releaseRetainedTransfer(st.fileId);
    }
    if (operation || st) {
      setFileSendPhase('idle');
      setIsSendingFile(false);
      setProgress(0);
    }
  }, [releaseRetainedTransfer]);

  useEffect(() => {
    const clearPeerTransfers = (peer: string): void => {
      if (targetUsername === peer || currentTransferRef.current?.recipientUsername === peer) {
        cancelCurrent();
      }
      sessionEstablishedAt.current.delete(peer);
      peersNeedingSessionRefresh.current.delete(peer);
      for (const [fileId, retained] of retainedTransfersRef.current) {
        if (!retained.userKeys.some((entry) => entry.username === peer)) continue;
        if (activeRetransmitContextRef.current === retained) {
          activeRetransmitContextRef.current = null;
        }
        releaseRetainedTransfer(fileId, retained);
      }
    };
    const handleUserBlocked = (event: Event): void => {
      const detail = exactEventDetail(event, ['username']);
      const peer = detail?.username;
      if (
        typeof peer !== 'string' ||
        peer !== peer.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(peer)
      ) return;

      clearPeerTransfers(peer);
    };
    const handleTransparencyRootChanged = (event: Event): void => {
      const detail = exactEventDetail(event, ['account', 'peer', 'rootCommitment', 'version']);
      const peer = detail?.peer;
      const account = detail?.account;
      if (
        account !== activeUsernameRef.current ||
        typeof account !== 'string' ||
        typeof peer !== 'string' ||
        peer !== peer.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(peer) ||
        !isKeyTransparencyPeerRevoked(account, peer)
      ) return;
      clearPeerTransfers(peer);
    };

    window.addEventListener(EventType.USER_BLOCKED, handleUserBlocked);
    window.addEventListener(EventType.KEY_TRANSPARENCY_ROOT_CHANGED, handleTransparencyRootChanged);
    return () => {
      window.removeEventListener(EventType.USER_BLOCKED, handleUserBlocked);
      window.removeEventListener(EventType.KEY_TRANSPARENCY_ROOT_CHANGED, handleTransparencyRootChanged);
    };
  }, [cancelCurrent, releaseRetainedTransfer, targetUsername]);

  useEffect(() => {
    const onBeforeUnload = () => {
      try { if (currentTransferRef.current) cancelCurrent(); } catch { }
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [cancelCurrent]);

  useLayoutEffect(() => {
    if (activeUsernameRef.current === currentUsername) return;
    accountGenerationRef.current += 1;
    activeUsernameRef.current = currentUsername;
    cancelCurrent();
    currentMacKeyRef.current?.fill(0);
    currentMacKeyRef.current = null;
    clearRetainedTransfers();
    sessionEstablishedAt.current.clear();
    peersNeedingSessionRefresh.current.clear();
    rateTokensRef.current = MAX_CHUNKS_PER_SECOND;
    lastRefillRef.current = Date.now();
  }, [currentUsername, cancelCurrent, clearRetainedTransfers]);

  useEffect(() => () => {
    accountGenerationRef.current += 1;
    cancelCurrent();
    currentMacKeyRef.current?.fill(0);
    currentMacKeyRef.current = null;
    clearRetainedTransfers();
  }, [cancelCurrent, clearRetainedTransfers]);

  return { sendFile, progress, isSendingFile, fileSendPhase, cancelCurrent };
}
