import { useRef, useState, useCallback, useEffect } from "react";
import * as pako from "pako";
import { CryptoUtils } from "../../../lib/unified-crypto";
import websocketClient from "../../../lib/websocket";
import { SignalType } from "../../../lib/signal-types";
import { EventType } from "../../../lib/event-types";
import { sanitizeFilename } from "../../../lib/sanitizers";
import { syncEncryptedStorage } from "../../../lib/encrypted-storage";

const DEFAULT_CHUNK_SIZE_SMALL = 192 * 1024;
const DEFAULT_CHUNK_SIZE_LARGE = 384 * 1024;
const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024;
const MAX_CHUNKS_PER_SECOND = 50;
const INACTIVITY_TIMEOUT_MS = 120000;
const P2P_CONNECT_TIMEOUT_MS = 3500;
const RATE_LIMITER_SLEEP_MS = 10;
const PAUSE_POLL_MS = 100;
const P2P_POLL_MS = 100;
const YIELD_INTERVAL = 8;
const MAC_SALT = new TextEncoder().encode('ft-mac-salt-v1');
const TOR_ENABLED_KEY = 'tor_enabled';

interface HybridPublicKeys {
  readonly x25519PublicBase64?: string;
  readonly kyberPublicBase64: string;
  readonly dilithiumPublicBase64?: string;
}

interface User {
  readonly username: string;
  readonly isOnline?: boolean;
  readonly hybridPublicKeys?: HybridPublicKeys;
}

interface TransferState {
  readonly fileId: string;
  readonly fileName: string;
  readonly fileSize: number;
  readonly chunkSize: number;
  readonly totalChunks: number;
  lastSentIndex: number;
  lastAckedIndex: number;
  paused: boolean;
  canceled: boolean;
  readonly startedAt: number;
  lastActivity: number;
  inactivityTimer?: NodeJS.Timeout;
}

interface P2PConnector {
  readonly connectToPeer?: (peer: string) => Promise<void>;
  readonly getConnectedPeers?: () => readonly string[];
}

interface LocalKeys {
  readonly dilithium: {
    readonly secretKey: Uint8Array;
    readonly publicKeyBase64: string;
  };
}

interface UserKeyEnvelope {
  readonly username: string;
  readonly envelope: unknown;
}

interface EncryptedMetadataResult {
  readonly success: boolean;
  readonly encryptedPayload?: Record<string, unknown>;
  readonly error?: string;
}

export function useFileSender(
  currentUsername: string,
  targetUsername: string | undefined,
  users: readonly User[],
  p2pConnector?: P2PConnector,
  getKeysOnDemand?: () => Promise<LocalKeys>,
  getPeerHybridKeys?: (peerUsername: string) => Promise<HybridPublicKeys | null>
) {
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);

  const currentTransferRef = useRef<TransferState | null>(null);
  const currentRawBytesRef = useRef<Uint8Array | null>(null);
  const currentAesKeyRef = useRef<CryptoKey | null>(null);
  const currentMacKeyRef = useRef<Uint8Array | null>(null);
  const rateTokensRef = useRef<number>(MAX_CHUNKS_PER_SECOND);
  const lastRefillRef = useRef<number>(Date.now());

  const SESSION_WAIT_MS = 12_000;
  const SESSION_POLL_BASE_MS = 200;
  const SESSION_POLL_MAX_MS = 1_500;
  const BUNDLE_REQUEST_COOLDOWN_MS = 5000;
  const SESSION_FRESH_COOLDOWN_MS = 10_000;

  const bundleRequestTracker = useRef<Map<string, number>>(new Map());
  const sessionEstablishedAt = useRef<Map<string, number>>(new Map());
  const peersNeedingSessionRefresh = useRef<Set<string>>(new Set());

  // Listen for session reset events
  useEffect(() => {
    const handleSessionReset = (event: Event) => {
      try {
        const detail = (event as CustomEvent).detail || {};
        const peerUsername = detail.peerUsername || detail.peer || detail.from;
        if (typeof peerUsername === 'string' && peerUsername) {
          peersNeedingSessionRefresh.current.add(peerUsername);
          sessionEstablishedAt.current.delete(peerUsername);
        }
      } catch { }
    };

    const handleSessionEstablished = (event: Event) => {
      try {
        const detail = (event as CustomEvent).detail || {};
        const peerUsername = detail.peer || detail.peerUsername || detail.fromPeer;
        if (typeof peerUsername === 'string' && peerUsername) {
          peersNeedingSessionRefresh.current.delete(peerUsername);
          sessionEstablishedAt.current.set(peerUsername, Date.now());
        }
      } catch { }
    };

    window.addEventListener('session-reset-received', handleSessionReset as EventListener);
    window.addEventListener('libsignal-session-ready', handleSessionEstablished as EventListener);
    window.addEventListener('session-established-received', handleSessionEstablished as EventListener);

    return () => {
      window.removeEventListener('session-reset-received', handleSessionReset as EventListener);
      window.removeEventListener('libsignal-session-ready', handleSessionEstablished as EventListener);
      window.removeEventListener('session-established-received', handleSessionEstablished as EventListener);
    };
  }, []);

  const refillTokens = useCallback((): void => {
    const now = Date.now();
    const elapsed = (now - lastRefillRef.current) / 1000;
    if (elapsed > 0) {
      const refill = elapsed * MAX_CHUNKS_PER_SECOND;
      rateTokensRef.current = Math.min(MAX_CHUNKS_PER_SECOND, rateTokensRef.current + refill);
      lastRefillRef.current = now;
    }
  }, []);

  const takeToken = useCallback((): boolean => {
    refillTokens();
    if (rateTokensRef.current >= 1) {
      rateTokensRef.current -= 1;
      return true;
    }
    return false;
  }, [refillTokens]);

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
    // Extended MAC binds metadata to the chunk: iv||authTag||encrypted||idx||total||messageId||filename
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

    const macBytes = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
    return CryptoUtils.Base64.arrayBufferToBase64(macBytes);
  }, []);

  const scheduleInactivityTimer = useCallback((state: TransferState): void => {
    if (state.inactivityTimer) clearTimeout(state.inactivityTimer);
    state.inactivityTimer = setTimeout(() => {
      if (currentTransferRef.current && currentTransferRef.current.fileId === state.fileId) {
        cancelCurrent();
      }
    }, INACTIVITY_TIMEOUT_MS);
  }, []);

  const isTorEnabled = useCallback((): boolean => {
    try {
      const flag = syncEncryptedStorage.getItem(TOR_ENABLED_KEY);
      if (typeof flag === 'string') return flag !== 'false';
    } catch { }
    return true;
  }, []);

  const isRecipientOnline = useCallback((): boolean => {
    if (!targetUsername) return false;
    const u = users.find(u => u.username === targetUsername);
    return !!u?.isOnline;
  }, [users, targetUsername]);

  const attemptP2P = useCallback(async (): Promise<boolean> => {
    try {
      if (!p2pConnector?.connectToPeer || !p2pConnector?.getConnectedPeers || !targetUsername) {
        return false;
      }

      let opened = false;
      const timer = new Promise<boolean>(resolve => setTimeout(() => resolve(false), P2P_CONNECT_TIMEOUT_MS));
      const attempt = (async () => {
        try {
          await p2pConnector.connectToPeer(targetUsername);
          const t0 = Date.now();
          while (Date.now() - t0 < P2P_CONNECT_TIMEOUT_MS) {
            const peers = p2pConnector.getConnectedPeers();
            if (Array.isArray(peers) && peers.includes(targetUsername)) {
              opened = true;
              break;
            }
            await new Promise(res => setTimeout(res, P2P_POLL_MS));
          }
        } catch { }
        return opened;
      })();

      const res = await Promise.race([timer, attempt]);
      return !!res;
    } catch {
      return false;
    }
  }, [p2pConnector, targetUsername]);

  const ensureWsReady = useCallback(async (): Promise<void> => {
    try {
      if (!websocketClient.isConnectedToServer()) {
        await websocketClient.connect();
      }
    } catch {
    }
  }, []);

  const getSessionApi = useCallback(() => {
    const edgeApi = (globalThis as any)?.edgeApi ?? null;
    return {
      async hasSession(args: { selfUsername: string; peerUsername: string; deviceId: number }) {
        if (typeof edgeApi?.hasSession !== 'function') {
          return { hasSession: false };
        }
        try {
          const promise = edgeApi.hasSession(args);
          const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000));
          return await Promise.race([promise, timeout]) as any;
        } catch {
          return { hasSession: false };
        }
      },
    };
  }, []);

  const ensureSignalSession = useCallback(async (forceReestablish: boolean = false): Promise<boolean> => {
    try {
      if (!targetUsername || !getKeysOnDemand) return false;

      const sessionApi = getSessionApi();
      const edgeApi: any = (window as any).edgeApi;
      const needsRefresh = forceReestablish || peersNeedingSessionRefresh.current.has(targetUsername);

      const initial = await sessionApi.hasSession({
        selfUsername: currentUsername,
        peerUsername: targetUsername,
        deviceId: 1,
      });

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

      // If session needs refresh and is stale, delete it
      if (needsRefresh && initial?.hasSession && !sessionIsFresh) {
        try {
          const deletePromise = edgeApi?.deleteSession?.({
            selfUsername: currentUsername,
            peerUsername: targetUsername,
            deviceId: 1
          });
          if (deletePromise) {
            const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000));
            await Promise.race([deletePromise, timeout]);
          }
          peersNeedingSessionRefresh.current.delete(targetUsername);
        } catch (e) {
          console.warn('[FILE-SENDER] Failed to delete stale session:', e);
        }
      }

      const deadline = Date.now() + SESSION_WAIT_MS;
      let delay = SESSION_POLL_BASE_MS;
      const MAX_REQUESTS = 2;
      let requestCount = 0;

      let sessionReadyFlag = false;
      const readyHandler = (event: Event) => {
        const customEvent = event as CustomEvent;
        const detail = customEvent.detail || {};
        if (detail.peer === targetUsername || detail.peerUsername === targetUsername) {
          sessionReadyFlag = true;
        }
      };
      window.addEventListener('libsignal-session-ready', readyHandler as EventListener);

      try {
        let lastRequestAt = 0;

        const firstCheck = await sessionApi.hasSession({
          selfUsername: currentUsername,
          peerUsername: targetUsername,
          deviceId: 1,
        });
        if (firstCheck?.hasSession) {
          sessionEstablishedAt.current.set(targetUsername, Date.now());
          return true;
        }

        while (Date.now() < deadline) {
          const nowTs = Date.now();
          const lastBundleRequest = bundleRequestTracker.current.get(targetUsername) || 0;
          const canRequestBundle = (nowTs - lastBundleRequest) >= BUNDLE_REQUEST_COOLDOWN_MS;

          if (canRequestBundle) {
            try {
              const keys = await getKeysOnDemand();
              if (keys?.dilithium?.secretKey && keys?.dilithium?.publicKeyBase64) {
                requestCount++;
                const requestBase = {
                  type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                  username: targetUsername,
                  from: currentUsername,
                  timestamp: nowTs,
                  challenge: CryptoUtils.Base64.arrayBufferToBase64(
                    globalThis.crypto.getRandomValues(new Uint8Array(32)),
                  ),
                  senderDilithium: keys.dilithium.publicKeyBase64,
                  reason: 'file-transfer',
                } as const;
                const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
                const signatureRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
                const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureRaw);
                await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
                lastRequestAt = nowTs;
                bundleRequestTracker.current.set(targetUsername, nowTs);
              }
            } catch (e) {
              console.error('[FILE-SENDER] Failed to send initial bundle request:', e);
            }
          }

          while (Date.now() < deadline) {
            await new Promise((r) => setTimeout(r, delay));

            if (sessionReadyFlag) {
              sessionEstablishedAt.current.set(targetUsername, Date.now());
              return true;
            }

            const check = await sessionApi.hasSession({
              selfUsername: currentUsername,
              peerUsername: targetUsername,
              deviceId: 1,
            });
            if (check?.hasSession) {
              sessionEstablishedAt.current.set(targetUsername, Date.now());
              return true;
            }

            if (requestCount < MAX_REQUESTS && Date.now() - lastRequestAt >= 3000) {
              const nowTs = Date.now();
              const lastBundleRequest = bundleRequestTracker.current.get(targetUsername) || 0;
              const canRetryBundle = (nowTs - lastBundleRequest) >= BUNDLE_REQUEST_COOLDOWN_MS;

              if (canRetryBundle) {
                try {
                  const keys = await getKeysOnDemand();
                  if (keys?.dilithium?.secretKey && keys?.dilithium?.publicKeyBase64) {
                    requestCount++;
                    const requestBase = {
                      type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                      username: targetUsername,
                      from: currentUsername,
                      timestamp: nowTs,
                      challenge: CryptoUtils.Base64.arrayBufferToBase64(
                        globalThis.crypto.getRandomValues(new Uint8Array(32)),
                      ),
                      senderDilithium: keys.dilithium.publicKeyBase64,
                      reason: 'file-transfer-retry',
                    } as const;
                    const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
                    const signatureRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
                    const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureRaw);
                    await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
                    lastRequestAt = nowTs;
                    bundleRequestTracker.current.set(targetUsername, nowTs);
                  }
                } catch (e) {
                  console.error('[FILE-SENDER] Failed to send retry bundle request:', e);
                }
              }
            }

            const randomSource = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 0xffffffff;
            const poisson = -Math.log(Math.max(1 - randomSource, 1e-6));
            delay = Math.min(delay + poisson * SESSION_POLL_BASE_MS, SESSION_POLL_MAX_MS);
          }
        }
      } finally {
        try { window.removeEventListener('libsignal-session-ready', readyHandler as EventListener); } catch { }
      }
      return false;
    } catch {
      return false;
    }
  }, [getKeysOnDemand, targetUsername, currentUsername]);

  const sendChunksServer = useCallback(async (
    state: TransferState,
    userKeys: readonly UserKeyEnvelope[]
  ): Promise<void> => {
    const rawBytes = currentRawBytesRef.current!;
    const aesKey = currentAesKeyRef.current!;
    const macKey = currentMacKeyRef.current!;

    const totalChunks = state.totalChunks;
    const chunkSize = state.chunkSize;
    const MAX_RESTARTS = 2;

    for (let restartAttempt = 0; restartAttempt <= MAX_RESTARTS; restartAttempt++) {
      let resetDetected = false;
      const resetHandler = (event: Event) => {
        try {
          const detail = (event as CustomEvent).detail || {};
          const peer = detail.peer || detail.peerUsername || detail.from;
          const target = userKeys[0]?.username;
          if (peer === target) {
            resetDetected = true;
          }
        } catch { }
      };
      window.addEventListener('session-reset-received', resetHandler as EventListener);

      try {
        const hasPendingReset = targetUsername && peersNeedingSessionRefresh.current.has(targetUsername);
        if (restartAttempt > 0 || hasPendingReset) {
          if (restartAttempt > 0) {
            state.lastSentIndex = -1;
            await ensureSignalSession(true);
          } else {
            await ensureSignalSession(false);
          }
        }

        while (state.lastSentIndex < totalChunks - 1) {
          if (resetDetected || (targetUsername && peersNeedingSessionRefresh.current.has(targetUsername))) {
            resetDetected = true;
            break;
          }

          if (state.canceled) {
            return;
          }
          if (state.paused) {
            await new Promise(res => setTimeout(res, PAUSE_POLL_MS));
            continue;
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
          const end = Math.min(start + chunkSize, rawBytes.length);
          const chunk = rawBytes.slice(start, end);
          const compressedChunk = pako.deflate(chunk);

          const { iv, authTag, encrypted } = await CryptoUtils.Encrypt.encryptBinaryWithAES(
            compressedChunk,
            aesKey
          );

          const chunkMac = await computeChunkMacAsync(
            new Uint8Array(iv),
            new Uint8Array(authTag),
            new Uint8Array(encrypted),
            macKey,
            nextIndex,
            totalChunks,
            state.fileId,
            state.fileName
          );

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
              chunkMac
            };

            const recipient = users.find(u => u.username === uk.username);
            if (!recipient?.hybridPublicKeys) {
              continue;
            }

            let encryptedMetadata: EncryptedMetadataResult | null = null;
            const attemptEncrypt = async (): Promise<EncryptedMetadataResult | null> => {
              const ENCRYPTION_TIMEOUT_MS = 15000;
              const encryptPromise = (window as any).edgeApi.encrypt({
                fromUsername: currentUsername,
                toUsername: uk.username,
                plaintext: JSON.stringify(chunkMetadata),
                recipientKyberPublicKey: recipient.hybridPublicKeys.kyberPublicBase64,
                recipientHybridKeys: recipient.hybridPublicKeys
              }) as Promise<EncryptedMetadataResult>;

              const timeoutPromise = new Promise<EncryptedMetadataResult>((_, reject) => {
                setTimeout(() => reject(new Error('Encryption timed out')), ENCRYPTION_TIMEOUT_MS);
              });

              return await Promise.race([encryptPromise, timeoutPromise]);
            };
            try {
              encryptedMetadata = await attemptEncrypt();
            } catch (e) {
              console.error('[FILE-SENDER] Metadata encryption error', { index: nextIndex, user: uk.username, error: (e as Error)?.message });
              encryptedMetadata = { success: false, error: (e as Error)?.message } as any;
            }

            if (!encryptedMetadata?.success || !encryptedMetadata?.encryptedPayload) {
              // Retry up to 2 times after re-establishing session
              const maxRetries = 2;
              for (let attempt = 0; attempt < maxRetries && (!encryptedMetadata?.success || !encryptedMetadata?.encryptedPayload); attempt++) {
                const errText = String((encryptedMetadata as any)?.error || '');
                const sessionLikely = /session|whisper|no valid sessions|invalid whisper message|decryption failed|timed out/i.test(errText);
                const hasPendingReset = peersNeedingSessionRefresh.current.has(uk.username);

                if (!sessionLikely && !hasPendingReset) break;

                const ok = await ensureSignalSession(true);
                if (ok) {
                  try { encryptedMetadata = await attemptEncrypt(); } catch (e) {
                    encryptedMetadata = { success: false, error: (e as Error)?.message } as any;
                  }
                } else {
                  break;
                }
              }
            }

            if (!encryptedMetadata?.success || !encryptedMetadata?.encryptedPayload) {
              resetDetected = true;
              break;
            }

            const chunkDataBase64 = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);

            const fullChunkMessage = {
              type: SignalType.ENCRYPTED_MESSAGE,
              to: uk.username,
              encryptedPayload: {
                ...encryptedMetadata.encryptedPayload,
                chunkData: chunkDataBase64
              }
            };

            websocketClient.send(JSON.stringify(fullChunkMessage));
          }

          state.lastSentIndex = nextIndex;
          state.lastActivity = Date.now();
          scheduleInactivityTimer(state);

          const pct = (state.lastSentIndex + 1) / totalChunks;
          setProgress(pct);

          if ((nextIndex & (YIELD_INTERVAL - 1)) === 0) {
            await new Promise(res => setTimeout(res, 0));
          }
        }

        if (!resetDetected && targetUsername && peersNeedingSessionRefresh.current.has(targetUsername)) {
          resetDetected = true;
        }

        if (resetDetected) {
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
        return;

      } finally {
        window.removeEventListener('session-reset-received', resetHandler as EventListener);
      }
    }
  }, [computeChunkMacAsync, currentUsername, scheduleInactivityTimer, users]);

  const sendFile = useCallback(async (file: File): Promise<void> => {
    if (!targetUsername) {
      throw new Error('No target username specified');
    }

    await ensureWsReady();

    const torEnabled = isTorEnabled();
    const online = isRecipientOnline();

    setIsSendingFile(true);
    setProgress(0);

    try {
      const rawBytes = new Uint8Array(await file.arrayBuffer());
      currentRawBytesRef.current = rawBytes;

      const chunkSize = file.size > LARGE_FILE_THRESHOLD ? DEFAULT_CHUNK_SIZE_LARGE : DEFAULT_CHUNK_SIZE_SMALL;
      const totalChunks = Math.ceil(rawBytes.length / chunkSize);
      const fileId = crypto.randomUUID();

      const safeName = sanitizeFilename(file.name || 'file');
      const state: TransferState = {
        fileId,
        fileName: safeName,
        fileSize: file.size,
        chunkSize,
        totalChunks,
        lastSentIndex: -1,
        lastAckedIndex: -1,
        paused: false,
        canceled: false,
        startedAt: Date.now(),
        lastActivity: Date.now()
      };

      currentTransferRef.current = state;
      scheduleInactivityTimer(state);

      // Generate raw symmetric key bytes
      const rawAesBytes = crypto.getRandomValues(new Uint8Array(32));
      const aesKey = await CryptoUtils.Keys.importRawAesKey(rawAesBytes);
      currentAesKeyRef.current = aesKey;
      const aesKeyBase64 = CryptoUtils.Base64.arrayBufferToBase64(rawAesBytes);

      const macInfo = new TextEncoder().encode(`ft:${safeName}:${file.size}`);
      currentMacKeyRef.current = await CryptoUtils.KDF.blake3Hkdf(
        rawAesBytes,
        MAC_SALT,
        macInfo,
        32
      );
      const macKeyBase64 = CryptoUtils.Base64.arrayBufferToBase64(currentMacKeyRef.current);
      try { rawAesBytes.fill(0); } catch { }

      let filteredUsers = users.filter((user) =>
        user.username === targetUsername &&
        user.username !== currentUsername &&
        user.hybridPublicKeys
      );

      // If recipient's keys not found, try to fetch them on-demand
      if (filteredUsers.length === 0 && getPeerHybridKeys && targetUsername) {
        try {
          const fetchedKeys = await getPeerHybridKeys(targetUsername);
          if (fetchedKeys && fetchedKeys.kyberPublicBase64 && fetchedKeys.dilithiumPublicBase64) {
            filteredUsers = [{
              username: targetUsername,
              hybridPublicKeys: {
                x25519PublicBase64: fetchedKeys.x25519PublicBase64 || '',
                kyberPublicBase64: fetchedKeys.kyberPublicBase64,
                dilithiumPublicBase64: fetchedKeys.dilithiumPublicBase64
              }
            }] as any;
          }
        } catch (fetchError) {
          console.error('[FILE-SENDER] Failed to fetch recipient keys:', fetchError);
        }
      }

      if (filteredUsers.length === 0) {
        console.error('[FILE-SENDER] Missing recipient keys', { to: targetUsername });
        throw new Error(
          `Cannot send file: Post-quantum hybrid encryption keys are required but not available for ${targetUsername}`
        );
      }

      if (!getKeysOnDemand) {
        console.error('[FILE-SENDER] getKeysOnDemand not provided');
        throw new Error('Encryption keys unavailable');
      }
      const localKeys = await getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
        console.error('[FILE-SENDER] Local Dilithium keys unavailable');
        throw new Error('Local Dilithium keys unavailable');
      }

      // Ensure libsignal session before encrypting metadata/chunks
      const sessionOk = await ensureSignalSession();
      if (!sessionOk) {
        console.error('[FILE-SENDER] No Signal session with recipient');
        throw new Error('Secure session not established with recipient');
      }

      const userKeys: readonly UserKeyEnvelope[] = await Promise.all(
        filteredUsers.map(async (user): Promise<UserKeyEnvelope> => {
          const envelope = await CryptoUtils.Hybrid.encryptForClient(
            { aesKey: aesKeyBase64, macKey: macKeyBase64 },
            user.hybridPublicKeys!,
            {
              to: user.username,
              from: currentUsername,
              type: SignalType.FILE_MESSAGE_CHUNK,
              context: 'file-transfer:aes-key',
              senderDilithiumSecretKey: localKeys.dilithium.secretKey,
              senderDilithiumPublicKey: localKeys.dilithium.publicKeyBase64
            }
          );
          return { username: user.username, envelope };
        })
      );

      if (!torEnabled && online) {
        try { await attemptP2P(); } catch { }
      }

      const fileBlob = new Blob([rawBytes], { type: file.type || 'application/octet-stream' });
      const blobUrl = URL.createObjectURL(fileBlob);
      const fileBase64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const result = reader.result as string;
          const commaIndex = result.indexOf(',');
          const payload = commaIndex >= 0 ? result.substring(commaIndex + 1) : result;
          resolve(payload);
        };
        reader.onerror = () => reject(reader.error);
        reader.readAsDataURL(fileBlob);
      });

      const localMessage = {
        id: fileId,
        content: blobUrl,
        sender: currentUsername,
        recipient: targetUsername,
        timestamp: Date.now(),
        filename: safeName,
        fileSize: file.size,
        mimeType: file.type || 'application/octet-stream',
        originalBase64Data: fileBase64,
        type: 'file',
        isCurrentUser: true,
        receipt: {
          delivered: false,
          read: false
        }
      };

      window.dispatchEvent(new CustomEvent(EventType.LOCAL_FILE_MESSAGE, { detail: localMessage }));

      await sendChunksServer(state, userKeys);

      try {
        const st = currentTransferRef.current;
        if (st?.inactivityTimer) {
          clearTimeout(st.inactivityTimer);
        }
      } catch { }
      currentTransferRef.current = null;
      currentRawBytesRef.current = null;
      currentAesKeyRef.current = null;
      currentMacKeyRef.current = null;

      setIsSendingFile(false);
    } catch (error) {
      console.error('[FILE-SENDER] Send failed', { error: (error as Error)?.message });
      setProgress(0);
      setIsSendingFile(false);
      throw error;
    }
  }, [
    targetUsername,
    isTorEnabled,
    isRecipientOnline,
    currentUsername,
    users,
    getKeysOnDemand,
    attemptP2P,
    scheduleInactivityTimer,
    sendChunksServer
  ]);

  const pauseCurrent = useCallback((): void => {
    const st = currentTransferRef.current;
    if (st) {
      st.paused = true;
    }
  }, []);

  const resumeCurrent = useCallback((): void => {
    const st = currentTransferRef.current;
    if (st) {
      st.paused = false;
      st.lastActivity = Date.now();
      scheduleInactivityTimer(st);
    }
  }, [scheduleInactivityTimer]);

  const cancelCurrent = useCallback((): void => {
    const st = currentTransferRef.current;
    if (st) {
      st.canceled = true;
      if (st.inactivityTimer) clearTimeout(st.inactivityTimer);
      currentTransferRef.current = null;
      currentRawBytesRef.current = null;
      currentAesKeyRef.current = null;
      currentMacKeyRef.current = null;
      setIsSendingFile(false);
    }
  }, []);

  return { sendFile, progress, isSendingFile, pauseCurrent, resumeCurrent, cancelCurrent };
}
