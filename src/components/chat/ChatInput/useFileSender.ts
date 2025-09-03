import { useRef, useState } from "react";
import * as pako from "pako";
import { CryptoUtils } from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";

// Rate limiting and timeouts
const DEFAULT_CHUNK_SIZE_SMALL = 256 * 1024; // 256KB
const DEFAULT_CHUNK_SIZE_LARGE = 512 * 1024; // 512KB for large files
const MAX_CHUNKS_PER_SECOND = 50; // throttle to avoid UI stalls
const INACTIVITY_TIMEOUT_MS = 120000; // sender inactivity timeout
const P2P_CONNECT_TIMEOUT_MS = 3500; // 3.5s to establish P2P, then fallback
const BUFFERED_LOW_WATERMARK = 256 * 1024; // resume when bufferedAmount < this

interface User {
  username: string;
  isOnline?: boolean;
  hybridPublicKeys?: {
    x25519PublicBase64: string;
    kyberPublicBase64: string;
  };
}

interface TransferState {
  fileId: string;
  fileName: string;
  fileSize: number;
  chunkSize: number;
  totalChunks: number;
  lastSentIndex: number; // -1 before sending any chunk
  lastAckedIndex: number; // for P2P resume
  paused: boolean;
  canceled: boolean;
  startedAt: number;
  lastActivity: number;
  inactivityTimer?: any;
}

export function useFileSender(currentUsername: string, targetUsername: string, users: User[]) {
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);

  // Track current transfer to allow pause/resume/cancel from UI
  const currentTransferRef = useRef<TransferState | null>(null);
  const currentRawBytesRef = useRef<Uint8Array | null>(null);
  const currentAesKeyRef = useRef<CryptoKey | null>(null);
  const currentMacKeyRef = useRef<Uint8Array | null>(null);
  const rateTokensRef = useRef<number>(MAX_CHUNKS_PER_SECOND);
  const lastRefillRef = useRef<number>(Date.now());

  function refillTokens() {
    const now = Date.now();
    const elapsed = (now - lastRefillRef.current) / 1000;
    if (elapsed > 0) {
      const refill = elapsed * MAX_CHUNKS_PER_SECOND;
      rateTokensRef.current = Math.min(MAX_CHUNKS_PER_SECOND, rateTokensRef.current + refill);
      lastRefillRef.current = now;
    }
  }

  function takeToken(): boolean {
    refillTokens();
    if (rateTokensRef.current >= 1) {
      rateTokensRef.current -= 1;
      return true;
    }
    return false;
  }

  
  async function computeChunkMacAsync(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, macKey: Uint8Array): Promise<string> {
    const macInput = new Uint8Array(iv.length + authTag.length + encrypted.length);
    macInput.set(iv, 0);
    macInput.set(authTag, iv.length);
    macInput.set(encrypted, iv.length + authTag.length);
    const macBytes = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
    return CryptoUtils.Base64.arrayBufferToBase64(macBytes);
  }

  function scheduleInactivityTimer(state: TransferState) {
    if (state.inactivityTimer) clearTimeout(state.inactivityTimer);
    state.inactivityTimer = setTimeout(() => {
      if (currentTransferRef.current && currentTransferRef.current.fileId === state.fileId) {
        console.warn('[useFileSender] Inactivity timeout, canceling transfer:', state.fileName);
        cancelCurrent();
      }
    }, INACTIVITY_TIMEOUT_MS);
  }

  function isTorEnabled(): boolean {
    const flag = localStorage.getItem('tor_enabled');
    if (flag === 'false') return false;
    // default to true
    return flag !== 'false';
  }

  function isRecipientOnline(): boolean {
    const u = users.find(u => u.username === targetUsername);
    return !!u?.isOnline;
  }

  async function attemptP2P(): Promise<boolean> {
    try {
      const svc = (window as any).p2pService;
      if (!svc || typeof svc.connectToPeer !== 'function') return false;

      let opened = false;
      const timer = new Promise<boolean>(resolve => setTimeout(() => resolve(false), P2P_CONNECT_TIMEOUT_MS));
      const attempt = (async () => {
        try {
          await svc.connectToPeer(targetUsername);
          // naive wait: see if peer is in connectedPeers
          if (typeof svc.getConnectedPeers === 'function') {
            const t0 = Date.now();
            while (Date.now() - t0 < P2P_CONNECT_TIMEOUT_MS) {
              const peers = svc.getConnectedPeers();
              if (Array.isArray(peers) && peers.includes(targetUsername)) {
                opened = true;
                break;
              }
              await new Promise(res => setTimeout(res, 100));
            }
          }
        } catch {}
        return opened;
      })();

      const res = await Promise.race([timer, attempt]);
      return !!res;
    } catch {
      return false;
    }
  }

  async function sendChunksServer(state: TransferState, userKeys: Array<{ username: string; encryptedAESKey: string; ephemeralX25519Public: string; kyberCiphertext: string }>) {
    const rawBytes = currentRawBytesRef.current!;
    const aesKey = currentAesKeyRef.current!;
    const macKey = currentMacKeyRef.current!;

    const totalChunks = state.totalChunks;
    const chunkSize = state.chunkSize;

    let bytesSent = 0;

    while (state.lastSentIndex < totalChunks - 1) {
      if (state.canceled) {
        console.log('[useFileSender] Transfer canceled');
        return;
      }
      if (state.paused) {
        await new Promise(res => setTimeout(res, 100));
        continue;
      }

      // Rate limiting
      if (!takeToken()) {
        await new Promise(res => setTimeout(res, 10));
        continue;
      }

      const nextIndex = state.lastSentIndex + 1;
      const start = nextIndex * chunkSize;
      const end = Math.min(start + chunkSize, rawBytes.length);
      const chunk = rawBytes.slice(start, end);

      // Compress
      const compressedChunk = pako.deflate(chunk);

      // Encrypt
      const { iv, authTag, encrypted } = await CryptoUtils.Encrypt.encryptBinaryWithAES(
        compressedChunk.buffer,
        aesKey
      );

      // MAC
      const chunkMac = await computeChunkMacAsync(new Uint8Array(iv), new Uint8Array(authTag), new Uint8Array(encrypted), macKey);

      for (const uk of userKeys) {
        const payload = {
          type: SignalType.FILE_MESSAGE_CHUNK,
          from: currentUsername,
          to: uk.username,
          encryptedAESKey: uk.encryptedAESKey,
          ephemeralX25519Public: uk.ephemeralX25519Public,
          kyberCiphertext: uk.kyberCiphertext,
          chunkIndex: nextIndex,
          totalChunks,
          chunkData: btoa(CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted)),
          filename: state.fileName,
          isLastChunk: nextIndex === totalChunks - 1,
          fileSize: state.fileSize,
          chunkSize,
          fileId: state.fileId,
          messageId: state.fileId,
          chunkMac
        };
        websocketClient.send(JSON.stringify(payload));
      }

      state.lastSentIndex = nextIndex;
      state.lastActivity = Date.now();
      scheduleInactivityTimer(state);

      bytesSent += (end - start) * userKeys.length;
      setProgress((state.lastSentIndex + 1) / totalChunks);

      // Yield occasionally
      if ((nextIndex & 0x7) === 0) await new Promise(res => setTimeout(res, 0));
    }

    setProgress(1);
  }

  async function sendFile(file: File) {
    const torEnabled = isTorEnabled();
    const online = isRecipientOnline();

    // Initialize state
    setIsSendingFile(true);
    setProgress(0);

    try {
      const rawBytes = new Uint8Array(await file.arrayBuffer());
      currentRawBytesRef.current = rawBytes;

      // Adaptive chunk size
      const chunkSize = file.size > 10 * 1024 * 1024 ? DEFAULT_CHUNK_SIZE_LARGE : DEFAULT_CHUNK_SIZE_SMALL;
      const totalChunks = Math.ceil(rawBytes.length / chunkSize);
      const fileId = crypto.randomUUID();

      const state: TransferState = {
        fileId,
        fileName: file.name,
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

      // Prepare crypto
      const aesKey = await CryptoUtils.Keys.generateAESKey();
      currentAesKeyRef.current = aesKey;
      const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
      const aesKeyBase64 = CryptoUtils.Base64.arrayBufferToBase64(rawAes);

      // MAC key from AES key using BLAKE3-HKDF
      const macSalt = new Uint8Array(32);
      crypto.getRandomValues(macSalt);
      const macInfo = new TextEncoder().encode(`ft:${file.name}:${file.size}`);
      currentMacKeyRef.current = await CryptoUtils.KDF.blake3Hkdf(new Uint8Array(rawAes), macSalt, macInfo, 32);

      // Find recipient hybrid keys
      const filteredUsers = users.filter((user) =>
        user.username === targetUsername &&
        user.username !== currentUsername &&
        user.hybridPublicKeys
      );

      if (filteredUsers.length === 0) {
        // Fallback to inline for small files if no hybrid keys
        const maxInlineBytes = 5 * 1024 * 1024;
        if (rawBytes.length > maxInlineBytes) {
          throw new Error(`No valid recipient keys for ${targetUsername} and file too large for inline fallback`);
        }

        // Ensure Signal session exists
        const sessionCheck = await (window as any).edgeApi?.hasSession?.({
          selfUsername: currentUsername,
          peerUsername: targetUsername,
          deviceId: 1
        });
        if (!sessionCheck?.hasSession) {
          websocketClient.send(JSON.stringify({ type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, username: targetUsername }));
          await new Promise(res => setTimeout(res, 500));
        }

        // Encode base64 safely
        let b64: string;
        if (typeof window !== 'undefined' && typeof Buffer === 'undefined' && rawBytes.length > 65536) {
          const blob = new Blob([rawBytes]);
          const reader = new FileReader();
          b64 = await new Promise<string>((resolve, reject) => {
            reader.onload = () => resolve((reader.result as string).split(",")[1]);
            reader.onerror = reject;
            reader.readAsDataURL(blob);
          });
        } else {
          // Browser small file or Node/Electron
          // @ts-ignore
          if (typeof Buffer !== 'undefined') {
            // Node/Electron
            // @ts-ignore
            b64 = Buffer.from(rawBytes).toString('base64');
          } else {
            // Safe chunked conversion to avoid call stack overflow
            let binary = '';
            const chunk = 8192; // 8KB chunks
            for (let i = 0; i < rawBytes.length; i += chunk) {
              const sub = rawBytes.subarray(i, i + chunk);
              // Build a small string per chunk
              let s = '';
              for (let j = 0; j < sub.length; j++) {
                s += String.fromCharCode(sub[j]);
              }
              binary += s;
            }
            b64 = btoa(binary);
          }
        }

        const messageId = crypto.randomUUID();
        const payload = {
          type: 'file-message',
          messageId: messageId,
          from: currentUsername,
          to: targetUsername,
          timestamp: Date.now(),
          fileName: file.name,
          fileType: file.type || 'application/octet-stream',
          fileSize: file.size,
          content: JSON.stringify({ messageId: messageId, fileName: file.name, fileType: file.type || 'application/octet-stream', fileSize: file.size, dataBase64: b64 })
        };

        const encrypted = await (window as any).edgeApi?.encrypt?.({ fromUsername: currentUsername, toUsername: targetUsername, plaintext: JSON.stringify(payload) });
        if (!encrypted?.ciphertextBase64) throw new Error('Failed to encrypt inline file');

        websocketClient.send(JSON.stringify({
          type: SignalType.ENCRYPTED_MESSAGE,
          to: targetUsername,
          encryptedPayload: { from: currentUsername, to: targetUsername, content: encrypted.ciphertextBase64, messageId: payload.messageId, type: encrypted.type, sessionId: encrypted.sessionId }
        }));

        // Create local message for inline files too
        const fileBlob = new Blob([rawBytes], { type: file.type || 'application/octet-stream' });
        const blobUrl = URL.createObjectURL(fileBlob);
        
        const localMessage = {
          id: messageId,
          content: blobUrl,
          sender: currentUsername,
          recipient: targetUsername,
          timestamp: payload.timestamp,
          filename: file.name,
          fileSize: file.size,
          mimeType: file.type || 'application/octet-stream',
          originalBase64Data: b64,
          type: 'file'
        };

        // Dispatch event to add message to chat
        console.log('[useFileSender] Dispatching local-file-message event (inline):', localMessage);
        window.dispatchEvent(new CustomEvent('local-file-message', { detail: localMessage }));
        console.log('[useFileSender] Event dispatched successfully (inline)');

        setProgress(1);
        setIsSendingFile(false);
        return;
      }

      // Prepare hybrid encryption of AES key per user
      const userKeys = await Promise.all(filteredUsers.map(async (user) => {
        const encryptedPayload = await CryptoUtils.Hybrid.encryptHybridPayload({ aesKey: aesKeyBase64 }, user.hybridPublicKeys!);
        return { username: user.username, encryptedAESKey: encryptedPayload.encryptedMessage, ephemeralX25519Public: encryptedPayload.ephemeralX25519Public, kyberCiphertext: encryptedPayload.kyberCiphertext };
      }));

      // Transport selection
      let useP2P = false;
      if (!torEnabled && online) {
        useP2P = await attemptP2P();
      }

      // Create local message for sender to see their own file
      const fileBlob = new Blob([rawBytes], { type: file.type || 'application/octet-stream' });
      const blobUrl = URL.createObjectURL(fileBlob);
      const fileBase64 = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve((reader.result as string).split(',')[1]);
        reader.readAsDataURL(fileBlob);
      });

      // Add message to local chat immediately for sender
      const localMessage = {
        id: fileId,
        content: blobUrl,
        sender: currentUsername,
        recipient: targetUsername,
        timestamp: Date.now(),
        filename: file.name,
        fileSize: file.size,
        mimeType: file.type || 'application/octet-stream',
        originalBase64Data: fileBase64,
        type: 'file'
      };

      // Dispatch event to add message to chat
      console.log('[useFileSender] Dispatching local-file-message event:', localMessage);
      window.dispatchEvent(new CustomEvent('local-file-message', { detail: localMessage }));
      console.log('[useFileSender] Event dispatched successfully');

      // For now, send chunks via server relay (receiver is ready) — P2P chunk path requires P2P receiver integration
      await sendChunksServer(state, userKeys);

      setIsSendingFile(false);
    } catch (error) {
      console.error('[useFileSender] File send failed:', error);
      setProgress(0);
      setIsSendingFile(false);
    }
  }

  function pauseCurrent() {
    const st = currentTransferRef.current;
    if (st) {
      st.paused = true;
      console.log('[useFileSender] Paused transfer:', st.fileName);
    }
  }

  function resumeCurrent() {
    const st = currentTransferRef.current;
    if (st) {
      st.paused = false;
      st.lastActivity = Date.now();
      scheduleInactivityTimer(st);
      console.log('[useFileSender] Resumed transfer:', st.fileName);
    }
  }

  function cancelCurrent() {
    const st = currentTransferRef.current;
    if (st) {
      st.canceled = true;
      if (st.inactivityTimer) clearTimeout(st.inactivityTimer);
      currentTransferRef.current = null;
      currentRawBytesRef.current = null;
      currentAesKeyRef.current = null;
      currentMacKeyRef.current = null;
      setIsSendingFile(false);
      console.log('[useFileSender] Canceled transfer:', st.fileName);
    }
  }

  return { sendFile, progress, isSendingFile, pauseCurrent, resumeCurrent, cancelCurrent };
}
