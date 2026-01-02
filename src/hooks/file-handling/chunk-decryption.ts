import * as pako from "pako";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { decodeBase64Chunk, validateEnvelope, releaseFileEntry, dispatchCanceledEvent } from "../../lib/utils/file-utils";
import type { ExtendedFileState } from "../../lib/types/file-types";

export interface DecryptionContext {
  fileEntry: ExtendedFileState;
  fileKey: string;
  from: string;
  safeFilename: string;
  chunkIndex: number;
  iv: Uint8Array;
  authTag: Uint8Array;
  encrypted: Uint8Array;
}

// Decode and parse encrypted chunk
export const parseEncryptedChunk = (chunkData: string): { iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array } | null => {
  const encryptedBytes = decodeBase64Chunk(chunkData);
  if (!encryptedBytes) return null;

  try {
    const parsed = CryptoUtils.Decrypt.deserializeEncryptedDataFromUint8Array(encryptedBytes);
    const iv = parsed?.iv as Uint8Array | undefined;
    const authTag = parsed?.authTag as Uint8Array | undefined;
    const encrypted = parsed?.encrypted as Uint8Array | undefined;

    if (!(iv instanceof Uint8Array && authTag instanceof Uint8Array && encrypted instanceof Uint8Array) ||
      iv.length === 0 || authTag.length === 0 || encrypted.length === 0) {
      return null;
    }

    return { iv, authTag, encrypted };
  } catch {
    return null;
  }
};

// Decrypt hybrid envelope to get AES/MAC keys
export const decryptEnvelope = async (
  envelope: any,
  hybridKeys: { x25519: { private: any }; kyber: { secretKey: Uint8Array } }
): Promise<{ aesKey: CryptoKey; macKey: Uint8Array } | null> => {
  if (!envelope || !validateEnvelope(envelope)) {
    return null;
  }

  try {
    const senderDilithiumPk = (envelope as any)?.metadata?.sender?.dilithiumPublicKey;
    const decrypted = await (CryptoUtils as any).Hybrid.decryptIncoming(
      envelope,
      {
        kyberSecretKey: hybridKeys.kyber?.secretKey,
        x25519SecretKey: hybridKeys.x25519?.private,
        senderDilithiumPublicKey: senderDilithiumPk
      }
    );

    const aesPayload = (decrypted?.payloadJson ?? null) as { aesKey?: string; macKey?: string } | null;
    if (!aesPayload || typeof aesPayload.aesKey !== 'string' || typeof aesPayload.macKey !== 'string') {
      return null;
    }

    const aesKeyBytes = CryptoUtils.Base64.base64ToUint8Array(aesPayload.aesKey);
    const aesKey = await CryptoUtils.Keys.importAESKey(aesKeyBytes);
    const macKey = CryptoUtils.Base64.base64ToUint8Array(aesPayload.macKey);

    return { aesKey, macKey };
  } catch (e) {
    console.error('[chunk-decryption] Failed to decrypt envelope:', e);
    return null;
  }
};

// Verify chunk MAC
export const verifyChunkMac = async (
  ctx: DecryptionContext,
  chunkMac: string,
  macKey: Uint8Array,
  totalChunks: number
): Promise<boolean> => {
  const idxBuf = new Uint8Array(8);
  const dv = new DataView(idxBuf.buffer);
  dv.setUint32(0, ctx.chunkIndex >>> 0, false);
  dv.setUint32(4, totalChunks >>> 0, false);
  const msgIdBytes = ctx.fileEntry.messageId ? new TextEncoder().encode(ctx.fileEntry.messageId) : new Uint8Array(0);
  const nameBytes = new TextEncoder().encode(ctx.safeFilename);
  const macInput = new Uint8Array(ctx.iv.length + ctx.authTag.length + ctx.encrypted.length + idxBuf.length + msgIdBytes.length + nameBytes.length);
  let mo = 0;
  macInput.set(ctx.iv, mo); mo += ctx.iv.length;
  macInput.set(ctx.authTag, mo); mo += ctx.authTag.length;
  macInput.set(ctx.encrypted, mo); mo += ctx.encrypted.length;
  macInput.set(idxBuf, mo); mo += idxBuf.length;
  macInput.set(msgIdBytes, mo); mo += msgIdBytes.length;
  macInput.set(nameBytes, mo);

  const computedMac = await CryptoUtils.Hash.generateBlake3Mac(macInput, new Uint8Array(macKey));
  const computedMacB64 = CryptoUtils.Base64.arrayBufferToBase64(computedMac);
  return computedMacB64 === chunkMac;
};

// Decrypt chunk with AES
export const decryptChunk = async (
  iv: Uint8Array,
  authTag: Uint8Array,
  encrypted: Uint8Array,
  aesKey: CryptoKey
): Promise<Uint8Array | null> => {
  try {
    const decryptedBytes = await CryptoUtils.AES.decryptBinaryWithAES(
      new Uint8Array(iv),
      new Uint8Array(authTag),
      new Uint8Array(encrypted),
      aesKey
    );

    if (!(decryptedBytes instanceof Uint8Array) || decryptedBytes.length === 0) {
      return null;
    }

    return decryptedBytes;
  } catch (e) {
    console.error('[chunk-decryption] AES decryption failed:', e);
    return null;
  }
};

// Decompress chunk
export const decompressChunk = (decryptedBytes: Uint8Array): Uint8Array => {
  try {
    return pako.inflate(decryptedBytes);
  } catch {
    return decryptedBytes;
  }
};

// Cleanup helper for failed transfers
export const cleanupFailedTransfer = (
  fileEntry: ExtendedFileState,
  fileKey: string,
  store: Record<string, any>,
  macState: Map<string, any>,
  cleanupTimers: Map<string, ReturnType<typeof setTimeout>>,
  blobCache: { clear: () => void },
  from: string,
  filename: string,
  reason: string,
  setLoginError: (err: string) => void,
  errorMessage: string
): void => {
  releaseFileEntry(fileEntry);
  delete store[fileKey];
  macState.delete(fileKey);
  const timer = cleanupTimers.get(fileKey);
  if (timer) {
    clearTimeout(timer);
    cleanupTimers.delete(fileKey);
  }
  blobCache.clear();
  setLoginError(errorMessage);
  dispatchCanceledEvent({ from, filename, reason });
};
