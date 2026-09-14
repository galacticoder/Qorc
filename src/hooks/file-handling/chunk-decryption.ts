import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { decodeBase64Chunk, releaseFileEntry, dispatchCanceledEvent } from "../../lib/utils/file-utils";
import type { ExtendedFileState } from "../../lib/types/file-types";
import { resolveTrustedPeerDilithiumPublicKey, type PeerIdentityLike } from "../../lib/utils/signal-bundle-utils";
import { HashingService } from '../../lib/cryptography/hashing';
import { isHybridEnvelopeWireShape } from '../../lib/transport/envelope-shape';
import { SignalType } from '../../lib/types/signal-types';
import { DEFAULT_CHUNK_SIZE_SMALL } from '../../lib/constants';

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
      iv.length !== 12 || authTag.length !== 16 || encrypted.length === 0 ||
      encrypted.length > DEFAULT_CHUNK_SIZE_SMALL + 1024) {
      iv?.fill(0);
      authTag?.fill(0);
      encrypted?.fill(0);
      return null;
    }

    return { iv, authTag, encrypted };
  } catch {
    return null;
  } finally {
    encryptedBytes.fill(0);
  }
};

// Decrypt hybrid envelope to get AES/MAC keys
export const decryptEnvelope = async (
  envelope: any,
  accountUsername: string,
  senderUsername: string,
  users: PeerIdentityLike[],
  findUser: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<{ aesKey: CryptoKey; macKey: Uint8Array } | null> => {
  if (!isHybridEnvelopeWireShape(envelope, SignalType.FILE_MESSAGE_CHUNK)) {
    return null;
  }

  let aesKeyBytes: Uint8Array | null = null;
  let macKey: Uint8Array | null = null;
  try {
    const senderDilithiumPk = (envelope as any)?.routing?.from;
    const senderIdentity = await resolveTrustedPeerDilithiumPublicKey(
      accountUsername,
      senderUsername,
      senderDilithiumPk,
      users,
      findUser
    );
    if (!senderIdentity.valid || !senderIdentity.expectedDilithium) {
      console.error('[FILE-ENVELOPE-IDENTITY]', senderIdentity.reason || 'UNAUTHORIZED_SENDER_KEY');
      return null;
    }
    const decrypted = await CryptoUtils.Hybrid.decryptIncoming(
      envelope,
      {
        senderDilithiumPublicKey: senderIdentity.expectedDilithium
      }
    );

    const aesPayload = (decrypted?.payloadJson ?? null) as { aesKey?: string; macKey?: string } | null;
    if (!aesPayload || typeof aesPayload.aesKey !== 'string' || typeof aesPayload.macKey !== 'string') {
      return null;
    }

    aesKeyBytes = CryptoUtils.Base64.base64ToUint8Array(aesPayload.aesKey);
    macKey = CryptoUtils.Base64.base64ToUint8Array(aesPayload.macKey);
    if (
      aesKeyBytes.length !== 32 ||
      macKey.length !== 32 ||
      CryptoUtils.Base64.arrayBufferToBase64(aesKeyBytes) !== aesPayload.aesKey ||
      CryptoUtils.Base64.arrayBufferToBase64(macKey) !== aesPayload.macKey
    ) {
      return null;
    }
    const ownedAesKeyBytes = new Uint8Array(aesKeyBytes.length);
    ownedAesKeyBytes.set(aesKeyBytes);
    let aesKey: CryptoKey;
    try {
      aesKey = await crypto.subtle.importKey(
          'raw',
          ownedAesKeyBytes,
          { name: 'AES-GCM', length: 256 },
          false,
          ['decrypt']
        );
    } finally {
      ownedAesKeyBytes.fill(0);
    }
    const result = { aesKey, macKey };
    macKey = null;
    return result;
  } catch (e) {
    console.error('[chunk-decryption] Failed to decrypt envelope:', e);
    return null;
  } finally {
    aesKeyBytes?.fill(0);
    macKey?.fill(0);
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

  let expectedMac: Uint8Array | null = null;
  try {
    expectedMac = CryptoUtils.Base64.base64ToUint8Array(chunkMac);
    if (
      expectedMac.length !== 32 ||
      CryptoUtils.Base64.arrayBufferToBase64(expectedMac) !== chunkMac
    ) return false;
    return await HashingService.verifyBlake3Mac(macInput, macKey, expectedMac);
  } catch {
    return false;
  } finally {
    idxBuf.fill(0);
    msgIdBytes.fill(0);
    nameBytes.fill(0);
    macInput.fill(0);
    expectedMac?.fill(0);
  }
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
      iv,
      authTag,
      encrypted,
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

// Cleanup helper for failed transfers
export const cleanupFailedTransfer = (
  fileEntry: ExtendedFileState,
  fileKey: string,
  store: Record<string, any>,
  macState: Map<string, any>,
  cleanupTimers: Map<string, ReturnType<typeof setTimeout>>,
  from: string,
  filename: string,
  reason: string,
  setLoginError: (err: string) => void,
  errorMessage: string
): void => {
  releaseFileEntry(fileEntry);
  delete store[fileKey];
  const macEntry = macState.get(fileKey);
  if (macEntry?.macKey instanceof Uint8Array) macEntry.macKey.fill(0);
  macState.delete(fileKey);
  const timer = cleanupTimers.get(fileKey);
  if (timer) {
    clearTimeout(timer);
    cleanupTimers.delete(fileKey);
  }
  setLoginError(errorMessage);
  dispatchCanceledEvent({ from, filename, reason });
};
