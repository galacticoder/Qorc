import { CryptoUtils } from "../utils/crypto-utils";
import { MAX_P2P_PEER_CACHE, P2P_ROUTE_PROOF_TTL_MS, CERT_CLOCK_SKEW_MS } from "../constants";
import { concatUint8Arrays } from "./shared-utils";

export const createP2PError = (code: string) => {
  const error = new Error(code);
  error.name = 'P2PError';
  (error as Error & { code?: string }).code = code;
  return error;
};

export const getChannelId = (localKey: string, remoteKey: string) =>
  localKey < remoteKey ? `${localKey}|${remoteKey}` : `${remoteKey}|${localKey}`;

export const createBoundedQueue = <T,>(maxSize: number) => {
  const queue: T[] = [];
  return {
    push(item: T) {
      queue.push(item);
      if (queue.length > maxSize) {
        queue.shift();
      }
    },
    items() {
      return [...queue];
    },
    clear() {
      queue.length = 0;
    },
  };
};

export const buildAuthenticator = () => {
  const cache = new Map<string, { expiresAt: number }>();
  return {
    memoize(key: string) {
      const cached = cache.get(key);
      if (cached && cached.expiresAt > Date.now()) {
        return true;
      }
      return false;
    },
    store(key: string, ttlMs: number) {
      cache.set(key, { expiresAt: Date.now() + ttlMs });
      if (cache.size > MAX_P2P_PEER_CACHE) {
        const now = Date.now();
        for (const [entryKey, entry] of cache) {
          if (entry.expiresAt <= now) {
            cache.delete(entryKey);
          }
        }
      }
    },
  };
};

export const toUint8 = (base64?: string) => {
  if (!base64) return null;
  try {
    return CryptoUtils.Base64.base64ToUint8Array(base64);
  } catch {
    return null;
  }
};

export const getCrypto = () => {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj?.subtle) {
    throw new Error('WebCrypto unavailable');
  }
  return cryptoObj;
};

export const generateRandomBase64 = (length = 48) => {
  const cryptoObj = getCrypto();
  const bytes = cryptoObj.getRandomValues(new Uint8Array(length));
  return CryptoUtils.Base64.arrayBufferToBase64(bytes);
};

export const generateMessageId = async (channelId: string, sequence: number) => {
  const cryptoObj = getCrypto();
  const randomBytes = cryptoObj.getRandomValues(new Uint8Array(48));
  const sequenceBuffer = new Uint8Array(8);
  new DataView(sequenceBuffer.buffer).setUint32(4, sequence, false);
  const channelBytes = new TextEncoder().encode(channelId);
  const material = concatUint8Arrays(randomBytes, sequenceBuffer, channelBytes);
  const macKey = cryptoObj.getRandomValues(new Uint8Array(32));
  const mac = await CryptoUtils.Hash.generateBlake3Mac(material, macKey);
  return CryptoUtils.Base64.arrayBufferToBase64(mac).replace(/[^a-zA-Z0-9]/g, '').slice(0, 48);
};

export const buildRouteProof = async (
  localDilithiumSecret: Uint8Array,
  localDilithiumPublic: string,
  peerDilithiumPublic: string,
  channelId: string,
  sequence: number,
) => {
  const cryptoObj = getCrypto();
  const nonce = cryptoObj.getRandomValues(new Uint8Array(24));
  const expiresAt = Date.now() + P2P_ROUTE_PROOF_TTL_MS;
  const payload = {
    kind: 'route-proof-v1',
    nonce: CryptoUtils.Base64.arrayBufferToBase64(nonce),
    at: Date.now(),
    expiresAt,
    from: localDilithiumPublic,
    to: peerDilithiumPublic,
    channelId,
    sequence,
  };
  const canonicalPayload = {
    at: payload.at,
    channelId: payload.channelId,
    expiresAt: payload.expiresAt,
    from: payload.from,
    kind: payload.kind,
    nonce: payload.nonce,
    sequence: payload.sequence,
    to: payload.to,
  };
  const canonical = new TextEncoder().encode(JSON.stringify(canonicalPayload));
  const signature = await CryptoUtils.Dilithium.sign(localDilithiumSecret, canonical);
  return {
    payload,
    signature: CryptoUtils.Base64.arrayBufferToBase64(signature),
  };
};

export const verifyRouteProof = async (
  proof: { payload: any; signature: string } | undefined,
  localDilithiumPublic: string,
  peerDilithiumPublic: string,
  channelId: string,
  minSequence: number,
) => {
  if (!proof?.payload || !proof.signature) {
    return false;
  }
  const { kind, nonce, at, from, to, channelId: proofChannel, sequence, expiresAt } = proof.payload;
  if (kind !== 'route-proof-v1') {
    return false;
  }
  if (typeof at !== 'number' || typeof expiresAt !== 'number') {
    return false;
  }
  const now = Date.now();
  if (at > (now + CERT_CLOCK_SKEW_MS) || expiresAt <= (now - CERT_CLOCK_SKEW_MS) || expiresAt - at > P2P_ROUTE_PROOF_TTL_MS) {
    return false;
  }
  if (typeof sequence !== 'number' || sequence < minSequence) {
    return false;
  }
  if (from !== peerDilithiumPublic || to !== localDilithiumPublic) {
    return false;
  }
  if (proofChannel !== channelId) {
    return false;
  }
  const nonceBytes = toUint8(nonce);
  if (!nonceBytes || nonceBytes.length !== 24) {
    return false;
  }
  const signatureBytes = toUint8(proof.signature);
  if (!signatureBytes) {
    return false;
  }
  const canonicalPayload = {
    at: at,
    channelId: proofChannel,
    expiresAt: expiresAt,
    from: from,
    kind: kind,
    nonce: nonce,
    sequence: sequence,
    to: to,
  };
  const canonical = new TextEncoder().encode(JSON.stringify(canonicalPayload));
  const peerKey = toUint8(peerDilithiumPublic);
  if (!peerKey) {
    return false;
  }
  try {
    const result = await CryptoUtils.Dilithium.verify(signatureBytes, canonical, peerKey);
    return result;
  } catch {
    return false;
  }
};
