import { CryptoUtils } from "../utils/crypto-utils";
import { P2P_ROUTE_PROOF_TTL_MS, CERT_CLOCK_SKEW_MS } from "../constants";
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from './byte-utils';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export const createP2PError = (code: string) => {
  const error = new Error(code);
  error.name = 'P2PError';
  (error as Error & { code?: string }).code = code;
  return error;
};

export const getChannelId = (localKey: string, remoteKey: string, sessionBinding: string) => {
  if (!/^[a-f0-9]{32}$/.test(sessionBinding)) {
    throw new Error('Invalid P2P session binding');
  }
  const [first, second] = localKey < remoteKey
    ? [localKey, remoteKey]
    : [remoteKey, localKey];
  const digest = blake3(
    new TextEncoder().encode(`${PROTOCOL_KEYS.P2P_CHANNEL}\0${sessionBinding}\0${first}\0${second}`),
    { dkLen: 32 }
  );
  return bytesToHex(digest);
};

export const toUint8 = (base64: unknown, expectedLength: number): Uint8Array | null => {
  if (
    typeof base64 !== 'string' ||
    !Number.isSafeInteger(expectedLength) ||
    expectedLength <= 0 ||
    base64.length !== 4 * Math.ceil(expectedLength / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)
  ) return null;
  try {
    const decoded = CryptoUtils.Base64.base64ToUint8Array(base64);
    if (
      decoded.length !== expectedLength ||
      CryptoUtils.Base64.arrayBufferToBase64(decoded) !== base64
    ) {
      decoded.fill(0);
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
};

export const buildRouteProof = (
  channelId: string,
  sequence: number,
): {
  kind: typeof PROTOCOL_KEYS.ROUTE_PROOF_KIND;
  at: number;
  expiresAt: number;
  channelId: string;
  sequence: number;
} => {
  if (!/^[a-f0-9]{64}$/.test(channelId)) throw new Error('Invalid P2P channel ID');
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error('Invalid P2P sequence');
  const at = Date.now();
  return {
    kind: PROTOCOL_KEYS.ROUTE_PROOF_KIND,
    at,
    expiresAt: at + P2P_ROUTE_PROOF_TTL_MS,
    channelId,
    sequence,
  };
};

export const verifyRouteProof = (
  proof: any,
  channelId: string,
  minSequence: number,
) => {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    return false;
  }
  if (Object.keys(proof).sort().join(',') !== 'at,channelId,expiresAt,kind,sequence') {
    return false;
  }
  const { kind, at, channelId: proofChannel, sequence, expiresAt } = proof;
  if (kind !== PROTOCOL_KEYS.ROUTE_PROOF_KIND) {
    return false;
  }
  if (!Number.isSafeInteger(at) || !Number.isSafeInteger(expiresAt)) {
    return false;
  }
  const now = Date.now();
  if (
    at > now + CERT_CLOCK_SKEW_MS ||
    expiresAt <= now - CERT_CLOCK_SKEW_MS ||
    expiresAt <= at ||
    expiresAt - at !== P2P_ROUTE_PROOF_TTL_MS
  ) {
    return false;
  }
  if (!Number.isSafeInteger(sequence) || sequence < minSequence) {
    return false;
  }
  if (typeof proofChannel !== 'string' || proofChannel !== channelId || !/^[a-f0-9]{64}$/.test(proofChannel)) {
    return false;
  }
  return true;
};

export interface P2PRouteReplayState {
  highest: number;
  slots: Array<number | undefined>;
}

export const createP2PRouteReplayState = (windowSize: number): P2PRouteReplayState => {
  if (!Number.isSafeInteger(windowSize) || windowSize < 1) {
    throw new Error('Invalid P2P route replay window');
  }
  return { highest: 0, slots: new Array<number | undefined>(windowSize) };
};

export const canAcceptP2PRouteSequence = (
  state: P2PRouteReplayState,
  sequence: number,
  windowSize: number,
): boolean => {
  if (
    !Number.isSafeInteger(state?.highest) || state.highest < 0 ||
    !Array.isArray(state.slots) || state.slots.length !== windowSize ||
    !Number.isSafeInteger(sequence) || sequence < 1 ||
    !Number.isSafeInteger(windowSize) || windowSize < 1
  ) return false;
  const minimumRetained = Math.max(1, state.highest - windowSize + 1);
  return sequence >= minimumRetained && state.slots[sequence % windowSize] !== sequence;
};

export const commitP2PRouteSequence = (
  state: P2PRouteReplayState,
  sequence: number,
  windowSize: number,
): void => {
  if (!canAcceptP2PRouteSequence(state, sequence, windowSize)) {
    throw new Error('Invalid or replayed P2P route sequence');
  }
  if (sequence > state.highest) state.highest = sequence;
  state.slots[sequence % windowSize] = sequence;
};
