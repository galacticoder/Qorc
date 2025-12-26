/**
 * Type definitions and constants for WebRTC calling service
 */

export interface CallState {
  id: string;
  type: 'audio' | 'video';
  direction: 'incoming' | 'outgoing';
  status: 'ringing' | 'connecting' | 'connected' | 'ended' | 'declined' | 'missed';
  peer: string;
  startTime?: number;
  endTime?: number;
  duration?: number;
  endReason?: 'user' | 'timeout' | 'missed' | 'failed' | 'connection-lost' | 'shutdown' | string;
}

export interface CallOffer {
  callId: string;
  type: 'audio' | 'video';
  from: string;
  to: string;
  sdp: RTCSessionDescriptionInit;
  timestamp: number;
}

export interface CallAnswer {
  callId: string;
  from: string;
  to: string;
  sdp: RTCSessionDescriptionInit;
  accepted: boolean;
}

export interface CallSignal {
  type: 'offer' | 'answer' | 'ice-candidate' | 'end-call' | 'decline-call' | 'connected';
  callId: string;
  from: string;
  to: string;
  data?: any;
  timestamp: number;
  isRenegotiation?: boolean;
  pqSignature?: {
    signature: string;
    publicKey: string;
  };
}

// Validation constants
export const CALL_SIGNAL_RATE_WINDOW_MS = 10_000;
export const CALL_SIGNAL_RATE_MAX = 2500;
export const MAX_CALL_ID_LENGTH = 256;
export const MAX_CALL_USERNAME_LENGTH = 256;
export const MAX_CALL_SIG_BASE64_LENGTH = 40_000;
export const MAX_CALL_SDP_LENGTH = 2_000_000;
export const MAX_CALL_CANDIDATE_LENGTH = 16_384;
export const CALL_SIGNAL_MAX_SKEW_MS = 30 * 60 * 1000;

// Helpers
export const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

export const hasPrototypePollutionKeys = (obj: Record<string, unknown>): boolean => {
  return ['__proto__', 'prototype', 'constructor'].some((key) => Object.prototype.hasOwnProperty.call(obj, key));
};

// Validate call signal
export const validateCallSignal = (detail: unknown): CallSignal | null => {
  if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return null;

  const type = (detail as any).type;
  const callId = (detail as any).callId;
  const from = (detail as any).from;
  const to = (detail as any).to;
  const timestamp = (detail as any).timestamp;

  if (
    type !== 'offer' &&
    type !== 'answer' &&
    type !== 'ice-candidate' &&
    type !== 'end-call' &&
    type !== 'decline-call' &&
    type !== 'connected'
  ) {
    return null;
  }
  if (typeof callId !== 'string' || callId.length === 0 || callId.length > MAX_CALL_ID_LENGTH) return null;
  if (typeof from !== 'string' || from.length === 0 || from.length > MAX_CALL_USERNAME_LENGTH) return null;
  if (typeof to !== 'string' || to.length === 0 || to.length > MAX_CALL_USERNAME_LENGTH) return null;
  if (!Number.isFinite(timestamp)) return null;
  const skew = Math.abs(Date.now() - timestamp);
  if (skew > CALL_SIGNAL_MAX_SKEW_MS) return null;

  const pqSignature = (detail as any).pqSignature;
  if (!isPlainObject(pqSignature) || hasPrototypePollutionKeys(pqSignature)) return null;
  if (typeof (pqSignature as any).signature !== 'string' || (pqSignature as any).signature.length > MAX_CALL_SIG_BASE64_LENGTH) return null;
  if (typeof (pqSignature as any).publicKey !== 'string' || (pqSignature as any).publicKey.length > MAX_CALL_SIG_BASE64_LENGTH) return null;

  const data = (detail as any).data;
  if (type === 'offer' || type === 'answer') {
    if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) return null;
    const sdpObj = (data as any).sdp;
    if (typeof sdpObj === 'string') {
      if (sdpObj.length === 0 || sdpObj.length > MAX_CALL_SDP_LENGTH) return null;
    } else if (isPlainObject(sdpObj)) {
      if (hasPrototypePollutionKeys(sdpObj)) return null;
      if (typeof sdpObj.type !== 'string' || sdpObj.type !== type) return null;
      if (typeof sdpObj.sdp !== 'string' || sdpObj.sdp.length === 0 || sdpObj.sdp.length > MAX_CALL_SDP_LENGTH) return null;
    } else {
      return null;
    }
  }
  if (type === 'ice-candidate') {
    if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) return null;
    if (typeof (data as any).candidate !== 'string' || (data as any).candidate.length === 0 || (data as any).candidate.length > MAX_CALL_CANDIDATE_LENGTH) return null;
    const sdpMLineIndex = (data as any).sdpMLineIndex;
    const sdpMid = (data as any).sdpMid;
    if (sdpMLineIndex != null && !Number.isFinite(sdpMLineIndex)) return null;
    if (sdpMid != null && typeof sdpMid !== 'string') return null;
  }

  return detail as unknown as CallSignal;
};
