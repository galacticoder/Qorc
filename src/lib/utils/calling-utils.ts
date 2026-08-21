import {
  CALLING_MAX_USERNAME_LENGTH,
  CALLING_MAX_CALL_ID_LENGTH,
  CALLING_EVENT_ALLOWED_PAYLOAD_KEYS
} from '../constants';
import { hasExactKeys, hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import type { CallSignal } from '../types/calling-types';

const CALL_SIGNAL_BASE_KEYS = ['callId', 'from', 'timestamp', 'to', 'type'] as const;
const CALL_SCREEN_STREAM_ID_REGEX = /^call-screen:[a-f0-9]{16,64}$/;
const MAX_MEDIA_DEVICE_ID_LENGTH = 1024;

export const stopMediaStream = (stream: MediaStream | null) => {
  if (!stream) return;

  try {
    const seen = new Set<string>();
    const tracks = typeof stream.getTracks === 'function' ? stream.getTracks() : [];
    tracks.forEach((track) => {
      if (!track || seen.has(track.id)) {
        return;
      }
      seen.add(track.id);
      try {
        if (track.readyState !== 'ended') {
          track.stop();
        }
      } catch { }
    });
  } catch { }
};

export const releaseVisualCanvas = (canvas: HTMLCanvasElement | null): void => {
  if (!canvas) return;
  try { canvas.remove(); } catch { }
  canvas.width = 1;
  canvas.height = 1;
};

export const clearCallMediaState = (
  refs: {
    localStreamRef: { current: MediaStream | null };
    localVideoCanvasRef: { current: HTMLCanvasElement | null };
    remoteVideoCanvasRef: { current: HTMLCanvasElement | null };
    remoteScreenCanvasRef: { current: HTMLCanvasElement | null };
  },
  setters: {
    setLocalStream: (stream: MediaStream | null) => void;
    setLocalVideoCanvas: (canvas: HTMLCanvasElement | null) => void;
    setRemoteVideoCanvas: (canvas: HTMLCanvasElement | null) => void;
    setRemoteScreenCanvas: (canvas: HTMLCanvasElement | null) => void;
  },
): void => {
  stopMediaStream(refs.localStreamRef.current);
  releaseVisualCanvas(refs.remoteVideoCanvasRef.current);
  releaseVisualCanvas(refs.remoteScreenCanvasRef.current);
  refs.localStreamRef.current = null;
  refs.localVideoCanvasRef.current = null;
  refs.remoteVideoCanvasRef.current = null;
  refs.remoteScreenCanvasRef.current = null;
  setters.setLocalStream(null);
  setters.setLocalVideoCanvas(null);
  setters.setRemoteVideoCanvas(null);
  setters.setRemoteScreenCanvas(null);
};

export const isValidMediaDeviceId = (value: unknown): value is string => (
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= MAX_MEDIA_DEVICE_ID_LENGTH &&
  !/[\x00-\x1f\x7f]/.test(value)
);

export const isValidCallingUsername = (username: string): boolean => {
  if (!username || typeof username !== 'string') return false;
  if (username.length === 0 || username.length > CALLING_MAX_USERNAME_LENGTH) return false;
  return /^[a-z0-9._-]+$/.test(username);
};

export const isValidCallId = (callId: string): boolean => {
  if (!callId || typeof callId !== 'string') return false;
  if (callId.length !== CALLING_MAX_CALL_ID_LENGTH) return false;
  return /^[a-f0-9]{32}$/.test(callId);
};

export const isValidCallScreenStreamId = (value: unknown): value is string => (
  typeof value === 'string' && CALL_SCREEN_STREAM_ID_REGEX.test(value)
);

export const isExactCallSignal = (value: unknown): value is CallSignal => {
  if (
    !isPlainObject(value) ||
    hasPrototypePollutionKeys(value) ||
    typeof value.type !== 'string' ||
    typeof value.callId !== 'string' ||
    !isValidCallId(value.callId) ||
    typeof value.from !== 'string' ||
    value.from !== value.from.toLowerCase() ||
    !isValidCallingUsername(value.from) ||
    typeof value.to !== 'string' ||
    value.to !== value.to.toLowerCase() ||
    !isValidCallingUsername(value.to) ||
    !Number.isSafeInteger(value.timestamp) ||
    (value.timestamp as number) < 0
  ) {
    return false;
  }

  if (value.type === 'offer') {
    return hasExactKeys(value, [...CALL_SIGNAL_BASE_KEYS, 'data']) &&
      isPlainObject(value.data) &&
      !hasPrototypePollutionKeys(value.data) &&
      hasExactKeys(value.data, ['callType']) &&
      (value.data.callType === 'audio' || value.data.callType === 'video');
  }

  if (value.type === 'answer') {
    return hasExactKeys(value, CALL_SIGNAL_BASE_KEYS);
  }

  if (
    value.type === 'screen-share-start' ||
    value.type === 'screen-share-ready' ||
    value.type === 'screen-share-stop'
  ) {
    return hasExactKeys(value, [...CALL_SIGNAL_BASE_KEYS, 'data']) &&
      isPlainObject(value.data) &&
      !hasPrototypePollutionKeys(value.data) &&
      hasExactKeys(value.data, ['streamId']) &&
      isValidCallScreenStreamId(value.data.streamId);
  }

  return (
    value.type === 'decline-call' ||
    value.type === 'end-call'
  ) && hasExactKeys(value, CALL_SIGNAL_BASE_KEYS);
};

const sanitizeCallingEventDetail = (detail: any): Record<string, unknown> => {
  if (!detail || typeof detail !== 'object') {
    return {};
  }

  const sanitized: Record<string, unknown> = {};
  for (const key of CALLING_EVENT_ALLOWED_PAYLOAD_KEYS) {
    if (!(key in detail)) {
      continue;
    }
    const value = detail[key];
    if (value === null || value === undefined) {
      continue;
    }
    if (typeof value === 'string') {
      const trimmed = value.slice(0, 256);
      if ((key === 'peer' || key === 'account') && !isValidCallingUsername(trimmed)) continue;
      if (key === 'callId' && !isValidCallId(trimmed)) continue;
      sanitized[key] = trimmed;
    } else if (typeof value === 'number') {
      if (!Number.isFinite(value)) continue;
      if ((key === 'at' || key === 'startTime' || key === 'endTime' || key === 'durationMs') && value < 0) continue;
      sanitized[key] = value;
    } else if (typeof value === 'boolean') {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

export const debounceEventDispatcher = () => {
  const queue: Array<{ name: string; detail: Record<string, unknown>; timestamp: number }> = [];
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const maxQueuedEvents = 128;

  const flush = () => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
    }
    timeoutId = null;
    const now = Date.now();
    const entries = queue.splice(0, queue.length);
    entries.forEach(({ name, detail, timestamp }) => {
      if (now - timestamp > 1000) return;
      try {
        window.dispatchEvent(new CustomEvent(name, { detail }));
      } catch { }
    });
  };

  const enqueue = (name: string, detail: any, immediate = false) => {
    if (immediate) {
      try {
        window.dispatchEvent(new CustomEvent(name, { detail: sanitizeCallingEventDetail(detail) }));
      } catch { }
      return;
    }

    if (queue.length >= maxQueuedEvents) flush();
    queue.push({ name, detail: sanitizeCallingEventDetail(detail), timestamp: Date.now() });
    if (timeoutId === null) {
      timeoutId = setTimeout(flush, 20);
    }
  };

  const cancel = () => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
    queue.splice(0, queue.length);
  };

  return { enqueue, cancel };
};

export type EventDebouncer = ReturnType<typeof debounceEventDispatcher>;
