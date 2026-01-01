import {
  CALLING_MAX_USERNAME_LENGTH,
  CALLING_MAX_CALL_ID_LENGTH,
  CALLING_EVENT_ALLOWED_PAYLOAD_KEYS
} from '../constants';

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

export const isValidCallingUsername = (username: string): boolean => {
  if (!username || typeof username !== 'string') return false;
  if (username.length === 0 || username.length > CALLING_MAX_USERNAME_LENGTH) return false;
  return /^[a-zA-Z0-9._-]+$/.test(username);
};

export const isValidCallId = (callId: string): boolean => {
  if (!callId || typeof callId !== 'string') return false;
  if (callId.length === 0 || callId.length > CALLING_MAX_CALL_ID_LENGTH) return false;
  return /^[a-zA-Z0-9_-]+$/.test(callId);
};

export const sanitizeEventDetail = (detail: any): Record<string, unknown> => {
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
      if (key === 'peer' && !isValidCallingUsername(trimmed)) continue;
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
  const queue = new Map<string, { detail: any; timestamp: number }>();
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let pendingAnimationFrame: number | null = null;

  const flush = () => {
    timeoutId = null;
    if (pendingAnimationFrame !== null) {
      cancelAnimationFrame(pendingAnimationFrame);
      pendingAnimationFrame = null;
    }

    const now = Date.now();
    const entries = Array.from(queue.entries());
    queue.clear();

    pendingAnimationFrame = requestAnimationFrame(() => {
      pendingAnimationFrame = null;
      entries.forEach(([name, { detail, timestamp }]) => {
        if (now - timestamp > 1000) {
          return;
        }
        try {
          window.dispatchEvent(new CustomEvent(name, { detail: sanitizeEventDetail(detail) }));
        } catch { }
      });
    });
  };

  const enqueue = (name: string, detail: any, immediate = false) => {
    if (immediate) {
      try {
        window.dispatchEvent(new CustomEvent(name, { detail: sanitizeEventDetail(detail) }));
      } catch { }
      return;
    }

    queue.set(name, { detail: sanitizeEventDetail(detail), timestamp: Date.now() });
    if (timeoutId === null) {
      timeoutId = setTimeout(flush, 20);
    }
  };

  const cancel = () => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
    if (pendingAnimationFrame !== null) {
      cancelAnimationFrame(pendingAnimationFrame);
      pendingAnimationFrame = null;
    }
    queue.clear();
  };

  return { enqueue, cancel };
};

export type EventDebouncer = ReturnType<typeof debounceEventDispatcher>;
