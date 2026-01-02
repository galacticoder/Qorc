import { sanitizeTextInput } from '../sanitizers';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { EventType } from '../types/event-types';
import type { IncomingFileChunks } from '../../pages/types';
import type { ExtendedFileState } from '../types/file-types';
import {
  BASE64_STANDARD_REGEX,
  BASE64_URLSAFE_REGEX,
  MAX_BASE64_CHARS,
  MAX_CONCURRENT_TRANSFERS,
  MAX_TOTAL_CHUNKS,
  FILE_SIZE_UNITS,
  FILE_SIZE_BASE,
  MAX_FILENAME_LENGTH,
  FILENAME_SANITIZE_REGEX,
  IMAGE_EXTENSIONS,
  VIDEO_EXTENSIONS,
  AUDIO_EXTENSIONS,
  BASE64_SAFE_REGEX,
  MAX_INLINE_BYTES,
} from '../constants';

// Sanitize event detail for file transfer events
export const sanitizeEventDetail = (detail: Record<string, unknown>): Record<string, unknown> => {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(detail)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeTextInput(value, { maxLength: 256, allowNewlines: false });
    } else if (typeof value === 'number') {
      sanitized[key] = Number.isFinite(value) ? value : 0;
    } else if (typeof value === 'boolean') {
      sanitized[key] = value;
    }
  }
  return sanitized;
};

// Dispatch file transfer progress event
export const dispatchProgressEvent = (detail: Record<string, unknown>): void => {
  try {
    const evt = new CustomEvent(EventType.FILE_TRANSFER_PROGRESS, { detail: sanitizeEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
};

// Dispatch file transfer complete event
export const dispatchCompleteEvent = (detail: Record<string, unknown>): void => {
  try {
    const evt = new CustomEvent(EventType.FILE_TRANSFER_COMPLETE, { detail: sanitizeEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
};

// Dispatch file transfer canceled event
export const dispatchCanceledEvent = (detail: Record<string, unknown>): void => {
  try {
    const evt = new CustomEvent(EventType.FILE_TRANSFER_CANCELED, { detail: sanitizeEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
};

// Normalize base64 string
export const normalizeBase64 = (input: string): string => input.replace(/\s+/g, '');

// Decode base64 chunk to Uint8Array
export const decodeBase64Chunk = (data: string): Uint8Array | null => {
  if (typeof data !== 'string' || data.length === 0 || data.length > MAX_BASE64_CHARS) {
    return null;
  }
  const normalized = normalizeBase64(data);
  const isUrlSafe = BASE64_URLSAFE_REGEX.test(normalized.replace(/=*$/, ''));
  const pattern = isUrlSafe ? BASE64_URLSAFE_REGEX : BASE64_STANDARD_REGEX;
  if (!pattern.test(normalized)) {
    return null;
  }
  let working = isUrlSafe ? normalized.replace(/-/g, '+').replace(/_/g, '/') : normalized;
  while (working.length % 4 !== 0) {
    working += '=';
  }
  try {
    if (typeof Buffer !== 'undefined') {
      return Uint8Array.from(Buffer.from(working, 'base64'));
    }
    const binary = atob(working);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
};

// Validate envelope structure
export const validateEnvelope = (envelope: unknown): envelope is Record<string, unknown> => {
  if (!isPlainObject(envelope) || hasPrototypePollutionKeys(envelope)) {
    return false;
  }
  return true;
};

// Check concurrent transfer limit
export const enforceConcurrentLimit = (store: IncomingFileChunks): boolean => {
  const active = Object.keys(store as Record<string, unknown>).length;
  return active < MAX_CONCURRENT_TRANSFERS;
};

// Create blob cache with LRU eviction
export const createBlobCache = () => {
  const entries: Array<{ url: string; source: string }> = [];
  const enqueue = (url: string, source: string) => {
    entries.push({ url, source });
    if (entries.length > MAX_TOTAL_CHUNKS) {
      const stale = entries.shift();
      if (stale) {
        try { URL.revokeObjectURL(stale.url); } catch { }
      }
    }
  };
  const clear = () => {
    while (entries.length) {
      const stale = entries.shift();
      if (stale) {
        try { URL.revokeObjectURL(stale.url); } catch { }
      }
    }
  };
  return { enqueue, clear };
};

// Release file entry resources
export const releaseFileEntry = (entry?: ExtendedFileState): void => {
  if (!entry) return;
  entry.decryptedChunks.length = 0;
  entry.receivedSet?.clear();
  entry.bytesReceivedApprox = 0;
  entry.aesKey = undefined;
};

// Format file size in human readable format
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return "0 Bytes";
  if (bytes < 0 || !Number.isFinite(bytes)) return "Unknown";

  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(FILE_SIZE_BASE)),
    FILE_SIZE_UNITS.length - 1
  );
  const value = bytes / Math.pow(FILE_SIZE_BASE, i);
  return `${value.toFixed(1)} ${FILE_SIZE_UNITS[i]}`;
};

// Check if filename has one of the specified extensions
export const hasExtension = (filename: string, extensions: readonly string[]): boolean => {
  if (!filename || typeof filename !== 'string' || filename.length > MAX_FILENAME_LENGTH) {
    return false;
  }
  const sanitizedFilename = filename.replace(FILENAME_SANITIZE_REGEX, '');
  const lowerFilename = sanitizedFilename.toLowerCase();
  return extensions.some(ext => lowerFilename.endsWith('.' + ext.toLowerCase()));
};

// Validate and sanitize file URL
export const isSafeFileUrl = (url: string | null | undefined): string | null => {
  if (!url || typeof url !== 'string') return null;
  try {
    const parsed = new URL(url, 'http://localhost');
    const protocol = parsed.protocol.toLowerCase();
    if (protocol === 'blob:' || protocol === 'http:' || protocol === 'https:') {
      return url;
    }
    return null;
  } catch {
    return null;
  }
};

// Create and trigger download link for file
export const createDownloadLink = (href: string, filename: string): void => {
  const link = document.createElement('a');
  link.href = href;
  link.download = filename || 'download';
  link.rel = 'noopener noreferrer';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

// Detect MIME type from filename
export const detectMimeType = (filename: string): string => {
  const lowerName = filename.toLowerCase();
  if (lowerName.endsWith('.webm')) return 'audio/webm';
  if (lowerName.endsWith('.mp3')) return 'audio/mpeg';
  if (lowerName.endsWith('.wav')) return 'audio/wav';
  if (lowerName.endsWith('.ogg')) return 'audio/ogg';
  if (lowerName.endsWith('.m4a')) return 'audio/mp4';
  if (lowerName.endsWith('.mp4')) return 'video/mp4';
  if (lowerName.endsWith('.png')) return 'image/png';
  if (lowerName.endsWith('.jpg') || lowerName.endsWith('.jpeg')) return 'image/jpeg';
  if (lowerName.endsWith('.gif')) return 'image/gif';
  if (lowerName.endsWith('.webp')) return 'image/webp';
  if (lowerName.endsWith('.pdf')) return 'application/pdf';
  return 'application/octet-stream';
};

// Check if file is image
export const isImageFile = (filename: string): boolean => hasExtension(filename, IMAGE_EXTENSIONS);

// Check if file is video
export const isVideoFile = (filename: string): boolean => hasExtension(filename, VIDEO_EXTENSIONS);

// Check if file is audio
export const isAudioFile = (filename: string): boolean => hasExtension(filename, AUDIO_EXTENSIONS);

// Check if file is voice note
export const isVoiceNote = (filename: string): boolean => {
  return (filename || '').toLowerCase().includes('voice-note');
};

// Validate and decode base64 for file URL
export const validateAndDecodeBase64 = (input: string | null | undefined): Uint8Array | null => {
  if (!input || typeof input !== 'string') return null;
  let cleanBase64 = input.trim();

  const inlinePrefixIndex = cleanBase64.indexOf(',');
  if (inlinePrefixIndex > 0 && inlinePrefixIndex < 128) {
    cleanBase64 = cleanBase64.slice(inlinePrefixIndex + 1);
  }

  if (!BASE64_SAFE_REGEX.test(cleanBase64.replace(/=+$/, ''))) {
    return null;
  }

  const estimatedBytes = Math.floor((cleanBase64.length * 3) / 4) - (cleanBase64.endsWith('==') ? 2 : cleanBase64.endsWith('=') ? 1 : 0);
  if (estimatedBytes <= 0 || estimatedBytes > MAX_INLINE_BYTES) {
    return null;
  }

  try {
    return Uint8Array.from(atob(cleanBase64), char => char.charCodeAt(0));
  } catch {
    return null;
  }
};
