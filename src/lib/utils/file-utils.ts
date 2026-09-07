import { sanitizeTextInput } from '../sanitizers';
import { EventType } from '../types/event-types';
import type { ExtendedFileState, FilePreviewKind } from '../types/file-types';
import { validateWebpContainer } from './image-container-validation';
import {
  BASE64_STANDARD_REGEX,
  MAX_BASE64_CHARS,
  MAX_CONCURRENT_TRANSFERS,
  MAX_CONCURRENT_TRANSFERS_PER_PEER,
  FILE_SIZE_UNITS,
  FILE_SIZE_BASE,
  MAX_FILENAME_LENGTH,
  FILENAME_SANITIZE_REGEX,
  IMAGE_EXTENSIONS,
  MAX_FILE_SIZE,
  MAX_VOICE_NOTE_BYTES,
  MAX_VOICE_NOTE_DURATION_SECONDS,
} from '../constants';
import { asciiMatchesAt, bytesMatchAt, readUint32BE } from './byte-utils';
import { tryDecodeCanonicalBase64 } from '../cryptography/base64';

const MAX_IMAGE_PREVIEW_BYTES = 32 * 1024 * 1024;
const MAX_IMAGE_PREVIEW_DIMENSION = 8192;
const MAX_IMAGE_PREVIEW_PIXELS = 16 * 1024 * 1024;
const MEDIA_HEADER_BYTES = 64;

const VOICE_NOTE_MIME_BY_EXTENSION = Object.freeze({
  webm: 'audio/webm',
  ogg: 'audio/ogg',
  m4a: 'audio/mp4',
  mp3: 'audio/mpeg',
} as const);

export const parseCurrentVoiceNoteFilename = (
  filename: unknown,
): { durationSeconds: number; mimeType: string } | null => {
  if (typeof filename !== 'string') return null;
  const match = /^voice-note-(\d+)s-(\d{13})\.(webm|ogg|m4a|mp3)$/.exec(filename);
  if (!match) return null;
  const durationSeconds = Number(match[1]);
  const timestamp = Number(match[2]);
  if (
    !Number.isSafeInteger(durationSeconds) ||
    durationSeconds < 1 ||
    durationSeconds > MAX_VOICE_NOTE_DURATION_SECONDS ||
    !Number.isSafeInteger(timestamp) ||
    timestamp <= 0
  ) return null;
  return {
    durationSeconds,
    mimeType: VOICE_NOTE_MIME_BY_EXTENSION[match[3] as keyof typeof VOICE_NOTE_MIME_BY_EXTENSION],
  };
};

// Sanitize event detail for file transfer events
const sanitizeFileEventDetail = (detail: Record<string, unknown>): Record<string, unknown> => {
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
    const evt = new CustomEvent(EventType.FILE_TRANSFER_PROGRESS, { detail: sanitizeFileEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
};

// Dispatch file transfer canceled event
export const dispatchCanceledEvent = (detail: Record<string, unknown>): void => {
  try {
    const evt = new CustomEvent(EventType.FILE_TRANSFER_CANCELED, { detail: sanitizeFileEventDetail(detail) });
    window.dispatchEvent(evt);
  } catch { }
};

// Decode base64 chunk to Uint8Array
export const decodeBase64Chunk = (data: string): Uint8Array | null => {
  if (
    typeof data !== 'string' ||
    data.length === 0 ||
    data.length > MAX_BASE64_CHARS ||
    data.length % 4 !== 0 ||
    !BASE64_STANDARD_REGEX.test(data)
  ) {
    return null;
  }
  return tryDecodeCanonicalBase64(data, 'base64 chunk');
};

// Check concurrent transfer limit
export const enforceConcurrentLimit = (
  store: Record<string, ExtendedFileState>,
  sender: string,
): boolean => {
  const keys = Object.keys(store as Record<string, unknown>);
  if (keys.length >= MAX_CONCURRENT_TRANSFERS) return false;
  const senderPrefix = `${sender}\0`;
  let senderTransfers = 0;
  for (const key of keys) {
    if (key.startsWith(senderPrefix)) senderTransfers += 1;
  }
  return senderTransfers < MAX_CONCURRENT_TRANSFERS_PER_PEER;
};

export const totalInboundFileBytes = (store: Record<string, ExtendedFileState>): number => {
  const map = store as Record<string, ExtendedFileState>;
  let total = 0;
  for (const key of Object.keys(map)) {
    total += map[key]?.bytesReceivedApprox || 0;
  }
  return total;
};

// Release file entry resources
export const releaseFileEntry = (entry?: ExtendedFileState): void => {
  if (!entry) return;
  if (!entry.transportAckDurablyCommitted) {
    entry.transportAckCanceled = true;
    entry.transportAckPending?.clear();
    entry.transportAckedIndices?.clear();
    entry.transportAckInFlight = undefined;
  }
  for (const chunk of entry.decryptedChunks) chunk?.fill(0);
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
    if (protocol === 'blob:') {
      return url;
    }
    return null;
  } catch {
    return null;
  }
};

const sniffAudioMime = (bytes: Uint8Array, fileSize: number): string | null => {
  if (bytesMatchAt(bytes, 0, [0x1a, 0x45, 0xdf, 0xa3])) return 'audio/webm';
  if (asciiMatchesAt(bytes, 0, 'OggS')) return 'audio/ogg';
  if (asciiMatchesAt(bytes, 0, 'fLaC')) return 'audio/flac';
  if (asciiMatchesAt(bytes, 0, 'RIFF') && asciiMatchesAt(bytes, 8, 'WAVE')) return 'audio/wav';
  if (asciiMatchesAt(bytes, 0, 'ID3')) return 'audio/mpeg';
  if (
    bytes.length >= 4 &&
    bytes[0] === 0xff &&
    (bytes[1] & 0xe0) === 0xe0 &&
    (bytes[1] & 0x18) !== 0x08 &&
    (bytes[1] & 0x06) !== 0 &&
    (bytes[2] & 0xf0) !== 0xf0 &&
    (bytes[2] & 0x0c) !== 0x0c
  ) {
    return 'audio/mpeg';
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xf6) === 0xf0) return 'audio/aac';
  if (bytes.length >= 12 && asciiMatchesAt(bytes, 4, 'ftyp')) {
    const boxSize = readUint32BE(bytes, 0);
    if (boxSize >= 8 && boxSize <= fileSize) return 'audio/mp4';
  }
  return null;
};

const sniffVideoMime = (bytes: Uint8Array, fileSize: number): string | null => {
  if (bytesMatchAt(bytes, 0, [0x1a, 0x45, 0xdf, 0xa3])) return 'video/webm';
  if (asciiMatchesAt(bytes, 0, 'OggS')) return 'video/ogg';
  if (asciiMatchesAt(bytes, 0, 'FLV') && bytes[3] === 1) return 'video/x-flv';
  if (asciiMatchesAt(bytes, 0, 'RIFF') && asciiMatchesAt(bytes, 8, 'AVI ')) return 'video/x-msvideo';
  if (
    bytesMatchAt(bytes, 0, [0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c])
  ) {
    return 'video/x-ms-wmv';
  }
  if (bytes.length >= 12 && asciiMatchesAt(bytes, 4, 'ftyp')) {
    const boxSize = readUint32BE(bytes, 0);
    if (boxSize >= 8 && boxSize <= fileSize) return 'video/mp4';
  }
  return null;
};

export const validateFilePreview = async (
  blob: Blob,
  previewKind: FilePreviewKind,
): Promise<string | null> => {
  if (!(blob instanceof Blob) || !Number.isSafeInteger(blob.size) || blob.size <= 0) return null;
  const maxBytes = previewKind === 'image'
    ? MAX_IMAGE_PREVIEW_BYTES
    : previewKind === 'voice'
      ? MAX_VOICE_NOTE_BYTES
      : MAX_FILE_SIZE;
  if (blob.size > maxBytes) return null;

  let header: Uint8Array | null = null;
  let imageBytes: Uint8Array | null = null;
  try {
    if (previewKind === 'image') {
      imageBytes = new Uint8Array(await blob.arrayBuffer());
      validateWebpContainer(imageBytes, {
        maxWidth: MAX_IMAGE_PREVIEW_DIMENSION,
        maxHeight: MAX_IMAGE_PREVIEW_DIMENSION,
        maxPixels: MAX_IMAGE_PREVIEW_PIXELS,
      });
      return 'image/webp';
    }
    header = new Uint8Array(await blob.slice(0, MEDIA_HEADER_BYTES).arrayBuffer());
    if (previewKind === 'video') return sniffVideoMime(header, blob.size);
    return sniffAudioMime(header, blob.size);
  } catch {
    return null;
  } finally {
    header?.fill(0);
    imageBytes?.fill(0);
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
  if (lowerName.endsWith('.webm')) {
    return parseCurrentVoiceNoteFilename(filename)?.mimeType ?? 'video/webm';
  }
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

export async function stripImageMetadata(file: File): Promise<File> {
  const extension = file.name.toLowerCase().match(/\.([a-z0-9]+)$/)?.[1] || '';
  if (file.type === 'image/svg+xml' || extension === 'svg') {
    throw new Error('SVG files cannot be metadata-sanitized safely');
  }
  const isImage = file.type.startsWith('image/') ||
    IMAGE_EXTENSIONS.some((candidate) => candidate === extension) ||
    /^(avif|heic|heif|jxl)$/.test(extension);
  if (!isImage) {
    return file;
  }

  return new Promise((resolve, reject) => {
    const img = new Image();
    const objectUrl = URL.createObjectURL(file);
    let settled = false;
    const finish = (result?: File, error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      img.onload = null;
      img.onerror = null;
      try { URL.revokeObjectURL(objectUrl); } catch { }
      if (result) resolve(result);
      else reject(error || new Error('Image metadata removal failed'));
    };
    const timeout = setTimeout(() => {
      try { img.src = ''; } catch { }
      finish(undefined, new Error('Image metadata removal timed out'));
    }, 30_000);

    img.onload = () => {
      try {
        const MAX_CANVAS_DIMENSION = 8192;
        const MAX_CANVAS_PIXELS = 16 * 1024 * 1024;
        let width = img.width;
        let height = img.height;

        if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width <= 0 || height <= 0) {
          finish(undefined, new Error('Image dimensions are invalid'));
          return;
        }

        if (width > MAX_CANVAS_DIMENSION || height > MAX_CANVAS_DIMENSION) {
          if (width > height) {
            height = Math.max(1, Math.round((height * MAX_CANVAS_DIMENSION) / width));
            width = MAX_CANVAS_DIMENSION;
          } else {
            width = Math.max(1, Math.round((width * MAX_CANVAS_DIMENSION) / height));
            height = MAX_CANVAS_DIMENSION;
          }
        }
        if (width * height > MAX_CANVAS_PIXELS) {
          const scale = Math.sqrt(MAX_CANVAS_PIXELS / (width * height));
          width = Math.max(1, Math.floor(width * scale));
          height = Math.max(1, Math.floor(height * scale));
        }

        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;

        const ctx = canvas.getContext('2d');
        if (!ctx) {
          finish(undefined, new Error('Image metadata removal is unavailable'));
          return;
        }

        ctx.drawImage(img, 0, 0, width, height);

        canvas.toBlob((blob) => {
          if (blob) {
            const newFilename = file.name.replace(/\.[^/.]+$/, "") + ".webp";
            const newFile = new File([blob], newFilename, {
              type: 'image/webp',
              lastModified: Date.now(),
            });
            finish(newFile);
          } else {
            finish(undefined, new Error('Image metadata removal produced no output'));
          }
        }, 'image/webp', 0.92);
      } catch {
        finish(undefined, new Error('Image metadata removal failed'));
      }
    };

    img.onerror = () => {
      finish(undefined, new Error('Image could not be decoded safely'));
    };

    img.src = objectUrl;
  });
}
