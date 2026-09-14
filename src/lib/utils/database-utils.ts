import { USERNAME_DISPLAY_MAX_LENGTH, SECURE_DB_BLOCKED_MIME_TYPES, MAX_FILE_SIZE } from '../constants';
import type { MessageReceipt } from '../../components/chat/messaging/types';

// Sanitize username for database operations
export const sanitizeDbUsername = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > USERNAME_DISPLAY_MAX_LENGTH) return null;
  if (/[\x00-\x1F\x7F]/.test(trimmed)) return null;
  return trimmed;
};

// Validate file data
export const validateFileData = (data: ArrayBuffer | Blob, fileId: string): void => {
  const size = data instanceof Blob ? data.size : data.byteLength;

  if (size > MAX_FILE_SIZE) {
    throw new Error(`File too large: ${size} bytes (max: ${MAX_FILE_SIZE})`);
  }

  if (size === 0) {
    throw new Error('File is empty');
  }

  if (!fileId || typeof fileId !== 'string' || fileId.length === 0 || fileId.length > 255) {
    throw new Error('Invalid file ID');
  }

  if (data instanceof Blob && data.type) {
    const mimeType = data.type.toLowerCase();
    if (SECURE_DB_BLOCKED_MIME_TYPES.some(blocked => mimeType.includes(blocked))) {
      throw new Error(`Blocked file type: ${data.type}`);
    }
  }
}

// Merge receipt fields to avoid overwriting more recent updates
export const mergeReceipts = (
  existing: MessageReceipt | undefined,
  pending: MessageReceipt | undefined
): MessageReceipt => ({
  delivered: existing?.delivered || pending?.delivered || false,
  read: existing?.read || pending?.read || false,
  deliveredAt: existing?.deliveredAt || pending?.deliveredAt,
  readAt: existing?.readAt || pending?.readAt,
});
