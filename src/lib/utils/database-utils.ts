import {
  SECURE_DB_BLOCKED_MIME_TYPES,
  MAX_FILE_SIZE,
  DATABASE_UTILS_FILE_ID_LENGTH_LIMIT,
} from '../constants';
import { isValidDisplayName } from '../sanitizers';
import type { MessageReceipt } from '../../components/chat/messaging/types';

// Sanitize username for database operations
export const sanitizeDbUsername = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return isValidDisplayName(trimmed) ? trimmed : null;
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

  if (!fileId || typeof fileId !== 'string' || fileId.length === 0 || fileId.length > DATABASE_UTILS_FILE_ID_LENGTH_LIMIT) {
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
