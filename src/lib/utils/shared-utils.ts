import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const validateEventDetail = (detail: unknown): detail is { messageId: string; newContent?: string } => {
  if (!isPlainObject(detail)) return false;
  if (hasPrototypePollutionKeys(detail)) return false;
  return typeof detail.messageId === 'string';
};

export const concatUint8Arrays = (...arrays: Uint8Array[]): Uint8Array => {
  if (arrays.length === 0) return new Uint8Array(0);
  if (arrays.length === 1) return new Uint8Array(arrays[0]);

  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
};