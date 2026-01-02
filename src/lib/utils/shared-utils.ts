import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';

export const validateEventDetail = (detail: unknown): detail is { messageId: string; newContent?: string } => {
  if (!isPlainObject(detail)) return false;
  if (hasPrototypePollutionKeys(detail)) return false;
  return typeof detail.messageId === 'string';
};