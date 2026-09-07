import {
  MAX_MESSAGE_JSON_BYTES,
  MAX_CALL_SIGNAL_BYTES
} from '../constants';

const textEncoder = new TextEncoder();

export const exceedsBytes = (input: string, limit: number): boolean => {
  return textEncoder.encode(input).length > limit;
};

export const safeJsonParse = (jsonString: string, maxBytes: number = MAX_MESSAGE_JSON_BYTES): any => {
  if (!jsonString || typeof jsonString !== 'string') return null;
  if (exceedsBytes(jsonString, maxBytes)) return null;
  const trimmed = jsonString.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  try {
    return JSON.parse(jsonString);
  } catch {
    return null;
  }
};

export const safeJsonParseForCallSignals = (jsonString: string): any => safeJsonParse(jsonString, MAX_CALL_SIGNAL_BYTES);
