/**
 * WebSocket Utility Functions
 */

export const estimateBase64DecodedBytes = (value: string): number => {
  const trimmed = value.trim();
  if (!trimmed) return 0;
  const pad = trimmed.endsWith('==') ? 2 : trimmed.endsWith('=') ? 1 : 0;
  return Math.floor((trimmed.length * 3) / 4) - pad;
};
