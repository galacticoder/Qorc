export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    hex += (byte < 16 ? '0' : '') + byte.toString(16);
  }
  return hex;
}

export function isHashedUsername(username: string): boolean {
  if (!username) return false;
  const trimmed = username.trim();
  if (trimmed.length < 32) return false;

  const hashPatterns = [
    /^[a-f0-9]{32}$/i,
    /^[a-f0-9]{40}$/i,
    /^[a-f0-9]{64}$/i,
    /^[a-f0-9]{128}$/i,
    /^[a-f0-9]{32,}$/i
  ];

  return hashPatterns.some(pattern => pattern.test(trimmed));
}

export function sanitizeUsernameInput(input: string): string {
  return typeof input === 'string' ? input.trim() : '';
}