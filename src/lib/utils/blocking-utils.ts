// Convert hex string to Uint8Array
export const hexToBytes = (hex: string): Uint8Array => {
  const len = hex.length;
  const bytes = new Uint8Array(len >>> 1);
  for (let i = 0; i < len; i += 2) {
    bytes[i >>> 1] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
};

// Convert Uint8Array to hex string
export const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

// Validate username format
export const validateUsername = (username: string): void => {
  if (typeof username !== 'string' || username.length < 3 || username.length > 128) {
    throw new Error('Invalid username');
  }

  if (/[\x00-\x1F\x7F]/.test(username)) {
    throw new Error('Username contains invalid control characters');
  }

  const isPseudonym = /^[a-f0-9]{32,}$/i.test(username);

  if (isPseudonym) {
    if (username.length > 128) {
      throw new Error('Invalid pseudonymized username length');
    }
    return;
  }

  if (!/^(?!__)[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])$/.test(username)) {
    throw new Error('Username contains invalid characters');
  }
  if (['__proto__', 'constructor', 'prototype'].includes(username)) {
    throw new Error('Username contains reserved identifier');
  }
};

// Check if username is a pseudonymized hash
export const isPseudonymizedUsername = (username: string): boolean => {
  return /^(?:[a-f0-9]{32}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(username);
};