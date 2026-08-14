export function wipeBytes(value) {
  if (!(value instanceof Uint8Array)) return;
  try {
    value.fill(0);
  } catch {
  }
}

export function wipeByteArrays(values) {
  if (!Array.isArray(values)) return;
  for (const value of values) wipeBytes(value);
}

export function wipeIssuedTokenBatch(batch) {
  wipeByteArrays(batch?.signedBlindedTokens);
  wipeBytes(batch?.proof);
}
