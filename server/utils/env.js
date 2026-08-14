export function envInt(name, fallback, min, max) {
  if (!Number.isSafeInteger(fallback) || !Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min > max) {
    throw new RangeError('Invalid integer environment bounds');
  }
  const clamp = (value) => Math.min(max, Math.max(min, value));
  const raw = process.env[name];
  if (typeof raw !== 'string' || !/^-?[0-9]+$/.test(raw.trim())) return clamp(fallback);
  const parsed = Number(raw.trim());
  return Number.isSafeInteger(parsed) ? clamp(parsed) : clamp(fallback);
}
