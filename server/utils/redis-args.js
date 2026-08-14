export function exactRedisScoreArgument(value, context = 'lease') {
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric < 0) {
    throw new Error(`Invalid Redis ${context} score`);
  }
  return String(numeric);
}
