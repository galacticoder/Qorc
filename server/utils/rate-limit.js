export function createTokenBucketRateLimiter(maxPerSecond) {
  const capacity = Math.max(1, maxPerSecond);
  let tokens = capacity;
  let updatedAt = Date.now();
  return () => {
    const now = Date.now();
    if (now > updatedAt) {
      tokens = Math.min(capacity, tokens + ((now - updatedAt) / 1000) * capacity);
      updatedAt = now;
    }
    if (tokens < 1) return false;
    tokens -= 1;
    return true;
  };
}
