export function createWindowBudget({ windowMs, maxCount, maxBytes }) {
  const states = new WeakMap();
  return (owner, bytes) => {
    const now = Date.now();
    let state = states.get(owner);
    if (!state || now - state.startedAt > windowMs) {
      state = { startedAt: now, count: 0, bytes: 0 };
      states.set(owner, state);
    }
    state.count += 1;
    state.bytes += Math.max(0, bytes);
    return state.count <= maxCount && state.bytes <= maxBytes;
  };
}
