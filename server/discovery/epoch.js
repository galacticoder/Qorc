import { DISCOVERY_EPOCH_DURATION_MS } from '../../shared/discovery-constants.js';

export { DISCOVERY_EPOCH_DURATION_MS } from '../../shared/discovery-constants.js';

export function getDiscoveryEpochInfo(now = Date.now()) {
  if (!Number.isFinite(now) || now < 0) {
    throw new Error('Invalid discovery epoch time');
  }
  const current = Math.floor(now / DISCOVERY_EPOCH_DURATION_MS);
  const startedAt = current * DISCOVERY_EPOCH_DURATION_MS;
  return {
    current,
    previous: Math.max(0, current - 1),
    startedAt,
    rotatesAt: startedAt + DISCOVERY_EPOCH_DURATION_MS
  };
}

export function currentDiscoveryEpochId(now = Date.now()) {
  return String(getDiscoveryEpochInfo(now).startedAt);
}
