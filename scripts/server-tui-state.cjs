'use strict';

function parseRegistration(rawValue, now = Date.now()) {
  const normalized = typeof rawValue === 'string' ? rawValue.trim() : '';
  if (normalized.length === 0 || normalized === '(nil)') {
    return { registration: 'pending', heartbeatAge: null };
  }

  try {
    const value = JSON.parse(normalized);
    const lastHeartbeat = Number(value?.lastHeartbeat || 0);
    if (!value || typeof value !== 'object' || !Number.isSafeInteger(lastHeartbeat) || lastHeartbeat <= 0) {
      return { registration: 'corrupt', heartbeatAge: null };
    }
    return {
      registration: 'registered',
      heartbeatAge: Math.max(0, Math.floor((now - lastHeartbeat) / 1000)),
    };
  } catch {
    return { registration: 'corrupt', heartbeatAge: null };
  }
}

module.exports = {
  parseRegistration,
};
