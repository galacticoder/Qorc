import os from 'node:os';

export const LOOPBACK_HOST = '127.0.0.1';
export const HAPROXY_PID_FILE = 'haproxy-auto.pid';
export const NO_STORE_CACHE_CONTROL = 'no-store, max-age=0';
export const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;
export const TEMP_DIRECTORY = os.tmpdir();
export const TOR_BOOTSTRAP_TIMEOUT_MS = 5 * 60 * 1000;
export const TOR_PUBLICATION_TIMEOUT_MS = 15 * 60 * 1000;
export const TOR_PROCESS_STOP_TIMEOUT_MS = 10 * 1000;

export function haproxyStatsSocketPath() {
  if (typeof process.getuid !== 'function') throw new Error('HAProxy requires a POSIX runtime');
  return `${TEMP_DIRECTORY}/haproxy-admin-${process.getuid()}.sock`;
}

export function haproxyStatsDashboardUrl(port = process.env.HAPROXY_STATS_PORT) {
  if (typeof port !== 'string' && typeof port !== 'number') {
    throw new Error('HAPROXY_STATS_PORT is required');
  }
  if (!/^\d{1,5}$/.test(String(port)) || Number(port) < 1 || Number(port) > 65535) {
    throw new Error('HAPROXY_STATS_PORT must be an integer from 1 through 65535');
  }
  return `http://localhost:${port}/haproxy-stats`;
}
