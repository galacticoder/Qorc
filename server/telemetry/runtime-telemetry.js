import fs from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { getClusterTelemetry } from '../cluster/cluster-integration.js';

const TLS_REFRESH_MS = 60_000;
let tlsCache = { checkedAt: 0, state: 'checking', commonName: null, daysRemaining: null };

function serviceEndpoint(raw, fallback) {
  const value = typeof raw === 'string' && raw.length > 0 ? raw : fallback;
  try {
    const url = new URL(value);
    const protocol = url.protocol.replace(/:$/, '');
    const port = url.port ? `:${url.port}` : '';
    const pathname = url.pathname && url.pathname !== '/' ? url.pathname : '';
    return `${protocol}://${url.hostname}${port}${pathname}`;
  } catch {
    return null;
  }
}

function databaseEndpoint() {
  if (process.env.DATABASE_URL) {
    const endpoint = serviceEndpoint(process.env.DATABASE_URL, '');
    if (endpoint) return endpoint;
  }
  const host = process.env.DB_CONNECT_HOST || process.env.PGHOST || '127.0.0.1';
  const port = process.env.PGPORT || '5432';
  const database = process.env.PGDATABASE || process.env.DB_NAME || 'Qor';
  return `postgres://${host}:${port}/${database}`;
}

function tlsSnapshot() {
  const now = Date.now();
  if (now - tlsCache.checkedAt < TLS_REFRESH_MS) return tlsCache;
  const certificatePath = process.env.TLS_CERT_PATH;
  if (!certificatePath) {
    tlsCache = { checkedAt: now, state: 'missing', commonName: null, daysRemaining: null };
    return tlsCache;
  }
  try {
    const certificate = new X509Certificate(fs.readFileSync(certificatePath));
    const expiresAt = Date.parse(certificate.validTo);
    const commonName = /(?:^|[\n,])\s*CN\s*=\s*([^,\n]+)/.exec(certificate.subject)?.[1]?.trim() || null;
    const daysRemaining = Number.isFinite(expiresAt)
      ? Math.ceil((expiresAt - now) / 86_400_000)
      : null;
    tlsCache = {
      checkedAt: now,
      state: daysRemaining !== null && daysRemaining < 0 ? 'expired' : 'valid',
      commonName,
      daysRemaining,
    };
  } catch {
    tlsCache = { checkedAt: now, state: 'unavailable', commonName: null, daysRemaining: null };
  }
  return tlsCache;
}

export function getServerRuntimeTelemetry() {
  const tls = tlsSnapshot();
  const cluster = getClusterTelemetry();
  return {
    serverId: cluster.serverId || process.env.SERVER_ID || 'default',
    pid: process.pid,
    clusterRegistration: cluster.registration,
    heartbeatAgeSeconds: cluster.heartbeatAgeSeconds,
    tlsState: tls.state,
    tlsCommonName: tls.commonName,
    tlsDaysRemaining: tls.daysRemaining,
    redisEndpoint: serviceEndpoint(process.env.REDIS_URL, 'rediss://redis:6379'),
    databaseEndpoint: databaseEndpoint(),
  };
}
