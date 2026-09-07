import { X509Certificate } from 'node:crypto';
import path from 'node:path';
import { getClusterTelemetry } from '../cluster/cluster-integration.js';
import { readSecureTlsFile } from '../utils/secure-file.js';
import { safeServiceEndpointForDisplay } from '../utils/safe-url.js';

const TLS_REFRESH_MS = 60_000;
let tlsCache = { checkedAt: 0, state: 'checking', commonName: null, daysRemaining: null };

function databaseEndpoint() {
  return safeServiceEndpointForDisplay(process.env.DATABASE_URL);
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
    const certificate = new X509Certificate(readSecureTlsFile(path.resolve(certificatePath)));
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
    serverId: cluster.serverId,
    pid: process.pid,
    clusterRegistration: cluster.registration,
    heartbeatAgeSeconds: cluster.heartbeatAgeSeconds,
    tlsState: tls.state,
    tlsCommonName: tls.commonName,
    tlsDaysRemaining: tls.daysRemaining,
    redisEndpoint: safeServiceEndpointForDisplay(process.env.REDIS_URL),
    databaseEndpoint: databaseEndpoint(),
  };
}
