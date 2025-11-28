import cluster from 'cluster';
import fs from 'fs';
import https from 'https';
import os from 'os';
import path from 'path';
import crypto from 'crypto';

export function parseClusterWorkers(rawValue, { logger = console, defaultWorkers = 1, maxWorkers = 32 } = {}) {
  const envValue = (rawValue || '').trim();
  if (!envValue) {
    return defaultWorkers;
  }

  const parsed = Number.parseInt(envValue, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    logger?.warn?.(`[BOOTSTRAP] Invalid CLUSTER_WORKERS value '${envValue}', using default: ${defaultWorkers}`);
    return defaultWorkers;
  }

  if (parsed > maxWorkers) {
    logger?.warn?.(`[BOOTSTRAP] CLUSTER_WORKERS value ${parsed} exceeds maximum ${maxWorkers}, using ${maxWorkers}`);
    return maxWorkers;
  }

  return parsed;
}

function validateCertificateContent(key, cert, { logger = console } = {}) {
  // Basic validation of certificate content
  if (!key || !cert) {
    logger?.error?.('[BOOTSTRAP] Missing key or certificate content');
    return false;
  }

  // Check if key looks like a PEM-encoded private key
  const keyStr = key.toString('utf8');
  if (!keyStr.includes('BEGIN') || !keyStr.includes('PRIVATE KEY')) {
    logger?.error?.('[BOOTSTRAP] Key does not appear to be a valid PEM-encoded private key');
    return false;
  }

  // Check if cert looks like a PEM-encoded certificate
  const certStr = cert.toString('utf8');
  if (!certStr.includes('BEGIN CERTIFICATE') || !certStr.includes('END CERTIFICATE')) {
    logger?.error?.('[BOOTSTRAP] Certificate does not appear to be a valid PEM-encoded certificate');
    return false;
  }

  try {
    crypto.createPrivateKey({ key, format: 'pem' });
  } catch (e) {
    logger?.error?.('[BOOTSTRAP] Private key parse failed:', e?.message || e);
    return false;
  }
  try {
    new crypto.X509Certificate(cert);
  } catch (e) {
    logger?.error?.('[BOOTSTRAP] Certificate parse failed:', e?.message || e);
    return false;
  }

  return true;
}

export function validateCertPath(certPath, { logger = console } = {}) {
  if (!certPath || typeof certPath !== 'string') return false;

  if (certPath.length > 1000) {
    logger?.error?.('[BOOTSTRAP] Certificate path too long:', certPath.length);
    return false;
  }

  const dangerousPatterns = ['../', '..\\', '%2e%2e', '%2f', '%5c', '\\0'];
  const lowerPath = certPath.toLowerCase();
  for (const pattern of dangerousPatterns) {
    if (lowerPath.includes(pattern)) {
      logger?.error?.('[BOOTSTRAP] Dangerous pattern detected in certificate path:', pattern);
      return false;
    }
  }

  const normalizedPath = path.resolve(certPath);

  const allowedExtensions = ['.pem', '.crt', '.key'];
  const ext = path.extname(normalizedPath).toLowerCase();
  if (!allowedExtensions.includes(ext)) {
    logger?.error?.('[BOOTSTRAP] Invalid certificate file extension:', ext);
    return false;
  }

  try {
    fs.accessSync(normalizedPath, fs.constants.R_OK);
  } catch (error) {
    logger?.error?.('[BOOTSTRAP] Certificate file not accessible:', error.message);
    return false;
  }

  return normalizedPath;
}

export function loadServerCertificates({ certPath, keyPath, logger = console } = {}) {
  const validCertPath = certPath ? validateCertPath(certPath, { logger }) : null;
  const validKeyPath = keyPath ? validateCertPath(keyPath, { logger }) : null;

  if (validCertPath && validKeyPath && fs.existsSync(validCertPath) && fs.existsSync(validKeyPath)) {
    logger?.log?.('[BOOTSTRAP] Using provided TLS certificate and key');
    try {
      const key = fs.readFileSync(validKeyPath);
      const cert = fs.readFileSync(validCertPath);

      // Validate certificate contents
      if (!validateCertificateContent(key, cert, { logger })) {
        const error = new Error('Invalid certificate or key content');
        logger?.error?.('[BOOTSTRAP]', error.message);
        throw error;
      }

      return {
        key,
        cert,
        source: 'provided',
      };
    } catch (error) {
      logger?.error?.('[BOOTSTRAP] Failed to read/validate TLS certificates:', error.message);
      throw new Error('TLS certificate loading failed. Cannot continue.');
    }
  }

  throw new Error('TLS_CERT_PATH and TLS_KEY_PATH are required.');
}

export function createHttpsServer({ app, key, cert }) {
  if (!app) throw new Error('createHttpsServer requires an Express app instance');
  if (!key || !cert) throw new Error('createHttpsServer requires TLS key and certificate');

  const httpsOptions = {
    key,
    cert,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
    ].join(':'),
    honorCipherOrder: true,
    sessionTimeout: 0,
    sessionIdContext: 'no-session-reuse',
    requestCert: false,
    rejectUnauthorized: false,
  };

  return https.createServer(httpsOptions, app);
}

export async function createServer({
  clusterSize,
  createApp,
  createWebSocketServer,
  onServerReady,
  prepareWorkerContext,
  tls: { certPath, keyPath } = {},
  logger = console,
  onWorkerExit,
  workerBootstrapTimeoutMs = 30000,
} = {}) {
  if (typeof createApp !== 'function') {
    throw new Error('createServer requires a createApp function');
  }

  const bindAddr = process.env.BIND_ADDRESS || '127.0.0.1';
  const loopbacks = new Set(['127.0.0.1', '::1', 'localhost', '0.0.0.0']);
  if (!loopbacks.has(bindAddr)) {
  }

  const requestedWorkers = clusterSize ?? process.env.CLUSTER_WORKERS;
  const workerCount = parseClusterWorkers(requestedWorkers, { logger });
  const useCluster = workerCount > 1;

  const startWorkerInstance = async ({ key, cert, source, context, workerId }) => {
    const app = await createApp({ context, workerId, isClusterWorker: cluster.isWorker });
    const server = createHttpsServer({ app, key, cert });
    const wss = typeof createWebSocketServer === 'function' ? await createWebSocketServer({ server, context, workerId }) : null;

    if (typeof onServerReady === 'function') {
      await onServerReady({ app, server, wss, context, workerId, tls: { key, cert, source } });
    }

    return { app, server, wss };
  };

  if (useCluster && cluster.isPrimary) {
    const { key, cert, source } = loadServerCertificates({ certPath, keyPath, logger });
    logger?.log?.(`[BOOTSTRAP] TLS source: ${source}`);

    const sharedContext = typeof prepareWorkerContext === 'function'
      ? await prepareWorkerContext({ key, cert, workerCount, mode: 'primary' })
      : {};

    logger?.log?.(`[BOOTSTRAP] Primary starting ${workerCount} workers (cpus=${os.cpus().length})`);

    for (let i = 0; i < workerCount; i += 1) {
      const worker = cluster.fork();
      worker.on('online', () => {
        worker.send({
          type: 'bootstrap:init',
          tls: { key, cert, source },
          context: sharedContext,
          workerId: worker.id,
        });
      });
    }

    const workerRespawns = new Map(); // workerId -> { count, lastRespawn }
    const RESPAWN_LIMIT = 5;
    const RESPAWN_WINDOW_MS = 60000; // 1 minute

    cluster.on('exit', (worker, code, signal) => {
      if (typeof onWorkerExit === 'function') {
        onWorkerExit({ worker, code, signal });
      } else {
        const now = Date.now();
        const workerId = worker.id;
        const respawnData = workerRespawns.get(workerId) || { count: 0, lastRespawn: now };

        // Reset counter if outside window
        if (now - respawnData.lastRespawn > RESPAWN_WINDOW_MS) {
          respawnData.count = 0;
        }

        respawnData.count++;
        respawnData.lastRespawn = now;
        workerRespawns.set(workerId, respawnData);

        // Check if respawn limit exceeded
        if (respawnData.count > RESPAWN_LIMIT) {
          logger?.error?.(`[BOOTSTRAP] Worker ${worker.process.pid} respawn limit exceeded (${RESPAWN_LIMIT} respawns in ${RESPAWN_WINDOW_MS}ms). Not respawning.`);
          logger?.error?.('[BOOTSTRAP] This indicates a critical issue. Please investigate and restart the server manually.');
          return;
        }

        logger?.warn?.(`[BOOTSTRAP] Worker ${worker.process.pid} exited (code=${code}, signal=${signal}). Respawning... (${respawnData.count}/${RESPAWN_LIMIT})`);
        const newWorker = cluster.fork();
        // Transfer respawn tracking to new worker
        workerRespawns.delete(workerId);
        workerRespawns.set(newWorker.id, respawnData);
      }
    });

    return { mode: 'cluster-primary', workerCount, context: sharedContext };
  }

  if (useCluster && cluster.isWorker) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('Timed out waiting for bootstrap init message'));
      }, workerBootstrapTimeoutMs);

      process.once('message', async (msg) => {
        clearTimeout(timer);

        if (!msg || msg.type !== 'bootstrap:init') {
          return reject(new Error('Unexpected bootstrap init payload'));
        }

        try {
          const { tls, context, workerId } = msg;
          const result = await startWorkerInstance({ key: tls.key, cert: tls.cert, source: tls.source, context, workerId });
          resolve({ mode: 'cluster-worker', ...result, context, workerId });
        } catch (error) {
          reject(error);
        }
      });
    });
  }

  const { key, cert, source } = loadServerCertificates({ certPath, keyPath, logger });
  logger?.log?.(`[BOOTSTRAP] TLS source: ${source}`);
  const context = typeof prepareWorkerContext === 'function'
    ? await prepareWorkerContext({ key, cert, workerCount: 1, mode: 'single' })
    : {};
  const result = await startWorkerInstance({ key, cert, source, context, workerId: 0 });

  return { mode: 'single', ...result, context };
}

export function registerShutdownHandlers({
  signals = ['SIGTERM', 'SIGINT', 'SIGQUIT'],
  handler,
  logger = console,
} = {}) {
  if (typeof handler !== 'function') {
    throw new Error('registerShutdownHandlers requires a handler function');
  }

  let isShuttingDown = false;

  const wrappedHandler = (signal) => {
    if (isShuttingDown) {
      logger?.warn?.(`[BOOTSTRAP] Already shutting down, ignoring ${signal}`);
      return;
    }
    isShuttingDown = true;

    logger?.log?.(`[BOOTSTRAP] Received ${signal}, initiating shutdown...`);

    const forceExitTimeout = setTimeout(() => {
      logger?.warn?.('[BOOTSTRAP] Shutdown timeout - forcing exit');
      process.exit(1);
    }, 10000);

    Promise.resolve(handler(signal))
      .then(() => {
        clearTimeout(forceExitTimeout);
        logger?.log?.('[BOOTSTRAP] Shutdown complete');
        process.exit(0);
      })
      .catch((error) => {
        clearTimeout(forceExitTimeout);
        logger?.error?.('[BOOTSTRAP] Error during shutdown:', error);
        process.exit(1);
      });
  };

  for (const signal of signals) {
    process.on(signal, () => wrappedHandler(signal));
  }

  return () => {
    for (const signal of signals) {
      process.removeListener(signal, wrappedHandler);
    }
  };
}
