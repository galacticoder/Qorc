import fs from 'fs';
import https from 'https';
import path from 'path';
import crypto from 'crypto';
import { LOOPBACK_HOST } from '../config/infrastructure.js';
import { envInt } from '../utils/env.js';
import { readSecureTlsFile } from '../utils/secure-file.js';

export { readSecureTlsFile } from '../utils/secure-file.js';

// Basic validation of certificate content
function validateCertificateContent(key, cert, { logger = console } = {}) {
  if (!key || !cert) {
    logger?.error?.('[BOOTSTRAP] Missing key or certificate content');
    return false;
  }

  const keyStr = key.toString('utf8');
  if (!keyStr.includes('BEGIN') || !keyStr.includes('PRIVATE KEY')) {
    logger?.error?.('[BOOTSTRAP] Key is not a valid PEM encoded private key');
    return false;
  }

  const certStr = cert.toString('utf8');
  if (!certStr.includes('BEGIN CERTIFICATE') || !certStr.includes('END CERTIFICATE')) {
    logger?.error?.('[BOOTSTRAP] Certificate is not a valid PEM encoded certificate');
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
    let key;
    let cert;
    try {
      key = readSecureTlsFile(validKeyPath, { privateKey: true });
      cert = readSecureTlsFile(validCertPath);

      if (!validateCertificateContent(key, cert, { logger })) {
        const error = new Error('Invalid certificate or key content');
        logger?.error?.('[BOOTSTRAP]', error.message);
        throw error;
      }

      return { key, cert };
    } catch (error) {
      key?.fill(0);
      cert?.fill(0);
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
    ecdhCurve: 'X25519MLKEM768',
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
    ].join(':'),
    honorCipherOrder: true,
    secureOptions: crypto.constants.SSL_OP_NO_TICKET,
    sessionTimeout: 0,
    sessionIdContext: 'no-session-reuse',
    requestCert: false,
  };
  let server;
  try {
    server = https.createServer(httpsOptions, app);
  } catch (error) {
    throw new Error(`Hybrid post-quantum TLS is unavailable: ${error.message}`);
  }
  server.on('newSession', (_sessionId, _sessionData, callback) => callback());
  server.on('resumeSession', (_sessionId, callback) => callback(null, null));

  const requestTimeoutMs = envInt('HTTPS_REQUEST_TIMEOUT_MS', 180_000, 5_000, 300_000);
  server.headersTimeout = envInt('HTTPS_HEADERS_TIMEOUT_MS', 15_000, 5_000, requestTimeoutMs);
  server.requestTimeout = requestTimeoutMs;
  server.keepAliveTimeout = envInt('HTTPS_KEEP_ALIVE_TIMEOUT_MS', 5_000, 1_000, 30_000);
  server.timeout = envInt('HTTPS_SOCKET_IDLE_TIMEOUT_MS', 120_000, 30_000, 10 * 60_000);
  server.maxHeadersCount = envInt('HTTPS_MAX_HEADER_COUNT', 64, 16, 256);
  server.maxRequestsPerSocket = envInt('HTTPS_MAX_REQUESTS_PER_SOCKET', 128, 1, 1_024);
  server.maxConnections = envInt('HTTPS_MAX_CONNECTIONS', 8_192, 64, 100_000);
  return server;
}

export async function createServer({
  createApp,
  createWebSocketServer,
  onServerReady,
  prepareServerContext,
  tls: { certPath, keyPath } = {},
  logger = console,
} = {}) {
  if (typeof createApp !== 'function') {
    throw new Error('createServer requires a createApp function');
  }
  if (typeof createWebSocketServer !== 'function') {
    throw new Error('createServer requires a createWebSocketServer function');
  }
  if (typeof onServerReady !== 'function') {
    throw new Error('createServer requires an onServerReady function');
  }
  if (typeof prepareServerContext !== 'function') {
    throw new Error('createServer requires a prepareServerContext function');
  }

  const bindAddr = process.env.BIND_ADDRESS || LOOPBACK_HOST;
  const loopbacks = new Set([LOOPBACK_HOST, '::1', 'localhost']);
  if (!loopbacks.has(bindAddr)) {
    (logger?.warn ?? console.warn)(
      `[BOOTSTRAP] Binding to non loopback address ${bindAddr}`
    );
  }

  const { key, cert } = loadServerCertificates({ certPath, keyPath, logger });
  try {
    const context = await prepareServerContext({ key, cert });
    const app = await createApp({ context });
    const server = createHttpsServer({ app, key, cert });
    const wss = await createWebSocketServer({ server, context });
    await onServerReady({ app, server, wss, context });
    return { app, server, wss, context };
  } finally {
    key.fill(0);
    cert.fill(0);
  }
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
      return;
    }
    isShuttingDown = true;

    logger?.log?.(`[BOOTSTRAP] Received ${signal}, initiating shutdown...`);

    const forceExitTimeout = setTimeout(() => {
      logger?.warn?.('[BOOTSTRAP] Shutdown timeout, forcing exit');
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

  const listeners = new Map();
  for (const signal of signals) {
    const listener = () => wrappedHandler(signal);
    listeners.set(signal, listener);
    process.on(signal, listener);
  }

  return () => {
    for (const [signal, listener] of listeners) {
      process.removeListener(signal, listener);
    }
    listeners.clear();
  };
}
