/**
 * Electron Main Process
 */

const nodeCrypto = require('crypto');
if (typeof global.crypto === 'undefined') {
  global.crypto = nodeCrypto.webcrypto;
}

const { app, BrowserWindow, ipcMain, desktopCapturer, dialog, shell, powerSaveBlocker } = require('electron');

process.on('unhandledRejection', (reason) => {
  try { console.error('[MAIN] UnhandledRejection:', reason?.message || String(reason)); } catch (_) { }
  try { dialog.showErrorBox('Unhandled Error', String(reason?.message || reason || 'Unknown')); } catch (_) { }
  try { app.exit(1); } catch (_) { try { process.exit(1); } catch (_) { } }
});
process.on('uncaughtException', (err) => {
  try { console.error('[MAIN] UncaughtException:', err?.message || String(err)); } catch (_) { }
  try { dialog.showErrorBox('Uncaught Exception', String(err?.message || err || 'Unknown')); } catch (_) { }
  try { app.exit(1); } catch (_) { try { process.exit(1); } catch (_) { } }
});

function fatalExit(message) {
  const msg = String(message || 'Fatal error');
  try { console.error('[MAIN] FATAL:', msg); } catch (_) { }
  try { process.stderr.write(msg + '\n'); } catch (_) { }
  try { dialog.showErrorBox('Application Error', msg); } catch (_) { }
  try { app.exit(1); } catch (_) { try { process.exit(1); } catch (_) { } }
}
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

app.disableHardwareAcceleration();

const { initDeviceCredentials } = require('./handlers/device-credentials.cjs');
const { SecurityMiddleware } = require('./handlers/security-middleware.cjs');
const { StorageHandler } = require('./handlers/storage-handler.cjs');
const { WebSocketHandler } = require('./handlers/websocket-handler.cjs');
const { QuantumResistantSignalHandler } = require('./handlers/signal-handler-v2.cjs');
const { FileHandler } = require('./handlers/file-handler.cjs');

const ElectronTorManager = require('./tor-manager.cjs');
const torManager = new ElectronTorManager({ appInstance: app });

if (process.env.ELECTRON_INSTANCE_ID) {
  const instanceId = process.env.ELECTRON_INSTANCE_ID;
  const baseUserDataPath = app.getPath('userData');
  const instanceUserDataPath = `${baseUserDataPath}-instance-${instanceId}`;
  app.setPath('userData', instanceUserDataPath);
}

let mainWindow = null;
let securityMiddleware = null;
let storageHandler = null;
let websocketHandler = null;
let signalHandlerV2 = null;
let fileHandler = null;
let powerSaveBlockerId = null;

async function setupSecureLogging() {
  process.on('uncaughtException', (err) => {
    dialog.showErrorBox('Critical Error', 'Application error occurred');
    app.quit();
  });
}

async function verifyLibsignalNativeAvailability() {
  try {
    const pkgJsonPath = require.resolve('@signalapp/libsignal-client/package.json');
    const pkgDir = path.dirname(pkgJsonPath);
    const prevCwd = process.cwd();
    let native;
    try {
      if (prevCwd !== pkgDir) process.chdir(pkgDir);
      const mod = await import('@signalapp/libsignal-client');
      native = mod?.default ?? mod;
    } finally {
      try { if (process.cwd() !== prevCwd) process.chdir(prevCwd); } catch (_) { }
    }

    if (!native || !native.IdentityKeyPair || typeof native.IdentityKeyPair.generate !== 'function') {
      throw new Error('libsignal-client API validation failed');
    }
    return { success: true };
  } catch (_) {
    dialog.showErrorBox('Cryptography Module Error', 'Required security modules are not available');
    return { success: false };
  }
}

async function initializeHandlers() {
  try {
    securityMiddleware = new SecurityMiddleware();
    const securityInit = await securityMiddleware.initialize();
    if (!securityInit?.success) {
      throw new Error('Security middleware initialization failed');
    }

    storageHandler = new StorageHandler(app, securityMiddleware);
    const storageInit = await storageHandler.initialize();
    if (!storageInit?.success) {
      throw new Error('Secure storage unavailable');
    }

    fileHandler = new FileHandler(securityMiddleware);
    const fileInit = fileHandler.initialize({
      maxFileSize: 100 * 1024 * 1024,
      basePaths: [app.getPath('userData'), require('os').tmpdir()]
    });
    if (!fileInit?.success) {
      throw new Error('File handler initialization failed');
    }

    // Ensure a stable device ID persisted on this machine 
    let deviceId;

    const existing = await storageHandler.getItem('device-id');
    if (existing?.success && existing.value) {
      deviceId = String(existing.value);
    } else {
      deviceId = crypto.randomBytes(16).toString('hex');
      const stored = await storageHandler.setItem('device-id', deviceId);
      if (!stored?.success) {
        throw new Error('Failed to persist device ID');
      }
    }

    // Ensure per-install Ed25519 device keypair (PEM 
    let devicePubPem;
    let devicePrivPem;

    const pub = await storageHandler.getItem('device-ed25519-public-pem');
    const priv = await storageHandler.getItem('device-ed25519-private-pem');

    if (pub?.success && priv?.success && pub.value && priv.value) {
      devicePubPem = String(pub.value);
      devicePrivPem = String(priv.value);
    } else {
      const { generateKeyPairSync } = require('crypto');
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');

      devicePrivPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
      devicePubPem = publicKey.export({ type: 'spki', format: 'pem' });

      const setPub = await storageHandler.setItem('device-ed25519-public-pem', devicePubPem);
      const setPriv = await storageHandler.setItem('device-ed25519-private-pem', devicePrivPem);

      if (!setPub?.success || !setPriv?.success) {
        throw new Error('Failed to persist device Ed25519 keypair');
      }
    }

    websocketHandler = new WebSocketHandler(securityMiddleware);

    try {
      let connectHostOverride = null;
      try {
        const envText = await fs.readFile(path.join(__dirname, '..', '.env'), 'utf8');
        for (const rawLine of envText.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line || line.startsWith('#')) continue;
          const eq = line.indexOf('=');
          if (eq === -1) continue;
          const key = line.slice(0, eq).trim();
          let val = line.slice(eq + 1);
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          if (key === 'SERVER_HOST') {
            connectHostOverride = val;
            break;
          }
        }
      } catch (_) { }
      if (connectHostOverride && (connectHostOverride === '127.0.0.1' || connectHostOverride === 'localhost' || connectHostOverride === '::1')) {
        websocketHandler.setConnectHost(connectHostOverride);
      }
      const clientVersion = (typeof app.getVersion === 'function') ? app.getVersion() : 'unknown';
      websocketHandler.setExtraHeaders({
        'x-device-id': deviceId,
        'x-client-version': String(clientVersion),
        'x-client-name': 'End2End Chat'
      });
      if (devicePubPem && devicePrivPem) {
        websocketHandler.setDeviceKeys({
          deviceId,
          publicKeyPem: devicePubPem,
          privateKeyPem: devicePrivPem,
        });
      }
    } catch (_) { }

    const defaultWsUrl = process.env.VITE_WS_URL || 'wss://localhost:8443';
    const wsInit = await websocketHandler.initialize({
      defaultUrl: defaultWsUrl,
      reconnectAttempts: 5,
      reconnectDelay: 2000
    });
    if (!wsInit?.success) {
      throw new Error('WebSocket handler initialization failed');
    }

    websocketHandler.onMessage = (message) => {
      if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents && !mainWindow.webContents.isDestroyed()) {
        try {
          mainWindow.webContents.send('edge:server-message', message);
        } catch (error) {
          console.error('[MAIN] Failed to send message to renderer:', error.message);
        }
      }
    };

    signalHandlerV2 = new QuantumResistantSignalHandler(securityMiddleware);
    const nativeCheck = await verifyLibsignalNativeAvailability();
    if (!nativeCheck.success) {
      throw new Error('libsignal-client verification failed');
    }

    const installPath = app.getPath('userData');
    initDeviceCredentials({ logger: console, installPath });

    return true;
  } catch (error) {
    const msg = String(error?.message || 'Initialization failed');
    console.error('[MAIN] Critical initialization failure:', msg);
    try { dialog.showErrorBox('Critical Initialization Failure', msg); } catch (_) { }
    return false;
  }
}

async function createWindow() {
  const webPreferences = {
    nodeIntegration: false,
    contextIsolation: true,
    enableRemoteModule: false,
    preload: path.join(__dirname, 'preload.cjs'),
    partition: 'persist:securechat',
    allowRunningInsecureContent: false,
    experimentalFeatures: false,
    sandbox: true,
    webSecurity: true,
    webgl: false
  };

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences,
    icon: path.join(__dirname, '../public/icon.png'),
    titleBarStyle: 'default',
    show: false,
    backgroundThrottling: false
  });

  try {
    await loadApp();
  } catch (error) {
    mainWindow.loadURL(`data:text/plain;charset=utf-8,Failed to load application`);
  }

  const showWindow = () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.show();
  };

  mainWindow.once('ready-to-show', showWindow);
  const fallbackTimer = setTimeout(showWindow, 3000);
  mainWindow.once('show', () => clearTimeout(fallbackTimer));


  mainWindow.on('close', async () => {
    if (torManager?.isTorRunning()) {
      await torManager.stopTor();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
    if (process.platform !== 'darwin') {
      try { app.quit(); } catch (_) { }
    }
  });

  setupSecurityPolicies();
}

async function loadApp() {
  const distPath = path.join(__dirname, '../dist/index.html');
  try {
    await fs.access(distPath);
    await mainWindow.loadFile(distPath);
  } catch (e) {
    dialog.showErrorBox('Application Error', 'Application build not found');
    app.quit();
  }
}

function setupSecurityPolicies() {
  app.on('web-contents-created', (event, contents) => {
    contents.session.webRequest.onHeadersReceived((details, callback) => {
      const responseHeaders = details.responseHeaders;
      const nonce = crypto.randomBytes(16).toString('base64');

      const cspPolicy = [
        "default-src 'self'; " +
        `script-src 'self' 'nonce-${nonce}'; ` +
        `style-src 'self' 'nonce-${nonce}' 'unsafe-inline'; ` +
        "img-src 'self' data: blob: https:; " +
        "media-src 'self' blob: data:; " +
        "connect-src 'self' wss: ws: https: blob:; " +
        "font-src 'self' data:; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "frame-ancestors 'none'; " +
        "upgrade-insecure-requests;"
      ];

      responseHeaders['content-security-policy'] = cspPolicy;
      responseHeaders['x-frame-options'] = ['DENY'];
      responseHeaders['x-content-type-options'] = ['nosniff'];
      responseHeaders['x-xss-protection'] = ['1; mode=block'];
      responseHeaders['referrer-policy'] = ['strict-origin-when-cross-origin'];
      responseHeaders['strict-transport-security'] = ['max-age=31536000; includeSubDomains'];
      responseHeaders['permissions-policy'] = ['camera=(), microphone=(), geolocation=(), payment=()'];

      callback({ responseHeaders });
    });

    contents.session.setPermissionRequestHandler((_webContents, permission, callback) => {
      const allowed = ['media', 'microphone', 'camera', 'display-capture'];
      callback(allowed.includes(permission));
    });

    contents.session.setPermissionCheckHandler((_webContents, permission) => {
      const allowed = ['media', 'microphone', 'camera', 'display-capture'];
      return allowed.includes(permission);
    });

    contents.on('will-navigate', (e, targetUrl) => {
      try {
        const currentUrlStr = contents.getURL();
        const target = new URL(targetUrl);

        if (target.protocol === 'file:' || target.protocol === 'blob:') {
          return;
        }

        if (currentUrlStr) {
          const current = new URL(currentUrlStr);
          if (current.origin === target.origin) {
            return;
          }
        }

        e.preventDefault();
      } catch (_) {
        e.preventDefault();
      }
    });

    contents.setWindowOpenHandler(({ url }) => {
      shell.openExternal(url).catch(() => { });
      return { action: 'deny' };
    });
  });
}

function registerIPCHandlers() {
  ipcMain.handle('get-user-data-path', async () => {
    try {
      return app.getPath('userData');
    } catch (_) {
      return null;
    }
  });

  ipcMain.handle('system:platform', () => ({
    platform: process.platform,
    arch: process.arch,
    version: process.version
  }));

  ipcMain.handle('app:version', () => app.getVersion());
  ipcMain.handle('app:name', () => app.getName());

  ipcMain.handle('secure:init', async () => {
    return storageHandler ? { success: true } : { success: false };
  });

  ipcMain.handle('secure:set', async (_evt, key, value) => {
    if (!storageHandler) {
      return { success: false, error: 'Storage not initialized' };
    }
    return await storageHandler.setItem(key, value);
  });

  ipcMain.handle('secure:get', async (_evt, key) => {
    if (!storageHandler) {
      return { success: false, error: 'Storage not initialized' };
    }
    return await storageHandler.getItem(key);
  });

  ipcMain.handle('secure:remove', async (_evt, key) => {
    if (!storageHandler) {
      return { success: false, error: 'Storage not initialized' };
    }
    return await storageHandler.removeItem(key);
  });

  ipcMain.handle('tor:start', async () => {
    try {
      return await torManager.startTor();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:stop', async () => {
    try {
      return await torManager.stopTor();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:status', async () => {
    try {
      return await torManager.getTorStatus();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:test-connection', async () => {
    try {
      return await torManager.verifyTorConnection();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:new-circuit', async () => {
    try {
      return await torManager.rotateCircuit();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:rotate-circuit', async () => {
    try {
      return await torManager.rotateCircuit();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:check-installation', async () => {
    try {
      return await torManager.checkTorInstallation();
    } catch (error) {
      return { isInstalled: false, error: error.message };
    }
  });

  ipcMain.handle('tor:download', async () => {
    try {
      return await torManager.downloadTor();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:install', async () => {
    try {
      return await torManager.installTor();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:configure', async (_event, options) => {
    setImmediate(async () => {
      try {
        const result = await torManager.configureTor(options);
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('tor:configure-complete', result);
        }
      } catch (error) {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('tor:configure-complete', { success: false, error: error.message });
        }
      }
    });

    return { success: true, pending: true };
  });

  ipcMain.handle('tor:uninstall', async () => {
    try {
      return await torManager.uninstallTor();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:cleanup-corrupted', async () => {
    try {
      return await torManager.cleanupCorruptedTor();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:info', async () => {
    try {
      return await torManager.getTorInfo();
    } catch (error) {
      return { error: error.message };
    }
  });

  ipcMain.handle('tor:get-info', async () => {
    try {
      return await torManager.getTorInfo();
    } catch (error) {
      return { error: error.message };
    }
  });

  ipcMain.handle('tor:setup-complete', async () => {
    if (websocketHandler) {
      websocketHandler.setTorReady(true);
    }
    return { success: true };
  });

  ipcMain.handle('tor:verify-connection', async () => {
    try {
      return await torManager.verifyTorConnection();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:get-ws-url', async (_event, url) => {
    try {
      return { success: true, url };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('tor:initialize', async (_event, config) => {
    try {
      const status = await torManager.getTorStatus();
      const bootstrapped = status.bootstrapped || false;

      // If Tor is up, mark WebSocket handler as Tor-ready so probes and connections are allowed
      if (websocketHandler && bootstrapped) {
        try {
          websocketHandler.setTorReady(true);
        } catch (e) {
          try {
            console.error('[MAIN] Failed to set WebSocket Tor readiness:', e && e.message ? e.message : e);
          } catch (_) { }
        }
      }

      return {
        success: true,
        bootstrapped,
        socksPort: torManager.effectiveSocksPort || 9150,
        controlPort: torManager.effectiveControlPort || 9151
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('edge:ws-connect', async () => {
    if (!websocketHandler) return { success: false, error: 'WebSocket handler not initialized' };
    return await websocketHandler.connect();
  });

  ipcMain.handle('edge:ws-disconnect', async () => {
    if (!websocketHandler) return { success: false, error: 'WebSocket handler not initialized' };
    return await websocketHandler.disconnect();
  });

  ipcMain.handle('edge:ws-send', async (_event, payload) => {
    if (!websocketHandler) return { success: false, error: 'WebSocket handler not initialized' };
    return await websocketHandler.send(payload);
  });

  // Token refresh via HTTP with device proof
  ipcMain.handle('auth:refresh', async (_event, { refreshToken }) => {
    try {
      if (!websocketHandler || !websocketHandler.serverUrl) {
        return { success: false, error: 'Server URL not configured' };
      }
      const wsUrl = new URL(websocketHandler.serverUrl);
      const httpProto = wsUrl.protocol === 'wss:' ? 'https:' : 'http:';
      const base = `${httpProto}//${wsUrl.host}`;
      const challengeUrl = `${base}/api/auth/refresh-challenge`;
      const refreshUrl = `${base}/api/auth/refresh`;

      const postJson = (url, headers, body) => new Promise((resolve, reject) => {
        const mod = url.startsWith('https:') ? require('https') : require('http');
        const data = Buffer.from(JSON.stringify(body), 'utf8');
        const req = mod.request(url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(data),
            ...headers,
          },
          timeout: 15000,
        }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            try {
              const payload = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
              if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) resolve(payload);
              else resolve({ success: false, status: res.statusCode, ...payload });
            } catch (e) { resolve({ success: false, error: 'Bad JSON' }); }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { try { req.destroy(new Error('timeout')); } catch { } });
        req.write(data);
        req.end();
      });

      const ch = await postJson(challengeUrl, {}, { refreshToken });
      if (!ch || ch.success !== true || !ch.nonce) {
        return { success: false, error: 'Challenge failed', details: ch };
      }

      const parts = String(refreshToken).split('.');
      if (parts.length < 2) return { success: false, error: 'Invalid refresh token' };
      const payloadJson = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      const jti = payloadJson?.jti;
      if (!jti) {
        return { success: false, error: 'Missing jti' };
      }

      const deviceId = websocketHandler.getDeviceId?.();
      if (!deviceId) {
        return { success: false, error: 'No device id' };
      }
      const signature = websocketHandler.signRefreshProof?.({ nonce: ch.nonce, jti });
      if (!signature) {
        return { success: false, error: 'Failed to sign device proof' };
      }

      const headers = {
        'x-device-id': deviceId,
        'x-device-proof': signature,
      };
      const rr = await postJson(refreshUrl, headers, { refreshToken });
      if (!rr || rr.success !== true || !rr.tokens?.accessToken || !rr.tokens?.refreshToken) {
        return { success: false, error: 'Refresh failed', details: rr };
      }
      return { success: true, tokens: rr.tokens };
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle('edge:set-server-url', async (_event, url) => {
    if (!websocketHandler) return { success: false, error: 'WebSocket handler not initialized' };
    return await websocketHandler.setServerUrl(url);
  });

  ipcMain.handle('edge:get-server-url', async () => {
    if (!websocketHandler) return { success: false, serverUrl: null };
    return { success: true, serverUrl: websocketHandler.serverUrl };
  });

  ipcMain.handle('edge:ws-probe-connect', async (_event, url, timeoutMs) => {
    if (!websocketHandler) return { success: false, error: 'WebSocket handler not initialized' };
    return await websocketHandler.probeConnect(url, typeof timeoutMs === 'number' ? timeoutMs : 12000);
  });

  ipcMain.handle('signal-v2:generate-identity', async (_event, { username }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.generateIdentity(username);
  });

  ipcMain.handle('signal-v2:generate-prekeys', async (_event, { username, startId, count }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.generatePreKeys(username, startId || 1, count || 100);
  });

  ipcMain.handle('signal-v2:generate-signed-prekey', async (_event, { username, keyId }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.generateSignedPreKey(username, keyId || 1);
  });

  ipcMain.handle('signal-v2:create-prekey-bundle', async (_event, args) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    const { username } = args || {};
    if (!username || typeof username !== 'string') {
      return { success: false, error: `Invalid username parameter: ${typeof username}` };
    }
    try {
      return await signalHandlerV2.createPreKeyBundle(username);
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('signal-v2:process-prekey-bundle', async (_event, { selfUsername, peerUsername, bundle }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.processPreKeyBundle(selfUsername, peerUsername, bundle);
  });

  ipcMain.handle('signal-v2:has-session', async (_event, { selfUsername, peerUsername, deviceId }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.hasSession(selfUsername, peerUsername, deviceId);
  });

  ipcMain.handle('signal-v2:encrypt', async (_event, args) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    try {
      const { fromUsername, toUsername, plaintext, ...options } = args || {};
      return await signalHandlerV2.encrypt(fromUsername, toUsername, plaintext, options);
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle('signal-v2:decrypt', async (_event, { fromUsername, toUsername, encryptedData }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.decrypt(fromUsername, toUsername, encryptedData);
  });

  ipcMain.handle('signal-v2:delete-session', async (_event, { selfUsername, peerUsername, deviceId }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.deleteSession(selfUsername, peerUsername, deviceId);
  });

  ipcMain.handle('signal-v2:delete-all-sessions', async (_event, { selfUsername, peerUsername }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return await signalHandlerV2.deleteAllSessions(selfUsername, peerUsername);
  });

  ipcMain.handle('signal-v2:set-storage-key', async (_event, { keyBase64 }) => {
    try {
      const storage = require('./handlers/signal-storage.cjs');
      const res = storage.setStorageKey({ keyBase64 });
      return res;
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle('signal-v2:set-static-mlkem-keys', async (_event, { username, publicKeyBase64, secretKeyBase64 }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    try {
      return await signalHandlerV2.setStaticMlkemKeys(username, publicKeyBase64, secretKeyBase64);
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle('signal-v2:trust-peer-identity', async (_event, { selfUsername, peerUsername, deviceId }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    try {
      return await signalHandlerV2.trustPeerIdentity(selfUsername, peerUsername, deviceId || 1);
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  });

  ipcMain.handle('signal-v2:clear-all', async () => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    signalHandlerV2.clearAll();
    return { success: true };
  });

  ipcMain.handle('screen:getSources', async () => {
    try {
      const options = {
        types: ['window', 'screen'],
        thumbnailSize: { width: 300, height: 300 },
        fetchWindowIcons: process.platform === 'win32'
      };

      const sources = await desktopCapturer.getSources(options);
      const validSources = sources.filter(s => s.id && s.name !== undefined);

      return validSources;
    } catch (error) {
      throw error;
    }
  });

  ipcMain.handle('power:psb-start', () => {
    try {
      if (powerSaveBlockerId !== null && powerSaveBlocker.isStarted(powerSaveBlockerId)) {
        return { success: true, id: powerSaveBlockerId };
      }
      powerSaveBlockerId = powerSaveBlocker.start('prevent-app-suspension');
      return { success: true, id: powerSaveBlockerId };
    } catch (e) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('power:psb-stop', () => {
    try {
      if (powerSaveBlockerId !== null && powerSaveBlocker.isStarted(powerSaveBlockerId)) {
        powerSaveBlocker.stop(powerSaveBlockerId);
      }
      powerSaveBlockerId = null;
      return { success: true };
    } catch (e) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('file:save', async (_event, { filename, data, mimeType }) => {
    try {
      if (!fileHandler) {
        return { success: false, error: 'File handler not initialized' };
      }

      if (!filename || !data) {
        throw new Error('Missing filename or data');
      }

      const downloadPath = app.getPath('downloads');
      const savePath = path.join(downloadPath, filename);
      const buffer = Buffer.from(data, 'base64');
      const result = await fileHandler.writeFile(savePath, buffer, { encoding: null });

      return { success: true, path: savePath };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('file:get-download-settings', () => {
    return {
      downloadPath: app.getPath('downloads'),
      autoSave: true
    };
  });

  ipcMain.handle('file:set-download-path', async (_event, newPath) => {
    try {
      if (!newPath || typeof newPath !== 'string') {
        return { success: false, error: 'Path must be a non-empty string' };
      }

      if (!path.isAbsolute(newPath)) {
        return { success: false, error: 'Path must be absolute' };
      }

      if (newPath.includes('\0')) {
        return { success: false, error: 'Path contains null bytes' };
      }

      if (fileHandler) {
        await fileHandler.validatePath(newPath);
      }

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('file:set-auto-save', (_event, autoSave) => {
    return { success: true };
  });

  ipcMain.handle('file:choose-download-path', async () => {
    try {
      const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openDirectory'],
        defaultPath: app.getPath('downloads')
      });

      if (result.canceled) {
        return { success: false, canceled: true };
      }

      return { success: true, path: result.filePaths[0] };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('link:fetch-preview', async (_event, url, options = {}) => {
    try {
      if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL');
      }

      const parsedUrl = new URL(url);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs allowed');
      }

      const timeout = Math.min(options.timeout || 10000, 30000);

      return await new Promise((resolve, reject) => {
        const https = require('https');
        const req = https.get(url, { timeout }, (res) => {
          if (res.statusCode !== 200) {
            return resolve({ url, error: `HTTP ${res.statusCode}` });
          }

          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
            if (data.length > 1048576) {
              req.destroy();
              resolve({ url, error: 'Response too large' });
            }
          });

          res.on('end', () => {
            const titleMatch = data.match(/<title[^>]*>([^<]+)<\/title>/i);
            const descMatch = data.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i);
            const ogTitleMatch = data.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
            const ogDescMatch = data.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']+)["']/i);

            resolve({
              url,
              title: ogTitleMatch?.[1] || titleMatch?.[1] || parsedUrl.hostname,
              description: ogDescMatch?.[1] || descMatch?.[1] || '',
              success: true
            });
          });
        });

        req.on('error', (error) => resolve({ url, error: error.message }));
        req.on('timeout', () => { req.destroy(); resolve({ url, error: 'Timeout' }); });
      });
    } catch (error) {
      return { url, error: error.message || 'Unknown error' };
    }
  });

  ipcMain.handle('shell:open-external', async (_event, url) => {
    try {
      if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL');
      }

      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        throw new Error('Only HTTP/HTTPS URLs are allowed');
      }

      if (url.length > 2048) {
        throw new Error('URL too long');
      }

      await shell.openExternal(url);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('renderer:ready', async () => {
    return { success: true };
  });

  // Onion P2P handlers
  try {
    const { OnionHandler } = require('./handlers/onion-handler.cjs');
    const onionHandler = new OnionHandler({
      torManager, onInboundMessage: (msg) => {
        try {
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('onion:message', msg);
          }
        } catch (_) { }
      }
    });

    ipcMain.handle('onion:create-endpoint', async (_event, args) => {
      try {
        const ttlSeconds = (args && typeof args.ttlSeconds === 'number') ? args.ttlSeconds : 600;
        return await onionHandler.createEndpoint({ ttlSeconds });
      } catch (e) {
        return { success: false, error: e?.message || String(e) };
      }
    });

    ipcMain.handle('onion:send', async (_event, toUsername, payload) => {
      try {
        return await onionHandler.send(String(toUsername || ''), payload);
      } catch (e) {
        return { success: false, error: e?.message || String(e) };
      }
    });

    ipcMain.handle('onion:close', async () => {
      try { return await onionHandler.deleteEndpoint(); } catch (e) { return { success: false, error: e?.message || String(e) }; }
    });
  } catch (e) {
    console.error('[MAIN] Onion handler init failed:', e?.message || e);
  }

  ipcMain.handle('webrtc:get-ice-config', async () => {
    try {
      const turnServers = process.env.TURN_SERVERS ? JSON.parse(process.env.TURN_SERVERS) : null;
      const stunServers = process.env.STUN_SERVERS ? JSON.parse(process.env.STUN_SERVERS) : null;
      const icePolicy = process.env.ICE_TRANSPORT_POLICY || 'all';

      const iceServers = [];

      if (stunServers && Array.isArray(stunServers)) {
        iceServers.push(...stunServers.map(url => ({ urls: url })));
      }

      if (turnServers && Array.isArray(turnServers)) {
        iceServers.push(...turnServers);
      }

      if (iceServers.length === 0) {
        return null;
      }

      return {
        iceServers,
        iceTransportPolicy: icePolicy
      };
    } catch (error) {
      return null;
    }
  });
}

async function cleanup() {
  try {
    if (torManager && torManager.isTorRunning()) {
      await torManager.stopTor();
    }

    if (websocketHandler) {
      await websocketHandler.disconnect();
    }

    if (securityMiddleware) {
      securityMiddleware.cleanup();
    }
  } catch (_) { }
}

app.whenReady().then(async () => {
  try {
    await setupSecureLogging();

    registerIPCHandlers();

    const handlersReady = await initializeHandlers();
    if (!handlersReady) {
      return fatalExit('Failed to initialize required services');
    }

    await createWindow();

    setupSecurityPolicies();
  } catch (e) {
    return fatalExit(e?.message || 'Unexpected startup error');
  }
}).catch((err) => {
  return fatalExit(err?.message || 'Startup chain failed');
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', async () => {
  await cleanup();
});