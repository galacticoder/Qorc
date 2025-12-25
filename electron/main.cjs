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
const { TrayHandler } = require('./handlers/tray-handler.cjs');
const { NotificationHandler } = require('./handlers/notification-handler.cjs');
const { P2PSignalingHandler } = require('./handlers/p2p-signaling-handler.cjs');
const WebSocket = require('ws');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { decryptEnvelope, encryptEnvelope } = require('./handlers/pq-crypto-handler.cjs');

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
let trayHandler = null;
let notificationHandler = null;
let p2pSignalingHandler = null;
let isWindowDestroyed = false;
let pendingP2PMessages = [];
let pendingSignalingMessages = [];
let pendingServerMessages = [];
let backgroundSessionState = null;
const PENDING_MESSAGES_KEY = 'pending-server-messages';

// Rate limiting for background notifications
let lastBackgroundNotificationTime = 0;
const BACKGROUND_NOTIFICATION_COOLDOWN_MS = 5000;
let backgroundMessageCount = 0;
let backgroundCallNotifiedFrom = new Set();

async function persistPendingMessages() {
  if (!storageHandler) {
    return;
  }
  if (pendingServerMessages.length === 0) {
    return;
  }
  try {
    const data = JSON.stringify(pendingServerMessages);
    await storageHandler.setItem(PENDING_MESSAGES_KEY, data);
  } catch (e) {
    console.error('[MAIN] Failed to persist pending messages:', e?.message || e);
  }
}

async function loadPersistedMessages() {
  if (!storageHandler) {
    return [];
  }
  try {
    const result = await storageHandler.getItem(PENDING_MESSAGES_KEY);
    if (result?.success && result.value) {
      const parsed = JSON.parse(result.value);
      if (Array.isArray(parsed)) {
        return parsed;
      }
    }
  } catch (e) {
    console.error('[MAIN] Failed to load persisted messages:', e?.message || e);
  }
  return [];
}

// Clear persisted messages after delivery
async function clearPersistedMessages() {
  if (!storageHandler) return;
  try {
    await storageHandler.removeItem(PENDING_MESSAGES_KEY);
  } catch (e) {
    console.error('[MAIN] Failed to clear persisted messages:', e?.message || e);
  }
}

// Send delivery receipt in background mode
async function sendBackgroundDeliveryReceipt(senderUsername, messageId, myUsername) {
  if (!signalHandlerV2 || !websocketHandler || !senderUsername || !myUsername) {
    return;
  }

  const pqKeys = backgroundSessionState?.pqSessionKeys;
  if (!pqKeys?.sendKey || !pqKeys?.sessionId) {
    return;
  }

  try {
    let hasKey = false;
    try {
      hasKey = signalHandlerV2.hasPeerKyberPublicKey?.(senderUsername) === true;
    } catch (keyCheckErr) {
      return;
    }

    if (!hasKey) {
      const userRequest = {
        type: 'check-user-exists',
        username: senderUsername,
        timestamp: Date.now()
      };

      const counter = Date.now();
      const pqEnvelope = await encryptEnvelope(userRequest, pqKeys.sendKey, pqKeys.sessionId, counter, pqKeys.fingerprint);

      if (pqEnvelope) {
        websocketHandler.send(JSON.stringify(pqEnvelope));
      }

      await new Promise(resolve => setTimeout(resolve, 2000));

      if (!signalHandlerV2.hasPeerKyberPublicKey(senderUsername)) {
        return;
      }
    }

    const deliveryReceiptData = {
      messageId: `delivery-receipt-${messageId || Date.now()}`,
      from: myUsername,
      to: senderUsername,
      content: 'delivery-receipt',
      timestamp: Date.now(),
      messageType: 'signal-protocol',
      signalType: 'signal-protocol',
      protocolType: 'signal',
      type: 'delivery-receipt'
    };

    const plaintext = JSON.stringify(deliveryReceiptData);

    const encryptResult = await signalHandlerV2.encrypt(myUsername, senderUsername, plaintext, {});

    if (encryptResult?.success && encryptResult?.encryptedPayload) {
      const deliveryPayload = {
        type: 'ENCRYPTED_MESSAGE',
        to: senderUsername,
        from: myUsername,
        encryptedPayload: encryptResult.encryptedPayload
      };

      const counter = Date.now();
      const pqEnvelope = await encryptEnvelope(deliveryPayload, pqKeys.sendKey, pqKeys.sessionId, counter, pqKeys.fingerprint);

      if (pqEnvelope) {
        websocketHandler.send(JSON.stringify(pqEnvelope));
      }
    }
  } catch (e) {
  }
}

async function deliverQueuedMessages() {
  try {
    if (!mainWindow || mainWindow.isDestroyed() || !mainWindow.webContents || mainWindow.webContents.isDestroyed()) {
      return;
    }

    const p2pCount = pendingP2PMessages.length;
    if (p2pCount > 0) {
      const messages = pendingP2PMessages.splice(0, pendingP2PMessages.length);
    }

    const sigCount = pendingSignalingMessages.length;
    if (sigCount > 0) {
      const messages = pendingSignalingMessages.splice(0, pendingSignalingMessages.length);
      for (const { msg } of messages) {
        try {
          mainWindow.webContents.send('p2p:signaling-message', msg);
        } catch (e) { }
      }
    }

    const persistedMessages = await loadPersistedMessages();
    if (persistedMessages.length > 0) {
      pendingServerMessages = [...persistedMessages, ...pendingServerMessages];
    }

    const serverCount = pendingServerMessages.length;
    if (serverCount > 0) {
      const messages = pendingServerMessages.splice(0, pendingServerMessages.length);
      let deliveredCount = 0;
      for (const { message } of messages) {
        try {
          const msgType = message?.type || (typeof message === 'object' ? message.type : 'unknown');
          mainWindow.webContents.send('edge:server-message', message);
          deliveredCount++;
        } catch (e) {
          console.error('[MAIN] Failed to deliver queued message:', e?.message);
        }
      }
      await clearPersistedMessages();
    }
  } catch (e) {
    console.error('[MAIN] Error delivering queued messages:', e?.message || e);
  }
}

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

    // Make sure a stable device ID persisted on machine 
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

    // Ensure per-install Ed25519 device keypair
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

    websocketHandler = new WebSocketHandler(securityMiddleware, storageHandler);

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
        'x-client-name': 'Qor-Chat'
      });
      if (devicePubPem && devicePrivPem) {
        websocketHandler.setDeviceKeys({
          deviceId,
          publicKeyPem: devicePubPem,
          privateKeyPem: devicePrivPem,
        });
      }
    } catch (_) { }

    // Try to load persisted server URL first fall back to env/default
    const storedServerUrl = await websocketHandler.loadStoredServerUrl();
    const defaultWsUrl = storedServerUrl || process.env.VITE_WS_URL || 'wss://localhost:8443';
    const wsInit = await websocketHandler.initialize({
      defaultUrl: defaultWsUrl,
      reconnectAttempts: 5,
      reconnectDelay: 2000
    });
    if (!wsInit?.success) {
      throw new Error('WebSocket handler initialization failed');
    }

    websocketHandler.onMessage = async (message) => {
      const msgType = message?.type || (typeof message === 'string' ? JSON.parse(message)?.type : 'unknown');

      const hasWindow = mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents && !mainWindow.webContents.isDestroyed();

      if (hasWindow) {
        try {
          mainWindow.webContents.send('edge:server-message', message);
        } catch (error) {
          console.error('[MAIN] Failed to send message to renderer:', error.message);
        }
      } else if (isWindowDestroyed) {
        try {
          const parsed = typeof message === 'string' ? JSON.parse(message) : message;

          if (parsed && parsed.type === 'pq-envelope' && parsed.ciphertext) {
            const recvKey = backgroundSessionState?.pqSessionKeys?.recvKey;
            const pqDecrypted = recvKey ? await decryptEnvelope(parsed, recvKey) : null;

            if (pqDecrypted && !pqDecrypted.encryptedPayload) {
              const pqType = pqDecrypted.type || '';
              if (pqType.startsWith('pq-heartbeat') || pqType === 'pq-heartbeat-ping' || pqType === 'pq-heartbeat-pong') {
                return;
              }

              if (pqType === 'user-exists-response' && pqDecrypted?.username) {
                const peerUsername = pqDecrypted.username;
                const hybridKeys = pqDecrypted.hybridKeys || pqDecrypted.hybridPublicKeys;
                const kyberKey = hybridKeys?.kyberPublicBase64;
                if (kyberKey && signalHandlerV2) {
                  signalHandlerV2.setPeerKyberPublicKey(peerUsername, kyberKey);
                }
                return;
              }
            }

            if (pqDecrypted && pqDecrypted.encryptedPayload && signalHandlerV2) {
              const myUsername = backgroundSessionState?.username;
              const fromUser = pqDecrypted.from;

              if (myUsername && fromUser) {
                try {
                  const signalResult = await signalHandlerV2.decrypt(fromUser, myUsername, pqDecrypted.encryptedPayload);

                  if (signalResult?.success && signalResult?.plaintext) {
                    const innerPayload = JSON.parse(signalResult.plaintext);
                    const innerType = innerPayload?.type || innerPayload?.signalType || '';

                    if (innerType === 'libsignal-deliver-bundle' && innerPayload?.bundle && innerPayload?.username) {
                      const bundle = innerPayload.bundle;
                      const peerUsername = innerPayload.username;
                      try {
                        await signalHandlerV2.processPreKeyBundle(myUsername, peerUsername, bundle);
                      } catch (bundleErr) {
                      }
                      return;
                    }

                    const ignoreTypes = [
                      'typing-start', 'typing-stop', 'typing-indicator',
                      'presence', 'status-update',
                      'pq-heartbeat-ping', 'pq-heartbeat-pong',
                      'session-reset-request', 'session-reset-ack',
                      'libsignal-request-bundle', 'libsignal-bundle-response'
                    ];

                    if (ignoreTypes.some(t => innerType === t || innerPayload?.signalType === t)) {
                      return;
                    }

                    const silentQueueTypes = [
                      'delivery-receipt', 'read-receipt',
                      'message-read', 'message-delivered'
                    ];

                    const isSilentQueue = silentQueueTypes.some(t => innerType === t || innerPayload?.signalType === t);

                    if (isSilentQueue) {
                      const receiptMessage = {
                        type: innerPayload.type || innerType,
                        ...innerPayload,
                        _decryptedInBackground: true,
                        _originalFrom: fromUser,
                        _timestamp: Date.now()
                      };
                      pendingServerMessages.push({ message: receiptMessage, timestamp: Date.now() });
                      persistPendingMessages();
                      return;
                    }

                    // Only notify for messages and calls
                    const isActualMessage = ['message', 'text', 'file-message'].includes(innerType) ||
                      (innerPayload?.content && typeof innerPayload.content === 'string' && innerPayload.content.trim().length > 0);
                    const isCallSignal = innerType?.startsWith?.('call-');

                    if (!isActualMessage && !isCallSignal) {
                      return;
                    }

                    const senderUsername = innerPayload?.from || fromUser;
                    if (isCallSignal) {
                      if (backgroundCallNotifiedFrom.has(senderUsername)) {
                        return;
                      }
                      backgroundCallNotifiedFrom.add(senderUsername);
                    }

                    const decryptedMessage = {
                      type: innerPayload.type || 'encrypted-message',
                      ...innerPayload,
                      _decryptedInBackground: true,
                      _originalFrom: fromUser,
                      _timestamp: Date.now()
                    };
                    pendingServerMessages.push({ message: decryptedMessage, timestamp: Date.now() });
                    persistPendingMessages();

                    // Show notification
                    backgroundMessageCount++;
                    const now = Date.now();
                    const timeSinceLast = now - lastBackgroundNotificationTime;
                    if (timeSinceLast >= BACKGROUND_NOTIFICATION_COOLDOWN_MS && notificationHandler) {
                      lastBackgroundNotificationTime = now;
                      let title, preview;
                      if (isCallSignal) {
                        title = 'Incoming Call';
                        preview = 'A user is calling you';
                      } else if (backgroundMessageCount > 1) {
                        title = 'New Messages';
                        preview = `You have ${backgroundMessageCount} new messages`;
                      } else {
                        title = 'New Message';
                        preview = 'You have a new message';
                      }
                      notificationHandler.show({ title, body: preview, silent: false });
                    }
                    if (trayHandler) trayHandler.incrementUnread();

                    // Send delivery receipt for actual messages while in background
                    if (isActualMessage && !isCallSignal) {
                      const messageId = innerPayload?.messageId || innerPayload?.id || `bg-${Date.now()}`;
                      sendBackgroundDeliveryReceipt(senderUsername, messageId, myUsername).catch(() => { });
                    }
                  }
                } catch (_) { }
              }
            } else if (!pqDecrypted) {
              try {
                const aadStr = parsed.aad ? Buffer.from(parsed.aad, 'base64').toString('utf8') : '';
                if (aadStr.startsWith('pq-heartbeat-') || aadStr.includes('typing-')) {
                  return;
                }
              } catch (_) { }
            }

          }
        } catch (_) { }
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
  setTimeout(() => {
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
      showWindow();
    }
  }, 3000);

  mainWindow.on('show', () => {
    isWindowDestroyed = false;
    backgroundMessageCount = 0;
    backgroundCallNotifiedFrom.clear();
    if (notificationHandler) notificationHandler.clearBadge();
    if (trayHandler) trayHandler.clearUnread();
    if (websocketHandler) websocketHandler.setBackgroundMode(false);
    if (p2pSignalingHandler) p2pSignalingHandler.setBackgroundMode(false);
  });

  mainWindow.on('close', (e) => {
    if (trayHandler?.getIsQuitting()) {
      return;
    }

    e.preventDefault();

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.hide();
      isWindowDestroyed = true;

      // Store session state
      backgroundSessionState = {
        isBackgroundMode: true,
        timestamp: Date.now(),
        wsConnected: websocketHandler?.isConnected?.() || false,
        sessionId: websocketHandler?.sessionId || null
      };

      if (websocketHandler) websocketHandler.setBackgroundMode(true);
      if (p2pSignalingHandler) p2pSignalingHandler.setBackgroundMode(true);

      const windowToDestroy = mainWindow;
      if (windowToDestroy && !windowToDestroy.isDestroyed() && windowToDestroy.webContents && !windowToDestroy.webContents.isDestroyed()) {
        windowToDestroy.webContents.send('app:entering-background');
      }
      mainWindow = null;

      setTimeout(() => {
        if (windowToDestroy && !windowToDestroy.isDestroyed()) {
          windowToDestroy.destroy();
        }
      }, 500);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
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
        `script-src 'self' 'nonce-${nonce}' 'wasm-unsafe-eval'; ` +
        "style-src 'self' 'unsafe-inline'; " +
        "style-src-elem 'self' 'unsafe-inline'; " +
        "style-src-attr 'unsafe-inline'; " +
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
      responseHeaders['permissions-policy'] = ['camera=(self), microphone=(self), geolocation=(), payment=()'];

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
  ipcMain.handle('session:get-background-state', () => {
    const wsConnected = websocketHandler?.isConnected?.() || false;

    if (backgroundSessionState && backgroundSessionState.isBackgroundMode) {
      const state = { ...backgroundSessionState };
      state.wsConnected = wsConnected;
      state.p2pSignalingConnected = p2pSignalingHandler?.isConnected?.() || false;
      return state;
    }
    return null;
  });

  ipcMain.handle('session:clear-background-state', () => {
    backgroundSessionState = null;
    return { success: true };
  });

  ipcMain.handle('session:set-background-username', (_evt, username) => {
    if (backgroundSessionState) {
      backgroundSessionState.username = username;
    }
    return { success: true };
  });

  // Store PQ session keys before renderer destruction
  ipcMain.handle('session:store-pq-keys', (_evt, { sessionId, sendKey, recvKey, fingerprint, establishedAt }) => {
    if (!backgroundSessionState) {
      backgroundSessionState = { isBackgroundMode: false, timestamp: Date.now() };
    }
    backgroundSessionState.pqSessionKeys = {
      sessionId,
      sendKey,
      recvKey,
      fingerprint,
      establishedAt
    };
    return { success: true };
  });

  // Retrieve stored PQ session keys for renderer restoring
  ipcMain.handle('session:get-pq-keys', () => {
    if (backgroundSessionState?.pqSessionKeys) {
      return { success: true, keys: backgroundSessionState.pqSessionKeys };
    }
    return { success: false, error: 'No stored PQ session keys' };
  });

  ipcMain.handle('session:clear-pq-keys', () => {
    if (backgroundSessionState) {
      delete backgroundSessionState.pqSessionKeys;
    }
    return { success: true };
  });

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
    const status = await torManager.getTorStatus();
    if (websocketHandler) {
      if (status) {
        websocketHandler.updateTorConfig({ socksPort: status.socksPort });
      }
      websocketHandler.setTorReady(true);
    }
    if (p2pSignalingHandler) {
      if (status) {
        p2pSignalingHandler.updateTorConfig({ socksPort: status.socksPort });
      }
      p2pSignalingHandler.setTorReady(true);
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

      if (bootstrapped) {
        const socksPort = torManager.getSocksPort?.() || torManager.effectiveSocksPort || 9150;

        if (websocketHandler) {
          try {
            websocketHandler.updateTorConfig({ socksPort });
            websocketHandler.setTorReady(true);
          } catch (e) {
            console.error('[MAIN] Failed to set WebSocket Tor readiness:', e?.message || e);
          }
        }

        if (p2pSignalingHandler) {
          try {
            p2pSignalingHandler.updateTorConfig({ socksPort });
            p2pSignalingHandler.setTorReady(true);
          } catch (e) {
            console.error('[MAIN] Failed to set P2P signaling Tor readiness:', e?.message || e);
          }
        }
      }

      return {
        success: true,
        bootstrapped,
        socksPort: torManager.getSocksPort?.() || torManager.effectiveSocksPort || 9150,
        controlPort: torManager.getControlPort?.() || torManager.effectiveControlPort || 9151
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
    if (!websocketHandler) return { success: false, serverUrl: '' };
    if (!websocketHandler.serverUrl) {
      await websocketHandler.loadStoredServerUrl();
    }
    return { success: true, serverUrl: websocketHandler.serverUrl || '' };
  });

  ipcMain.handle('edge:ws-probe-connect', async (_event, url, timeoutMs) => {
    if (!websocketHandler) return { success: false, error: 'WebSocket handler not initialized' };
    return await websocketHandler.probeConnect(url, typeof timeoutMs === 'number' ? timeoutMs : 12000);
  });

  ipcMain.handle('notification:show', async (_event, { title, body, silent, data }) => {
    if (!notificationHandler) return { success: false, error: 'Notification handler not initialized' };
    return notificationHandler.show({ title, body, silent, data });
  });

  ipcMain.handle('notification:set-enabled', async (_event, enabled) => {
    if (!notificationHandler) return { success: false };
    notificationHandler.setEnabled(enabled);
    return { success: true };
  });

  ipcMain.handle('notification:set-badge', async (_event, count) => {
    if (!notificationHandler) return { success: false };
    if (typeof count === 'number' && count >= 0) {
      notificationHandler.setBadgeCount(count);
      if (trayHandler) trayHandler.setUnreadCount(count);
    }
    return { success: true };
  });

  ipcMain.handle('notification:clear-badge', async () => {
    if (notificationHandler) notificationHandler.clearBadge();
    if (trayHandler) trayHandler.clearUnread();
    return { success: true };
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

  ipcMain.handle('signal-v2:set-peer-kyber-key', async (_event, { peerUsername, kyberPublicKeyBase64 }) => {
    if (!signalHandlerV2) return { success: false, error: 'Signal V2 handler not initialized' };
    return signalHandlerV2.setPeerKyberPublicKey(peerUsername, kyberPublicKeyBase64);
  });

  ipcMain.handle('signal-v2:has-peer-kyber-key', async (_event, { peerUsername }) => {
    if (!signalHandlerV2) return { success: false, hasKey: false };
    return { success: true, hasKey: signalHandlerV2.hasPeerKyberPublicKey(peerUsername) };
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
      if (!torManager || !torManager.isTorRunning() || !torManager.bootstrapped) {
        return { url, error: 'Tor not available' };
      }

      if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL');
      }

      const parsedUrl = new URL(url);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Only HTTP/HTTPS URLs allowed');
      }

      const timeout = Math.min(options.timeout || 15000, 30000);
      const MAX_PREVIEW_BYTES = 2 * 1024 * 1024; // 2MB cap
      const TOR_STANDARD_UA = 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0';

      const { SocksProxyAgent } = await import('socks-proxy-agent');
      const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${torManager.effectiveSocksPort}`);

      const buildPreview = (html) => {
        const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
        const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i);
        const ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
        const ogDescMatch = html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']+)["']/i);
        const ogImageMatch = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["']/i);
        const siteNameMatch = html.match(/<meta[^>]*property=["']og:site_name["'][^>]*content=["']([^"']+)["']/i);

        return {
          url,
          title: ogTitleMatch?.[1] || titleMatch?.[1] || parsedUrl.hostname,
          description: ogDescMatch?.[1] || descMatch?.[1] || '',
          image: ogImageMatch?.[1] || null,
          siteName: siteNameMatch?.[1] || null,
          success: true
        };
      };

      return await new Promise((resolve) => {
        const https = require('https');
        const http = require('http');
        const requestModule = parsedUrl.protocol === 'https:' ? https : http;
        let resolved = false;
        const safeResolve = (payload) => {
          if (resolved) return;
          resolved = true;
          resolve(payload);
        };

        const req = requestModule.request({
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          agent: proxyAgent,
          timeout,
          headers: {
            'User-Agent': TOR_STANDARD_UA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'identity',
            'Connection': 'close'
          }
        }, (res) => {
          if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
            req.destroy();
            return safeResolve({ url, redirectTo: res.headers.location, needsRedirect: true });
          }

          let data = '';
          res.on('data', (chunk) => {
            if (resolved) return;
            data += chunk;
            if (data.length > MAX_PREVIEW_BYTES) {
              req.destroy();
              if (typeof res.destroy === 'function') res.destroy();
              const preview = buildPreview(data.slice(0, MAX_PREVIEW_BYTES));
              return safeResolve({ ...preview, truncated: true, statusCode: res.statusCode });
            }
          });

          res.on('end', () => {
            if (resolved) return;
            if (data.length === 0) {
              return safeResolve({ url, error: `HTTP ${res.statusCode}` });
            }
            const preview = buildPreview(data);
            if (res.statusCode !== 200 && !preview.title && !preview.description && !preview.image) {
              return safeResolve({ url, error: `HTTP ${res.statusCode}` });
            }
            safeResolve({ ...preview, statusCode: res.statusCode });
          });
        });

        req.on('error', (error) => safeResolve({ url, error: error.message }));
        req.on('timeout', () => { req.destroy(); safeResolve({ url, error: 'Timeout' }); });
        req.end();
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
    if (websocketHandler?.isConnected?.() && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('edge:server-message', { type: '__ws_connection_opened' });
    }
    return { success: true };
  });

  ipcMain.handle('session:request-pending-messages', async () => {
    await deliverQueuedMessages();
    return { success: true, delivered: pendingServerMessages.length === 0 };
  });

  // P2P Signaling handlers
  try {
    p2pSignalingHandler = new P2PSignalingHandler();
    p2pSignalingHandler.setTorReady(torManager.isTorRunning());
    p2pSignalingHandler.updateTorConfig({ socksPort: torManager.getSocksPort?.() || 9150 });
    p2pSignalingHandler.onMessage = (msg) => {
      try {
        if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents && !mainWindow.webContents.isDestroyed()) {
          mainWindow.webContents.send('p2p:signaling-message', msg);
        } else if (isWindowDestroyed) {
          pendingSignalingMessages.push({ msg, timestamp: Date.now() });
        }
      } catch (e) { }
    };

    ipcMain.handle('p2p:signaling-connect', async (_event, serverUrl, options) => {
      if (!p2pSignalingHandler) return { success: false, error: 'P2P signaling handler not initialized' };
      p2pSignalingHandler.setTorReady(torManager.isTorRunning());
      p2pSignalingHandler.updateTorConfig({ socksPort: torManager.getSocksPort?.() || 9150 });
      const result = await p2pSignalingHandler.connect(serverUrl, options);
      return result;
    });

    ipcMain.handle('p2p:signaling-disconnect', async () => {
      if (!p2pSignalingHandler) return { success: false, error: 'P2P signaling handler not initialized' };
      return p2pSignalingHandler.disconnect();
    });

    ipcMain.handle('p2p:signaling-send', async (_event, message) => {
      if (!p2pSignalingHandler) return { success: false, error: 'P2P signaling handler not initialized' };
      return p2pSignalingHandler.send(message);
    });

    ipcMain.handle('p2p:signaling-status', async () => {
      if (!p2pSignalingHandler) return { connected: false };
      return { connected: p2pSignalingHandler.isConnected() };
    });
  } catch (e) {
    console.error('[MAIN] P2P signaling handler init failed:', e?.message || e);
  }

  ipcMain.handle('webrtc:get-ice-config', async () => {
    try {
      // Get server URL from websocket handler if available
      let serverUrl = websocketHandler?.serverUrl || '';
      if (!serverUrl) {
        return null;
      }

      // Convert WebSocket URL to HTTP
      const wsUrl = new URL(serverUrl);
      const httpProto = wsUrl.protocol === 'wss:' ? 'https:' : 'http:';
      const baseUrl = `${httpProto}//${wsUrl.host}`;

      // Fetch ICE config from server
      const https = require('https');
      const http = require('http');

      return await new Promise((resolve) => {
        const url = new URL(`${baseUrl}/api/ice/config`);
        const requestModule = url.protocol === 'https:' ? https : http;

        const req = requestModule.request({
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname,
          method: 'GET',
          timeout: 10000,
          headers: { 'Accept': 'application/json' }
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            try {
              if (res.statusCode !== 200) {
                return resolve(null);
              }
              const ice = JSON.parse(data);
              if (ice && Array.isArray(ice.iceServers) && ice.iceServers.length > 0) {
                resolve({
                  iceServers: ice.iceServers,
                  iceTransportPolicy: ice.iceTransportPolicy || 'all'
                });
              } else {
                resolve(null);
              }
            } catch {
              resolve(null);
            }
          });
        });

        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.end();
      });
    } catch (error) {
      return null;
    }
  });
}

async function cleanup() {
  try {
    if (pendingServerMessages.length > 0) {
      await persistPendingMessages();
    }

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

async function showWindowFromTray() {
  if (websocketHandler) websocketHandler.setBackgroundMode(false);
  if (p2pSignalingHandler) p2pSignalingHandler.setBackgroundMode(false);

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    mainWindow.focus();
  } else {
    await createWindow();
  }
  isWindowDestroyed = false;
}

async function quitApp() {
  if (trayHandler) {
    trayHandler.setIsQuitting(true);
  }
  await cleanup();
  app.quit();
}

function initializeTrayAndNotifications() {
  trayHandler = new TrayHandler();
  const trayResult = trayHandler.initialize({
    iconPath: path.join(__dirname, '../public/icon.png'),
    onShowWindow: showWindowFromTray,
    onQuit: quitApp
  });

  if (!trayResult.success) {
    console.warn('[Main] Tray initialization failed:', trayResult.error);
  }

  // Initialize notifications
  notificationHandler = new NotificationHandler();
  notificationHandler.initialize({
    onNotificationClick: (data) => {
      showWindowFromTray();
    }
  });
}

app.whenReady().then(async () => {
  try {
    await setupSecureLogging();

    registerIPCHandlers();

    const handlersReady = await initializeHandlers();
    if (!handlersReady) {
      return fatalExit('Failed to initialize required services');
    }

    initializeTrayAndNotifications();

    await createWindow();

    setupSecurityPolicies();
  } catch (e) {
    return fatalExit(e?.message || 'Unexpected startup error');
  }
}).catch((err) => {
  return fatalExit(err?.message || 'Startup chain failed');
});

app.on('activate', () => {
  showWindowFromTray();
});

app.on('window-all-closed', () => {
  if (trayHandler && typeof trayHandler.getIsQuitting === 'function' && !trayHandler.getIsQuitting()) {
    return;
  }
  app.quit();
});

let isQuitting = false;
app.on('before-quit', (event) => {
  if (isQuitting) return;

  event.preventDefault();
  isQuitting = true;

  (async () => {
    try {
      if (trayHandler) {
        trayHandler.setIsQuitting(true);
        trayHandler.destroy();
      }
      await cleanup();
    } finally {
      app.quit();
    }
  })();
});