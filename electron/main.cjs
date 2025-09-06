const { app, BrowserWindow, ipcMain, desktopCapturer, dialog, shell, powerSaveBlocker } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const isDev = process.env.NODE_ENV === 'development';

// Disable GPU acceleration to avoid Vulkan/graphics driver issues
app.disableHardwareAcceleration();

// Add additional command line switches for better compatibility
app.commandLine.appendSwitch('--disable-gpu');
app.commandLine.appendSwitch('--disable-gpu-sandbox');
app.commandLine.appendSwitch('--disable-software-rasterizer');

// Route all console output to a file to avoid EBADF when parent stdio closes
try {
  const logFilePath = path.join(os.tmpdir(), 'end2end-chat-electron-main.log');
  const formatArg = (a) => {
    try {
      if (typeof a === 'string') return a;
      if (a instanceof Error) return a.stack || a.message;
      return JSON.stringify(a);
    } catch (_e) {
      return String(a);
    }
  };
  const writeLine = (level, args) => {
    const line = `[${new Date().toISOString()}] [${level}] ` + Array.from(args).map(formatArg).join(' ') + '\n';
    try { fs.appendFileSync(logFilePath, line); } catch (_e) { /* ignore */ }
  };
  const make = (level) => function() { writeLine(level, arguments); };
  console.log = make('LOG');
  console.info = make('INFO');
  console.warn = make('WARN');
  console.error = make('ERROR');
  console.debug = make('DEBUG');
  process.on('uncaughtException', (err) => {
    try { writeLine('UNCAUGHT', [err && (err.stack || err.message || String(err))]); } catch (_) {}
  });
} catch (_e) {
  // no-op
}

// Require Tor manager after console/stdio safety is applied
const torManager = require('./tor-manager.cjs');

// Keep a global reference of the window object
let mainWindow;

function createWindow() {
  // Use in-memory partition in dev to avoid orphaned profiles, persistent in production
  const partitionName = isDev ? 'securechat-dev' : 'persist:securechat';

  // Base web preferences with secure defaults
  const webPreferences = {
    nodeIntegration: false,
    contextIsolation: true,
    enableRemoteModule: false,
    preload: path.join(__dirname, 'preload.cjs'),
    partition: partitionName,
    // Enable media access for voice notes and video calls
    allowRunningInsecureContent: false,
    experimentalFeatures: false
  };

  // Only weaken security in development for WebRTC/screen sharing testing
  if (isDev) {
    // Enable experimental features only in dev for WebRTC/screen sharing
    webPreferences.experimentalFeatures = true;
    // webPreferences.webSecurity = false;
    // webPreferences.allowRunningInsecureContent = true;
  }

  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences,
    icon: path.join(__dirname, '../public/icon.png'), // Add your app icon
    titleBarStyle: 'default',
    show: false // Don't show until ready
  });

  // Load the app - try dev server first, then dist build, then show error
  const tryLoadDevServer = () => {
    return new Promise((resolve) => {
      const http = require('http');
      const req = http.request({
        hostname: 'localhost',
        port: 5173,
        path: '/',
        method: 'HEAD',
        timeout: 2000
      }, (res) => {
        resolve(true);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      req.end();
    });
  };

  const loadApp = async () => {
    // First try dev server (regardless of NODE_ENV since user might run electron directly)
    const devServerAvailable = await tryLoadDevServer();
    
    if (devServerAvailable) {
      console.log('Loading from Vite dev server...');
      mainWindow.loadURL('http://localhost:5173');
      // Open DevTools when loading from dev server
      mainWindow.webContents.openDevTools();
    } else {
      // Try dist build
      const distPath = path.join(__dirname, '../dist/index.html');
      if (fs.existsSync(distPath)) {
        console.log('Loading from dist build...');
        mainWindow.loadFile(distPath);
      } else {
        console.error('Neither dev server nor dist build available.');
        // Show helpful error page
        const errorHtml = `
          <html>
            <head><title>End2End Chat - Setup Required</title></head>
            <body style="font-family: Arial, sans-serif; padding: 40px; text-align: center;">
              <h1>🔧 Setup Required</h1>
              <p>To run the application, you need either:</p>
              <ol style="text-align: left; display: inline-block;">
                <li><strong>Development mode:</strong> Run <code>bash startClient.sh</code></li>
                <li><strong>Production build:</strong> Run <code>pnpm run build</code> first</li>
              </ol>
              <p><small>This window will close in 10 seconds...</small></p>
              <script>setTimeout(() => window.close(), 10000);</script>
            </body>
          </html>
        `;
        mainWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(errorHtml)}`);
      }
    }
  };
  
  loadApp();

  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    
    // Focus on window
    if (isDev) {
      mainWindow.focus();
    }
  });

  // Ensure app quits when last window is closed in dev to avoid relaunch loops
  mainWindow.on('closed', () => {
    if (process.platform !== 'darwin') {
      try { app.quit(); } catch (_) {}
    }
  });

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Handle window controls
  mainWindow.on('minimize', (event) => {
    event.preventDefault();
    mainWindow.minimize();
  });

  mainWindow.on('close', async (event) => {
    if (torManager.isTorRunning()) {
      try {
        console.log('[ELECTRON] Shutting down Tor before closing...');
        await torManager.stopTor();
      } catch (_) {}
    }
  });
}

// This method will be called when Electron has finished initialization
app.whenReady().then(() => {
  createWindow();

  // Handle permission requests for media devices and security
  app.on('web-contents-created', (event, contents) => {
    // Set up permission handlers for media access
    contents.session.setPermissionRequestHandler((_webContents, permission, callback) => {
      console.log('[ELECTRON] Permission request:', permission);

      // Allow media permissions (microphone, camera, screen capture)
      if (permission === 'media' || permission === 'microphone' || permission === 'camera') {
        console.log('[ELECTRON] Granting media permission:', permission);
        callback(true);
        return;
      }

      // Allow display capture for screen sharing
      if (permission === 'display-capture') {
        console.log('[ELECTRON] Granting display-capture permission');
        callback(true);
        return;
      }

      // Deny other permissions by default
      console.log('[ELECTRON] Denying permission:', permission);
      callback(false);
    });

    // Handle permission check requests
    contents.session.setPermissionCheckHandler((_webContents, permission, requestingOrigin) => {
      console.log('[ELECTRON] Permission check:', permission, 'from:', requestingOrigin);

      // Allow media permissions
      if (permission === 'media' || permission === 'microphone' || permission === 'camera' || permission === 'display-capture') {
        console.log('[ELECTRON] Permission check granted for:', permission);
        return true;
      }

      console.log('[ELECTRON] Permission check denied for:', permission);
      return false;
    });

    // Prevent external navigation while allowing same-origin/app-served URLs
    contents.on('will-navigate', (e, targetUrl) => {
      try {
        const currentUrlStr = contents.getURL();
        const target = new URL(targetUrl);

        // Always allow internal schemes served by the app
        if (target.protocol === 'file:' || target.protocol === 'blob:') {
          return; // allow navigation
        }

        if (currentUrlStr) {
          const current = new URL(currentUrlStr);
          if (current.origin === target.origin) {
            return; // allow same-origin navigation (e.g., internal routes, OAuth redirects)
          }
        }

        // Different origin: block navigation
        e.preventDefault();
        console.log('[SECURITY] Blocked external navigation to:', targetUrl);
      } catch (err) {
        // On parsing error, be conservative and block
        e.preventDefault();
        console.warn('[SECURITY] Error evaluating navigation target; blocking:', targetUrl, err?.message || err);
      }
    });

    // Intercept downloads and log progress; default behavior should not navigate the page
    contents.session.on('will-download', (event, item) => {
      console.log('[ELECTRON] Download started:', item.getFilename());
      item.on('done', (_e, state) => {
        console.log('[ELECTRON] Download finished:', state);
      });
    });

    // Security: Prevent new window creation (legacy)
    contents.on('new-window', (event, navigationUrl) => {
      event.preventDefault();
      console.log('[SECURITY] Blocked new window creation to:', navigationUrl);
    });

    // Security: Modern window open handler - redirect to external browser
    contents.setWindowOpenHandler(({ url }) => {
      console.log('[SECURITY] Redirecting window.open to external browser:', url);
      // Use shell.openExternal to open in system browser
      shell.openExternal(url).catch(err => {
        console.error('[SECURITY] Failed to open URL externally:', err);
      });
      return { action: 'deny' }; // Deny opening in Electron
    });
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', async () => {
  if (torManager.isTorRunning()) {
    console.log('[ELECTRON] Shutting down Tor before quit...');
    await torManager.stopTor();
  }
});



// IPC Handlers for Tor functionality
ipcMain.handle('tor:check-installation', async () => {
  try {
    return await torManager.checkTorInstallation();
  } catch (error) {
    console.error('[IPC] Error checking Tor installation:', error);
    return { isInstalled: false, error: error.message };
  }
});

ipcMain.handle('tor:download', async (event, options) => {
  try {
    return await torManager.downloadTor(options);
  } catch (error) {
    console.error('[IPC] Error downloading Tor:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:install', async () => {
  try {
    return await torManager.installTor();
  } catch (error) {
    console.error('[IPC] Error installing Tor:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:configure', async (event, options) => {
  try {
    return await torManager.configureTor(options);
  } catch (error) {
    console.error('[IPC] Error configuring Tor:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:start', async () => {
  try {
    return await torManager.startTor();
  } catch (error) {
    console.error('[IPC] Error starting Tor:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:stop', async () => {
  try {
    return await torManager.stopTor();
  } catch (error) {
    console.error('[IPC] Error stopping Tor:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:status', () => {
  try {
    return torManager.getTorStatus();
  } catch (error) {
    console.error('[IPC] Error getting Tor status:', error);
    return { isRunning: false, error: error.message };
  }
});

ipcMain.handle('tor:uninstall', async () => {
  try {
    return await torManager.uninstallTor();
  } catch (error) {
    console.error('[IPC] Error uninstalling Tor:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:info', async () => {
  try {
    return await torManager.getTorInfo();
  } catch (error) {
    console.error('[IPC] Error getting Tor info:', error);
    return { error: error.message };
  }
});

// Handle tor:get-info for compatibility (alias to tor:info)
ipcMain.handle('tor:get-info', async () => {
  // Delegate to the canonical tor:info handler
  try {
    return await torManager.getTorInfo();
  } catch (error) {
    console.error('[IPC] Error getting Tor info (via tor:get-info alias):', error);
    return { error: error.message };
  }
});

ipcMain.handle('tor:verify-connection', async () => {
  try {
    return await torManager.verifyTorConnection();
  } catch (error) {
    console.error('[IPC] Error verifying Tor connection:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('tor:rotate-circuit', async () => {
  try {
    return await torManager.rotateCircuit();
  } catch (error) {
    console.error('[IPC] Error rotating Tor circuit:', error);
    return { success: false, error: error.message };
  }
});

// Get platform info
ipcMain.handle('system:platform', () => {
  return {
    platform: process.platform,
    arch: process.arch,
    version: process.version
  };
});

// Handle websocket connection
let wsConnection = null;
let torSetupComplete = false;

ipcMain.handle('edge:ws-send', async (event, payload) => {
  try {
    // Check if Tor setup is complete before attempting connection
    if (!torSetupComplete) {
      console.log('[ELECTRON] WebSocket connection blocked - Tor setup not complete');
      return { success: false, error: 'Tor setup not complete' };
    }

    if (!wsConnection || wsConnection.readyState !== 1) {
      // Connect to server if not connected
      const WebSocket = require('ws');
      wsConnection = new WebSocket('wss://localhost:8443', {
        rejectUnauthorized: false // Accept self-signed certificates in development
      });

      wsConnection.on('open', () => {
        console.log('[ELECTRON] Connected to websocket server');
      });

      wsConnection.on('message', (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          console.log('[ELECTRON] Received from server:', parsed.type);
          
          // Forward to renderer process
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('edge:server-message', parsed);
          }
        } catch (error) {
          console.error('[ELECTRON] Error parsing server message:', error);
        }
      });

      wsConnection.on('error', (error) => {
        console.error('[ELECTRON] WebSocket error:', error);
      });

      wsConnection.on('close', () => {
        console.log('[ELECTRON] WebSocket connection closed');
        wsConnection = null;
      });

      // Wait for connection to be established
      await new Promise((resolve, reject) => {
        wsConnection.on('open', resolve);
        wsConnection.on('error', reject);
        setTimeout(() => reject(new Error('Connection timeout')), 10000);
      });
    }

    // Send message to server
    if (wsConnection && wsConnection.readyState === 1) {
      const message = typeof payload === 'string' ? payload : JSON.stringify(payload);
      wsConnection.send(message);
      console.log('[ELECTRON] Sent to server:', message.substring(0, 100));
      return { success: true };
    } else {
      throw new Error('WebSocket not connected');
    }
  } catch (error) {
    console.error('[ELECTRON] Error sending websocket message:', error);
    return { success: false, error: error.message };
  }
});

// Explicitly connect the WebSocket without sending any payload
ipcMain.handle('edge:ws-connect', async () => {
  try {
    // Check if Tor setup is complete before attempting connection
    if (!torSetupComplete) {
      console.log('[ELECTRON] WebSocket connection blocked - Tor setup not complete');
      return { success: false, error: 'Tor setup not complete' };
    }

    if (wsConnection && wsConnection.readyState === 1) {
      return { success: true };
    }

    const WebSocket = require('ws');
    wsConnection = new WebSocket('wss://localhost:8443', {
      rejectUnauthorized: false
    });

    wsConnection.on('open', () => {
      console.log('[ELECTRON] Connected to websocket server');
    });

    wsConnection.on('message', (data) => {
      try {
        const parsed = JSON.parse(data.toString());
        console.log('[ELECTRON] Received from server:', parsed.type);
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('edge:server-message', parsed);
        }
      } catch (error) {
        console.error('[ELECTRON] Error parsing server message:', error);
      }
    });

    wsConnection.on('error', (error) => {
      console.error('[ELECTRON] WebSocket error:', error);
    });

    wsConnection.on('close', () => {
      console.log('[ELECTRON] WebSocket connection closed');
      wsConnection = null;
    });

    await new Promise((resolve, reject) => {
      wsConnection.on('open', resolve);
      wsConnection.on('error', reject);
      setTimeout(() => reject(new Error('Connection timeout')), 10000);
    });

    return { success: true };
  } catch (error) {
    console.error('[ELECTRON] Error connecting websocket:', error);
    return { success: false, error: error.message };
  }
});

// Minimal in-memory Signal-like session management and crypto placeholders
const crypto = require('crypto');
const signalState = {
  identities: new Map(), // username -> identity/bundle
  sessions: new Map(), // sortedPairKey -> { sessionId }
};

function sortedPairKey(a, b) {
  return [String(a || ''), String(b || '')].sort().join('|');
}

function randomBase64(bytes) {
  return crypto.randomBytes(bytes).toString('base64');
}

ipcMain.handle('signal:generate-identity', async (_event, { username } = {}) => {
  try {
    const registrationId = Math.floor(Math.random() * 1_000_000_000);
    const deviceId = 1;
    const identityKeyBase64 = randomBase64(32);
    signalState.identities.set(username, {
      registrationId,
      deviceId,
      identityKeyBase64,
    });
    return { success: true, registrationId, deviceId };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('signal:generate-prekeys', async (_event, { username } = {}) => {
  try {
    const id = `${Date.now()}`;
    const publicKeyBase64 = randomBase64(32);
    const ed25519SignatureBase64 = randomBase64(64);
    const dilithiumSignatureBase64 = randomBase64(64);
    const kyberPreKeyId = 1;
    const kyberPreKeyPublicBase64 = randomBase64(32);
    const kyberPreKeySignatureBase64 = randomBase64(64);
    // Generate ~100 one-time prekeys
    const oneTimePreKeys = Array.from({ length: 100 }, (_, i) => ({ id: i + 1, publicKeyBase64: randomBase64(32) }));
    const existing = signalState.identities.get(username) || {};
    signalState.identities.set(username, {
      ...existing,
      signedPreKey: { id, publicKeyBase64, ed25519SignatureBase64, dilithiumSignatureBase64 },
      kyber: { id: kyberPreKeyId, publicKeyBase64: kyberPreKeyPublicBase64, signatureBase64: kyberPreKeySignatureBase64 },
      oneTimePreKeys,
      updatedAt: Date.now(),
    });
    return { success: true, count: oneTimePreKeys.length };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('signal:get-prekey-bundle', async (_event, { username } = {}) => {
  try {
    const entry = signalState.identities.get(username) || {};
    const bundle = {
      registrationId: entry.registrationId ?? Math.floor(Math.random() * 1_000_000_000),
      deviceId: entry.deviceId ?? 1,
      identityKeyBase64: entry.identityKeyBase64 ?? randomBase64(32),
      preKeyId: entry.preKeyId ?? null,
      preKeyPublicBase64: entry.preKeyPublicBase64 ?? null,
      signedPreKeyId: entry.signedPreKey?.id ?? '1',
      signedPreKeyPublicBase64: entry.signedPreKey?.publicKeyBase64 ?? randomBase64(32),
      signedPreKeySignatureBase64: entry.signedPreKey?.ed25519SignatureBase64 ?? randomBase64(64),
      kyberPreKeyId: entry.kyber?.id ?? 1,
      kyberPreKeyPublicBase64: entry.kyber?.publicKeyBase64 ?? randomBase64(32),
      kyberPreKeySignatureBase64: entry.kyber?.signatureBase64 ?? randomBase64(64),
      oneTimePreKeys: Array.isArray(entry.oneTimePreKeys) ? entry.oneTimePreKeys : [],
    };
    return bundle;
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('signal:process-prekey-bundle', async (_event, { selfUsername, peerUsername } = {}) => {
  try {
    const key = sortedPairKey(selfUsername, peerUsername);
    if (!signalState.sessions.has(key)) {
      signalState.sessions.set(key, { sessionId: randomBase64(12), establishedAt: Date.now() });
    }
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('signal:has-session', async (_event, { selfUsername, peerUsername } = {}) => {
  try {
    const key = sortedPairKey(selfUsername, peerUsername);
    const hasSession = signalState.sessions.has(key);
    return { success: true, hasSession };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('signal:encrypt', async (_event, { fromUsername, toUsername, plaintext } = {}) => {
  try {
    const key = sortedPairKey(fromUsername, toUsername);
    if (!signalState.sessions.has(key)) {
      signalState.sessions.set(key, { sessionId: randomBase64(12), establishedAt: Date.now() });
    }
    const session = signalState.sessions.get(key);
    const ciphertextBase64 = Buffer.from(String(plaintext) ?? '', 'utf8').toString('base64');
    return { type: 1, sessionId: session.sessionId, ciphertextBase64 };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('signal:decrypt', async (_event, { ciphertextBase64 } = {}) => {
  try {
    const plaintext = Buffer.from(String(ciphertextBase64 || ''), 'base64').toString('utf8');
    return { plaintext };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('renderer:ready', async () => {
  console.log('[ELECTRON] Renderer process ready');
  return { success: true };
});



// Handle Tor setup completion notification
ipcMain.handle('tor:setup-complete', async () => {
  console.log('[ELECTRON] Tor setup marked as complete');
  torSetupComplete = true;
  return { success: true };
});

// Handle app info requests
ipcMain.handle('app:version', () => {
  return app.getVersion();
});

ipcMain.handle('app:name', () => {
  return app.getName();
});

// Power save blocker controls for calls
let psbId = null;
ipcMain.handle('power:psb-start', () => {
  try {
    if (psbId !== null && powerSaveBlocker.isStarted(psbId)) {
      return { success: true, id: psbId };
    }
    psbId = powerSaveBlocker.start('prevent-app-suspension');
    console.log('[POWER] Power save blocker started:', psbId);
    return { success: true, id: psbId };
  } catch (e) {
    console.error('[POWER] Failed to start power save blocker:', e);
    return { success: false, error: e.message };
  }
});

ipcMain.handle('power:psb-stop', () => {
  try {
    if (psbId !== null && powerSaveBlocker.isStarted(psbId)) {
      powerSaveBlocker.stop(psbId);
      console.log('[POWER] Power save blocker stopped:', psbId);
    }
    psbId = null;
    return { success: true };
  } catch (e) {
    console.error('[POWER] Failed to stop power save blocker:', e);
    return { success: false, error: e.message };
  }
});

// Handle edge: IPC methods for compatibility with preload.js
ipcMain.handle('edge:encrypt', async (_event, args) => {
  try {
    // Use the same logic as signal:encrypt
    const plaintext = Buffer.from(String(args?.plaintext || ''), 'utf8').toString('base64');
    return { ciphertextBase64: plaintext };
  } catch (error) {
    console.error('[IPC] Error in edge:encrypt:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('edge:decrypt', async (_event, args) => {
  try {
    // Use the same logic as signal:decrypt
    const plaintext = Buffer.from(String(args?.ciphertextBase64 || ''), 'base64').toString('utf8');
    return { plaintext };
  } catch (error) {
    console.error('[IPC] Error in edge:decrypt:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('edge:setupSession', async (_event, args) => {
  try {
    console.log('[IPC] edge:setupSession called with args:', args);
    return { success: true, message: 'Session setup placeholder' };
  } catch (error) {
    console.error('[IPC] Error in edge:setupSession:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('edge:publishBundle', async (_event, args) => {
  try {
    console.log('[IPC] edge:publishBundle called with args:', args);
    return { success: true, message: 'Bundle publish placeholder' };
  } catch (error) {
    console.error('[IPC] Error in edge:publishBundle:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('edge:requestBundle', async (_event, args) => {
  try {
    console.log('[IPC] edge:requestBundle called with args:', args);
    return { success: true, message: 'Bundle request placeholder' };
  } catch (error) {
    console.error('[IPC] Error in edge:requestBundle:', error);
    return { success: false, error: error.message };
  }
});

// Handle screen sharing
ipcMain.handle('screen:getSources', async () => {
  try {
    console.log('[ELECTRON] ===== SCREEN SOURCES REQUEST RECEIVED =====');
    console.log('[ELECTRON] Getting screen sources...');
    const sources = await desktopCapturer.getSources({
      types: ['window', 'screen'],
      thumbnailSize: { width: 150, height: 150 }
    });
    console.log('[ELECTRON] Found', sources.length, 'screen sources');
    console.log('[ELECTRON] Sources:', sources.map(s => ({ id: s.id, name: s.name })));
    return sources;
  } catch (error) {
    console.error('[ELECTRON] Error getting screen sources:', error);
    throw error;
  }
});

// Test handler for debugging
ipcMain.on('test-screen-sources', (event, data) => {
  console.log('[ELECTRON] ===== TEST SCREEN SOURCES RECEIVED =====');
  console.log('[ELECTRON] Test data:', data);
  event.reply('test-screen-sources-reply', { success: true, message: 'IPC is working!' });
});

// File download settings
let downloadSettings = {
  downloadPath: getDefaultDownloadPath(),
  autoSave: true
};

function getDefaultDownloadPath() {
  switch (process.platform) {
    case 'win32':
      return path.join(os.homedir(), 'Downloads');
    case 'darwin':
      return path.join(os.homedir(), 'Downloads');
    case 'linux':
      return path.join(os.homedir(), 'Downloads');
    default:
      return path.join(os.homedir(), 'Downloads');
  }
}

// File download handlers
ipcMain.handle('file:save', async (event, { filename, data, mimeType }) => {
  try {
    console.log('[ELECTRON] Saving file:', { 
      filename, 
      dataLength: data?.length, 
      mimeType,
      downloadPath: downloadSettings.downloadPath,
      autoSave: downloadSettings.autoSave
    });
    
    if (!filename || !data) {
      throw new Error('Missing filename or data');
    }
    
    let savePath;
    if (downloadSettings.autoSave) {
      // Auto-save to configured download directory
      savePath = path.join(downloadSettings.downloadPath, filename);
      
      // Ensure directory exists
      if (!fs.existsSync(downloadSettings.downloadPath)) {
        console.log('[ELECTRON] Creating download directory:', downloadSettings.downloadPath);
        fs.mkdirSync(downloadSettings.downloadPath, { recursive: true });
      }
      
      // Handle duplicate filenames
      let counter = 1;
      let originalPath = savePath;
      while (fs.existsSync(savePath)) {
        const ext = path.extname(filename);
        const name = path.basename(filename, ext);
        savePath = path.join(downloadSettings.downloadPath, `${name} (${counter})${ext}`);
        counter++;
      }
      console.log('[ELECTRON] Final save path:', savePath);
    } else {
      // Show save dialog
      const result = await dialog.showSaveDialog(mainWindow, {
        defaultPath: path.join(downloadSettings.downloadPath, filename),
        filters: [
          { name: 'All Files', extensions: ['*'] }
        ]
      });
      
      if (result.canceled) {
        console.log('[ELECTRON] Save dialog canceled');
        return { success: false, canceled: true };
      }
      
      savePath = result.filePath;
      console.log('[ELECTRON] User selected save path:', savePath);
    }
    
    // Convert base64 data to buffer and save
    console.log('[ELECTRON] Converting base64 to buffer...');
    const buffer = Buffer.from(data, 'base64');
    console.log('[ELECTRON] Buffer created, size:', buffer.length);
    
    fs.writeFileSync(savePath, buffer);
    
    console.log('[ELECTRON] File saved successfully to:', savePath);
    return { success: true, path: savePath };
  } catch (error) {
    console.error('[ELECTRON] Error saving file:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('file:get-download-settings', () => {
  return downloadSettings;
});

ipcMain.handle('file:set-download-path', async (event, newPath) => {
  try {
    // Input validation
    if (!newPath || typeof newPath !== 'string') {
      return { success: false, error: 'Path must be a non-empty string' };
    }

    // Require absolute path
    if (!path.isAbsolute(newPath)) {
      return { success: false, error: 'Path must be absolute' };
    }

    // Check for null bytes in raw input
    if (newPath.includes('\0')) {
      return { success: false, error: 'Path contains null bytes' };
    }

    // Validate raw path segments before normalization to catch traversal attempts
    const pathSegments = newPath.split(path.sep);
    for (const segment of pathSegments) {
      if (segment === '..') {
        return { success: false, error: 'Path contains directory traversal sequences' };
      }
    }

    // Normalize and resolve path
    const resolved = path.resolve(newPath);

    // Additional safety check: ensure resolved path is within reasonable bounds
    // This catches any remaining traversal attempts after resolution
    const userHomeDir = require('os').homedir();
    const commonBaseDirs = [userHomeDir, '/tmp', '/var/tmp'];
    let isWithinAllowedBase = false;
    
    for (const baseDir of commonBaseDirs) {
      const resolvedBase = path.resolve(baseDir);
      if (resolved.startsWith(resolvedBase)) {
        isWithinAllowedBase = true;
        break;
      }
    }
    
    // Allow paths in common system locations or user directories
    if (!isWithinAllowedBase && !resolved.startsWith('/home/') && !resolved.startsWith('/Users/')) {
      return { success: false, error: 'Path is outside allowed directories' };
    }

    // Validate path exists or can be created
    if (!fs.existsSync(resolved)) {
      fs.mkdirSync(resolved, { recursive: true });
    }
    
    downloadSettings.downloadPath = resolved;
    return { success: true };
  } catch (error) {
    console.error('[ELECTRON] Error setting download path:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('file:set-auto-save', (event, autoSave) => {
  downloadSettings.autoSave = autoSave;
  return { success: true };
});

ipcMain.handle('file:choose-download-path', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory'],
      defaultPath: downloadSettings.downloadPath
    });
    
    if (result.canceled) {
      return { success: false, canceled: true };
    }
    
    return { success: true, path: result.filePaths[0] };
  } catch (error) {
    console.error('[ELECTRON] Error choosing download path:', error);
    return { success: false, error: error.message };
  }
});

// Link Preview Handler - Uses Tor proxy for secure fetching
ipcMain.handle('link:fetch-preview', async (event, url, options = {}) => {
  try {
    const { timeout = 10000, userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', maxRedirects = 5 } = options;

    console.log('[LINK-PREVIEW] Fetching preview for:', url);

    // Use Tor proxy for the request
    const { SocksProxyAgent } = require('socks-proxy-agent');
    const https = require('https');
    const http = require('http');
    const { URL } = require('url');
    const zlib = require('zlib');
    
    const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${torManager.effectiveSocksPort || 9050}`);
    
    return new Promise((resolve) => {
      try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const client = isHttps ? https : http;
        
        const requestOptions = {
          agent: proxyAgent,
          timeout: timeout,
          headers: {
            'User-Agent': userAgent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'close',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none'
          }
        };
        
        const req = client.get(url, requestOptions, (res) => {
          let data = Buffer.alloc(0);
          let redirectCount = 0;

          console.log(`[LINK-PREVIEW] Response status: ${res.statusCode}`);
          console.log(`[LINK-PREVIEW] Response headers:`, res.headers);

          // Handle redirects
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            if (redirectCount >= maxRedirects) {
              resolve({ error: 'Too many redirects' });
              return;
            }

            redirectCount++;
            const redirectUrl = new URL(res.headers.location, url).href;
            console.log(`[LINK-PREVIEW] Redirecting to: ${redirectUrl}`);

            // Recursively handle redirect (simplified - in production you'd want proper redirect handling)
            resolve({ error: 'Redirect handling not implemented in this version' });
            return;
          }

          if (res.statusCode !== 200) {
            console.log(`[LINK-PREVIEW] Non-200 status code: ${res.statusCode}`);
            resolve({ error: `HTTP ${res.statusCode}` });
            return;
          }

          // Check content type
          const contentType = res.headers['content-type'] || '';
          console.log(`[LINK-PREVIEW] Content type: ${contentType}`);
          if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
            console.log(`[LINK-PREVIEW] Not HTML content: ${contentType}`);
            resolve({ error: 'Not HTML content' });
            return;
          }

          // Handle compressed responses
          const encoding = res.headers['content-encoding'];
          console.log(`[LINK-PREVIEW] Content encoding: ${encoding}`);

          res.on('data', chunk => {
            data = Buffer.concat([data, chunk]);
            // Limit response size to prevent memory issues
            if (data.length > 1024 * 1024) { // 1MB limit
              res.destroy();
              resolve({ error: 'Response too large' });
            }
          });
          
          res.on('end', () => {
            try {
              let htmlContent = '';

              // Decompress the response based on encoding
              if (encoding === 'gzip') {
                console.log('[LINK-PREVIEW] Decompressing gzip content...');
                htmlContent = zlib.gunzipSync(data).toString('utf8');
              } else if (encoding === 'deflate') {
                console.log('[LINK-PREVIEW] Decompressing deflate content...');
                htmlContent = zlib.inflateSync(data).toString('utf8');
              } else if (encoding === 'br') {
                console.log('[LINK-PREVIEW] Decompressing brotli content...');
                htmlContent = zlib.brotliDecompressSync(data).toString('utf8');
              } else {
                console.log('[LINK-PREVIEW] No compression, using raw content...');
                htmlContent = data.toString('utf8');
              }

              console.log(`[LINK-PREVIEW] Decompressed HTML length: ${htmlContent.length}`);
              console.log(`[LINK-PREVIEW] HTML preview (first 500 chars): ${htmlContent.substring(0, 500)}`);

              const preview = parseHtmlForPreview(htmlContent, url);
              console.log('[LINK-PREVIEW] Successfully parsed preview:', preview);
              resolve(preview);
            } catch (parseError) {
              console.error('[LINK-PREVIEW] Parse error:', parseError);
              resolve({ error: 'Failed to parse HTML' });
            }
          });
        });
        
        req.on('error', (error) => {
          console.error('[LINK-PREVIEW] Request error:', error);
          resolve({ error: error.message || 'Request failed' });
        });
        
        req.on('timeout', () => {
          req.destroy();
          resolve({ error: 'Request timeout' });
        });
        
      } catch (error) {
        console.error('[LINK-PREVIEW] Setup error:', error);
        resolve({ error: error.message || 'Failed to setup request' });
      }
    });
    
  } catch (error) {
    console.error('[LINK-PREVIEW] Handler error:', error);
    return { error: error.message || 'Unknown error' };
  }
});

// HTML parsing function for link previews
function parseHtmlForPreview(html, url) {
  const preview = { url };

  try {
    console.log('[LINK-PREVIEW] Parsing HTML for URL:', url);
    console.log('[LINK-PREVIEW] HTML length:', html.length);
    console.log('[LINK-PREVIEW] HTML preview (first 500 chars):', html.substring(0, 500));

    // Simple regex-based HTML parsing (for production, consider using a proper HTML parser)

    // Extract title
    const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/is);
    if (titleMatch) {
      preview.title = decodeHtmlEntities(titleMatch[1].trim());
      console.log('[LINK-PREVIEW] Found title:', preview.title);
    } else {
      console.log('[LINK-PREVIEW] No title found');
    }

    // Extract Open Graph tags - improved regex patterns
    // Try both property-first and content-first patterns
    let ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']*?)["']/i);
    if (!ogTitleMatch) {
      ogTitleMatch = html.match(/<meta[^>]*content=["']([^"']*?)["'][^>]*property=["']og:title["']/i);
    }
    if (ogTitleMatch) {
      preview.title = decodeHtmlEntities(ogTitleMatch[1]);
      console.log('[LINK-PREVIEW] Found OG title:', preview.title);
    }

    let ogDescMatch = html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*?)["']/i);
    if (!ogDescMatch) {
      ogDescMatch = html.match(/<meta[^>]*content=["']([^"']*?)["'][^>]*property=["']og:description["']/i);
    }
    if (ogDescMatch) {
      preview.description = decodeHtmlEntities(ogDescMatch[1]);
      console.log('[LINK-PREVIEW] Found OG description:', preview.description);
    }

    let ogImageMatch = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']*?)["']/i);
    if (!ogImageMatch) {
      ogImageMatch = html.match(/<meta[^>]*content=["']([^"']*?)["'][^>]*property=["']og:image["']/i);
    }
    if (ogImageMatch) {
      preview.image = resolveUrl(ogImageMatch[1], url);
      console.log('[LINK-PREVIEW] Found OG image:', preview.image);
    }

    let ogSiteMatch = html.match(/<meta[^>]*property=["']og:site_name["'][^>]*content=["']([^"']*?)["']/i);
    if (!ogSiteMatch) {
      ogSiteMatch = html.match(/<meta[^>]*content=["']([^"']*?)["'][^>]*property=["']og:site_name["']/i);
    }
    if (ogSiteMatch) {
      preview.siteName = decodeHtmlEntities(ogSiteMatch[1]);
      console.log('[LINK-PREVIEW] Found OG site name:', preview.siteName);
    }

    // Fallback to standard meta tags
    if (!preview.description) {
      let descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*?)["']/i);
      if (!descMatch) {
        descMatch = html.match(/<meta[^>]*content=["']([^"']*?)["'][^>]*name=["']description["']/i);
      }
      if (descMatch) {
        preview.description = decodeHtmlEntities(descMatch[1]);
        console.log('[LINK-PREVIEW] Found meta description:', preview.description);
      } else {
        console.log('[LINK-PREVIEW] No description found');
      }
    }
    
    // Additional fallbacks for Twitter Card meta tags
    if (!preview.title) {
      const twitterTitleMatch = html.match(/<meta[^>]*name=["']twitter:title["'][^>]*content=["']([^"']*?)["']/i);
      if (twitterTitleMatch) {
        preview.title = decodeHtmlEntities(twitterTitleMatch[1]);
        console.log('[LINK-PREVIEW] Found Twitter title:', preview.title);
      }
    }

    if (!preview.description) {
      const twitterDescMatch = html.match(/<meta[^>]*name=["']twitter:description["'][^>]*content=["']([^"']*?)["']/i);
      if (twitterDescMatch) {
        preview.description = decodeHtmlEntities(twitterDescMatch[1]);
        console.log('[LINK-PREVIEW] Found Twitter description:', preview.description);
      }
    }

    if (!preview.image) {
      const twitterImageMatch = html.match(/<meta[^>]*name=["']twitter:image["'][^>]*content=["']([^"']*?)["']/i);
      if (twitterImageMatch) {
        preview.image = resolveUrl(twitterImageMatch[1], url);
        console.log('[LINK-PREVIEW] Found Twitter image:', preview.image);
      }
    }

    // Extract favicon
    const faviconMatch = html.match(/<link[^>]*rel=["'](?:shortcut icon|icon)["'][^>]*href=["']([^"']*?)["']/i);
    if (faviconMatch) {
      preview.faviconUrl = resolveUrl(faviconMatch[1], url);
    } else {
      // Fallback to default favicon location
      try {
        const { URL } = require('url');
        const parsedUrl = new URL(url);
        preview.faviconUrl = `${parsedUrl.protocol}//${parsedUrl.host}/favicon.ico`;
      } catch (e) {
        // Ignore favicon errors
      }
    }
    
    // Limit text lengths
    if (preview.title && preview.title.length > 100) {
      preview.title = preview.title.substring(0, 97) + '...';
    }
    if (preview.description && preview.description.length > 200) {
      preview.description = preview.description.substring(0, 197) + '...';
    }

    console.log('[LINK-PREVIEW] Final preview object:', preview);
    return preview;
  } catch (error) {
    console.error('[LINK-PREVIEW] HTML parsing error:', error);
    return { url, error: 'Failed to parse HTML content' };
  }
}

// Helper function to decode HTML entities
function decodeHtmlEntities(text) {
  const entities = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#39;': "'",
    '&apos;': "'",
    '&nbsp;': ' '
  };
  
  return text.replace(/&[#\w]+;/g, (entity) => {
    return entities[entity] || entity;
  });
}

// Helper function to resolve relative URLs
function resolveUrl(relativeUrl, baseUrl) {
  try {
    const { URL } = require('url');
    return new URL(relativeUrl, baseUrl).href;
  } catch (error) {
    return relativeUrl;
  }
}

// External URL handler - secure opening of links
ipcMain.handle('shell:open-external', async (event, url) => {
  try {
    // Validate URL for security
    if (!url || typeof url !== 'string') {
      throw new Error('Invalid URL');
    }
    
    // Only allow HTTP/HTTPS URLs
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      throw new Error('Only HTTP/HTTPS URLs are allowed');
    }
    
    // Limit URL length
    if (url.length > 2048) {
      throw new Error('URL too long');
    }
    
    console.log('[ELECTRON] Opening external URL:', url);
    await shell.openExternal(url);
    return { success: true };
  } catch (error) {
    console.error('[ELECTRON] Error opening external URL:', error);
    return { success: false, error: error.message };
  }
});

console.log('[ELECTRON] Main process started');
console.log('[ELECTRON] Platform:', process.platform);
console.log('[ELECTRON] Architecture:', process.arch);
console.log('[ELECTRON] Development mode:', isDev);
console.log('[ELECTRON] Default download path:', downloadSettings.downloadPath);