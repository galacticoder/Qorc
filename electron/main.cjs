const { app, BrowserWindow, ipcMain, desktopCapturer } = require('electron');
const path = require('path');
const isDev = process.env.NODE_ENV === 'development';
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
    experimentalFeatures: true
  };

  // Only weaken security in development for WebRTC/screen sharing testing
  if (isDev) {
    webPreferences.webSecurity = false;
    webPreferences.allowRunningInsecureContent = true;
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

  // Load the app
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    // Open DevTools in development
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    
    // Focus on window
    if (isDev) {
      mainWindow.focus();
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
      console.log('[ELECTRON] Shutting down Tor before closing...');
      await torManager.stopTor();
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

    // Prevent navigation away from our app (e.g., when clicking blob: links for download)
    contents.on('will-navigate', (e, url) => {
      e.preventDefault();
      console.log('[SECURITY] Blocked navigation to:', url);
    });

    // Intercept downloads to avoid renderer navigation/logouts
    contents.session.on('will-download', (event, item) => {
      // Keep default behavior but ensure it does not navigate the page
      console.log('[ELECTRON] Download started:', item.getFilename());
      // Explicitly prevent any navigation side-effects
      try {
        if (typeof contents.isLoading === 'function' && contents.isLoading()) {
          if (typeof contents.stopLoading === 'function') {
            contents.stopLoading();
          }
        }
      } catch (err) {
        console.error('[ELECTRON] Failed to stop loading during download:', err);
      }
      item.on('done', (_e, state) => {
        console.log('[ELECTRON] Download finished:', state);
      });
    });

    // Security: Prevent new window creation
    contents.on('new-window', (event, navigationUrl) => {
      event.preventDefault();
      console.log('[SECURITY] Blocked new window creation to:', navigationUrl);
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

ipcMain.handle('edge:ws-send', async (event, payload) => {
  try {
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

// Handle app info requests
ipcMain.handle('app:version', () => {
  return app.getVersion();
});

ipcMain.handle('app:name', () => {
  return app.getName();
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

console.log('[ELECTRON] Main process started');
console.log('[ELECTRON] Platform:', process.platform);
console.log('[ELECTRON] Architecture:', process.arch);
console.log('[ELECTRON] Development mode:', isDev);
