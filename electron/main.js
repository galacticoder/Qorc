const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const isDev = process.env.NODE_ENV === 'development';
const torManager = require('./tor-manager');

// Keep a global reference of the window object
let mainWindow;

function createWindow() {
  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    },
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

// Security: Prevent new window creation
app.on('web-contents-created', (event, contents) => {
  contents.on('new-window', (event, navigationUrl) => {
    event.preventDefault();
    console.log('[SECURITY] Blocked new window creation to:', navigationUrl);
  });
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

// Get platform info
ipcMain.handle('system:platform', () => {
  return {
    platform: process.platform,
    arch: process.arch,
    version: process.version
  };
});

// Handle app info requests
ipcMain.handle('app:version', () => {
  return app.getVersion();
});

ipcMain.handle('app:name', () => {
  return app.getName();
});

console.log('[ELECTRON] Main process started');
console.log('[ELECTRON] Platform:', process.platform);
console.log('[ELECTRON] Architecture:', process.arch);
console.log('[ELECTRON] Development mode:', isDev);
