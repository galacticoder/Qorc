const { contextBridge, ipcRenderer } = require('electron');

console.log('[PRELOAD] Starting preload script...');
console.log('[PRELOAD] contextBridge available:', !!contextBridge);
console.log('[PRELOAD] ipcRenderer available:', !!ipcRenderer);

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Platform information
  platform: process.platform,
  arch: process.arch,
  
  // App information
  getAppVersion: () => ipcRenderer.invoke('app:version'),
  getAppName: () => ipcRenderer.invoke('app:name'),
  getPlatformInfo: () => ipcRenderer.invoke('system:platform'),
  
  // Tor management functions
  checkTorInstallation: () => ipcRenderer.invoke('tor:check-installation'),
  downloadTor: (options) => ipcRenderer.invoke('tor:download', options),
  installTor: () => ipcRenderer.invoke('tor:install'),
  configureTor: (options) => ipcRenderer.invoke('tor:configure', options),
  startTor: () => ipcRenderer.invoke('tor:start'),
  stopTor: () => ipcRenderer.invoke('tor:stop'),
  getTorStatus: () => ipcRenderer.invoke('tor:status'),
  getTorInfo: () => ipcRenderer.invoke('tor:info'),
  uninstallTor: () => ipcRenderer.invoke('tor:uninstall'),
  verifyTorConnection: () => ipcRenderer.invoke('tor:verify-connection'),
  rotateTorCircuit: () => ipcRenderer.invoke('tor:rotate-circuit'),
  
  // Utility functions
  isElectron: true,
  isDevelopment: process.env.NODE_ENV === 'development',
  
  // Event listeners for Tor status updates
  onTorStatusChange: (callback) => {
    ipcRenderer.on('tor:status-change', callback);
    return () => ipcRenderer.removeListener('tor:status-change', callback);
  },
  
  onTorProgress: (callback) => {
    ipcRenderer.on('tor:progress', callback);
    return () => ipcRenderer.removeListener('tor:progress', callback);
  },
  
  // Security: Only allow specific channels
  send: (channel, data) => {
    const validChannels = ['tor:rotate-circuit', 'tor:new-session'];
    if (validChannels.includes(channel)) {
      ipcRenderer.send(channel, data);
    }
  },
  
  receive: (channel, func) => {
    const validChannels = ['tor:status-update', 'tor:error', 'tor:connected', 'tor:disconnected'];
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => func(...args));
    }
  }
});

// Expose edgeApi for server communication and Signal Protocol
contextBridge.exposeInMainWorld('edgeApi', {
  // WebSocket communication
  wsSend: (message) => ipcRenderer.invoke('edge:ws-send', message),
  wsConnect: () => ipcRenderer.invoke('edge:ws-connect'),
  
  // Server message listener - centralized dispatcher
  onServerMessage: (callback) => {
    // Use the centralized dispatcher instead of direct IPC listener
    const handler = (event) => callback(event.detail);
    window.addEventListener('edge:server-message', handler);
    return () => window.removeEventListener('edge:server-message', handler);
  },
  
  // Signal Protocol functions (placeholders for now)
  generateIdentity: (options) => ipcRenderer.invoke('signal:generate-identity', options),
  generatePreKeys: (options) => ipcRenderer.invoke('signal:generate-prekeys', options),
  getPreKeyBundle: (options) => ipcRenderer.invoke('signal:get-prekey-bundle', options),
  processPreKeyBundle: (options) => ipcRenderer.invoke('signal:process-prekey-bundle', options),
  hasSession: (options) => ipcRenderer.invoke('signal:has-session', options),
  encrypt: (options) => ipcRenderer.invoke('signal:encrypt', options),
  decrypt: (options) => ipcRenderer.invoke('signal:decrypt', options),
  
  // Renderer ready notification
  rendererReady: () => ipcRenderer.invoke('renderer:ready'),

  // Screen sharing support
  getScreenSources: () => {
    console.log('[PRELOAD] getScreenSources called');
    return ipcRenderer.invoke('screen:getSources');
  },

  // Test function to verify preload script is working
  testFunction: () => {
    console.log('[PRELOAD] Test function called - preload script is working');
    return 'preload-working';
  },

  // Debug function to check what's available
  debugElectronAPI: () => {
    console.log('[PRELOAD] Debug function called');
    // Note: This function runs in the renderer context, not preload context
    // The actual checks will be performed when called from the renderer
    return {
      preloadScriptLoaded: true,
      timestamp: new Date().toISOString(),
      platform: process.platform
    };
  }
});

console.log('[PRELOAD] contextBridge.exposeInMainWorld completed');

// Log that preload script has loaded
console.log('[PRELOAD] ===== ELECTRON PRELOAD SCRIPT LOADED =====');
console.log('[PRELOAD] Platform:', process.platform);
console.log('[PRELOAD] Node version:', process.version);
console.log('[PRELOAD] Screen sharing function defined in contextBridge');
console.log('[PRELOAD] Current timestamp:', new Date().toISOString());



// Centralized server message dispatcher - single IPC listener that dispatches DOM events
// All consumers should use electronAPI.onServerMessage() which subscribes to these DOM events
try {
  ipcRenderer.on('edge:server-message', (_event, data) => {
    try {
      window.dispatchEvent(new CustomEvent('edge:server-message', { detail: data }));
    } catch {}
  });
} catch {}
