const { contextBridge, ipcRenderer } = require('electron');

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
  
  // Server message listener
  onServerMessage: (callback) => {
    ipcRenderer.on('edge:server-message', (event, message) => callback(message));
    return () => ipcRenderer.removeListener('edge:server-message', callback);
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
  rendererReady: () => ipcRenderer.invoke('renderer:ready')
});

// Log that preload script has loaded
console.log('[PRELOAD] Electron preload script loaded');
console.log('[PRELOAD] Platform:', process.platform);
console.log('[PRELOAD] Node version:', process.version);

// Bridge server messages into the isolated world via a DOM event for React hooks
try {
  ipcRenderer.on('edge:server-message', (_event, data) => {
    try {
      window.dispatchEvent(new CustomEvent('edge:server-message', { detail: data }));
    } catch {}
  });
} catch {}
