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

// Log that preload script has loaded
console.log('[PRELOAD] Electron preload script loaded');
console.log('[PRELOAD] Platform:', process.platform);
console.log('[PRELOAD] Node version:', process.version);
