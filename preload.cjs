const { contextBridge, ipcRenderer } = require('electron');

// Expose Tor and system functionality for the auto-setup
contextBridge.exposeInMainWorld('electronAPI', {
  // Platform information
  platform: process.platform,
  arch: process.arch,

  // Tor management functions
  checkTorInstallation: () => ipcRenderer.invoke('tor:check-installation'),
  downloadTor: () => ipcRenderer.invoke('tor:download'),
  installTor: () => ipcRenderer.invoke('tor:install'),
  configureTor: (options) => ipcRenderer.invoke('tor:configure', options),
  startTor: () => ipcRenderer.invoke('tor:start'),
  stopTor: () => ipcRenderer.invoke('tor:stop'),
  getTorStatus: () => ipcRenderer.invoke('tor:status'),
  uninstallTor: () => ipcRenderer.invoke('tor:uninstall'),

  // System information
  getPlatformInfo: () => ipcRenderer.invoke('system:platform'),

  // Tor verification
  verifyTorConnection: () => ipcRenderer.invoke('tor:verify-connection'),
  getTorInfo: () => ipcRenderer.invoke('tor:get-info'),
  rotateTorCircuit: () => ipcRenderer.invoke('tor:rotate-circuit'),

  // Utility
  isElectron: true,
  isDevelopment: process.env.NODE_ENV === 'development',
});

contextBridge.exposeInMainWorld('edgeApi', {
  // Libsignal identity and prekeys
  generateIdentity: (args) => ipcRenderer.invoke('edge:generateIdentity', args),
  generatePreKeys: (args) => ipcRenderer.invoke('edge:generatePreKeys', args),
  getPreKeyBundle: (args) => ipcRenderer.invoke('edge:getPreKeyBundle', args),
  processPreKeyBundle: (args) => ipcRenderer.invoke('edge:processPreKeyBundle', args),

  // Encryption helpers
  hasSession: (args) => ipcRenderer.invoke('edge:hasSession', args),
  encrypt: (args) => ipcRenderer.invoke('edge:encrypt', args),
  decrypt: (args) => ipcRenderer.invoke('edge:decrypt', args),

  // Note: Typing indicators are now sent as encrypted messages through the normal message system

  // Legacy/unused placeholders (safe to keep for compatibility)
  setupSession: (args) => ipcRenderer.invoke('edge:setupSession', args),
  publishBundle: (args) => ipcRenderer.invoke('edge:publishBundle', args),
  requestBundle: (args) => ipcRenderer.invoke('edge:requestBundle', args),
  wsSend: (payload) => ipcRenderer.invoke('edge:ws-send', payload),
  rendererReady: () => ipcRenderer.invoke('edge:renderer-ready'),
});

// Bridge server messages into the isolated world via a DOM event
ipcRenderer.on('edge:server-message', (_event, data) => {
  try {
    window.dispatchEvent(new CustomEvent('edge:server-message', { detail: data }));
  } catch {}
});

// Note: Typing indicators are now handled as encrypted messages through the normal message system


