const { contextBridge, ipcRenderer } = require('electron');

// SECURITY: Validate and sanitize all inputs to prevent injection attacks
function validateTorOptions(options) {
  if (!options || typeof options !== 'object') {
    throw new Error('Invalid options: must be an object');
  }

  // Validate torrc text safely. The config is written to a file and never executed via a shell.
  if (typeof options.config === 'string') {
    // Reasonable size limit to avoid abuse
    if (options.config.length > 50000) {
      throw new Error('Configuration too large');
    }

    // Forbid embedded null bytes and non-printable characters (except tab/newline/CR)
    if (/\x00/.test(options.config)) {
      throw new Error('Invalid configuration: contains null bytes');
    }
    if (/[^\x09\x0A\x0D\x20-\x7E]/.test(options.config)) {
      throw new Error('Invalid configuration: contains invalid characters');
    }
  }

  return options;
}

// Expose Tor and system functionality for the auto-setup
contextBridge.exposeInMainWorld('electronAPI', {
  // Platform information - static values only
  platform: process.platform,
  arch: process.arch,

  // Tor management functions with input validation
  checkTorInstallation: () => ipcRenderer.invoke('tor:check-installation'),
  downloadTor: (options) => ipcRenderer.invoke('tor:download', options),
  installTor: () => ipcRenderer.invoke('tor:install'),
  configureTor: (options) => {
    try {
      const validatedOptions = validateTorOptions(options);
      return ipcRenderer.invoke('tor:configure', validatedOptions);
    } catch (error) {
      return Promise.reject(error);
    }
  },
  startTor: () => ipcRenderer.invoke('tor:start'),
  stopTor: () => ipcRenderer.invoke('tor:stop'),
  getTorStatus: () => ipcRenderer.invoke('tor:status'),
  uninstallTor: () => ipcRenderer.invoke('tor:uninstall'),

  // System information
  getPlatformInfo: () => ipcRenderer.invoke('system:platform'),

  // Tor verification
  verifyTorConnection: () => ipcRenderer.invoke('tor:verify-connection'),
  getTorInfo: () => ipcRenderer.invoke('tor:info'),
  rotateTorCircuit: () => ipcRenderer.invoke('tor:rotate-circuit'),

  // Utility
  isElectron: true,
  isDevelopment: process.env.NODE_ENV === 'development',
});

contextBridge.exposeInMainWorld('edgeApi', {
  // Libsignal identity and prekeys
  generateIdentity: (args) => ipcRenderer.invoke('signal:generate-identity', args),
  generatePreKeys: (args) => ipcRenderer.invoke('signal:generate-prekeys', args),
  getPreKeyBundle: (args) => ipcRenderer.invoke('signal:get-prekey-bundle', args),
  processPreKeyBundle: (args) => ipcRenderer.invoke('signal:process-prekey-bundle', args),

  // Encryption helpers
  hasSession: (args) => ipcRenderer.invoke('signal:has-session', args),
  encrypt: (args) => ipcRenderer.invoke('signal:encrypt', args),
  decrypt: (args) => ipcRenderer.invoke('signal:decrypt', args),

  // Note: Typing indicators are now sent as encrypted messages through the normal message system

  // Legacy/unused placeholders (safe to keep for compatibility)
  setupSession: (args) => ipcRenderer.invoke('signal:setup-session', args),
  publishBundle: (args) => ipcRenderer.invoke('signal:publish-bundle', args),
  requestBundle: (args) => ipcRenderer.invoke('signal:request-bundle', args),
  wsSend: (payload) => ipcRenderer.invoke('edge:ws-send', payload),
  wsConnect: () => ipcRenderer.invoke('edge:ws-connect'),
  rendererReady: () => ipcRenderer.invoke('renderer:ready'),
  torSetupComplete: () => ipcRenderer.invoke('tor:setup-complete'),
});

// Bridge server messages into the isolated world via a DOM event
ipcRenderer.on('edge:server-message', (_event, data) => {
  try {
    window.dispatchEvent(new CustomEvent('edge:server-message', { detail: data }));
  } catch (error) {
    console.error('[PRELOAD] Failed to dispatch server message:', error);
  }
});

// Note: Typing indicators are now handled as encrypted messages through the normal message system