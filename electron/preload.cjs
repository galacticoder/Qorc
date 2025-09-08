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

  // Screen sharing
  getScreenSources: () => {
    // No input validation needed - takes no parameters
    return ipcRenderer.invoke('screen:getSources');
  },

  // File operations
  saveFile: (data) => {
    // Validate saveFile input
    if (!data || typeof data !== 'object') {
      return Promise.reject(new Error('saveFile requires an object parameter'));
    }
    if (!data.filename || typeof data.filename !== 'string' || data.filename.length > 255) {
      return Promise.reject(new Error('Invalid filename'));
    }
    if (!data.data || typeof data.data !== 'string') {
      return Promise.reject(new Error('Invalid file data'));
    }
    if (!data.mimeType || typeof data.mimeType !== 'string') {
      return Promise.reject(new Error('Invalid MIME type'));
    }
    // Check for path traversal in filename
    if (data.filename.includes('..') || data.filename.includes('/') || data.filename.includes('\\')) {
      return Promise.reject(new Error('Filename contains invalid characters'));
    }
    return ipcRenderer.invoke('file:save', data);
  },
  
  getDownloadSettings: () => {
    // No input validation needed - takes no parameters
    return ipcRenderer.invoke('file:get-download-settings');
  },
  
  setDownloadPath: (path) => {
    // Validate path input
    if (!path || typeof path !== 'string') {
      return Promise.reject(new Error('Path must be a non-empty string'));
    }
    if (path.length > 1000) {
      return Promise.reject(new Error('Path too long'));
    }
    // Check for null bytes
    if (path.includes('\0')) {
      return Promise.reject(new Error('Path contains null bytes'));
    }
    return ipcRenderer.invoke('file:set-download-path', path);
  },
  
  setAutoSave: (autoSave) => {
    // Validate boolean input
    if (typeof autoSave !== 'boolean') {
      return Promise.reject(new Error('autoSave must be a boolean'));
    }
    return ipcRenderer.invoke('file:set-auto-save', autoSave);
  },
  
  chooseDownloadPath: () => {
    // No input validation needed - takes no parameters
    return ipcRenderer.invoke('file:choose-download-path');
  },

  // Link Preview - secure fetching through Tor
  fetchLinkPreview: (url, options = {}) => {
    // Validate URL input
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a non-empty string'));
    }
    if (url.length > 2048) {
      return Promise.reject(new Error('URL too long'));
    }
    // Basic URL format validation
    try {
      new URL(url.startsWith('http') ? url : 'https://' + url);
    } catch {
      return Promise.reject(new Error('Invalid URL format'));
    }
    
    // Validate options if provided
    if (options && typeof options !== 'object') {
      return Promise.reject(new Error('Options must be an object'));
    }
    
    // Sanitize options
    const sanitizedOptions = {};
    if (options.timeout && typeof options.timeout === 'number' && options.timeout > 0 && options.timeout <= 60000) {
      sanitizedOptions.timeout = options.timeout;
    }
    if (options.userAgent && typeof options.userAgent === 'string' && options.userAgent.length <= 500) {
      sanitizedOptions.userAgent = options.userAgent;
    }
    if (options.maxRedirects && typeof options.maxRedirects === 'number' && options.maxRedirects >= 0 && options.maxRedirects <= 10) {
      sanitizedOptions.maxRedirects = options.maxRedirects;
    }
    
    return ipcRenderer.invoke('link:fetch-preview', url, sanitizedOptions);
  },

  // External URL opening - secure shell.openExternal
  openExternal: (url) => {
    // Validate URL input
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a non-empty string'));
    }
    if (url.length > 2048) {
      return Promise.reject(new Error('URL too long'));
    }
    // Basic URL format validation
    try {
      new URL(url);
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return Promise.reject(new Error('Only HTTP/HTTPS URLs are allowed'));
      }
    } catch {
      return Promise.reject(new Error('Invalid URL format'));
    }
    
    return ipcRenderer.invoke('shell:open-external', url);
  },

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
  setServerUrl: (url) => ipcRenderer.invoke('edge:set-server-url', url),
  getServerUrl: () => ipcRenderer.invoke('edge:get-server-url'),
  rendererReady: () => ipcRenderer.invoke('renderer:ready'),
  torSetupComplete: () => ipcRenderer.invoke('tor:setup-complete'),
  // Power save blocker for calls
  powerSaveBlockerStart: () => ipcRenderer.invoke('power:psb-start'),
  powerSaveBlockerStop: () => ipcRenderer.invoke('power:psb-stop'),
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