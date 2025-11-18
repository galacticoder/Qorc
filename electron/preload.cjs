/**
 * Electron Preload Script 
 * Secure bridge between renderer and main process with full input validation
 */

const { contextBridge, ipcRenderer } = require('electron');

const MAX_TOR_CONFIG_SIZE = 50000;
const MAX_URL_LENGTH = 2048;
const MAX_PATH_LENGTH = 1000;
const MAX_FILENAME_LENGTH = 255;

function validateTorOptions(options) {
  if (!options || typeof options !== 'object') {
    throw new Error('Invalid options');
  }

  if (typeof options.config === 'string') {
    if (options.config.length > MAX_TOR_CONFIG_SIZE) {
      throw new Error('Configuration too large');
    }

    if (/\x00/.test(options.config)) {
      throw new Error('Null bytes not allowed');
    }
    if (/[^\x09\x0A\x0D\x20-\x7E]/.test(options.config)) {
      throw new Error('Invalid characters in configuration');
    }

    const allowedDirectives = new Set([
      'AvoidDiskWrites',
      'Bridge',
      'CircuitBuildTimeout',
      'ClientOnly',
      'ClientTransportPlugin',
      'ControlPort',
      'CookieAuthentication',
      'DataDirectory',
      'DisableDebuggerAttachment',
      'DisableNetwork',
      'EnforceDistinctSubnets',
      'EntryNodes',
      'ExitNodes',
      'ExitPolicy',
      'ExcludeExitNodes',
      'ExcludeNodes',
      'FetchDirInfoEarly',
      'FetchDirInfoExtraEarly',
      'FetchUselessDescriptors',
      'GeoIPFile',
      'GeoIPv6File',
      'HashedControlPassword',
      'LearnCircuitBuildTimeout',
      'Log',
      'MaxCircuitDirtiness',
      'NewCircuitPeriod',
      'NumEntryGuards',
      'ProtocolWarnings',
      'SafeLogging',
      'SocksAuth',
      'SocksListenAddress',
      'SocksPolicy',
      'SocksPort',
      'StrictNodes',
      'TrackHostExits',
      'TrackHostExitsExpire',
      'UseBridges',
      'UseEntryGuards',
      'UseMicrodescriptors'
    ]);

    const lines = options.config.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }
      const match = trimmed.match(/^([A-Za-z][A-Za-z0-9_]*)\b/);
      if (!match) {
        throw new Error(`Invalid Tor config syntax: ${line}`);
      }
      const directive = match[1];
      if (!allowedDirectives.has(directive)) {
        throw new Error(`Forbidden Tor config directive: ${directive}`);
      }
    }
  }

  return options;
}

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  arch: process.arch,
  // Instance ID to allow per-instance isolation of secrets for multiple accounts on device just leaving it this way for now will change later
  instanceId: process.env.ELECTRON_INSTANCE_ID || process.env.INSTANCE_ID || '1',

  secureStore: {
    init: async () => {
      const res = await ipcRenderer.invoke('secure:init');
      return !!res?.success;
    },
    get: async (key) => {
      const res = await ipcRenderer.invoke('secure:get', key);
      if (res && res.success) return res.value || null;
      return null;
    },
    set: async (key, value) => {
      const res = await ipcRenderer.invoke('secure:set', key, value);
      return !!res?.success;
    },
    remove: async (key) => {
      const res = await ipcRenderer.invoke('secure:remove', key);
      return !!res?.success;
    }
  },

  checkTorInstallation: () => ipcRenderer.invoke('tor:check-installation'),
  downloadTor: () => ipcRenderer.invoke('tor:download'),
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
  
  onTorConfigureComplete: (callback) => {
    const listener = (_event, data) => callback(_event, data);
    ipcRenderer.once('tor:configure-complete', listener);
    return () => ipcRenderer.removeListener('tor:configure-complete', listener);
  },

  initializeTor: (config) => {
    if (!config || typeof config !== 'object') {
      return Promise.reject(new Error('Invalid Tor configuration'));
    }
    return ipcRenderer.invoke('tor:initialize', config);
  },
  testTorConnection: () => ipcRenderer.invoke('tor:test-connection'),
  makeTorRequest: (options) => {
    if (!options || typeof options !== 'object') {
      return Promise.reject(new Error('Invalid Tor request options'));
    }
    return ipcRenderer.invoke('tor:request', options);
  },
  getTorWebSocketUrl: (url) => {
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a string'));
    }
    if (url.length > MAX_URL_LENGTH) {
      return Promise.reject(new Error('URL too long'));
    }
    return ipcRenderer.invoke('tor:get-ws-url', url);
  },

  getPlatformInfo: () => ipcRenderer.invoke('system:platform'),

  verifyTorConnection: () => ipcRenderer.invoke('tor:verify-connection'),
  getTorInfo: () => ipcRenderer.invoke('tor:info'),
  rotateTorCircuit: () => ipcRenderer.invoke('tor:new-circuit'),

  getScreenSources: () => {
    return ipcRenderer.invoke('screen:getSources');
  },

  getIceConfiguration: () => {
    return ipcRenderer.invoke('webrtc:get-ice-config');
  },

  // Onion transport APIs
  createOnionEndpoint: (options = {}) => {
    const ttl = typeof options.ttlSeconds === 'number' && options.ttlSeconds > 0 && options.ttlSeconds <= 3600 ? options.ttlSeconds : 600;
    return ipcRenderer.invoke('onion:create-endpoint', { ttlSeconds: ttl });
  },
  connectOnionWebSocket: async (_opts) => {
    return null;
  },
  onOnionMessage: (callback) => {
    if (typeof callback !== 'function') return () => {};
    const listener = (_event, data) => { try { callback(_event, data); } catch (_) {} };
    ipcRenderer.on('onion:message', listener);
    return () => ipcRenderer.removeListener('onion:message', listener);
  },
  sendOnionMessage: (toUsername, payload) => {
    return ipcRenderer.invoke('onion:send', toUsername, payload);
  },

  saveFile: (data) => {
    if (!data || typeof data !== 'object') {
      return Promise.reject(new Error('saveFile requires an object parameter'));
    }
    if (!data.filename || typeof data.filename !== 'string' || data.filename.length > MAX_FILENAME_LENGTH) {
      return Promise.reject(new Error('Invalid filename'));
    }
    if (!data.data || typeof data.data !== 'string') {
      return Promise.reject(new Error('Invalid file data'));
    }
    if (!data.mimeType || typeof data.mimeType !== 'string') {
      return Promise.reject(new Error('Invalid MIME type'));
    }
    if (data.filename.includes('..') || data.filename.includes('/') || data.filename.includes('\\')) {
      return Promise.reject(new Error('Filename contains invalid characters'));
    }
    return ipcRenderer.invoke('file:save', data);
  },
  
  getDownloadSettings: () => {
    return ipcRenderer.invoke('file:get-download-settings');
  },
  
  setDownloadPath: (path) => {
    if (!path || typeof path !== 'string') {
      return Promise.reject(new Error('Path must be a non-empty string'));
    }
    if (path.length > MAX_PATH_LENGTH) {
      return Promise.reject(new Error('Path too long'));
    }
    if (path.includes('\0')) {
      return Promise.reject(new Error('Path contains null bytes'));
    }
    return ipcRenderer.invoke('file:set-download-path', path);
  },
  
  setAutoSave: (autoSave) => {
    if (typeof autoSave !== 'boolean') {
      return Promise.reject(new Error('autoSave must be a boolean'));
    }
    return ipcRenderer.invoke('file:set-auto-save', autoSave);
  },
  
  chooseDownloadPath: () => {
    return ipcRenderer.invoke('file:choose-download-path');
  },

  fetchLinkPreview: (url, options = {}) => {
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a non-empty string'));
    }
    if (url.length > MAX_URL_LENGTH) {
      return Promise.reject(new Error('URL too long'));
    }
    try {
      new URL(url.startsWith('http') ? url : 'https://' + url);
    } catch {
      return Promise.reject(new Error('Invalid URL format'));
    }
    
    if (options && typeof options !== 'object') {
      return Promise.reject(new Error('Options must be an object'));
    }
    
    const sanitizedOptions = {};
    if (options.timeout && typeof options.timeout === 'number' && options.timeout > 0 && options.timeout <= 60000) {
      sanitizedOptions.timeout = options.timeout;
    }
    if (options.userAgent !== undefined) {
      const TOR_STANDARD_UA = 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0';
      if (options.userAgent && options.userAgent !== TOR_STANDARD_UA) {
        return Promise.reject(new Error('Custom User-Agent not allowed'));
      }
      sanitizedOptions.userAgent = TOR_STANDARD_UA;
    }
    if (options.maxRedirects && typeof options.maxRedirects === 'number' && options.maxRedirects >= 0 && options.maxRedirects <= 10) {
      sanitizedOptions.maxRedirects = options.maxRedirects;
    }
    
    return ipcRenderer.invoke('link:fetch-preview', url, sanitizedOptions);
  },

  openExternal: (url) => {
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a non-empty string'));
    }
    if (url.length > MAX_URL_LENGTH) {
      return Promise.reject(new Error('URL too long'));
    }
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

  isElectron: true
});

const validateSignalArgs = (methodName, args) => {
  if (!args || typeof args !== 'object') {
    throw new Error(`${methodName}: args must be an object`);
  }
  const size = JSON.stringify(args).length;
  if (size > 100_000) {
    throw new Error(`${methodName}: args too large`);
  }
  return args;
};

contextBridge.exposeInMainWorld('edgeApi', {
  generateIdentity(args) {
    try { return ipcRenderer.invoke('signal-v2:generate-identity', validateSignalArgs('generateIdentity', args)); } catch (error) { return Promise.reject(error); }
  },
  generatePreKeys(args) {
    try { return ipcRenderer.invoke('signal-v2:generate-prekeys', validateSignalArgs('generatePreKeys', args)); } catch (error) { return Promise.reject(error); }
  },
  getPreKeyBundle(args) {
    try {
      return ipcRenderer.invoke('signal-v2:create-prekey-bundle', validateSignalArgs('getPreKeyBundle', args)).then((res) => {
        if (res && res.success && res.bundle) return res.bundle;
        return res?.bundle || res;
      });
    } catch (error) { return Promise.reject(error); }
  },
  processPreKeyBundle(args) {
    try { return ipcRenderer.invoke('signal-v2:process-prekey-bundle', validateSignalArgs('processPreKeyBundle', args)); } catch (error) { return Promise.reject(error); }
  },

  hasSession(args) {
    try { return ipcRenderer.invoke('signal-v2:has-session', validateSignalArgs('hasSession', args)); } catch (error) { return Promise.reject(error); }
  },
  encrypt(args) {
    try { return ipcRenderer.invoke('signal-v2:encrypt', validateSignalArgs('encrypt', args)); } catch (error) { return Promise.reject(error); }
  },
  setStaticMlkemKeys(args) {
    try { return ipcRenderer.invoke('signal-v2:set-static-mlkem-keys', validateSignalArgs('setStaticMlkemKeys', args)); } catch (error) { return Promise.reject(error); }
  },
  decrypt(args) {
    try { return ipcRenderer.invoke('signal-v2:decrypt', validateSignalArgs('decrypt', args)); } catch (error) { return Promise.reject(error); }
  },
  deleteSession(args) {
    try { return ipcRenderer.invoke('signal-v2:delete-session', validateSignalArgs('deleteSession', args)); } catch (error) { return Promise.reject(error); }
  },
  deleteAllSessions(args) {
    try { return ipcRenderer.invoke('signal-v2:delete-all-sessions', validateSignalArgs('deleteAllSessions', args)); } catch (error) { return Promise.reject(error); }
  },

  trustPeerIdentity(args) {
    try { return ipcRenderer.invoke('signal-v2:trust-peer-identity', validateSignalArgs('trustPeerIdentity', args)); } catch (error) { return Promise.reject(error); }
  },

  setSignalStorageKey(args) {
    try { return ipcRenderer.invoke('signal-v2:set-storage-key', validateSignalArgs('setSignalStorageKey', args)); } catch (error) { return Promise.reject(error); }
  },

  wsSend: (payload) => ipcRenderer.invoke('edge:ws-send', payload),
  wsConnect: () => ipcRenderer.invoke('edge:ws-connect'),
  wsDisconnect: () => ipcRenderer.invoke('edge:ws-disconnect'),
  wsProbeConnect: (url, timeoutMs) => {
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a non-empty string'));
    }
    if (url.length > MAX_URL_LENGTH) {
      return Promise.reject(new Error('URL too long'));
    }
    return ipcRenderer.invoke('edge:ws-probe-connect', url, timeoutMs);
  },
  setServerUrl: (url) => {
    if (!url || typeof url !== 'string') {
      return Promise.reject(new Error('URL must be a non-empty string'));
    }
    if (url.length > MAX_URL_LENGTH) {
      return Promise.reject(new Error('URL too long'));
    }
    return ipcRenderer.invoke('edge:set-server-url', url);
  },
  getServerUrl: () => ipcRenderer.invoke('edge:get-server-url'),
  rendererReady: () => ipcRenderer.invoke('renderer:ready'),
  torSetupComplete: () => ipcRenderer.invoke('tor:setup-complete'),
  powerSaveBlockerStart: () => ipcRenderer.invoke('power:psb-start'),
  powerSaveBlockerStop: () => ipcRenderer.invoke('power:psb-stop'),
  refreshTokens: (args) => ipcRenderer.invoke('auth:refresh', args),
  storePQKeys: async ({ username, kyberPublicKey, dilithiumPublicKey, x25519PublicKey }) => {
    try {
      if (!username || typeof username !== 'string') return { success: false, error: 'invalid-username' };
      const payload = { kyberPublicKey: String(kyberPublicKey || ''), dilithiumPublicKey: String(dilithiumPublicKey || ''), x25519PublicKey: String(x25519PublicKey || '') };
      await ipcRenderer.invoke('secure:init');
      const key = `pq:${username}`;
      const res = await ipcRenderer.invoke('secure:set', key, JSON.stringify(payload));
      return { success: !!(res && res.success) };
    } catch (e) { return { success: false, error: (e && e.message) || 'error' }; }
  }
});

ipcRenderer.on('edge:server-message', (_event, data) => {
  try {
    window.dispatchEvent(new CustomEvent('edge:server-message', { detail: data }));
  } catch (error) {
    console.error('[PRELOAD] Failed to dispatch server message:', error);
  }
});