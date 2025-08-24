const { contextBridge, ipcRenderer } = require('electron');

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

  // Typing indicators (bypasses Signal Protocol to prevent EBADF errors)
  sendTypingIndicator: (args) => ipcRenderer.invoke('edge:typing-indicator', args),

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

// Bridge typing indicator messages into the isolated world via a DOM event
ipcRenderer.on('edge:typing-indicator', (_event, data) => {
  try {
    window.dispatchEvent(new CustomEvent('edge:typing-indicator', { detail: data }));
  } catch {}
});


