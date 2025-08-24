const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('edgeApi', {
  encrypt: (args) => ipcRenderer.invoke('edge:encrypt', args),
  decrypt: (args) => ipcRenderer.invoke('edge:decrypt', args),
  setupSession: (args) => ipcRenderer.invoke('edge:setupSession', args),
  publishBundle: (args) => ipcRenderer.invoke('edge:publishBundle', args),
  requestBundle: (args) => ipcRenderer.invoke('edge:requestBundle', args),
});


