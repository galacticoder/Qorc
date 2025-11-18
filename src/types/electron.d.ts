interface ScreenSource {
  id: string;
  name: string;
  thumbnail: {
    isEmpty: boolean;
    toDataURL: () => string;
  };
}

interface ElectronAPI {
  // Platform information
  platform: string;
  arch: string;
  isElectron: boolean;
  
  // App information
  getAppVersion: () => Promise<string>;
  getAppName: () => Promise<string>;
  getPlatformInfo: () => Promise<any>;
  
  // Tor management
  checkTorInstallation: () => Promise<any>;
  downloadTor: (options: any) => Promise<any>;
  installTor: () => Promise<any>;
  configureTor: (options: any) => Promise<any>;
  startTor: () => Promise<any>;
  stopTor: () => Promise<any>;
  getTorStatus: () => Promise<any>;
  getTorInfo: () => Promise<any>;
  uninstallTor: () => Promise<any>;
  verifyTorConnection: () => Promise<any>;
  rotateTorCircuit: () => Promise<any>;

  // Onion P2P
  createOnionEndpoint: (options: { purpose?: 'p2p'; ttlSeconds?: number }) => Promise<{ success: boolean; wsUrl?: string; token?: string; serviceId?: string; error?: string }>;
  connectOnionWebSocket: (options: { wsUrl: string; token?: string }) => Promise<any> | null;
  onOnionMessage: (callback: (event: any, data: any) => void) => () => void;
  sendOnionMessage: (toUsername: string, payload: any) => Promise<{ success: boolean; error?: string }>;
  
  // Event listeners
  onTorStatusChange: (callback: (event: any, data: any) => void) => () => void;
  onTorProgress: (callback: (event: any, data: any) => void) => () => void;
  onTorConfigureComplete: (callback: (event: any, data: any) => void) => () => void;
  
  // Communication
  send: (channel: string, data: any) => void;
  
  // WebSocket
  wsConnect: (url: string) => Promise<any>;
  wsSend: (data: any) => Promise<any>;
  wsDisconnect: () => Promise<any>;
  onWsMessage: (callback: (event: any, data: any) => void) => () => void;
  onWsError: (callback: (event: any, error: any) => void) => () => void;
  onWsClose: (callback: (event: any) => void) => () => void;
  
  // Server URL management
  setServerUrl: (url: string) => Promise<{ success: boolean; error?: string; serverUrl?: string }>;
  getServerUrl: () => Promise<{ success: boolean; serverUrl: string }>;
  
  // Screen sharing
  getScreenSources: () => Promise<ScreenSource[]>;
  
  // File operations
  saveFile: (data: { filename: string; data: string; mimeType: string }) => Promise<{ success: boolean; path?: string; error?: string; canceled?: boolean }>;
  getDownloadSettings: () => Promise<{ downloadPath: string; autoSave: boolean }>;
  setDownloadPath: (path: string) => Promise<{ success: boolean; error?: string }>;
  setAutoSave: (autoSave: boolean) => Promise<{ success: boolean }>;
  chooseDownloadPath: () => Promise<{ success: boolean; path?: string; canceled?: boolean }>;
  
  // Renderer
  rendererReady: () => Promise<void>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

export {};