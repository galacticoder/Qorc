// Electron API type declarations

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
  isDevelopment: boolean;
  
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
  
  // Event listeners
  onTorStatusChange: (callback: (event: any, data: any) => void) => () => void;
  onTorProgress: (callback: (event: any, data: any) => void) => () => void;
  
  // Communication
  send: (channel: string, data: any) => void;
  
  // WebSocket
  wsConnect: (url: string) => Promise<any>;
  wsSend: (data: any) => Promise<any>;
  wsDisconnect: () => Promise<any>;
  onWsMessage: (callback: (event: any, data: any) => void) => () => void;
  onWsError: (callback: (event: any, error: any) => void) => () => void;
  onWsClose: (callback: (event: any) => void) => () => void;
  
  // Screen sharing
  getScreenSources: () => Promise<ScreenSource[]>;
  
  // Renderer
  rendererReady: () => Promise<void>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

export {};