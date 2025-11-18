/// <reference types="vite/client" />

declare global {
  interface Window {
    edgeApi: {
      // Libsignal identity and prekeys
      generateIdentity: (args: any) => Promise<any>;
      generatePreKeys: (args: any) => Promise<any>;
      getPreKeyBundle: (args: any) => Promise<any>;
      processPreKeyBundle: (args: any) => Promise<any>;

      // Encryption helpers
      hasSession: (args: any) => Promise<any>;
      encrypt: (args: any) => Promise<any>;
      decrypt: (args: any) => Promise<any>;

      // Typing indicators
      sendTypingIndicator: (args: any) => Promise<any>;

      // Identity / storage helpers
      hasIdentity?: (args: { username: string }) => Promise<{ hasIdentity: boolean }>;
      trustPeerIdentity?: (args: { selfUsername: string; peerUsername: string; deviceId?: number }) => Promise<{ success: boolean; error?: string }>;
      setSignalStorageKey?: (args: { keyBase64: string }) => Promise<any>;

      wsSend: (payload: any) => Promise<any>;
      rendererReady: () => Promise<any>;
      getScreenSources?: () => Promise<Array<{ id: string; name: string; type: 'screen' | 'window' }>>;
    };
    electronAPI?: {
      platform?: string;
      arch?: string;
      isElectron?: boolean;
      getScreenSources?: () => Promise<Array<{ id: string; name: string }>>;
      send?: (channel: string, data?: any) => void;
      receive?: (channel: string, func: (...args: any[]) => void) => void;
      showErrorDialog?: (args: { title: string; message: string }) => Promise<any>;
    };
  }
}

export {};
