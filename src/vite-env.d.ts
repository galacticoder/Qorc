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

      // Typing indicators (bypasses Signal Protocol to prevent EBADF errors)
      sendTypingIndicator: (args: any) => Promise<any>;

      // Legacy/unused placeholders
      setupSession: (args: any) => Promise<any>;
      publishBundle: (args: any) => Promise<any>;
      requestBundle: (args: any) => Promise<any>;
      wsSend: (payload: any) => Promise<any>;
      rendererReady: () => Promise<any>;
    };
  }
}

export {};
