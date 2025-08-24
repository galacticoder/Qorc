import { useEffect } from "react";
// WebSocket moved to Electron main; listen via IPC and send via edgeApi
import { SignalType } from "@/lib/signals";

type MessageHandler = (data: any) => Promise<void>;

export const useWebSocket = (
  handleServerMessage: MessageHandler,
  handleEncryptedMessage: MessageHandler,
  setLoginError: (error: string) => void
) => {
  useEffect(() => {
    const handler = async (data: any) => {
      try {
        console.log('[useWebSocket] Received message from main process:', {
          type: data?.type,
          dataType: typeof data,
          keys: data ? Object.keys(data) : [],
          hasEncryptedPayload: !!data?.encryptedPayload,
          encryptedPayloadKeys: data?.encryptedPayload ? Object.keys(data.encryptedPayload) : []
        });
        
        // Skip IPC responses and invalid messages
        if (!data || typeof data !== 'object' || !data.type || data.type === 'ok') {
          console.log('[useWebSocket] Skipping non-server message:', data);
          return;
        }
        
        // Route encrypted types to encrypted handler; others to server handler
        if (data?.type === 'encrypted-message' || data?.type === 'dr-send' || data?.type === 'x3dh-deliver-bundle') {
          console.log('[useWebSocket] Routing to encrypted handler:', {
            type: data.type,
            hasEncryptedPayload: !!data.encryptedPayload,
            encryptedPayloadKeys: data.encryptedPayload ? Object.keys(data.encryptedPayload) : []
          });
          await handleEncryptedMessage(data);
        } else {
          console.log('[useWebSocket] Routing to server handler:', {
            type: data.type,
            keys: Object.keys(data)
          });
          await handleServerMessage(data);
        }
      } catch (e) {
        console.error('IPC server-message handler error:', e);
      }
    };
    const listener = (evt: any) => handler(evt?.detail ?? evt);
    window.addEventListener('edge:server-message', listener as any);
    return () => window.removeEventListener('edge:server-message', listener as any);
  }, [handleServerMessage, handleEncryptedMessage]);

  // Remaining registration replaced by IPC routing above
};