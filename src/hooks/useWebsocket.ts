import { useEffect } from "react";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";

type MessageHandler = (data: any) => Promise<void>;

export const useWebSocket = (
  handleServerMessage: MessageHandler,
  handleEncryptedMessage: MessageHandler,
  setLoginError: (error: string) => void
) => {
  useEffect(() => {
    websocketClient.setLoginErrorCallback(setLoginError)

    const connect = async () => {
      try {
        if (!websocketClient.isConnectedToServer()) {
          await websocketClient.connect();
        }
      } catch (error) {
        console.error("WebSocket connection error:", error);
      }
    };

    connect();

    return () => {
      websocketClient.close();
    };
  }, [setLoginError]);

  useEffect(() => {
    const registeredSignalTypes = Object.values(SignalType);
    const rawHandler = async (data: unknown) => {
      await handleEncryptedMessage(data);
    };

    registeredSignalTypes.forEach(signal => {
      if (
        signal !== SignalType.ENCRYPTED_MESSAGE &&
        signal !== SignalType.DR_SEND &&
        signal !== SignalType.X3DH_DELIVER_BUNDLE
      ) {
        websocketClient.registerMessageHandler(signal, handleServerMessage);
      }
    });

    // Ensure generic ERROR messages are handled too
    websocketClient.registerMessageHandler(SignalType.ERROR, handleServerMessage);

    websocketClient.registerMessageHandler(SignalType.ENCRYPTED_MESSAGE, handleEncryptedMessage);
    websocketClient.registerMessageHandler(SignalType.DR_SEND, handleEncryptedMessage);
    websocketClient.registerMessageHandler(SignalType.X3DH_DELIVER_BUNDLE, handleEncryptedMessage);
    websocketClient.registerMessageHandler("raw", rawHandler);

    // Capture rate-limit messages to configure client backoff
    websocketClient.registerMessageHandler(SignalType.ERROR, (msg: any) => {
      const rl = msg?.rateLimitInfo;
      if (rl?.blocked && typeof rl.remainingBlockTime === 'number') {
        // remainingBlockTime is seconds from server
        websocketClient.setGlobalRateLimit(rl.remainingBlockTime);
      }
      return handleServerMessage(msg);
    });

    return () => {
      registeredSignalTypes.forEach(signal => {
        websocketClient.unregisterMessageHandler(signal);
      });
      websocketClient.unregisterMessageHandler(SignalType.ERROR);
      websocketClient.unregisterMessageHandler("raw");
    };
  }, [handleServerMessage, handleEncryptedMessage]);
};