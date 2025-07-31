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
    console.log("Initializing WebSocket connection...");

    const connect = async () => {
      try {
        if (!websocketClient.isConnectedToServer()) {
          console.log("Connecting to WebSocket server...");
          await websocketClient.connect();
        }
      } catch (error) {
        console.error("WebSocket connection error:", error);
        setLoginError("Failed to connect to server");
      }
    };

    connect();

    return () => {
      console.log("Cleaning up WebSocket connection...");
      websocketClient.close();
    };
  }, [setLoginError]);

  useEffect(() => {
    const registeredSignalTypes = Object.values(SignalType);
    const rawHandler = (data: unknown) => {
      console.log("Raw message received:", data);
    };

    registeredSignalTypes.forEach(signal => {
      websocketClient.registerMessageHandler(signal, handleServerMessage);
    });

    websocketClient.registerMessageHandler("raw", rawHandler);

    return () => {
      	registeredSignalTypes.forEach(signal => {
        websocketClient.unregisterMessageHandler(signal);
      });
      websocketClient.unregisterMessageHandler("raw");
    };
  }, [handleServerMessage, handleEncryptedMessage]);
};