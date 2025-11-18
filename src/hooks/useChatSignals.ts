import { useCallback } from "react";
import { handleSignalMessages } from "@/lib/signals";
import type { useAuth } from "@/hooks/useAuth";

interface ChatSignalsProps {
  Authentication: ReturnType<typeof useAuth>;
  Database: any;
  fileHandler: {
    handleFileMessageChunk: (data: any, meta: any) => Promise<void>;
  };
  encryptedHandler: (message: any) => Promise<void>;
  handleMessageHistory?: (data: any) => Promise<void>;
}

export const useChatSignals = ({ Authentication, Database, fileHandler, encryptedHandler, handleMessageHistory }: ChatSignalsProps) => {
  return useCallback(
    async (data: any) => {
      await handleSignalMessages(data, {
        Authentication,
        Database,
        handleFileMessageChunk: fileHandler.handleFileMessageChunk,
        handleEncryptedMessagePayload: encryptedHandler,
        handleMessageHistory: handleMessageHistory,
      });
    },
    [Authentication, Database, fileHandler, encryptedHandler, handleMessageHistory]
  );
};