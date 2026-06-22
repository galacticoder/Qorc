import { useCallback } from "react";
import { handleSignalMessages } from "@/lib/signals/signals";
import type { useAuth } from "@/hooks/auth/useAuth";

interface ChatSignalsProps {
  Authentication: ReturnType<typeof useAuth>;
  Database: any;
  fileHandler: {
    handleFileMessageChunk: (data: any, meta: any) => Promise<void>;
  };
  encryptedHandler: (message: any) => Promise<void>;
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>;
}

export const useChatSignals = ({ Authentication, Database, fileHandler, encryptedHandler, findUser }: ChatSignalsProps) => {
  return useCallback(
    async (data: any) => {
      await handleSignalMessages(data, {
        Authentication,
        Database,
        handleFileMessageChunk: fileHandler.handleFileMessageChunk,
        handleEncryptedMessagePayload: encryptedHandler,
        findUser,
      });
    },
    [Authentication, Database, fileHandler, encryptedHandler, findUser]
  );
};
