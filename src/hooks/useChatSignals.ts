import { useCallback } from "react";
import { handleSignalMessages } from "@/lib/signals/signals";
import type { useAuth } from "@/hooks/auth/useAuth";

interface ChatSignalsProps {
  Authentication: ReturnType<typeof useAuth>;
  encryptedHandler: (message: any) => Promise<boolean | void>;
}

export const useChatSignals = ({ Authentication, encryptedHandler }: ChatSignalsProps) => {
  return useCallback(
    async (data: any) => {
      await handleSignalMessages(data, {
        Authentication,
        handleEncryptedMessagePayload: encryptedHandler,
      });
    },
    [Authentication, encryptedHandler]
  );
};
