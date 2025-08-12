import { SignalType } from "@/lib/signals";
import { Message } from "@/components/chat/types";

export interface AuthProps {
  username: string;
  isLoggedIn: boolean;
  isGeneratingKeys: boolean;
  loginError: string;
  accountAuthenticated: boolean;
  privateKeyRef: React.MutableRefObject<CryptoKey | null>;
  publicKeyRef: React.MutableRefObject<CryptoKey | null>;
  loginUsernameRef: React.MutableRefObject<string>;
  initializeKeys: () => Promise<void>;
  handleAccountSubmit: (
    mode: "login" | "register",
    username: string,
    password: string
  ) => Promise<void>;
  handleServerPasswordSubmit: (password: string) => Promise<void>;
  handleAuthSuccess: (
    username: string,
    onSuccess?: (messages: Message[]) => void
  ) => void;
  setAccountAuthenticated: React.Dispatch<React.SetStateAction<boolean>>;
  setLoginError: React.Dispatch<React.SetStateAction<string>>;
}

export interface FileChunkData {
  decryptedChunks: Blob[];
  totalChunks: number;
  encryptedAESKey: string;
  filename: string;
  aesKey?: CryptoKey;
  receivedCount: number;
}

export type IncomingFileChunks = Record<string, FileChunkData>;