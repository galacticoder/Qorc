export interface AuthProps {
  username: string;
  isLoggedIn: boolean;
  isGeneratingKeys: boolean;
  isSubmittingAuth?: boolean;
  loginError: string;
  accountAuthenticated: boolean;
  hybridKeysRef: React.MutableRefObject<{ x25519: { private: CryptoKey | Uint8Array }, kyber: { secretKey: Uint8Array } } | null>;
  loginUsernameRef: React.MutableRefObject<string>;
  initializeKeys: () => Promise<void>;
  handleAccountSubmit: (
    mode: "login" | "register",
    username: string,
    password: string
  ) => Promise<void>;
  handleServerPasswordSubmit: (password: string) => Promise<void>;
  handleAuthSuccess: (
    username: string
  ) => void;
  setAccountAuthenticated: React.Dispatch<React.SetStateAction<boolean>>;
  setLoginError: React.Dispatch<React.SetStateAction<string>>;
}

export interface FileChunkData {
  decryptedChunks: Blob[];
  totalChunks: number;
  encryptedAESKey: string;
  ephemeralX25519Public?: string;
  kyberCiphertext?: string;
  filename: string;
  aesKey?: CryptoKey;
  receivedCount: number;
}

export type IncomingFileChunks = Record<string, FileChunkData>;