/**
 * Signal Handler Types
 */

export interface SignalHandlers {
  Authentication: any;
  Database: any;
  handleFileMessageChunk: (data: any, meta: any) => Promise<void>;
  handleEncryptedMessagePayload: (message: any) => Promise<void>;
}

export interface AuthRefs {
  setServerHybridPublic?: (keys: any) => void;
  serverHybridPublic?: any;
  handleAuthSuccess?: (username: string, recovered: boolean) => void;
  loginUsernameRef?: React.RefObject<string>;
  aesKeyRef?: React.RefObject<CryptoKey | null>;
  setAccountAuthenticated?: (val: boolean) => void;
  setIsLoggedIn?: (val: boolean) => void;
  setLoginError?: (msg: string) => void;
  setPassphraseHashParams?: (params: any) => void;
  passphrasePlaintextRef?: React.RefObject<string>;
  passphraseRef?: React.RefObject<string>;
  setShowPassphrasePrompt?: (val: boolean) => void;
  passwordRef?: React.RefObject<string>;
  setIsSubmittingAuth?: (val: boolean) => void;
  setAuthStatus?: (status: string) => void;
  setTokenValidationInProgress?: (val: boolean) => void;
  setServerTrustRequest?: (val: any) => void;
  keyManagerRef?: React.RefObject<any>;
  setUsername?: (name: string) => void;
  setMaxStepReached?: (step: string) => void;
  setRecoveryActive?: (val: boolean) => void;
  getKeysOnDemand?: () => Promise<any>;
  hybridKeysRef?: React.RefObject<any>;
  accountAuthenticated?: boolean;
  isLoggedIn?: boolean;
  isRegistrationMode?: boolean;
}

export interface DatabaseRefs {
  setUsers?: (fn: any) => void;
}
