/**
 * Signal Handler Types
 */

import type { AuthLifecycle } from '../auth/auth-lifecycle';

export interface SignalHandlers {
  Authentication: any;
  handleEncryptedMessagePayload: (message: any) => Promise<boolean | void>;
}

export interface AuthRefs {
  setServerHybridPublic?: (keys: any) => void;
  serverHybridPublicRef?: React.RefObject<any>;
  handleAuthSuccess?: (username: string) => void;
  loginUsernameRef?: React.RefObject<string>;
  originalUsernameRef?: React.RefObject<string>;
  setAccountAuthenticated?: (val: boolean) => void;
  setIsLoggedIn?: (val: boolean) => void;
  setLoginError?: (msg: string) => void;
  passphrasePlaintextRef?: React.RefObject<string>;
  setShowPassphrasePrompt?: (val: boolean) => void;
  setShowPasswordPrompt?: (val: boolean) => void;
  passwordRef?: React.RefObject<string>;
  setIsSubmittingAuth?: (val: boolean) => void;
  setAuthStatus?: (status: string) => void;
  setTokenValidationInProgress?: (val: boolean) => void;
  keyManagerOwnerRef?: React.RefObject<string>;
  setUsername?: (name: string) => void;
  setRecoveryActive?: (val: boolean) => void;
  setVaultReady?: (val: boolean) => void;
  getKeysOnDemand?: () => Promise<any>;
  hybridKeysRef?: React.RefObject<any>;
  authLifecycle?: AuthLifecycle;
}
