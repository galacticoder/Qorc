/**
 * Signal Handler Types
 */

import type { RefObject } from 'react';
import type { AuthLifecycle } from '../auth/auth-lifecycle';
import type { HybridKeys, ServerHybridPublicKeys } from './auth-types';

export interface SignalHandlers {
  Authentication: AuthRefs;
  handleEncryptedMessagePayload: (message: any) => Promise<boolean | void>;
}

export interface AuthRefs {
  setServerHybridPublic: (keys: ServerHybridPublicKeys | null) => void;
  serverHybridPublicRef: RefObject<ServerHybridPublicKeys | null>;
  handleAuthSuccess: (username: string) => Promise<void>;
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
  setAccountAuthenticated: (val: boolean) => void;
  setIsLoggedIn: (val: boolean) => void;
  setLoginError: (msg: string) => void;
  passphrasePlaintextRef: RefObject<string>;
  setShowPassphrasePrompt: (val: boolean) => void;
  setShowPasswordPrompt: (val: boolean) => void;
  passwordRef: RefObject<string>;
  setIsSubmittingAuth: (val: boolean) => void;
  setAuthStatus: (status: string) => void;
  setTokenValidationInProgress: (val: boolean) => void;
  keyManagerOwnerRef: RefObject<string>;
  setUsername: (name: string) => void;
  setRecoveryActive: (val: boolean) => void;
  setVaultReady: (val: boolean) => void;
  getKeysOnDemand: () => Promise<HybridKeys | null>;
  hybridKeysRef: RefObject<HybridKeys | null>;
  authLifecycle: AuthLifecycle;
}
