import { RefObject } from "react";
import websocketClient from "../../lib/websocket/websocket";
import { syncEncryptedStorage } from "../../lib/database/encrypted-storage";
import { SecureDB } from "../../lib/database/secureDB";
import { clearStringRef } from "../../lib/utils/auth-utils";
import type { HybridKeys } from "../../lib/types/auth-types";
import { account, session } from "../../lib/tauri-bindings";
import { tokenVault } from "../../lib/database/token-vault";
import { markExplicitLogout } from "../../lib/auth/logout-marker";
import { unifiedSignalTransport } from "../../lib/transport/unified-signal-transport";
import { receiptBatcher } from "../message-handling/receipt-batcher";
import { identityChangeStore } from "../../lib/security/identity-change-store";
import { blockingSystem } from "../../lib/blocking/blocking-system";
import { blockStatusCache } from "../../lib/blocking/block-status-cache";
import { profilePictureSystem } from "../../lib/avatar/profile-picture-system";
import { resetAvatarStoreClient } from "../../lib/avatar/avatar-store-client";
import { resetBlindRoutingClient } from "../../lib/transport/blind-routing-client";
import type { AuthLifecycle } from "../../lib/auth/auth-lifecycle";
import { clearResumePool } from "../../lib/signals/resume-tokens";
import { p2pTransport } from "../../lib/transport/p2p-transport";
import { deliveryReceiptOutbox } from "../../lib/signals/delivery-receipt-outbox";
import { keyTransparencyClient } from "../../lib/key-transparency/client";
import { keyTransparencyWarningStore } from "../../lib/key-transparency/warning-store";

export interface LogoutRefs {
  loginUsernameRef: RefObject<string>;
  passwordRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  hybridKeysRef: RefObject<HybridKeys | null>;
  keyManagerOwnerRef: RefObject<string>;
  getKeysPromiseRef: RefObject<Promise<any> | null>;
}

export interface LogoutSetters {
  setIsLoggedIn: (v: boolean) => void;
  setLoginError: (v: string) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setIsRegistrationMode: (v: boolean) => void;
  setIsSubmittingAuth: (v: boolean) => void;
  setUsername: (v: string) => void;
  setTokenValidationInProgress: (v: boolean) => void;
  setVaultReady?: (v: boolean) => void;
  setShowPassphrasePrompt?: (v: boolean) => void;
  setShowPasswordPrompt?: (v: boolean) => void;
}

export const createLogout = (
  refs: LogoutRefs,
  setters: LogoutSetters,
  clearAuthenticationState: () => Promise<void>,
  lifecycle: AuthLifecycle
) => {
  return async (secureDBRef?: RefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    const logoutUsername = refs.loginUsernameRef.current;
    const logoutDatabase = secureDBRef?.current || null;
    const logoutAccountOwner = logoutDatabase?.getAccountScope() || refs.keyManagerOwnerRef.current;
    const operation = lifecycle.begin('');
    let localSecretCleanupFailed = false;

    // Invalidate account bound singleton state before first await
    unifiedSignalTransport.resetForAccountTransition();
    deliveryReceiptOutbox.setPersistence(null, null);
    deliveryReceiptOutbox.setActiveAccount(null);
    receiptBatcher.setActiveAccount(null);
    identityChangeStore.clear();
    blockingSystem.setSecureDB(null);
    blockStatusCache.clear();
    profilePictureSystem.setSecureDB(null);
    resetAvatarStoreClient();
    resetBlindRoutingClient();
    keyTransparencyClient.destroy();
    keyTransparencyWarningStore.clear();
    syncEncryptedStorage.reset();
    logoutDatabase?.dispose();
    if (secureDBRef) secureDBRef.current = null;

    const connectionClose = websocketClient.close({ killSession: true })
      .then(() => true, () => false);
    const p2pClose = p2pTransport.shutdown().then(() => true, () => false);
    try { websocketClient.resetConnectionPrivacyMode(); } catch { }
    const tokenVaultClear = tokenVault.clearAll().then(() => true, () => false);
    const resumePoolClear = logoutUsername
      ? clearResumePool(logoutUsername).then(() => true, () => false)
      : Promise.resolve(false);

    clearStringRef(refs.passwordRef);
    clearStringRef(refs.passphrasePlaintextRef);
    refs.hybridKeysRef.current = null;
    refs.keyManagerOwnerRef.current = '';
    refs.getKeysPromiseRef.current = null;

    // Drop in memory account master, private keys, database handle, signal state at the start of teardown
    if (/^[a-f0-9]{64}$/.test(logoutAccountOwner)) {
      try { await account.lock(logoutAccountOwner); } catch { localSecretCleanupFailed = true; }
    } else {
      if (logoutUsername) {
        localSecretCleanupFailed = true;
      }
    }
    const [connectionClosed, p2pClosed, tokenVaultCleared, resumePoolCleared] = await Promise.all([
      connectionClose,
      p2pClose,
      tokenVaultClear,
      resumePoolClear,
    ]);
    if (!connectionClosed || !p2pClosed || !tokenVaultCleared || !resumePoolCleared) {
      localSecretCleanupFailed = true;
    }
    if (!lifecycle.isCurrent(operation)) return;

    try {
      await markExplicitLogout();
    } catch { localSecretCleanupFailed = true; }
    if (!lifecycle.isCurrent(operation)) return;

    await clearAuthenticationState().catch(() => {
      localSecretCleanupFailed = true;
    });
    if (!lifecycle.isCurrent(operation)) return;

    try {
      setters.setTokenValidationInProgress(false);
    } catch { }

    try {
      await session.setBackgroundState(false);
    } catch { }
    if (!lifecycle.isCurrent(operation)) return;

    try {
      if (typeof window !== 'undefined' && (window as any).gc) {
        (window as any).gc();
      }
    } catch { }

    if (!lifecycle.isCurrent(operation)) return;
    refs.loginUsernameRef.current = "";

    setters.setIsLoggedIn(false);
    setters.setLoginError(localSecretCleanupFailed
      ? 'Logged out, but some local secret files could not be deleted.'
      : loginErrorMessage);
    setters.setAccountAuthenticated(false);
    setters.setIsRegistrationMode(false);
    setters.setIsSubmittingAuth(false);
    setters.setUsername("");
    setters.setVaultReady?.(false);
    setters.setShowPassphrasePrompt?.(false);
    setters.setShowPasswordPrompt?.(false);
  };
};

export const createGetLogout = (logout: (secureDBRef?: RefObject<SecureDB | null>, loginErrorMessage?: string) => Promise<void>) => {
  return (Database: { secureDBRef: RefObject<SecureDB | null> }) => {
    return async () => await logout(Database.secureDBRef, "Logged out");
  };
};
