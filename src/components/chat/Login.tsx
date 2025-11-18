import React, { useState, useEffect, useCallback, useMemo } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { EncryptionIcon, LockClosedIcon, CheckIcon } from "./icons";
import { TorIndicator } from "../ui/TorIndicator";
import { SignInForm } from "./Login/SignIn.tsx";
import { SignUpForm } from "./Login/SignUp.tsx";
import { PassphrasePrompt } from "./Login/PassphrasePrompt.tsx";
import { PasswordHashPrompt } from "./Login/PasswordHashPrompt.tsx";
import { ServerPasswordForm } from "./Login/ServerPassword.tsx";
import { RecoveryPassphrase } from "./Login/RecoveryPassphrase.tsx";

interface ServerKeys {
  readonly x25519PublicBase64: string;
  readonly kyberPublicBase64: string;
  readonly dilithiumPublicBase64: string;
}

interface ServerTrustRequest {
  readonly newKeys: ServerKeys;
  readonly pinned: ServerKeys | null;
}

interface LoginProps {
  readonly onServerPasswordSubmit?: (serverPassword: string) => Promise<void>;
  readonly isGeneratingKeys: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly accountAuthenticated: boolean;
  readonly isRegistrationMode: boolean;
  readonly initialUsername?: string;
  readonly initialPassword?: string;
  readonly maxStepReached?: 'login' | 'passphrase' | 'server';
  readonly recoveryActive?: boolean;
  readonly pseudonym?: string;
  readonly serverTrustRequest?: ServerTrustRequest | null;
  readonly onAcceptServerTrust?: () => void;
  readonly onRejectServerTrust?: () => void;
  readonly onAccountSubmit: (
    mode: "login" | "register",
    username: string,
    password: string,
    passphrase?: string
  ) => Promise<void>;
  readonly onPassphraseSubmit?: (passphrase: string, mode: "login" | "register") => Promise<void>;
  readonly onPasswordHashSubmit?: (password: string) => Promise<void>;
  readonly showPassphrasePrompt: boolean;
  readonly setShowPassphrasePrompt: (show: boolean) => void;
  readonly showPasswordPrompt?: boolean;
  readonly setShowPasswordPrompt?: (show: boolean) => void;
}

const dispatchAuthEvent = (eventName: string, detail: Record<string, unknown>): void => {
  try {
    window.dispatchEvent(new CustomEvent(eventName, { detail }));
  } catch {}
};

const truncateKey = (key: string, maxLength: number = 44): string => {
  if (typeof key !== 'string' || key.length === 0) return '';
  const safeLength = Math.min(maxLength, key.length);
  return key.slice(0, safeLength) + (key.length > maxLength ? '...' : '');
};

export const Login = React.memo<LoginProps>(({
  onAccountSubmit,
  onServerPasswordSubmit,
  isGeneratingKeys,
  authStatus,
  error,
  onPassphraseSubmit,
  onPasswordHashSubmit,
  accountAuthenticated,
  showPassphrasePrompt,
  showPasswordPrompt,
  setShowPasswordPrompt,
  serverTrustRequest,
  onAcceptServerTrust,
  onRejectServerTrust,
  setShowPassphrasePrompt,
  initialUsername = "",
  initialPassword = "",
  maxStepReached = 'login',
  recoveryActive = false,
  pseudonym = "",
}) => {
  const [serverPassword, setServerPassword] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [mode, setMode] = useState<"login" | "register">("login");

  const displayUsername = useMemo(() => pseudonym || initialUsername || '', [pseudonym, initialUsername]);

  const handleRecoveryPassphraseSubmit = useCallback(async (pp: string): Promise<void> => {
    try {
      await onPassphraseSubmit?.(pp, 'login');
    } catch {}
  }, [onPassphraseSubmit]);

  const handleUseDifferentAccount = useCallback((): void => {
    dispatchAuthEvent('auth-ui-back', { to: 'server' });
  }, []);

  if (recoveryActive && showPassphrasePrompt) {
    return (
      <div className="w-full max-w-md mx-auto">
        <Card className="w-full">
          <CardHeader>
            <div className="flex-1 flex flex-col items-center">
              <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center" aria-hidden="true">
                <LockClosedIcon className="h-8 w-8 text-primary" />
              </div>
              <CardTitle className="text-2xl text-center">Unlock your vault</CardTitle>
              <CardDescription className="text-center">
                Enter your passphrase to restore access
              </CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <RecoveryPassphrase
              username={displayUsername}
              authStatus={authStatus}
              error={error}
              onSubmit={handleRecoveryPassphraseSubmit}
              onUseDifferentAccount={handleUseDifferentAccount}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  const handleAccountSubmit = useCallback(async (username: string, password: string): Promise<void> => {
    setIsSubmitting(true);
    try {
      await onAccountSubmit(mode, username, password);
    } catch {
      setIsSubmitting(false);
    }
  }, [mode, onAccountSubmit]);

  const handlePassphraseSubmit = useCallback(async (passphrase: string): Promise<void> => {
    setIsSubmitting(true);
    try {
      await onPassphraseSubmit?.(passphrase, mode);
    } catch {
      setIsSubmitting(false);
    }
  }, [mode, onPassphraseSubmit]);

  const handleServerPasswordSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (!serverPassword.trim() || isSubmitting || isGeneratingKeys || !onServerPasswordSubmit) return;

    setIsSubmitting(true);
    try {
      await onServerPasswordSubmit(serverPassword);
    } catch {
      setIsSubmitting(false);
    }
  }, [serverPassword, isSubmitting, isGeneratingKeys, onServerPasswordSubmit]);

  useEffect(() => {
    if (showPassphrasePrompt) {
      setIsSubmitting(false);
    }
  }, [showPassphrasePrompt]);

  useEffect(() => {
    if (accountAuthenticated) {
      setIsSubmitting(false);
    }
  }, [accountAuthenticated]);

  useEffect(() => {
    if (accountAuthenticated && !isGeneratingKeys) {
      setIsSubmitting(false);
    }
  }, [accountAuthenticated, isGeneratingKeys]);

  const handleAuthError = useCallback((_e: Event): void => {
    try {
      setIsSubmitting(false);
    } catch {}
  }, []);

  useEffect(() => {
    window.addEventListener('auth-error', handleAuthError as EventListener);
    return () => window.removeEventListener('auth-error', handleAuthError as EventListener);
  }, [handleAuthError]);

  useEffect(() => {
    if (error) {
      setIsSubmitting(false);
    }
  }, [error]);


  const handleBack = useCallback((): void => {
    const dispatchBack = (to: 'login' | 'passphrase' | 'server'): void => {
      dispatchAuthEvent('auth-ui-back', { to });
    };

    if (showPasswordPrompt && setShowPasswordPrompt) {
      setShowPasswordPrompt(false);
      dispatchBack('login');
      return;
    }
    if (showPassphrasePrompt) {
      setShowPassphrasePrompt(false);
      dispatchBack('login');
      return;
    }
    if (accountAuthenticated) {
      setShowPassphrasePrompt(true);
      dispatchBack('passphrase');
      return;
    }
    dispatchBack('server');
  }, [showPasswordPrompt, setShowPasswordPrompt, showPassphrasePrompt, setShowPassphrasePrompt, accountAuthenticated]);

  const handleForward = useCallback((): void => {
    try {
      const atLogin = !showPassphrasePrompt && !accountAuthenticated;
      const atPassphrase = !!showPassphrasePrompt;
      let to: 'passphrase' | 'server_password' | null = null;
      
      if (atLogin) {
        if (maxStepReached === 'passphrase') to = 'passphrase';
        else if (maxStepReached === 'server') to = 'server_password';
      } else if (atPassphrase) {
        if (maxStepReached === 'server') to = 'server_password';
      }
      
      if (to) {
        dispatchAuthEvent('auth-ui-forward', { to });
      }
    } catch {}
  }, [showPassphrasePrompt, accountAuthenticated, maxStepReached]);

  const isForwardDisabled = useMemo(() => {
    const atLogin = !showPassphrasePrompt && !accountAuthenticated;
    const atPassphrase = !!showPassphrasePrompt;
    
    if (atLogin) return !(maxStepReached === 'passphrase' || maxStepReached === 'server');
    if (atPassphrase) return !(maxStepReached === 'server');
    return true;
  }, [showPassphrasePrompt, accountAuthenticated, maxStepReached]);

  const handleInputChange = useCallback((field: string, value: string): void => {
    dispatchAuthEvent('auth-ui-input', { field, value });
  }, []);

  const handleModeToggle = useCallback((): void => {
    setMode((prev) => (prev === 'login' ? 'register' : 'login'));
  }, []);

  const stepIndicators = useMemo(() => [
    { key: 'login', label: 'Login', active: !showPassphrasePrompt && !accountAuthenticated },
    { key: 'passphrase', label: 'Passphrase', active: !!showPassphrasePrompt },
    { key: 'server', label: 'Server', active: !!accountAuthenticated },
  ], [showPassphrasePrompt, accountAuthenticated]);

  return (
    <div className="w-full max-w-md mx-auto">
      <Card className="w-full">
        <CardHeader className="space-y-4">
          {!(recoveryActive && showPassphrasePrompt) && (
            <div className="flex justify-between items-center">
              <button
                type="button"
                className="px-3 py-1.5 rounded-md border"
                onClick={handleBack}
                disabled={isSubmitting || isGeneratingKeys}
                aria-label="Go back"
              >
                ← Back
              </button>
              <button
                type="button"
                className="px-3 py-1.5 rounded-md border"
                onClick={handleForward}
                disabled={isSubmitting || isGeneratingKeys || isForwardDisabled}
                aria-label="Go forward"
              >
                Forward →
              </button>
            </div>
          )}
          <div className="flex justify-between items-start">
            <div className="flex-1 flex flex-col items-center">
              <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center" aria-hidden="true">
                <EncryptionIcon className="h-8 w-8 text-primary" />
              </div>
              <CardTitle className="text-2xl text-center">end2end</CardTitle>
              <CardDescription className="text-center">
                End-to-end encrypted messaging using X25519 + ML-KEM-1024 hybrid encryption and PostQuantumAEAD
              </CardDescription>
            </div>
            <TorIndicator />
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {!(recoveryActive && showPassphrasePrompt) && (
            <div className="flex items-center justify-center gap-6" role="navigation" aria-label="Authentication progress">
              {stepIndicators.map((s, idx) => (
                <div key={s.key} className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${s.active ? 'bg-primary' : 'bg-muted-foreground/30'}`} aria-hidden="true" />
                  <span className={`text-sm ${s.active ? 'text-primary font-medium' : 'text-muted-foreground'}`}>{s.label}</span>
                  {idx < 2 && <span className="text-muted-foreground/50" aria-hidden="true">→</span>}
                </div>
              ))}
            </div>
          )}

          {recoveryActive && showPassphrasePrompt ? (
            <RecoveryPassphrase
              username={displayUsername}
              authStatus={authStatus}
              error={error}
              onSubmit={handlePassphraseSubmit}
              onUseDifferentAccount={handleUseDifferentAccount}
            />
          ) : serverTrustRequest && (
            <Alert variant="warning" className="space-y-2" role="alert">
              <AlertDescription>
                <p className="font-semibold">Server keys changed. Review before trusting:</p>
                <div className="grid grid-cols-1 gap-1 text-xs font-mono" aria-label="Server key comparison">
                  <span>
                    <span className="font-semibold">Old X25519:</span> {truncateKey(serverTrustRequest.pinned?.x25519PublicBase64 || '')}
                  </span>
                  <span>
                    <span className="font-semibold">Old Kyber:</span> {truncateKey(serverTrustRequest.pinned?.kyberPublicBase64 || '')}
                  </span>
                  <span>
                    <span className="font-semibold">Old Dilithium:</span> {truncateKey(serverTrustRequest.pinned?.dilithiumPublicBase64 || '')}
                  </span>
                  <span>
                    <span className="font-semibold">New X25519:</span> {truncateKey(serverTrustRequest.newKeys.x25519PublicBase64)}
                  </span>
                  <span>
                    <span className="font-semibold">New Kyber:</span> {truncateKey(serverTrustRequest.newKeys.kyberPublicBase64)}
                  </span>
                  <span>
                    <span className="font-semibold">New Dilithium:</span> {truncateKey(serverTrustRequest.newKeys.dilithiumPublicBase64)}
                  </span>
                </div>
              </AlertDescription>
              <div className="flex gap-2">
                <button
                  type="button"
                  className="px-3 py-1.5 rounded-md bg-primary text-white"
                  onClick={onAcceptServerTrust}
                  disabled={isSubmitting || isGeneratingKeys}
                  aria-label="Trust new server keys"
                >
                  Trust new server
                </button>
                <button
                  type="button"
                  className="px-3 py-1.5 rounded-md border"
                  onClick={onRejectServerTrust}
                  disabled={isSubmitting || isGeneratingKeys}
                  aria-label="Reject server keys"
                >
                  Cancel
                </button>
              </div>
            </Alert>
          )}
          {showPasswordPrompt ? (
            <PasswordHashPrompt
              onSubmit={async (pwd) => {
                try { await onPasswordHashSubmit?.(pwd); } catch {}
              }}
              disabled={isSubmitting || isGeneratingKeys}
              authStatus={authStatus}
              initialPassword={initialPassword}
              onChangePassword={(v) => handleInputChange('password', v)}
            />
          ) : (showPassphrasePrompt && !recoveryActive) ? (
            <PassphrasePrompt
              mode={mode}
              onSubmit={handlePassphraseSubmit}
              disabled={isSubmitting || isGeneratingKeys}
              authStatus={authStatus}
              initialPassphrase={""}
              initialConfirmPassphrase={""}
              onChangePassphrase={(v) => handleInputChange('passphrase', v)}
              onChangeConfirm={(v) => handleInputChange('passphraseConfirm', v)}
            />
          ) : accountAuthenticated ? (
            <ServerPasswordForm
              serverPassword={serverPassword}
              setServerPassword={setServerPassword}
              disabled={isSubmitting || isGeneratingKeys}
              authStatus={authStatus}
              onSubmit={handleServerPasswordSubmit}
            />
          ) : mode === "register" ? (
            <SignUpForm
              onSubmit={handleAccountSubmit}
              disabled={isSubmitting || isGeneratingKeys || !!serverTrustRequest}
              authStatus={authStatus}
              error={error}
              hasServerTrustRequest={!!serverTrustRequest}
              initialUsername={initialUsername}
              initialPassword={initialPassword}
              onChangeUsername={(v) => handleInputChange('username', v)}
              onChangePassword={(v) => handleInputChange('password', v)}
              onChangeConfirmPassword={(v) => handleInputChange('confirmPassword', v)}
            />
          ) : (
            <SignInForm
              onSubmit={handleAccountSubmit}
              disabled={isSubmitting || isGeneratingKeys || !!serverTrustRequest}
              authStatus={authStatus}
              error={error}
              hasServerTrustRequest={!!serverTrustRequest}
              initialUsername={initialUsername}
              initialPassword={initialPassword}
              onChangeUsername={(v) => handleInputChange('username', v)}
              onChangePassword={(v) => handleInputChange('password', v)}
            />
          )}

          {error && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-2">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <LockClosedIcon className="h-3 w-3" aria-hidden="true" />
              <span>Your messages are secured with end-to-end encryption</span>
            </div>
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <CheckIcon className="h-3 w-3" aria-hidden="true" />
              <span>Only the intended recipients can read your messages</span>
            </div>
          </div>
        </CardContent>

        <CardFooter className="flex flex-col gap-2">
          {!accountAuthenticated && !showPassphrasePrompt && (
            <div className="text-sm text-center text-muted-foreground">
              {mode === "login" ? (
                <>
                  Don't have an account?{" "}
                  <button
                    type="button"
                    className="text-primary underline disabled:opacity-50 disabled:cursor-not-allowed"
                    onClick={handleModeToggle}
                    disabled={isSubmitting || isGeneratingKeys}
                    aria-label="Switch to registration"
                  >
                    Register
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{" "}
                  <button
                    type="button"
                    className="text-primary underline disabled:opacity-50 disabled:cursor-not-allowed"
                    onClick={handleModeToggle}
                    disabled={isSubmitting || isGeneratingKeys}
                    aria-label="Switch to login"
                  >
                    Login
                  </button>
                </>
              )}
            </div>
          )}
        </CardFooter>
      </Card>

    </div>
  );
});
