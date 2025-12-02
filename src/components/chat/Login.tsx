import React, { useState, useEffect, useCallback, useMemo } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { EncryptionIcon, LockClosedIcon } from "./icons";
import { TorIndicator } from "../ui/TorIndicator";
import { SignInForm } from "./Login/SignIn.tsx";
import { SignUpForm } from "./Login/SignUp.tsx";
import { PassphrasePrompt } from "./Login/PassphrasePrompt.tsx";
import { PasswordHashPrompt } from "./Login/PasswordHashPrompt.tsx";
import { ServerPasswordForm } from "./Login/ServerPassword.tsx";

import { toast } from "sonner";

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
  } catch { }
};

const truncateKey = (key: string, maxLength: number = 16): string => {
  if (typeof key !== 'string' || key.length === 0) return '';
  const safeLength = Math.min(maxLength, key.length);
  return key.slice(0, safeLength) + '...';
};

const AnimatedHeightWrapper = ({ children, className }: { children: React.ReactNode; className?: string }) => {
  const contentRef = React.useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState<number | undefined>(undefined);

  useEffect(() => {
    if (!contentRef.current) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setHeight(entry.target.scrollHeight);
      }
    });

    observer.observe(contentRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      className={className}
      style={{
        height: height,
        transition: 'height 300ms cubic-bezier(0.4, 0, 0.2, 1)',
        overflow: 'hidden'
      }}
    >
      <div ref={contentRef}>
        {children}
      </div>
    </div>
  );
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
  pseudonym = "",
}) => {
  const [serverPassword, setServerPassword] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [isRateLimited, setIsRateLimited] = useState<boolean>(false);

  // Show error as toast notification
  useEffect(() => {
    if (error) {
      toast.error(error);
      setIsSubmitting(false);
    }
  }, [error]);

  // Reset local submitting state when rate limited or auth error
  useEffect(() => {
    const handleRateLimited = () => {
      toast.error('Too many attempts. Please wait before trying again.');
      setIsSubmitting(false);
      setIsRateLimited(true);
    };
    const handleAuthError = () => {
      setIsSubmitting(false);
    };
    window.addEventListener('auth-rate-limited', handleRateLimited as any);
    window.addEventListener('auth-error', handleAuthError as any);
    return () => {
      window.removeEventListener('auth-rate-limited', handleRateLimited as any);
      window.removeEventListener('auth-error', handleAuthError as any);
    };
  }, []);

  const displayUsername = useMemo(() => pseudonym || initialUsername || '', [pseudonym, initialUsername]);

  const resetToLogin = useCallback((): void => {
    setIsSubmitting(false);
    setIsRateLimited(false);
    setShowPassphrasePrompt(false);
    if (setShowPasswordPrompt) {
      setShowPasswordPrompt(false);
    }
    dispatchAuthEvent('auth-ui-back', { to: 'server' });
  }, [setShowPassphrasePrompt, setShowPasswordPrompt]);





  const handleAccountSubmit = useCallback(async (username: string, password: string): Promise<void> => {
    if (isRateLimited) return;
    setIsSubmitting(true);
    try {
      await onAccountSubmit(mode, username, password);
      setIsRateLimited(false);
    } catch (err) {
      setIsSubmitting(false);
      if (err instanceof Error) {
        toast.error(err.message);
      }
    }
  }, [mode, onAccountSubmit, isRateLimited]);

  const handlePassphraseSubmit = useCallback(async (passphrase: string): Promise<void> => {
    if (isRateLimited) return;
    setIsSubmitting(true);
    try {
      await onPassphraseSubmit?.(passphrase, mode);
      setIsRateLimited(false);
    } catch (err) {
      setIsSubmitting(false);
      toast.error(err instanceof Error ? err.message : 'Authentication failed.');
      resetToLogin();
    }
  }, [mode, onPassphraseSubmit, isRateLimited, resetToLogin]);

  const handleServerPasswordSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (!serverPassword.trim() || isSubmitting || isGeneratingKeys || !onServerPasswordSubmit || isRateLimited) return;

    setIsSubmitting(true);
    try {
      await onServerPasswordSubmit(serverPassword);
      setIsRateLimited(false);
    } catch (err) {
      setIsSubmitting(false);
      toast.error(err instanceof Error ? err.message : 'Server authentication failed.');
    }
  }, [serverPassword, isSubmitting, isGeneratingKeys, onServerPasswordSubmit, isRateLimited]);

  useEffect(() => {
    if (showPassphrasePrompt) {
      setIsSubmitting(false);
    }
  }, [showPassphrasePrompt]);

  useEffect(() => {
    if (accountAuthenticated) {
      setIsSubmitting(false);
      setIsRateLimited(false);
    }
  }, [accountAuthenticated]);

  useEffect(() => {
    if (accountAuthenticated && !isGeneratingKeys) {
      setIsSubmitting(false);
    }
  }, [accountAuthenticated, isGeneratingKeys]);

  const handleInputChange = useCallback((field: string, value: string): void => {
    dispatchAuthEvent('auth-ui-input', { field, value });
  }, []);

  const handleModeToggle = useCallback((): void => {
    setMode((prev) => (prev === 'login' ? 'register' : 'login'));
  }, []);

  const handleAcceptTrust = useCallback(() => {
    onAcceptServerTrust?.();
  }, [onAcceptServerTrust]);

  const handleRejectTrust = useCallback(() => {
    onRejectServerTrust?.();
  }, [onRejectServerTrust]);

  return (
    <div className="w-full max-w-md mx-auto select-none">
      <Card className="w-full bg-card/30 border border-white/10 hover:border-primary/30 hover:bg-card/50 transition-all duration-500 backdrop-blur-md shadow-lg rounded-2xl overflow-hidden">
        <CardHeader className="space-y-6 p-8 select-none">
          <div className="flex flex-col sm:flex-row justify-between items-center sm:items-start gap-4">
            <div className="flex-1 flex flex-col items-center gap-4 w-full">
              <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center" aria-hidden="true">
                <EncryptionIcon className="h-8 w-8 text-primary" />
              </div>
              <div className="text-center space-y-2">
                <CardTitle className="text-2xl select-none">
                  {mode === "login" ? "Sign In" : "Sign Up"}
                </CardTitle>
                <CardDescription className="select-none">
                  {showPasswordPrompt
                    ? "Enter your password"
                    : showPassphrasePrompt
                      ? "Secure your account"
                      : accountAuthenticated
                        ? "Complete setup"
                        : mode === "login"
                          ? "Enter your credentials"
                          : "Create your account"}
                </CardDescription>
              </div>
            </div>
            <div className="sm:absolute sm:top-8 sm:right-8">
              <TorIndicator />
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-6 p-8 pt-0 select-none transition-all duration-300 ease-in-out">
          {/* Server Trust Request */}
          {serverTrustRequest && (
            <div className="p-6 rounded-lg bg-card/30 border border-primary/30 space-y-4 backdrop-blur-sm overflow-hidden transition-all duration-300 ease-in-out animate-in fade-in-0">
              <div className="space-y-2">
                <p className="font-semibold text-primary select-none">Server Keys Changed</p>
                <p className="text-sm text-muted-foreground select-none">Review the new server keys before proceeding</p>
              </div>
              <div className="grid grid-cols-1 gap-2 text-xs font-mono bg-muted/30 p-3 rounded select-none">
                <div>
                  <span className="text-muted-foreground">Old X25519:</span>{' '}
                  <span>{truncateKey(serverTrustRequest.pinned?.x25519PublicBase64 || 'None')}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">New X25519:</span>{' '}
                  <span className="text-primary">{truncateKey(serverTrustRequest.newKeys.x25519PublicBase64)}</span>
                </div>
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={handleAcceptTrust}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                  className="flex-1"
                  size="sm"
                >
                  Trust Server
                </Button>
                <Button
                  onClick={handleRejectTrust}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                  variant="outline"
                  size="sm"
                  className="flex-1"
                >
                  Reject
                </Button>
              </div>
            </div>
          )}

          {/* Form Content */}
          <AnimatedHeightWrapper className="w-full">
            <div
              key={`${showPasswordPrompt}-${showPassphrasePrompt}-${accountAuthenticated}-${mode}`}
              className="animate-in fade-in-0 slide-in-from-bottom-2 duration-300 delay-100"
            >
              {showPasswordPrompt ? (
                <PasswordHashPrompt
                  onSubmit={async (pwd) => {
                    try {
                      await onPasswordHashSubmit?.(pwd);
                    } catch (err) {
                      if (err instanceof Error) {
                        toast.error(err.message);
                      }
                    }
                  }}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                  authStatus={authStatus}
                  initialPassword={initialPassword}
                  onChangePassword={(v) => handleInputChange('password', v)}
                />
              ) : showPassphrasePrompt ? (
                <PassphrasePrompt
                  mode={mode}
                  onSubmit={handlePassphraseSubmit}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
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
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                  authStatus={authStatus}
                  onSubmit={handleServerPasswordSubmit}
                />
              ) : mode === "register" ? (
                <SignUpForm
                  onSubmit={handleAccountSubmit}
                  disabled={isSubmitting || isGeneratingKeys || !!serverTrustRequest || isRateLimited}
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
                  disabled={isSubmitting || isGeneratingKeys || !!serverTrustRequest || isRateLimited}
                  authStatus={authStatus}
                  error={error}
                  hasServerTrustRequest={!!serverTrustRequest}
                  initialUsername={initialUsername}
                  initialPassword={initialPassword}
                  onChangeUsername={(v) => handleInputChange('username', v)}
                  onChangePassword={(v) => handleInputChange('password', v)}
                />
              )}
            </div>
          </AnimatedHeightWrapper>
        </CardContent>

        <CardFooter className="flex flex-col gap-2 p-8 pt-0 select-none">
          {!accountAuthenticated && !showPassphrasePrompt && !showPasswordPrompt && (
            <div className="text-sm text-center text-muted-foreground">
              {mode === "login" ? (
                <>
                  Don't have an account?{" "}
                  <button
                    type="button"
                    className="text-primary underline hover:no-underline disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    onClick={handleModeToggle}
                    disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                    aria-label="Switch to registration"
                  >
                    Sign Up
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{" "}
                  <button
                    type="button"
                    className="text-primary underline hover:no-underline disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                    onClick={handleModeToggle}
                    disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                    aria-label="Switch to login"
                  >
                    Sign In
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
