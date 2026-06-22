import React, { useState, useEffect, useCallback } from "react";
import { SignInForm } from "./Login/SignIn.tsx";
import { SignUpForm } from "./Login/SignUp.tsx";
import { ServerPasswordForm } from "./Login/ServerPassword.tsx";
import { TorIndicator } from "../ui/TorIndicator";
import { toast } from "sonner";
import { system } from "../../lib/tauri-bindings";
import { EventType } from "../../lib/types/event-types.ts";
import { QorBrandLogo } from "../ui/QorBrandLogo";

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
  readonly isGeneratingKeys: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly accountAuthenticated: boolean;
  readonly isRegistrationMode: boolean;
  readonly initialUsername?: string;
  readonly initialPassword?: string;
  readonly maxStepReached?: 'login' | 'server';

  readonly pseudonym?: string;
  readonly serverTrustRequest?: ServerTrustRequest | null;
  readonly onAcceptServerTrust?: () => void;
  readonly onRejectServerTrust?: () => void;
  readonly onAccountSubmit: (
    mode: "login" | "register",
    username: string,
    password: string,
    passphrase?: string,
  ) => Promise<void>;
  readonly onPassphraseSubmit: (passphrase: string) => Promise<void>;
  readonly showPassphrasePrompt: boolean;
  readonly setShowPassphrasePrompt: (show: boolean) => void;
  readonly showPasswordPrompt: boolean;
  readonly setShowPasswordPrompt: (show: boolean) => void;
  readonly handleServerPasswordSubmit: (password: string) => Promise<void>;
  readonly setIsRegistrationMode?: (val: boolean) => void;
}

const TERMS_URL = "https://qor.chat/terms";
const PRIVACY_URL = "https://qor.chat/privacy";

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
  return (
    <div
      className={className}
      style={{
        display: 'grid',
        gridTemplateRows: '1fr',
        transition: 'grid-template-rows 300ms cubic-bezier(0.4, 0, 0.2, 1)',
      }}
    >
      <div style={{ overflow: 'hidden' }}>
        {children}
      </div>
    </div>
  );
};

export const Login = React.memo<LoginProps>(({
  onAccountSubmit,
  isGeneratingKeys,
  authStatus,
  error,
  accountAuthenticated,
  isRegistrationMode,
  serverTrustRequest,
  onAcceptServerTrust,
  onRejectServerTrust,
  showPasswordPrompt,
  handleServerPasswordSubmit,
  setIsRegistrationMode,
  initialUsername = "",
  initialPassword = "",
  maxStepReached: _maxStepReached = 'login',
  pseudonym: _pseudonym = "",
}) => {
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [mode, setMode] = useState<"login" | "register">(isRegistrationMode ? "register" : "login");
  const [isRateLimited, setIsRateLimited] = useState<boolean>(false);
  const [serverPassword, setServerPassword] = useState<string>("");

  useEffect(() => {
    setMode(isRegistrationMode ? "register" : "login");
  }, [isRegistrationMode]);

  useEffect(() => {
    if (error) {
      toast.error(error);
      setIsSubmitting(false);
    }
  }, [error]);

  useEffect(() => {
    const handleRateLimited = () => {
      toast.error('Too many attempts. Please wait before trying again.');
      setIsSubmitting(true);
      setIsRateLimited(true);
    };
    const handleAuthError = () => {
      setIsSubmitting(false);
    };
    window.addEventListener(EventType.AUTH_RATE_LIMITED, handleRateLimited as any);
    window.addEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    return () => {
      window.removeEventListener(EventType.AUTH_RATE_LIMITED, handleRateLimited as any);
      window.removeEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    };
  }, []);

  const handleAccountSubmit = useCallback(async (username: string, password: string, passphrase?: string): Promise<void> => {
    if (isRateLimited) return;
    setIsSubmitting(true);
    try {
      await onAccountSubmit(mode, username, password, passphrase);
      setIsRateLimited(false);
    } catch (err) {
      setIsSubmitting(false);
      if (err instanceof Error) {
        toast.error(err.message);
      }
    }
  }, [mode, onAccountSubmit, isRateLimited]);

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
    dispatchAuthEvent(EventType.AUTH_UI_INPUT, { field, value });
  }, []);

  const handleModeToggle = useCallback((event: React.MouseEvent<HTMLAnchorElement>): void => {
    event.preventDefault();
    setMode((prev) => {
      const newMode = prev === 'login' ? 'register' : 'login';
      setIsRegistrationMode?.(newMode === 'register');
      return newMode;
    });
  }, [setIsRegistrationMode]);

  const handleBackToSetup = useCallback((event: React.MouseEvent<HTMLAnchorElement>): void => {
    event.preventDefault();
    dispatchAuthEvent(EventType.AUTH_UI_BACK, { to: 'server' });
  }, []);

  const handleExternalLink = useCallback((event: React.MouseEvent<HTMLAnchorElement>, url: string): void => {
    event.preventDefault();
    void system.openExternal(url).catch(() => {
      window.open(url, '_blank', 'noopener,noreferrer');
    });
  }, []);

  const handleAcceptTrust = useCallback(() => {
    onAcceptServerTrust?.();
  }, [onAcceptServerTrust]);

  const handleRejectTrust = useCallback(() => {
    onRejectServerTrust?.();
  }, [onRejectServerTrust]);

  const isSignup = mode === "register" && !showPasswordPrompt;
  const prefix = isSignup ? "signup" : "login";
  const heading = showPasswordPrompt ? "Server access" : isSignup ? "Create account" : "Sign in";
  const description = showPasswordPrompt
    ? "Identify yourself to the server."
    : isSignup
      ? "Choose your username, password, and local encryption passphrase."
      : "Use the account for this server and unlock your local encryption key.";

  return (
    <section className={`screen screen-${prefix}`}>
      <div className={`${prefix}-scene`}>
        <div className={`${prefix}-screen-brand`} aria-label="Qor Chat">
          <QorBrandLogo className={`${prefix}-brand-mark`} imageClassName={`${prefix}-brand-logo`} />
          <span className={`${prefix}-brand-name`}>Qor Chat</span>
        </div>

        <TorIndicator variant={prefix} />

        <a className={`${prefix}-back-setup`} href="setup.html" onClick={handleBackToSetup}>
          Back to setup
        </a>

        <main className={`${prefix}-simple`} aria-label={isSignup ? "Create account" : "Sign in"}>
          <header className={`${prefix}-simple-head`}>
            <h1>{heading}</h1>
            {!isSignup && !showPasswordPrompt && <p aria-hidden="true"></p>}
            <p>{description}</p>
          </header>

          {serverTrustRequest && (
            <div className="auth-simple-trust" role="status" aria-live="polite">
              <div>
                <p>Server keys changed</p>
                <span>Review the new server keys before proceeding.</span>
              </div>
              <dl>
                <div>
                  <dt>Old X25519</dt>
                  <dd>{truncateKey(serverTrustRequest.pinned?.x25519PublicBase64 || 'None')}</dd>
                </div>
                <div>
                  <dt>New X25519</dt>
                  <dd>{truncateKey(serverTrustRequest.newKeys.x25519PublicBase64)}</dd>
                </div>
              </dl>
              <div className="auth-simple-trust-actions">
                <button
                  type="button"
                  onClick={handleAcceptTrust}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                >
                  Trust server
                </button>
                <button
                  type="button"
                  onClick={handleRejectTrust}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                >
                  Reject
                </button>
              </div>
            </div>
          )}

          <AnimatedHeightWrapper>
            <div key={`${accountAuthenticated}-${mode}-${showPasswordPrompt}`}>
              {showPasswordPrompt ? (
                <ServerPasswordForm
                  serverPassword={serverPassword}
                  setServerPassword={setServerPassword}
                  disabled={isSubmitting || isGeneratingKeys}
                  authStatus={authStatus}
                  onSubmit={async (event) => {
                    event.preventDefault();
                    setIsSubmitting(true);
                    try {
                      await handleServerPasswordSubmit(serverPassword);
                    } finally {
                      setIsSubmitting(false);
                    }
                  }}
                />
              ) : isSignup ? (
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
                  onChangePassphrase={(v) => handleInputChange('passphrase', v)}
                  onChangeConfirmPassphrase={(v) => handleInputChange('confirmPassphrase', v)}
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
                  onChangePassphrase={(v) => handleInputChange('passphrase', v)}
                />
              )}
            </div>
          </AnimatedHeightWrapper>

          {!accountAuthenticated && !showPasswordPrompt && (
            <>
              <p className={`${prefix}-simple-legal`}>
                By signing {isSignup ? "up" : "in"}, you agree to the{' '}
                <a href={TERMS_URL} target="_blank" rel="noreferrer" onClick={(event) => handleExternalLink(event, TERMS_URL)}>
                  Terms of Service
                </a>{' '}
                and{' '}
                <a href={PRIVACY_URL} target="_blank" rel="noreferrer" onClick={(event) => handleExternalLink(event, PRIVACY_URL)}>
                  Privacy Policy
                </a>.
              </p>
              <p className={`${prefix}-simple-switch`}>
                {isSignup ? "Already have an account? " : "Don't have an account? "}
                <a
                  href={isSignup ? "login.html" : "signup.html"}
                  onClick={handleModeToggle}
                  aria-label={isSignup ? "Switch to login" : "Switch to registration"}
                >
                  {isSignup ? "Sign in" : "Create one"}
                </a>
              </p>
            </>
          )}
        </main>
      </div>
    </section>
  );
});
