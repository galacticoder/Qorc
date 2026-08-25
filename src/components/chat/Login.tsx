import React, { useState, useEffect, useCallback } from "react";
import { SignInForm } from "./Login/SignIn.tsx";
import { SignUpForm } from "./Login/SignUp.tsx";
import { ServerPasswordForm } from "./Login/ServerPassword.tsx";
import { TorIndicator } from "../ui/TorIndicator";
import { toast } from "sonner";
import { system } from "../../lib/tauri-bindings";
import { EventType } from "../../lib/types/event-types.ts";
import { QorBrandLogo } from "../ui/QorBrandLogo";
import { ThemeToggleButton } from "../ui/ThemeToggleButton";

interface LoginProps {
  readonly isGeneratingKeys: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly accountAuthenticated: boolean;
  readonly isRegistrationMode: boolean;
  readonly initialUsername?: string;
  readonly onAccountSubmit: (
    mode: "login" | "register",
    username: string,
    password: string,
    passphrase: string,
  ) => Promise<void>;
  readonly showPasswordPrompt: boolean;
  readonly handleServerPasswordSubmit: (password: string) => Promise<void>;
  readonly setIsRegistrationMode?: (val: boolean) => void;
}

const TERMS_URL = "https://www.qor-chat.com/terms";
const PRIVACY_URL = "https://www.qor-chat.com/privacy";

const dispatchAuthEvent = (eventName: string, detail: Record<string, unknown>): void => {
  try {
    window.dispatchEvent(new CustomEvent(eventName, { detail }));
  } catch { }
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
  showPasswordPrompt,
  handleServerPasswordSubmit,
  setIsRegistrationMode,
  initialUsername = "",
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
    let rateLimitTimeout: ReturnType<typeof setTimeout> | null = null;
    const clearRateLimit = () => {
      setIsRateLimited(false);
      setIsSubmitting(false);
      rateLimitTimeout = null;
    };
    const handleRateLimited = (event: Event) => {
      toast.error('Too many attempts. Please wait before trying again.');
      setIsSubmitting(true);
      setIsRateLimited(true);
      if (rateLimitTimeout) clearTimeout(rateLimitTimeout);
      const detail = event instanceof CustomEvent ? event.detail : null;
      const now = Date.now();
      const declaredUntil = Number(detail?.rateLimitUntil);
      const remainingSeconds = Number(detail?.remainingSeconds);
      const fallbackDelay = Number.isFinite(remainingSeconds) && remainingSeconds > 0
        ? Math.min(Math.ceil(remainingSeconds) * 1000, 24 * 60 * 60 * 1000)
        : 60_000;
      const delay = Number.isSafeInteger(declaredUntil) && declaredUntil > now
        ? Math.min(declaredUntil - now, 24 * 60 * 60 * 1000)
        : fallbackDelay;
      rateLimitTimeout = setTimeout(clearRateLimit, delay + 50);
    };
    const handleAuthError = () => {
      setIsSubmitting(false);
    };
    window.addEventListener(EventType.AUTH_RATE_LIMITED, handleRateLimited as any);
    window.addEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    return () => {
      if (rateLimitTimeout) clearTimeout(rateLimitTimeout);
      window.removeEventListener(EventType.AUTH_RATE_LIMITED, handleRateLimited as any);
      window.removeEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    };
  }, []);

  const handleAccountSubmit = useCallback(async (username: string, password: string, passphrase: string): Promise<void> => {
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

  const handleModeToggle = useCallback((): void => {
    setMode((prev) => {
      const newMode = prev === 'login' ? 'register' : 'login';
      setIsRegistrationMode?.(newMode === 'register');
      return newMode;
    });
  }, [setIsRegistrationMode]);

  const handleBackToSetup = useCallback((): void => {
    dispatchAuthEvent(EventType.AUTH_UI_BACK, { to: 'server' });
  }, []);

  const handleExternalLink = useCallback((url: string): void => {
    void system.openExternal(url).catch(() => { });
  }, []);

  const isBusy = isSubmitting || isGeneratingKeys || isRateLimited;

  const isSignup = mode === "register" && !showPasswordPrompt;
  const prefix = isSignup ? "signup" : "login";
  const heading = showPasswordPrompt
    ? "Server access"
    : isSignup
      ? "Create account"
      : "Sign in";
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

        <button
          type="button"
          className={`${prefix}-back-setup`}
          onClick={() => { if (!isBusy) handleBackToSetup(); }}
          disabled={isBusy}
          aria-disabled={isBusy}
          tabIndex={isBusy ? -1 : undefined}
          style={isBusy ? { pointerEvents: 'none', opacity: 0.4, cursor: 'not-allowed' } : undefined}
        >
          Change server
        </button>

        <ThemeToggleButton className="auth-theme-toggle" />

        <main className={`${prefix}-simple`} aria-label={isSignup ? "Create account" : "Sign in"}>
          <header className={`${prefix}-simple-head`}>
            <h1>{heading}</h1>
            {!isSignup && !showPasswordPrompt && <p aria-hidden="true"></p>}
            <p>{description}</p>
          </header>

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
                    const submittedPassword = serverPassword;
                    setServerPassword("");
                    setIsSubmitting(true);
                    try {
                      await handleServerPasswordSubmit(submittedPassword);
                    } finally {
                      setIsSubmitting(false);
                    }
                  }}
                />
              ) : isSignup ? (
                <SignUpForm
                  onSubmit={handleAccountSubmit}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                  authStatus={authStatus}
                  initialUsername={initialUsername}
                />
              ) : (
                <SignInForm
                  onSubmit={handleAccountSubmit}
                  disabled={isSubmitting || isGeneratingKeys || isRateLimited}
                  authStatus={authStatus}
                  initialUsername={initialUsername}
                />
              )}
            </div>
          </AnimatedHeightWrapper>

          {!accountAuthenticated && !showPasswordPrompt && (
            <>
              <p className={`${prefix}-simple-legal`}>
                By signing {isSignup ? "up" : "in"}, you agree to the{' '}
                <button type="button" onClick={() => handleExternalLink(TERMS_URL)}>
                  Terms of Service
                </button>{' '}
                and{' '}
                <button type="button" onClick={() => handleExternalLink(PRIVACY_URL)}>
                  Privacy Policy
                </button>.
              </p>
              <p className={`${prefix}-simple-switch`}>
                {isSignup ? "Already have an account? " : "Don't have an account? "}
                <button
                  type="button"
                  onClick={() => { if (!isBusy) handleModeToggle(); }}
                  disabled={isBusy}
                  aria-label={isSignup ? "Switch to login" : "Switch to registration"}
                  aria-disabled={isBusy}
                  tabIndex={isBusy ? -1 : undefined}
                  style={isBusy ? { pointerEvents: 'none', opacity: 0.4, cursor: 'not-allowed' } : undefined}
                >
                  {isSignup ? "Sign in" : "Create Account"}
                </button>
              </p>
            </>
          )}
        </main>
      </div>
    </section>
  );
});
