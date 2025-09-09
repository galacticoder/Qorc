import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { EncryptionIcon, LockClosedIcon, CheckIcon } from "./icons";
import { TorIndicator } from "../ui/TorIndicator";
import { BrowserTorNotice } from "../ui/BrowserTorNotice";

import { SignInForm } from "./Login/SignIn.tsx";
import { SignUpForm } from "./Login/SignUp.tsx";
import { PassphrasePrompt } from "./Login/PassphrasePrompt.tsx";
import { PasswordHashPrompt } from "./Login/PasswordHashPrompt.tsx";
import { ServerPasswordForm } from "./Login/ServerPassword.tsx";

interface LoginProps {
  onServerPasswordSubmit?: (serverPassword: string) => Promise<void>;
  isGeneratingKeys: boolean;
  authStatus?: string;
  error?: string;
  accountAuthenticated: boolean;
  isRegistrationMode: boolean;
  initialUsername?: string;
  initialPassword?: string;
  maxStepReached?: 'login' | 'passphrase' | 'server';
  serverTrustRequest?: { //trust prompt for new changed server keys
    newKeys: { x25519PublicBase64: string; kyberPublicBase64: string };
    pinned: { x25519PublicBase64: string; kyberPublicBase64: string } | null;
  } | null;
  onAcceptServerTrust?: () => void;
  onRejectServerTrust?: () => void;
  onAccountSubmit: (
    mode: "login" | "register",
    username: string,
    password: string,
    passphrase?: string
  ) => Promise<void>;
  onPassphraseSubmit?: (passphrase: string, mode: "login" | "register") => Promise<void>;
  onPasswordHashSubmit?: (password: string) => Promise<void>;
  showPassphrasePrompt: boolean;
  setShowPassphrasePrompt: (show: boolean) => void;
  showPasswordPrompt?: boolean;
  setShowPasswordPrompt?: (show: boolean) => void;
}

export function Login({
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
  isRegistrationMode,
  initialUsername = "",
  initialPassword = "",
  maxStepReached = 'login',
}: LoginProps) {
  const [serverPassword, setServerPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mode, setMode] = useState<"login" | "register">("login");

  const handleAccountSubmit = async (username: string, password: string) => {
    setIsSubmitting(true);
    try {
      await onAccountSubmit(mode, username, password);
    } catch (err) {
      console.error("Account Login/Register failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePassphraseSubmit = async (passphrase: string) => {
    setIsSubmitting(true);
    try {
      await onPassphraseSubmit?.(passphrase, mode);
    } catch (err) {
      console.error("Passphrase submission failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleServerPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!serverPassword.trim() || isSubmitting || isGeneratingKeys || !onServerPasswordSubmit)
      return;

    setIsSubmitting(true);
    try {
      await onServerPasswordSubmit(serverPassword);
    } catch (err) {
      console.error("Server password submission failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };


  const handleBack = () => {
    // Utility to dispatch back event so the auth hook can clean up state
    const dispatchBack = (to: 'login' | 'passphrase' | 'server') => {
      try {
        const ev = new CustomEvent('auth-ui-back', { detail: { to } });
        window.dispatchEvent(ev);
      } catch {}
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
      // Go back to passphrase step from server password screen
      setShowPassphrasePrompt(true);
      dispatchBack('passphrase');
      return;
    }
    // If we're at the account login/register screen, go back to server selection
    dispatchBack('server');
  };

  return (
    <div

      className="w-full max-w-md mx-auto"
    >
      <Card className="w-full">
        <CardHeader className="space-y-4">
          {/* Navigation above the lock icon */}
          <div className="flex justify-between items-center">
            <button
              type="button"
              className="px-3 py-1.5 rounded-md border"
              onClick={handleBack}
              disabled={isSubmitting || isGeneratingKeys}
            >
              ← Back
            </button>
            <button
              type="button"
              className="px-3 py-1.5 rounded-md border"
              onClick={() => {
                try {
                  // Determine current step
                  const atLogin = !showPassphrasePrompt && !accountAuthenticated;
                  const atPassphrase = !!showPassphrasePrompt;
                  // Determine next reachable step based on maxStepReached
                  let to: 'passphrase' | 'server_password' | null = null;
                  if (atLogin) {
                    if (maxStepReached === 'passphrase') to = 'passphrase';
                    else if (maxStepReached === 'server') to = 'server_password';
                  } else if (atPassphrase) {
                    if (maxStepReached === 'server') to = 'server_password';
                  }
                  if (!to) return; // do nothing if step not yet reached
                  const ev = new CustomEvent('auth-ui-forward', { detail: { to } });
                  window.dispatchEvent(ev);
                } catch {}
              }}
              disabled={isSubmitting || isGeneratingKeys || (
                // Disable when no next step has been reached yet
                (() => {
                  const atLogin = !showPassphrasePrompt && !accountAuthenticated;
                  const atPassphrase = !!showPassphrasePrompt;
                  if (atLogin) return !(maxStepReached === 'passphrase' || maxStepReached === 'server');
                  if (atPassphrase) return !(maxStepReached === 'server');
                  return true; // at server step, no forward
                })()
              )}
            >
              Forward →
            </button>
          </div>
          <div className="flex justify-between items-start">
            <div className="flex-1 flex flex-col items-center">
              <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                <EncryptionIcon className="h-8 w-8 text-primary" />
              </div>
              <CardTitle className="text-2xl text-center">end2end</CardTitle>
              <CardDescription className="text-center">
                End-to-end encrypted messaging using X25519 + Kyber768 hybrid encryption and AES-GCM
              </CardDescription>
            </div>
            <TorIndicator />
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Step Indicator */}
          <div className="flex items-center justify-center gap-6">
            {[
              { key: 'login', label: 'Login', active: !showPassphrasePrompt && !accountAuthenticated },
              { key: 'passphrase', label: 'Passphrase', active: !!showPassphrasePrompt },
              { key: 'server', label: 'Server', active: !!accountAuthenticated },
            ].map((s, idx) => (
              <div key={s.key} className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${s.active ? 'bg-primary' : 'bg-muted-foreground/30'}`} />
                <span className={`text-sm ${s.active ? 'text-primary font-medium' : 'text-muted-foreground'}`}>{s.label}</span>
                {idx < 2 && <span className="text-muted-foreground/50">→</span>}
              </div>
            ))}
          </div>

          {serverTrustRequest && (
            <div className="p-3 border rounded-md bg-amber-50 border-amber-200">
              <div className="font-semibold mb-2">Server identity changed</div>
              <div className="text-sm mb-2">Verify the new server keys below before trusting.</div>
              <div className="text-xs font-mono break-all">
                <div className="mb-1">
                  <span className="font-semibold">Old X25519:</span> {(serverTrustRequest.pinned?.x25519PublicBase64 || '').slice(0, 44)}...
                </div>
                <div className="mb-2">
                  <span className="font-semibold">Old Kyber:</span> {(serverTrustRequest.pinned?.kyberPublicBase64 || '').slice(0, 44)}...
                </div>
                <div className="mb-1">
                  <span className="font-semibold">New X25519:</span> {serverTrustRequest.newKeys.x25519PublicBase64.slice(0, 44)}...
                </div>
                <div className="mb-3">
                  <span className="font-semibold">New Kyber:</span> {serverTrustRequest.newKeys.kyberPublicBase64.slice(0, 44)}...
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  className="px-3 py-1.5 rounded-md bg-primary text-white"
                  onClick={onAcceptServerTrust}
                  disabled={isSubmitting || isGeneratingKeys}
                >
                  Trust new server
                </button>
                <button
                  type="button"
                  className="px-3 py-1.5 rounded-md border"
                  onClick={onRejectServerTrust}
                  disabled={isSubmitting || isGeneratingKeys}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
          {showPasswordPrompt ? (
            <PasswordHashPrompt
              onSubmit={async (pwd) => {
                try { await onPasswordHashSubmit?.(pwd); } catch {}
              }}
              disabled={isSubmitting || isGeneratingKeys}
              authStatus={authStatus}
              initialPassword={initialPassword}
              onChangePassword={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'password', value: v } })); } catch {}
              }}
            />
          ) : showPassphrasePrompt ? (
            <PassphrasePrompt
              mode={mode}
              onSubmit={handlePassphraseSubmit}
              disabled={isSubmitting || isGeneratingKeys}
              authStatus={authStatus}
              initialPassphrase={""}
              initialConfirmPassphrase={""}
              onChangePassphrase={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'passphrase', value: v } })); } catch {}
              }}
              onChangeConfirm={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'passphraseConfirm', value: v } })); } catch {}
              }}
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
              onChangeUsername={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'username', value: v } })); } catch {}
              }}
              onChangePassword={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'password', value: v } })); } catch {}
              }}
              onChangeConfirmPassword={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'confirmPassword', value: v } })); } catch {}
              }}
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
              onChangeUsername={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'username', value: v } })); } catch {}
              }}
              onChangePassword={(v) => {
                try { (window as any).dispatchEvent?.(new CustomEvent('auth-ui-input', { detail: { field: 'password', value: v } })); } catch {}
              }}
            />
          )}

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-2">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <LockClosedIcon className="h-3 w-3" />
              <span>Your messages are secured with end-to-end encryption</span>
            </div>
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <CheckIcon className="h-3 w-3" />
              <span>Only the intended recipients can read your messages</span>
            </div>
          </div>
        </CardContent>

        <CardFooter className="flex flex-col gap-2">
          {!accountAuthenticated && !showPassphrasePrompt && (
            <div className="text-sm text-center text-muted-foreground">
              {mode === "login" ? (
                <>
                  Don’t have an account?{" "}
                  <button
                    type="button"
                    className="text-primary underline"
                    onClick={() => setMode("register")}
                  >
                    Register
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{" "}
                  <button
                    type="button"
                    className="text-primary underline"
                    onClick={() => setMode("login")}
                  >
                    Login
                  </button>
                </>
              )}
            </div>
          )}
        </CardFooter>
      </Card>

      {/* Browser Tor Notice */}
      <div className="mt-4">
        <BrowserTorNotice />
      </div>
    </div>
  );
}