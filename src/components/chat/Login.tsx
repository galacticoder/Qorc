import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "../ui/card";
import { Alert, AlertDescription } from "../ui/alert";
import { EncryptionIcon, LockClosedIcon, CheckIcon } from "./icons";
import { TorIndicator } from "../ui/TorIndicator";
import { BrowserTorNotice } from "../ui/BrowserTorNotice";

import { SignInForm } from "./Login/SignIn.tsx";
import { SignUpForm } from "./Login/SignUp.tsx";
import { PassphrasePrompt } from "./Login/PassphrasePrompt.tsx";
import { ServerPasswordForm } from "./Login/ServerPassword.tsx";

interface LoginProps {
  onServerPasswordSubmit?: (serverPassword: string) => Promise<void>;
  isGeneratingKeys: boolean;
  authStatus?: string;
  error?: string;
  accountAuthenticated: boolean;
  isRegistrationMode: boolean;
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
  showPassphrasePrompt: boolean;
  setShowPassphrasePrompt: (show: boolean) => void;
}

export function Login({
  onAccountSubmit,
  onServerPasswordSubmit,
  isGeneratingKeys,
  authStatus,
  error,
  onPassphraseSubmit,
  accountAuthenticated,
  showPassphrasePrompt,
  serverTrustRequest,
  onAcceptServerTrust,
  onRejectServerTrust,
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

  return (
    <div

      className="w-full max-w-md mx-auto"
    >
      <Card className="w-full">
        <CardHeader className="space-y-4">
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
          {showPassphrasePrompt ? (
            <PassphrasePrompt
              mode={mode}
              onSubmit={handlePassphraseSubmit}
              disabled={isSubmitting || isGeneratingKeys}
              authStatus={authStatus}
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
            />
          ) : (
            <SignInForm
              onSubmit={handleAccountSubmit}
              disabled={isSubmitting || isGeneratingKeys || !!serverTrustRequest}
              authStatus={authStatus}
              error={error}
              hasServerTrustRequest={!!serverTrustRequest}
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
