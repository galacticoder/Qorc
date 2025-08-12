import { useState } from "react";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Label } from "../ui/label";
import { LockClosedIcon, CheckIcon } from "@radix-ui/react-icons";
import { Alert, AlertDescription } from "../ui/alert";
import { KeyRing, EncryptionIcon } from "./icons";
import { PasswordFieldWithConfirm } from "./PasswordFieldWithConfirm.tsx";
import { Input } from "../ui/input";


interface LoginProps {
  onServerPasswordSubmit?: (serverPassword: string) => Promise<void>;
  isGeneratingKeys: boolean;
  error?: string;
  accountAuthenticated: boolean;
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
  error,
  onPassphraseSubmit,
  accountAuthenticated,
  showPassphrasePrompt
}: LoginProps) {
  const [username, setUsername] = useState("");
  const [serverPassword, setServerPassword] = useState("");
  const [localPassword, setLocalPassword] = useState("");
  const [confirmLocalPassword, setConfirmLocalPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mode, setMode] = useState<"login" | "register">("login");

  const isPassphraseValid = passphrase.length >= 12;
  const isLocalPasswordValid = localPassword.length > 0; // optional, you can add min length if you want
  const doPasswordsMatch = localPassword === confirmLocalPassword;
  const doPassphrasesMatch = passphrase === confirmPassphrase;  


  const handleAccountSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || isSubmitting || isGeneratingKeys) return;
    if (mode === "register") {
      if (
        localPassword !== confirmLocalPassword
      ) {
        return;
      }
    }

    setIsSubmitting(true);
    try {
      await onAccountSubmit(mode, username.trim(), localPassword, passphrase);
    } catch (err) {
      console.error("Account Login/Register failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleServerPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      !serverPassword.trim() ||
      isSubmitting ||
      isGeneratingKeys ||
      !onServerPasswordSubmit
    )
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

  const handlePassphraseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase.trim() || isSubmitting || isGeneratingKeys || !onPassphraseSubmit) return;

    setIsSubmitting(true);
    try {
      // Pass mode along so parent knows if login or register
      await onPassphraseSubmit(passphrase, mode);
    } catch (err) {
      console.error("Passphrase submission failed", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form
      onSubmit={
        showPassphrasePrompt
          ? handlePassphraseSubmit
          : accountAuthenticated
          ? handleServerPasswordSubmit
          : handleAccountSubmit
      }
      className="w-full max-w-md mx-auto"
    >
      <Card className="w-full">
        <CardHeader className="space-y-4">
          <div className="mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
            <EncryptionIcon className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-2xl text-center">SecureChat</CardTitle>
          <CardDescription className="text-center">
            End-to-end encrypted messaging using 4096-bit RSA and AES-GCM
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* passphrase after login/register form always*/}
          {showPassphrasePrompt ? (
            <div className="space-y-4">
              {mode === "register" ? (
                <PasswordFieldWithConfirm
                  label="Secure Encryption Passphrase"
                  value={passphrase}
                  confirmValue={confirmPassphrase}
                  onChange={setPassphrase}
                  onConfirmChange={setConfirmPassphrase}
                  required
                  minLength={12}
                  strengthCheck
                  warningMessage={
                    <>
                      This passphrase encrypts all your account data. If you forget it,{" "}
                      <strong>you will lose access</strong> to all your messages and files.
                    </>
                  }
                />
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="passphrase">Secure Encryption Passphrase</Label>
                  <Input
                    id="passphrase"
                    type="password"
                    placeholder="Enter your encryption passphrase"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    disabled={isSubmitting || isGeneratingKeys}
                    required
                  />
                </div>
              )}
            </div>
          ) : accountAuthenticated ? (
            /* server password */
            <div className="space-y-2">
              <Label htmlFor="serverPassword">Server Password</Label>
              <Input
                id="serverPassword"
                type="password"
                placeholder="Enter server password"
                value={serverPassword}
                onChange={(e) => setServerPassword(e.target.value)}
                disabled={isSubmitting || isGeneratingKeys}
                required
              />
            </div>
          ) : (
            /* login/register*/
            <>
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={isSubmitting || isGeneratingKeys}
                  required
                  minLength={3}
                  maxLength={16}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="localPassword">
                  {mode === "login" ? "Password" : "Create Password"}
                </Label>
                <Input
                  id="localPassword"
                  type="password"
                  placeholder={
                    mode === "login"
                      ? "Enter your password"
                      : "Choose a password for your account"
                  }
                  value={localPassword}
                  onChange={(e) => setLocalPassword(e.target.value)}
                  disabled={isSubmitting || isGeneratingKeys}
                  required
                />
              </div>

              {mode === "register" && (
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm Password</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    placeholder="Re-enter your password"
                    value={confirmLocalPassword}
                    onChange={(e) => setConfirmLocalPassword(e.target.value)}
                    disabled={isSubmitting || isGeneratingKeys}
                    required
                  />
                  {localPassword &&
                    confirmLocalPassword &&
                    localPassword !== confirmLocalPassword && (
                      <p className="text-xs text-red-500">Passwords do not match</p>
                    )}
                </div>
              )}
            </>
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
          <Button
            type="submit"
            className="w-full"
            disabled={
              isSubmitting ||
              isGeneratingKeys ||
              (showPassphrasePrompt
                ? !isPassphraseValid || (mode === "register" && !doPassphrasesMatch)
                : accountAuthenticated
                  ? !serverPassword
                  : !username.trim() || (mode === "register" && (!isLocalPasswordValid || !doPasswordsMatch))
              )
            }

          >
            {isGeneratingKeys ? (
              <span className="flex items-center gap-2">
                <KeyRing className="animate-spin h-4 w-4" />
                Generating encryption keys...
              </span>
            ) : isSubmitting ? (
              showPassphrasePrompt
                ? "Submitting Passphrase..."
                : accountAuthenticated
                ? "Verifying Server Password..."
                : mode === "register"
                ? "Registering..."
                : "Logging In..."
            ) : showPassphrasePrompt ? (
              "Submit Passphrase"
            ) : accountAuthenticated ? (
              "Verify Server Password"
            ) : mode === "register" ? (
              "Register Account"
            ) : (
              "Login to Account"
            )}
          </Button>

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
    </form>
  );
}
