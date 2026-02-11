import React, { useState, useCallback, useMemo } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";
import { isValidUsername } from "../../../lib/sanitizers";
import {
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  PASSWORD_MAX_LENGTH,
} from "../../../lib/constants";

interface SignUpFormProps {
  readonly onSubmit: (username: string, password: string, passphrase: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly hasServerTrustRequest?: boolean;
  readonly initialUsername?: string;
  readonly initialPassword?: string;
  readonly onChangeUsername?: (v: string) => void;
  readonly onChangePassword?: (v: string) => void;
  readonly onChangeConfirmPassword?: (v: string) => void;
  readonly onChangePassphrase?: (v: string) => void;
}

export function SignUpForm({
  onSubmit,
  disabled,
  authStatus,
  hasServerTrustRequest,
  initialUsername = "",
  initialPassword = "",
  onChangeUsername,
  onChangePassword,
  onChangeConfirmPassword,
  onChangePassphrase
}: SignUpFormProps) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleUsernameChange = useCallback((v: string): void => {
    setUsername(v);
    onChangeUsername?.(v);
  }, [onChangeUsername]);

  const handlePasswordChange = useCallback((v: string): void => {
    setPassword(v);
    onChangePassword?.(v);
  }, [onChangePassword]);

  const handleConfirmChange = useCallback((v: string): void => {
    setConfirmPassword(v);
    onChangeConfirmPassword?.(v);
  }, [onChangeConfirmPassword]);

  const handlePassphraseChange = useCallback((v: string): void => {
    setPassphrase(v);
    onChangePassphrase?.(v);
  }, [onChangePassphrase]);

  const handleConfirmPassphraseChange = useCallback((v: string): void => {
    setConfirmPassphrase(v);
  }, []);

  const isUsernameValid = useMemo(() => username.trim().length >= USERNAME_MIN_LENGTH, [username]);
  const isPasswordValid = useMemo(() => password.length > 0, [password]);
  const doPasswordsMatch = useMemo(() => password === confirmPassword, [password, confirmPassword]);
  const isPassphraseValid = useMemo(() => passphrase.trim().length >= 8, [passphrase]);
  const doPassphrasesMatch = useMemo(() => passphrase === confirmPassphrase, [passphrase, confirmPassphrase]);

  const isFormValid = useMemo(() =>
    isUsernameValid && isPasswordValid && doPasswordsMatch && isPassphraseValid && doPassphrasesMatch,
    [isUsernameValid, isPasswordValid, doPasswordsMatch, isPassphraseValid, doPassphrasesMatch]
  );

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();
    if (!isValidUsername(sanitizedUsername)) return;
    if (password.length > PASSWORD_MAX_LENGTH) return;
    if (!isPassphraseValid || !doPassphrasesMatch) return;

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password, passphrase.trim());
    } finally {
      setIsSubmitting(false);
    }
  }, [disabled, isSubmitting, isFormValid, username, password, passphrase, isPassphraseValid, doPassphrasesMatch, onSubmit]);

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username" className="text-muted-foreground font-medium">Username</Label>
        <Input
          id="username"
          placeholder="Choose your username"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          minLength={USERNAME_MIN_LENGTH}
          maxLength={USERNAME_MAX_LENGTH}
          autoComplete="username"
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password" className="text-muted-foreground font-medium">Create Password</Label>
        <Input
          id="password"
          type="password"
          placeholder="Choose a password"
          value={password}
          onChange={(e) => handlePasswordChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          maxLength={PASSWORD_MAX_LENGTH}
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="confirmPassword" className="text-muted-foreground font-medium">Confirm Password</Label>
        <Input
          id="confirmPassword"
          type="password"
          placeholder="Confirm your password"
          value={confirmPassword}
          onChange={(e) => handleConfirmChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          maxLength={PASSWORD_MAX_LENGTH}
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
        {!doPasswordsMatch && confirmPassword.length > 0 && (
          <p className="text-destructive text-xs font-medium animate-pulse">Passwords do not match</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="passphrase" className="text-muted-foreground font-medium">Encryption Passphrase</Label>
        <Input
          id="passphrase"
          type="password"
          placeholder="New encryption passphrase"
          value={passphrase}
          onChange={(e) => handlePassphraseChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
        {passphrase.length > 0 && !isPassphraseValid && (
          <p className="text-destructive text-xs font-medium animate-pulse">Passphrase too short (min 8 chars)</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="confirmPassphrase" className="text-muted-foreground font-medium">Confirm Passphrase</Label>
        <Input
          id="confirmPassphrase"
          type="password"
          placeholder="Confirm your passphrase"
          value={confirmPassphrase}
          onChange={(e) => handleConfirmPassphraseChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
        {!doPassphrasesMatch && confirmPassphrase.length > 0 && (
          <p className="text-destructive text-xs font-medium animate-pulse">Passphrases do not match</p>
        )}
      </div>

      {hasServerTrustRequest && !isSubmitting && (
        <p className="text-destructive text-sm text-center font-medium animate-pulse">
          Verify server identity before registering
        </p>
      )}

      <Button
        type="submit"
        size="lg"
        variant="ghost"
        className="w-full h-14 text-base font-semibold transition-all shadow-xl shadow-primary/20 hover:shadow-primary/40 hover:scale-[1.02] active:scale-[0.98] bg-primary hover:bg-primary/90 border-0"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || "Registering...") : "Create Account"}
      </Button>
    </form>
  );
}