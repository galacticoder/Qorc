import React, { useState, useCallback, useMemo } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";
import { USERNAME_MAX_LENGTH, PASSWORD_MAX_LENGTH } from "../../../lib/constants";

interface SignInFormProps {
  readonly onSubmit: (username: string, password: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly hasServerTrustRequest?: boolean;
  readonly initialUsername?: string;
  readonly initialPassword?: string;
  readonly onChangeUsername?: (v: string) => void;
  readonly onChangePassword?: (v: string) => void;
}

export function SignInForm({
  onSubmit,
  disabled,
  authStatus,
  hasServerTrustRequest,
  initialUsername = "",
  initialPassword = "",
  onChangeUsername,
  onChangePassword
}: SignInFormProps) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleUsernameChange = useCallback((v: string): void => {
    setUsername(v);
    onChangeUsername?.(v);
  }, [onChangeUsername]);

  const handlePasswordChange = useCallback((v: string): void => {
    setPassword(v);
    onChangePassword?.(v);
  }, [onChangePassword]);

  const isFormValid = useMemo(() =>
    username.trim().length > 0 && password.length > 0,
    [username, password]
  );

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();

    if (sanitizedUsername.length === 0 || sanitizedUsername.length > USERNAME_MAX_LENGTH) return;
    if (password.length < 1 || password.length > PASSWORD_MAX_LENGTH) return;

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password);
    } finally {
      setIsSubmitting(false);
    }
  }, [disabled, isSubmitting, isFormValid, username, password, onSubmit]);

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username" className="text-muted-foreground font-medium">Username</Label>
        <Input
          id="username"
          placeholder="Enter your username"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          maxLength={USERNAME_MAX_LENGTH}
          autoComplete="username"
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password" className="text-muted-foreground font-medium">Password</Label>
        <Input
          id="password"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => handlePasswordChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="current-password"
          maxLength={PASSWORD_MAX_LENGTH}
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
      </div>

      {hasServerTrustRequest && !isSubmitting && (
        <p className="text-destructive text-sm text-center font-medium animate-pulse">
          Verify server identity before proceeding
        </p>
      )}

      <Button
        type="submit"
        size="lg"
        variant="ghost"
        className="w-full h-14 text-base font-semibold transition-all shadow-xl shadow-primary/20 hover:shadow-primary/40 hover:scale-[1.02] active:scale-[0.98] bg-primary hover:bg-primary/90 border-0"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || "Logging In...") : "Sign In"}
      </Button>
    </form>
  );
}