import React, { useState, useCallback } from "react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";

interface PasswordHashPromptProps {
  readonly onSubmit: (password: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly initialPassword?: string;
  readonly onChangePassword?: (v: string) => void;
}

const PASSWORD_MAX_LENGTH = 1000;

export function PasswordHashPrompt({
  onSubmit,
  disabled,
  authStatus,
  initialPassword = "",
  onChangePassword
}: PasswordHashPromptProps) {
  const [password, setPassword] = useState(initialPassword);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleChange = useCallback((v: string): void => {
    setPassword(v);
    onChangePassword?.(v);
  }, [onChangePassword]);

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (!password.trim() || disabled || isSubmitting) return;
    if (password.length > PASSWORD_MAX_LENGTH) return;

    setIsSubmitting(true);
    try {
      await onSubmit(password);
    } finally {
      setIsSubmitting(false);
    }
  }, [password, disabled, isSubmitting, onSubmit]);

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="text-center space-y-1">
        <h3 className="text-lg font-semibold tracking-tight">Password Required</h3>
        <p className="text-sm text-muted-foreground">
          Verify your identity to continue
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="password-hash" className="text-muted-foreground font-medium">Password</Label>
        <Input
          id="password-hash"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => handleChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoFocus
          autoComplete="current-password"
          maxLength={PASSWORD_MAX_LENGTH}
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
      </div>

      {authStatus && (
        <div className="text-sm text-center text-muted-foreground animate-pulse">
          {authStatus}
        </div>
      )}

      <Button
        type="submit"
        className="w-full font-semibold shadow-lg hover:shadow-xl transition-all duration-200"
        disabled={disabled || isSubmitting || !password.trim()}
      >
        {isSubmitting ? "Verifying..." : "Authenticate"}
      </Button>
    </form>
  );
}
