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
      <div className="text-center">
        <h3 className="text-lg font-semibold">Password Required</h3>
        <p className="text-sm text-muted-foreground mt-1">
          Server requires secure password verification for authentication
        </p>
      </div>
      
      <div className="space-y-2">
        <Label htmlFor="password-hash">Password</Label>
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
        />
      </div>

      {authStatus && (
        <div className="text-sm text-center text-muted-foreground">
          {authStatus}
        </div>
      )}

      <Button 
        type="submit" 
        className="w-full" 
        disabled={disabled || isSubmitting || !password.trim()}
      >
        {isSubmitting ? "Processing..." : "Authenticate"}
      </Button>
    </form>
  );
}
