import React, { useState, useCallback, useMemo } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

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

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 32;
const PASSWORD_MAX_LENGTH = 1000;
const USERNAME_REGEX = /^[a-zA-Z0-9_-]+$/;

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
    username.trim().length >= USERNAME_MIN_LENGTH && password.length > 0,
    [username, password]
  );

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();
    
    if (!USERNAME_REGEX.test(sanitizedUsername)) return;
    if (sanitizedUsername.length < USERNAME_MIN_LENGTH || sanitizedUsername.length > USERNAME_MAX_LENGTH) return;
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
        <Label htmlFor="username">Username</Label>
        <Input
          id="username"
          placeholder="Enter your username"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          minLength={USERNAME_MIN_LENGTH}
          maxLength={USERNAME_MAX_LENGTH}
          autoComplete="username"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
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
        />
      </div>


      {hasServerTrustRequest && !isSubmitting && (
        <p className="text-amber-600 text-sm text-center">
          Please verify the server identity before logging in
        </p>
      )}

      <Button
        type="submit"
        className="w-full"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || "Logging In...") : "Login to Account"}
      </Button>
    </form>
  );
}