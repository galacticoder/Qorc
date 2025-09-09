import React, { useState } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface SignUpFormProps {
  onSubmit: (username: string, password: string) => Promise<void>;
  disabled: boolean;
  authStatus?: string;
  error?: string;
  hasServerTrustRequest?: boolean;
  initialUsername?: string;
  initialPassword?: string;
}

export function SignUpForm({ onSubmit, disabled, authStatus, error, hasServerTrustRequest, initialUsername = "", initialPassword = "", onChangeUsername, onChangePassword, onChangeConfirmPassword }: SignUpFormProps & { onChangeUsername?: (v:string)=>void; onChangePassword?: (v:string)=>void; onChangeConfirmPassword?: (v:string)=>void; }) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);
  const [confirmPassword, setConfirmPassword] = useState("");

  const handleUsernameChange = (v:string) => { setUsername(v); onChangeUsername?.(v); };
  const handlePasswordChange = (v:string) => { setPassword(v); onChangePassword?.(v); };
  const handleConfirmChange = (v:string) => { setConfirmPassword(v); onChangeConfirmPassword?.(v); };
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isUsernameValid = username.trim().length >= 3;
  const isPasswordValid = password.length > 0;
  const doPasswordsMatch = password === confirmPassword;

  const isFormValid = isUsernameValid && isPasswordValid && doPasswordsMatch;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    // SECURITY: Sanitize and validate inputs
    const sanitizedUsername = username.trim();
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(sanitizedUsername)) {
      console.error('Username can only contain letters, numbers, underscores, and hyphens');
      return;
    }
    
    // SECURITY: Validate username length
    if (sanitizedUsername.length < 3 || sanitizedUsername.length > 32) {
      console.error('Username must be 3-32 characters');
      return;
    }
    
    // NOTE: Password strength and complexity checks disabled per request.
    // Only presence and matching confirmation are required.
    if (password.length > 1000) {
      console.error('Password too long');
      return;
    }

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username">Username</Label>
        <Input
          id="username"
          placeholder="Choose your username"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          minLength={3}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="password">Create Password</Label>
        <Input
          id="password"
          type="password"
          placeholder="Choose a password"
          value={password}
          onChange={(e) => handlePasswordChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="confirmPassword">Confirm Password</Label>
        <Input
          id="confirmPassword"
          type="password"
          placeholder="Confirm your password"
          value={confirmPassword}
          onChange={(e) => handleConfirmChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
        />
        {!doPasswordsMatch && confirmPassword.length > 0 && (
          <p className="text-red-500 text-xs">Passwords do not match</p>
        )}
      </div>

      {/* {error && <p className="text-red-500 text-sm">{error}</p>} */}

      {hasServerTrustRequest && !isSubmitting && (
        <p className="text-amber-600 text-sm text-center">
          Please verify the server identity before registering
        </p>
      )}

      <Button
        type="submit"
        className="w-full"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || "Registering...") : "Register Account"}
      </Button>
    </form>
  );
}