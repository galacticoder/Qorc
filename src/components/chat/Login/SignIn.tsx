import React, { useState } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface SignInFormProps {
  onSubmit: (username: string, password: string) => Promise<void>;
  disabled: boolean;
  authStatus?: string;
  error?: string;
  hasServerTrustRequest?: boolean;
  initialUsername?: string;
  initialPassword?: string;
}

export function SignInForm({ onSubmit, disabled, authStatus, error, hasServerTrustRequest, initialUsername = "", initialPassword = "", onChangeUsername, onChangePassword }: SignInFormProps & { onChangeUsername?: (v:string)=>void; onChangePassword?: (v:string)=>void; }) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);

  const handleUsernameChange = (v: string) => { setUsername(v); onChangeUsername?.(v); };
  const handlePasswordChange = (v: string) => { setPassword(v); onChangePassword?.(v); };
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isFormValid = username.trim().length >= 3 && password.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    // SECURITY: Sanitize and validate inputs
    const sanitizedUsername = username.trim();
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(sanitizedUsername)) {
      console.error('Invalid username format');
      return;
    }
    
    // SECURITY: Validate username length
    if (sanitizedUsername.length < 3 || sanitizedUsername.length > 32) {
      console.error('Username must be 3-32 characters');
      return;
    }
    
    // SECURITY: Validate password length
    if (password.length < 1 || password.length > 1000) {
      console.error('Invalid password length');
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
          placeholder="Enter your username"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          minLength={3}
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
        />
      </div>

      {/* {error && <p className="text-red-500 text-sm">{error}</p>} */}

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