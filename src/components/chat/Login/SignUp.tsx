// SignUp.tsx
import React, { useState } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface SignUpFormProps {
  onSubmit: (username: string, password: string) => Promise<void>;
  disabled: boolean;
  error?: string;
}

export function SignUpForm({ onSubmit, disabled, error }: SignUpFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isUsernameValid = username.trim().length >= 3;
  const isPasswordValid = password.length > 0;
  const doPasswordsMatch = password === confirmPassword;

  const isFormValid = isUsernameValid && isPasswordValid && doPasswordsMatch;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    setIsSubmitting(true);
    try {
      await onSubmit(username.trim(), password);
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
          onChange={(e) => setUsername(e.target.value)}
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
          onChange={(e) => setPassword(e.target.value)}
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
          onChange={(e) => setConfirmPassword(e.target.value)}
          disabled={disabled || isSubmitting}
          required
        />
        {!doPasswordsMatch && confirmPassword.length > 0 && (
          <p className="text-red-500 text-xs">Passwords do not match</p>
        )}
      </div>

      {/* {error && <p className="text-red-500 text-sm">{error}</p>} */}

      <Button
        type="submit"
        className="w-full"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? "Registering..." : "Register Account"}
      </Button>
    </form>
  );
}
