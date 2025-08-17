import React, { useState } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface SignInFormProps {
  onSubmit: (username: string, password: string) => Promise<void>;
  disabled: boolean;
  error?: string;
  hasServerTrustRequest?: boolean;
}

export function SignInForm({ onSubmit, disabled, error, hasServerTrustRequest }: SignInFormProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isFormValid = username.trim().length >= 3 && password.length > 0;

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
          placeholder="Enter your username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
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
          onChange={(e) => setPassword(e.target.value)}
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
        {isSubmitting ? "Logging In..." : "Login to Account"}
      </Button>
    </form>
  );
}
