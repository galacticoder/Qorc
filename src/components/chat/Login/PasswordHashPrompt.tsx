import React, { useState } from "react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";

interface PasswordHashPromptProps {
  onSubmit: (password: string) => Promise<void>;
  disabled: boolean;
  authStatus?: string;
  initialPassword?: string;
  onChangePassword?: (v:string)=>void;
}

export function PasswordHashPrompt({ onSubmit, disabled, authStatus, initialPassword = "", onChangePassword }: PasswordHashPromptProps) {
  const [password, setPassword] = useState(initialPassword);
  const handleChange = (v:string) => { setPassword(v); onChangePassword?.(v); };
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim() || disabled || isSubmitting) return;

    setIsSubmitting(true);
      try {
      await onSubmit(password);
    } catch (error) {
      console.error("Password hash submission failed:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

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
