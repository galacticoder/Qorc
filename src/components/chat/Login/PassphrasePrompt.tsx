import React, { useState } from "react";
import { PasswordFieldWithConfirm } from "./PasswordFieldWithConfirm.tsx";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface PassphrasePromptProps {
  mode: "login" | "register";
  onSubmit: (passphrase: string) => Promise<void>;
  disabled: boolean;
  authStatus?: string;
}

export function PassphrasePrompt({ mode, onSubmit, disabled, authStatus }: PassphrasePromptProps) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isPassphraseValid = passphrase.length >= 12;
  const doPassphrasesMatch = passphrase === confirmPassphrase;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    
    // SECURITY: Validate passphrase
    const trimmedPassphrase = passphrase.trim();
    if (!trimmedPassphrase) return;
    
    // SECURITY: Validate passphrase length
    if (trimmedPassphrase.length < 12) {
      console.error('Passphrase must be at least 12 characters');
      return;
    }
    
    if (trimmedPassphrase.length > 1000) {
      console.error('Passphrase too long');
      return;
    }
    
    // NOTE: Weak passphrase pattern checks disabled per request.
    // Only the minimum length requirement is enforced for the passphrase.
    
    if (mode === "register" && !doPassphrasesMatch) return;
    if (!isPassphraseValid) return;

    setIsSubmitting(true);
    try {
      await onSubmit(trimmedPassphrase);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {mode === "register" ? (
        <PasswordFieldWithConfirm
          label="Secure Encryption Passphrase"
          value={passphrase}
          confirmValue={confirmPassphrase}
          onChange={setPassphrase}
          onConfirmChange={setConfirmPassphrase}
          required
          minLength={12}
          strengthCheck
          warningMessage={
            <>
              This passphrase encrypts all your account data. If you forget it,{" "}
              <strong>you will lose access</strong> to all your messages and files.
            </>
          }
          disabled={disabled || isSubmitting}
        />
      ) : (
        <div className="space-y-2">
          <Label htmlFor="passphrase">Secure Encryption Passphrase</Label>
          <Input
            id="passphrase"
            type="password"
            placeholder="Enter your encryption passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            disabled={disabled || isSubmitting}
            required
          />
          <div className="text-sm text-muted-foreground">
            Your passphrase is required to enable blocking functionality and access encrypted data.
          </div>
        </div>
      )}

      <Button
        type="submit"
        className="w-full"
        disabled={
          disabled ||
          isSubmitting ||
          !passphrase.trim() ||
          (mode === "register" && !doPassphrasesMatch) ||
          !isPassphraseValid
        }
      >
        {isSubmitting ? (authStatus || "Submitting Passphrase...") : "Submit Passphrase"}
      </Button>
    </form>
  );
}