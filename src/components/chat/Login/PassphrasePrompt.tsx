import React, { useState } from "react";
import { PasswordFieldWithConfirm } from "./PasswordFieldWithConfirm.tsx";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface PassphrasePromptProps {
  mode: "login" | "register";
  onSubmit: (passphrase: string) => Promise<void>;
  disabled: boolean;
}

export function PassphrasePrompt({ mode, onSubmit, disabled }: PassphrasePromptProps) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isPassphraseValid = passphrase.length >= 12;
  const doPassphrasesMatch = passphrase === confirmPassphrase;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    if (!passphrase.trim()) return;
    if (mode === "register" && !doPassphrasesMatch) return;
    if (!isPassphraseValid) return;

    setIsSubmitting(true);
    try {
      await onSubmit(passphrase);
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
        {isSubmitting ? "Submitting Passphrase..." : "Submit Passphrase"}
      </Button>
    </form>
  );
}
