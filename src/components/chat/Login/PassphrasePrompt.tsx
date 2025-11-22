import React, { useState, useCallback, useMemo } from "react";
import { PasswordField } from "./PasswordField.tsx";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface PassphrasePromptProps {
  readonly mode: "login" | "register";
  readonly onSubmit: (passphrase: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly initialPassphrase?: string;
  readonly initialConfirmPassphrase?: string;
  readonly onChangePassphrase?: (v: string) => void;
  readonly onChangeConfirm?: (v: string) => void;
}

const PASSPHRASE_MIN_LENGTH = 12;
const PASSPHRASE_MAX_LENGTH = 1000;

export function PassphrasePrompt({
  mode,
  onSubmit,
  disabled,
  authStatus,
  initialPassphrase = "",
  initialConfirmPassphrase = "",
  onChangePassphrase,
  onChangeConfirm
}: PassphrasePromptProps) {
  const [passphrase, setPassphrase] = useState(initialPassphrase);
  const [confirmPassphrase, setConfirmPassphrase] = useState(initialConfirmPassphrase);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handlePassChange = useCallback((v: string): void => {
    setPassphrase(v);
    onChangePassphrase?.(v);
  }, [onChangePassphrase]);

  const handleConfirm = useCallback((v: string): void => {
    setConfirmPassphrase(v);
    onChangeConfirm?.(v);
  }, [onChangeConfirm]);

  const isPassphraseValid = useMemo(() => passphrase.length >= PASSPHRASE_MIN_LENGTH, [passphrase]);
  const doPassphrasesMatch = useMemo(() => passphrase === confirmPassphrase, [passphrase, confirmPassphrase]);

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (isSubmitting) return;

    const trimmedPassphrase = passphrase.trim();
    if (!trimmedPassphrase) return;
    if (trimmedPassphrase.length < PASSPHRASE_MIN_LENGTH) return;
    if (trimmedPassphrase.length > PASSPHRASE_MAX_LENGTH) return;
    if (mode === "register" && !doPassphrasesMatch) return;
    if (!isPassphraseValid) return;

    setIsSubmitting(true);
    try {
      await onSubmit(trimmedPassphrase);
    } finally {
      setIsSubmitting(false);
    }
  }, [isSubmitting, passphrase, mode, doPassphrasesMatch, isPassphraseValid, onSubmit]);

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {mode === "register" ? (
        <PasswordField
          label="Encryption Passphrase"
          value={passphrase}
          confirmValue={confirmPassphrase}
          onChange={handlePassChange}
          onConfirmChange={handleConfirm}
          required
          minLength={PASSPHRASE_MIN_LENGTH}
          maxLength={PASSPHRASE_MAX_LENGTH}
          strengthCheck
          warningMessage="This passphrase encrypts your data. Do not forget it."
          disabled={disabled || isSubmitting}
        />
      ) : (
        <div className="space-y-2">
          <Label htmlFor="passphrase" className="text-muted-foreground font-medium">Encryption Passphrase</Label>
          <Input
            id="passphrase"
            type="password"
            placeholder="Enter your passphrase"
            value={passphrase}
            onChange={(e) => handlePassChange(e.target.value)}
            disabled={disabled || isSubmitting}
            required
            autoComplete="current-password"
            maxLength={PASSPHRASE_MAX_LENGTH}
            className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
          />
        </div>
      )}

      <Button
        type="submit"
        className="w-full font-semibold shadow-lg hover:shadow-xl transition-all duration-200"
        disabled={
          disabled ||
          isSubmitting ||
          !passphrase.trim() ||
          (mode === "register" && !doPassphrasesMatch) ||
          !isPassphraseValid
        }
      >
        {isSubmitting ? (authStatus || "Processing...") : "Submit Passphrase"}
      </Button>
    </form>
  );
}