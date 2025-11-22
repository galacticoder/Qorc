import React, { useEffect, useCallback, useMemo, useState } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Button } from "../../ui/button";

interface RecoveryPassphraseProps {
  readonly username: string;
  readonly onSubmit: (passphrase: string) => Promise<void>;
  readonly onUseDifferentAccount: () => void;
  readonly authStatus?: string;
  readonly error?: string;
}

const PASSPHRASE_MAX_LENGTH = 1000;

const toHex = (buf: ArrayBuffer): string => {
  const arr = new Uint8Array(buf);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
};

export const RecoveryPassphrase: React.FC<RecoveryPassphraseProps> = ({ username, onSubmit, onUseDifferentAccount, authStatus, error }) => {
  const [passphrase, setPassphrase] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [displayHash, setDisplayHash] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (username && crypto?.subtle) {
          const enc = new TextEncoder();
          const digest = await crypto.subtle.digest('SHA-256', enc.encode(username + '|recovery_v1'));
          if (!cancelled) setDisplayHash(toHex(digest).slice(0, 16));
        } else {
          if (!cancelled) setDisplayHash('••••••••');
        }
      } catch {
        if (!cancelled) setDisplayHash('••••••••');
      }
    })();
    return () => { cancelled = true; };
  }, [username]);

  const disabled = useMemo(() => submitting || passphrase.trim().length === 0, [submitting, passphrase]);

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled) return;
    if (passphrase.length > PASSPHRASE_MAX_LENGTH) return;

    setSubmitting(true);
    try {
      await onSubmit(passphrase);
    } finally {
      setSubmitting(false);
    }
  }, [disabled, passphrase, onSubmit]);

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <p className="text-sm text-muted-foreground">
          For your security, enter your passphrase to unlock your keys on this device.
          This is not your server password.
        </p>
        <div className="inline-block px-3 py-1 rounded-full bg-muted/50 border border-border/50">
          <p className="text-xs font-mono text-muted-foreground">
            ID: <span className="text-foreground font-semibold">{displayHash}</span>
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="recovery-passphrase" className="text-muted-foreground font-medium">Passphrase</Label>
          <Input
            id="recovery-passphrase"
            name="passphrase"
            type="password"
            className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter your encryption passphrase"
            autoComplete="current-password"
            disabled={submitting}
            aria-required="true"
            aria-disabled={submitting}
            spellCheck={false}
            maxLength={PASSPHRASE_MAX_LENGTH}
          />
        </div>

        {authStatus && (
          <div className="text-sm text-center text-muted-foreground animate-pulse" role="status" aria-live="polite">
            {authStatus}
          </div>
        )}

        <div className="flex flex-col gap-3">
          <Button
            type="submit"
            className="w-full font-semibold shadow-lg hover:shadow-xl transition-all duration-200"
            disabled={disabled}
          >
            {submitting ? 'Unlocking...' : 'Confirm'}
          </Button>
          <Button
            type="button"
            variant="outline"
            className="w-full border-border/50 hover:bg-accent/50 transition-colors"
            onClick={onUseDifferentAccount}
            disabled={submitting}
          >
            Use a different account
          </Button>
        </div>
      </form>
    </div>
  );
};


