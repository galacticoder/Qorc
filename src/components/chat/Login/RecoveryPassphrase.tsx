import React, { useEffect, useCallback, useMemo, useState } from "react";

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
    <div className="w-full max-w-md mx-auto">
      <div className="w-full border rounded-md shadow-sm bg-white dark:bg-slate-900">
        <div className="p-6 border-b">
          <h2 className="text-xl font-semibold text-center">Unlock your account</h2>
          <p className="text-sm text-center text-muted-foreground mt-2">
            For your security, enter your passphrase to unlock your keys on this device.
            This is not your server password.
          </p>
          <p className="text-xs text-center text-muted-foreground mt-2">
            Account ID (hashed): <span className="font-mono">{displayHash}</span>
          </p>
        </div>
        <div className="p-6 space-y-4">
          {authStatus ? (
            <div className="text-sm text-muted-foreground text-center" role="status" aria-live="polite">
              {authStatus}
            </div>
          ) : null}
          {error ? (
            <div className="text-sm text-red-600 text-center" role="alert" id="recovery-error">
              {error}
            </div>
          ) : null}
          <form onSubmit={handleSubmit}>
            <div>
              <label htmlFor="recovery-passphrase" className="text-sm block mb-1">Passphrase</label>
              <input
                id="recovery-passphrase"
                name="passphrase"
                type="password"
                className="w-full px-3 py-2 border rounded-md bg-transparent"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter your encryption passphrase"
                autoComplete="current-password"
                disabled={submitting}
                aria-required="true"
                aria-disabled={submitting}
                aria-invalid={!!error}
                aria-describedby={error ? "recovery-error" : undefined}
                spellCheck={false}
                maxLength={PASSPHRASE_MAX_LENGTH}
              />
            </div>
            <div className="flex items-center gap-3">
              <button
                type="submit"
                className="px-4 py-2 rounded-md bg-primary text-white disabled:opacity-50"
                disabled={disabled}
              >
                {submitting ? 'Unlocking…' : 'Confirm'}
              </button>
              <button
                type="button"
                className="px-4 py-2 rounded-md border"
                onClick={onUseDifferentAccount}
                disabled={submitting}
              >
                Use a different account
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

