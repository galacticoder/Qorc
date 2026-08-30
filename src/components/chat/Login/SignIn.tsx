import React, { useState, useCallback, useMemo } from "react";
import {
  PASSPHRASE_MAX_LENGTH,
  PASSWORD_MAX_LENGTH,
  USERNAME_MAX_LENGTH,
} from "../../../lib/constants";

interface SignInFormProps {
  readonly onSubmit: (username: string, password: string, passphrase: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly initialUsername?: string;
  readonly submitLabel?: string;
}

export function SignInForm({
  onSubmit,
  disabled,
  authStatus,
  initialUsername = "",
  submitLabel = "Sign in",
}: SignInFormProps) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isFormValid = useMemo(() =>
    username.trim().length > 0 &&
      password.length > 0 &&
      passphrase.trim().length > 0,
    [username, password, passphrase]
  );

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();
    const trimmedPassphrase = passphrase.trim();

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password, trimmedPassphrase);
    } finally {
      setPassword("");
      setPassphrase("");
      setIsSubmitting(false);
    }
  }, [disabled, isSubmitting, isFormValid, username, password, passphrase, onSubmit]);

  return (
    <form
      onSubmit={handleSubmit}
      className={`login-simple-form${isSubmitting ? " is-submitting" : ""}`}
      aria-busy={isSubmitting}
    >
      <div className="login-simple-field">
        <label htmlFor="username">Username</label>
        <input
          className="login-simple-input"
          id="username"
          placeholder="Enter your username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          maxLength={USERNAME_MAX_LENGTH}
          autoComplete="username"
        />
      </div>

      <div className="login-simple-field">
        <label htmlFor="password">Password</label>
        <input
          className="login-simple-input"
          id="password"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="current-password"
          maxLength={PASSWORD_MAX_LENGTH}
        />
      </div>

      <div className="login-simple-field">
        <label htmlFor="passphrase">Passphrase</label>
        <input
          className="login-simple-input"
          id="passphrase"
          type="password"
          placeholder="Enter your passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="current-password"
          maxLength={PASSPHRASE_MAX_LENGTH}
        />
      </div>

      <button
        type="submit"
        className="login-simple-submit"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || `${submitLabel}...`) : submitLabel}
      </button>
    </form>
  );
}
