import React, { useState, useCallback, useMemo } from "react";
import { USERNAME_MAX_LENGTH, PASSWORD_MAX_LENGTH } from "../../../lib/constants";

interface SignInFormProps {
  readonly onSubmit: (username: string, password: string, passphrase: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly hasServerTrustRequest?: boolean;
  readonly initialUsername?: string;
  readonly initialPassword?: string;
  readonly onChangeUsername?: (v: string) => void;
  readonly onChangePassword?: (v: string) => void;
  readonly onChangePassphrase?: (v: string) => void;
}

export function SignInForm({
  onSubmit,
  disabled,
  authStatus,
  hasServerTrustRequest,
  initialUsername = "",
  initialPassword = "",
  onChangeUsername,
  onChangePassword,
  onChangePassphrase
}: SignInFormProps) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);
  const [passphrase, setPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleUsernameChange = useCallback((v: string): void => {
    setUsername(v);
    onChangeUsername?.(v);
  }, [onChangeUsername]);

  const handlePasswordChange = useCallback((v: string): void => {
    setPassword(v);
    onChangePassword?.(v);
  }, [onChangePassword]);

  const handlePassphraseChange = useCallback((v: string): void => {
    setPassphrase(v);
    onChangePassphrase?.(v);
  }, [onChangePassphrase]);

  const isFormValid = useMemo(() =>
    username.trim().length > 0 && password.length > 0 && passphrase.trim().length > 0,
    [username, password, passphrase]
  );

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();

    if (sanitizedUsername.length === 0 || sanitizedUsername.length > USERNAME_MAX_LENGTH) return;
    if (password.length < 1 || password.length > PASSWORD_MAX_LENGTH) return;
    if (passphrase.trim().length === 0) return;

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password, passphrase.trim());
    } finally {
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
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          maxLength={USERNAME_MAX_LENGTH}
          autoComplete="username"
        />
      </div>

      <div className="login-simple-field">
        <label htmlFor="passphrase">Encryption passphrase</label>
        <input
          className="login-simple-input"
          id="passphrase"
          type="password"
          placeholder="Enter your encryption passphrase"
          value={passphrase}
          onChange={(e) => handlePassphraseChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="current-password"
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
          onChange={(e) => handlePasswordChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="current-password"
          maxLength={PASSWORD_MAX_LENGTH}
        />
      </div>

      {hasServerTrustRequest && !isSubmitting && (
        <p className="auth-simple-message">
          Verify server identity before proceeding
        </p>
      )}

      <button
        type="submit"
        className="login-simple-submit"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || "Signing in...") : "Sign in"}
      </button>
    </form>
  );
}
