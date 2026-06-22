import React, { useState, useCallback, useMemo } from "react";
import { isValidUsername } from "../../../lib/sanitizers";
import {
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  PASSWORD_MAX_LENGTH,
} from "../../../lib/constants";

interface SignUpFormProps {
  readonly onSubmit: (username: string, password: string, passphrase: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly error?: string;
  readonly hasServerTrustRequest?: boolean;
  readonly initialUsername?: string;
  readonly initialPassword?: string;
  readonly onChangeUsername?: (v: string) => void;
  readonly onChangePassword?: (v: string) => void;
  readonly onChangeConfirmPassword?: (v: string) => void;
  readonly onChangePassphrase?: (v: string) => void;
  readonly onChangeConfirmPassphrase?: (v: string) => void;
}

export function SignUpForm({
  onSubmit,
  disabled,
  authStatus,
  hasServerTrustRequest,
  initialUsername = "",
  initialPassword = "",
  onChangeUsername,
  onChangePassword,
  onChangeConfirmPassword,
  onChangePassphrase,
  onChangeConfirmPassphrase
}: SignUpFormProps) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleUsernameChange = useCallback((v: string): void => {
    setUsername(v);
    onChangeUsername?.(v);
  }, [onChangeUsername]);

  const handlePasswordChange = useCallback((v: string): void => {
    setPassword(v);
    onChangePassword?.(v);
  }, [onChangePassword]);

  const handleConfirmChange = useCallback((v: string): void => {
    setConfirmPassword(v);
    onChangeConfirmPassword?.(v);
  }, [onChangeConfirmPassword]);

  const handlePassphraseChange = useCallback((v: string): void => {
    setPassphrase(v);
    onChangePassphrase?.(v);
  }, [onChangePassphrase]);

  const handleConfirmPassphraseChange = useCallback((v: string): void => {
    setConfirmPassphrase(v);
    onChangeConfirmPassphrase?.(v);
  }, [onChangeConfirmPassphrase]);

  const isUsernameValid = useMemo(() => username.trim().length >= USERNAME_MIN_LENGTH, [username]);
  const isPasswordValid = useMemo(() => password.length > 0, [password]);
  const doPasswordsMatch = useMemo(() => password === confirmPassword, [password, confirmPassword]);
  const isPassphraseValid = useMemo(() => passphrase.trim().length >= 8, [passphrase]);
  const doPassphrasesMatch = useMemo(() => passphrase === confirmPassphrase, [passphrase, confirmPassphrase]);

  const isFormValid = useMemo(() =>
    isUsernameValid && isPasswordValid && doPasswordsMatch && isPassphraseValid && doPassphrasesMatch,
    [isUsernameValid, isPasswordValid, doPasswordsMatch, isPassphraseValid, doPassphrasesMatch]
  );

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();
    if (!isValidUsername(sanitizedUsername)) return;
    if (password.length > PASSWORD_MAX_LENGTH) return;
    if (!isPassphraseValid || !doPassphrasesMatch) return;

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password, passphrase.trim());
    } finally {
      setIsSubmitting(false);
    }
  }, [disabled, isSubmitting, isFormValid, username, password, passphrase, isPassphraseValid, doPassphrasesMatch, onSubmit]);

  return (
    <form
      onSubmit={handleSubmit}
      className={`signup-simple-form${isSubmitting ? " is-submitting" : ""}`}
      aria-busy={isSubmitting}
    >
      <div className="signup-simple-field">
        <label htmlFor="username">Username</label>
        <input
          className="signup-simple-input"
          id="username"
          placeholder="Choose your username"
          value={username}
          onChange={(e) => handleUsernameChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          minLength={USERNAME_MIN_LENGTH}
          maxLength={USERNAME_MAX_LENGTH}
          autoComplete="username"
        />
      </div>

      <div className="signup-simple-field">
        <label htmlFor="password">Password</label>
        <input
          className="signup-simple-input"
          id="password"
          type="password"
          placeholder="Create password"
          value={password}
          onChange={(e) => handlePasswordChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          maxLength={PASSWORD_MAX_LENGTH}
        />
      </div>

      <div className="signup-simple-field">
        <label htmlFor="confirmPassword">Confirm password</label>
        <input
          className="signup-simple-input"
          id="confirmPassword"
          type="password"
          placeholder="Confirm password"
          value={confirmPassword}
          onChange={(e) => handleConfirmChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          maxLength={PASSWORD_MAX_LENGTH}
        />
        {!doPasswordsMatch && confirmPassword.length > 0 && (
          <p className="auth-simple-message">Passwords do not match</p>
        )}
      </div>

      <div className="signup-simple-field">
        <label htmlFor="passphrase">Encryption passphrase</label>
        <input
          className="signup-simple-input"
          id="passphrase"
          type="password"
          placeholder="New encryption passphrase"
          value={passphrase}
          onChange={(e) => handlePassphraseChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
        />
        {passphrase.length > 0 && !isPassphraseValid && (
          <p className="auth-simple-message">Passphrase too short (min 8 chars)</p>
        )}
      </div>

      <div className="signup-simple-field">
        <label htmlFor="confirmPassphrase">Confirm passphrase</label>
        <input
          className="signup-simple-input"
          id="confirmPassphrase"
          type="password"
          placeholder="Confirm passphrase"
          value={confirmPassphrase}
          onChange={(e) => handleConfirmPassphraseChange(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
        />
        {!doPassphrasesMatch && confirmPassphrase.length > 0 && (
          <p className="auth-simple-message">Passphrases do not match</p>
        )}
      </div>

      {hasServerTrustRequest && !isSubmitting && (
        <p className="auth-simple-message">
          Verify server identity before registering
        </p>
      )}

      <button
        type="submit"
        className="signup-simple-submit"
        disabled={disabled || isSubmitting || !isFormValid}
      >
        {isSubmitting ? (authStatus || "Creating account...") : "Create account"}
      </button>
    </form>
  );
}
