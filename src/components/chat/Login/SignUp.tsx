import React, { useState, useCallback, useMemo, useEffect } from "react";
import { isValidUsername } from "../../../lib/sanitizers";
import {
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
  PASSPHRASE_MIN_LENGTH,
  PASSPHRASE_MAX_LENGTH,
} from "../../../lib/constants";

interface SignUpFormProps {
  readonly onSubmit: (username: string, password: string, passphrase: string) => Promise<void>;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly initialUsername?: string;
}

export function SignUpForm({
  onSubmit,
  disabled,
  authStatus,
  initialUsername = "",
}: SignUpFormProps) {
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isUsernameValid = useMemo(() => username.trim().length >= USERNAME_MIN_LENGTH, [username]);
  const isPasswordValid = useMemo(() => password.length >= PASSWORD_MIN_LENGTH, [password]);
  const doPasswordsMatch = useMemo(() => password === confirmPassword, [password, confirmPassword]);
  const isPassphraseValid = useMemo(
    () => passphrase.trim().length >= PASSPHRASE_MIN_LENGTH,
    [passphrase],
  );
  const doPassphrasesMatch = useMemo(() => passphrase === confirmPassphrase, [passphrase, confirmPassphrase]);
  const secretsAreDistinct = useMemo(() => password !== passphrase.trim(), [password, passphrase]);

  const isFormValid = useMemo(() =>
    isUsernameValid && isPasswordValid && doPasswordsMatch && isPassphraseValid &&
      doPassphrasesMatch && secretsAreDistinct,
    [isUsernameValid, isPasswordValid, doPasswordsMatch, isPassphraseValid, doPassphrasesMatch, secretsAreDistinct]
  );

  useEffect(() => {
    console.log('[SIGNUP-DIAG] button gate', {
      disabled, isSubmitting, isFormValid,
      isUsernameValid, isPasswordValid, doPasswordsMatch,
      isPassphraseValid, doPassphrasesMatch, secretsAreDistinct
    });
  }, [disabled, isSubmitting, isFormValid, isUsernameValid, isPasswordValid, doPasswordsMatch, isPassphraseValid, doPassphrasesMatch, secretsAreDistinct]);

  const handleSubmit = useCallback(async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    console.log('[SIGNUP-DIAG] submit attempt', { disabled, isSubmitting, isFormValid });
    if (disabled || isSubmitting || !isFormValid) return;

    const sanitizedUsername = username.trim();
    if (!isValidUsername(sanitizedUsername)) return;
    if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) return;
    if (
      !isPassphraseValid ||
      passphrase.trim().length > PASSPHRASE_MAX_LENGTH ||
      !doPassphrasesMatch ||
      !secretsAreDistinct
    ) return;

    setIsSubmitting(true);
    try {
      await onSubmit(sanitizedUsername, password, passphrase.trim());
    } finally {
      setPassword("");
      setConfirmPassword("");
      setPassphrase("");
      setConfirmPassphrase("");
      setIsSubmitting(false);
    }
  }, [disabled, isSubmitting, isFormValid, username, password, passphrase, isPassphraseValid, doPassphrasesMatch, secretsAreDistinct, onSubmit]);

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
          onChange={(e) => setUsername(e.target.value)}
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
          onChange={(e) => setPassword(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          minLength={PASSWORD_MIN_LENGTH}
          maxLength={PASSWORD_MAX_LENGTH}
        />
        {password.length > 0 && !isPasswordValid && (
          <p className="auth-simple-message">Password too short (min {PASSWORD_MIN_LENGTH} chars)</p>
        )}
      </div>

      <div className="signup-simple-field">
        <label htmlFor="confirmPassword">Confirm password</label>
        <input
          className="signup-simple-input"
          id="confirmPassword"
          type="password"
          placeholder="Confirm password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          minLength={PASSWORD_MIN_LENGTH}
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
          onChange={(e) => setPassphrase(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          minLength={PASSPHRASE_MIN_LENGTH}
          maxLength={PASSPHRASE_MAX_LENGTH}
        />
        {passphrase.length > 0 && !isPassphraseValid && (
          <p className="auth-simple-message">Passphrase too short (min {PASSPHRASE_MIN_LENGTH} chars)</p>
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
          onChange={(e) => setConfirmPassphrase(e.target.value)}
          disabled={disabled || isSubmitting}
          required
          autoComplete="new-password"
          minLength={PASSPHRASE_MIN_LENGTH}
          maxLength={PASSPHRASE_MAX_LENGTH}
        />
        {!doPassphrasesMatch && confirmPassphrase.length > 0 && (
          <p className="auth-simple-message">Passphrases do not match</p>
        )}
        {!secretsAreDistinct && passphrase.length > 0 && (
          <p className="auth-simple-message">Password and passphrase must be different</p>
        )}
      </div>

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
