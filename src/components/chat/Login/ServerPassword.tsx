import React from "react";
import { SERVER_PASSWORD_MAX_LENGTH } from "../../../lib/constants";

interface ServerPasswordFormProps {
  readonly serverPassword: string;
  readonly setServerPassword: (v: string) => void;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly onSubmit: (e: React.FormEvent) => void;
}

export function ServerPasswordForm({
  serverPassword,
  setServerPassword,
  disabled,
  authStatus,
  onSubmit,
}: ServerPasswordFormProps) {
  return (
    <form
      onSubmit={onSubmit}
      className={`login-simple-form${disabled ? " is-submitting" : ""}`}
      aria-busy={disabled}
    >
      <div className="login-simple-field">
        <label htmlFor="serverPassword">Server password</label>
        <input
          className="login-simple-input"
          id="serverPassword"
          type="password"
          placeholder="Enter server password"
          value={serverPassword}
          onChange={(e) => setServerPassword(e.target.value)}
          disabled={disabled}
          required
          autoComplete="current-password"
          maxLength={SERVER_PASSWORD_MAX_LENGTH}
        />
      </div>
      <button
        type="submit"
        className="login-simple-submit"
        disabled={disabled}
      >
        {disabled ? (authStatus || "Verifying...") : "Submit server password"}
      </button>
    </form>
  );
}
