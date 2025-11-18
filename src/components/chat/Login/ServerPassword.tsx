import React from "react";
import { Label } from "../../ui/label";
import { Input } from "../../ui/input";
import { Button } from "../../ui/button";

interface ServerPasswordFormProps {
  readonly serverPassword: string;
  readonly setServerPassword: (v: string) => void;
  readonly disabled: boolean;
  readonly authStatus?: string;
  readonly onSubmit: (e: React.FormEvent) => void;
}

const SERVER_PASSWORD_MAX_LENGTH = 1000;

export function ServerPasswordForm({
  serverPassword,
  setServerPassword,
  disabled,
  authStatus,
  onSubmit,
}: ServerPasswordFormProps) {
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="serverPassword">Server Password</Label>
        <Input
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
      <Button type="submit" className="w-full" disabled={disabled}>
        {disabled ? (authStatus || "Submitting...") : "Submit Server Password"}
      </Button>
    </form>
  );
}