import React from "react";
import { Label } from "../../ui/label";
import { Input } from "../../ui/input";
import { Button } from "../../ui/button";

interface ServerPasswordFormProps {
  serverPassword: string;
  setServerPassword: (v: string) => void;
  disabled: boolean;
  onSubmit: (e: React.FormEvent) => void;
}

export function ServerPasswordForm({
  serverPassword,
  setServerPassword,
  disabled,
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
        />
      </div>
      <Button type="submit" className="w-full" disabled={disabled}>
        {disabled ? "Submitting..." : "Submit Server Password"}
      </Button>
    </form>
  );
}
