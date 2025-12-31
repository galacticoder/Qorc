import React from "react";
import { Label } from "../../ui/label";
import { Input } from "../../ui/input";
import { Button } from "../../ui/button";
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
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="serverPassword" className="text-muted-foreground font-medium">Server Password</Label>
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
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
      </div>
      <Button
        type="submit"
        size="lg"
        variant="ghost"
        className="w-full h-14 text-base font-semibold transition-all shadow-xl shadow-primary/20 hover:shadow-primary/40 hover:scale-[1.02] active:scale-[0.98] bg-primary hover:bg-primary/90 border-0"
        disabled={disabled}
      >
        {disabled ? (authStatus || "Verifying...") : "Submit Server Password"}
      </Button>
    </form>
  );
}