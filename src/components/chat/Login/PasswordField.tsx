import React, { useMemo } from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";

interface PasswordFieldProps {
  readonly label: string;
  readonly value: string;
  readonly confirmValue: string;
  readonly onChange: (value: string) => void;
  readonly onConfirmChange: (value: string) => void;
  readonly required?: boolean;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly strengthCheck?: boolean;
  readonly warningMessage?: React.ReactNode;
  readonly disabled?: boolean;
}

export function PasswordField({
  label,
  value,
  confirmValue,
  onChange,
  onConfirmChange,
  required = false,
  minLength = 0,
  maxLength,
  strengthCheck = false,
  warningMessage,
  disabled = false,
}: PasswordFieldProps) {
  const isStrongEnough = useMemo(() => value.length >= minLength, [value, minLength]);
  const showMismatch = useMemo(() => value && confirmValue && value !== confirmValue, [value, confirmValue]);

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor={`${label}-main`} className="text-muted-foreground font-medium">{label}</Label>
        <Input
          id={`${label}-main`}
          type="password"
          placeholder={`Enter ${label.toLowerCase()}`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={required}
          minLength={minLength}
          maxLength={maxLength}
          disabled={disabled}
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
        {strengthCheck && !isStrongEnough && value.length > 0 && (
          <p className="text-xs text-destructive font-medium animate-pulse">
            Must be at least {minLength} characters
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${label}-confirm`} className="text-muted-foreground font-medium">Confirm {label}</Label>
        <Input
          id={`${label}-confirm`}
          type="password"
          placeholder={`Confirm ${label.toLowerCase()}`}
          value={confirmValue}
          onChange={(e) => onConfirmChange(e.target.value)}
          required={required}
          minLength={minLength}
          disabled={disabled}
          className="bg-background/50 border-border/50 focus:bg-background/80 transition-all duration-200"
        />
        {showMismatch && (
          <p className="text-xs text-destructive font-medium animate-pulse">Passwords do not match</p>
        )}
        {warningMessage && (
          <div className="text-xs text-muted-foreground bg-muted/50 p-2 rounded border border-border/50">
            {warningMessage}
          </div>
        )}
      </div>
    </div>
  );
}