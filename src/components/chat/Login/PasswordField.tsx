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
  strengthCheck = false,
  warningMessage,
  disabled = false,
}: PasswordFieldProps) {
  const isStrongEnough = useMemo(() => value.length >= minLength, [value, minLength]);
  const showMismatch = useMemo(() => value && confirmValue && value !== confirmValue, [value, confirmValue]);

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${label}-main`}>{label}</Label>
        <Input
          id={`${label}-main`}
          type="password"
          placeholder={`Enter ${label.toLowerCase()}`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={required}
          minLength={minLength}
          disabled={disabled}
        />
        {strengthCheck && !isStrongEnough && value.length > 0 && (
          <p className="text-xs text-red-500">
            {label} should be at least {minLength} characters long.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${label}-confirm`}>Confirm {label}</Label>
        <Input
          id={`${label}-confirm`}
          type="password"
          placeholder={`Confirm ${label.toLowerCase()}`}
          value={confirmValue}
          onChange={(e) => onConfirmChange(e.target.value)}
          required={required}
          minLength={minLength}
          disabled={disabled}
        />
        {showMismatch && (
          <p className="text-xs text-red-500">{label}s do not match</p>
        )}
        {warningMessage && (
          <p className="text-xs text-yellow-600">{warningMessage}</p>
        )}
      </div>
    </>
  );
}