import React from "react";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";

interface PasswordFieldWithConfirmProps {
  label: string;
  value: string;
  confirmValue: string;
  onChange: (value: string) => void;
  onConfirmChange: (value: string) => void;
  required?: boolean;
  minLength?: number;
  strengthCheck?: boolean;
  warningMessage?: React.ReactNode;
  disabled?: boolean; // added here
}

export function PasswordFieldWithConfirm({
  label,
  value,
  confirmValue,
  onChange,
  onConfirmChange,
  required = false,
  minLength = 0,
  strengthCheck = false,
  warningMessage,
  disabled = false, // default false
}: PasswordFieldWithConfirmProps) {
  const isStrongEnough = value.length >= minLength;
  const showMismatch = value && confirmValue && value !== confirmValue;

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
