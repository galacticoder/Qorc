import { useState, type InputHTMLAttributes } from 'react';
import { Eye, EyeOff } from 'lucide-react';

type PasswordInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & {
  revealLabel?: string;
};

export function PasswordInput({ revealLabel = 'password', ...props }: PasswordInputProps) {
  const [revealed, setRevealed] = useState(false);
  const visible = revealed && !props.disabled && Boolean(props.value);

  return (
    <div
      className="auth-password-input"
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setRevealed(false);
      }}
    >
      <input
        {...props}
        type={visible ? 'text' : 'password'}
        onChange={(event) => {
          if (!event.currentTarget.value) setRevealed(false);
          props.onChange?.(event);
        }}
      />
      <button
        type="button"
        className="auth-password-reveal"
        aria-label={`${visible ? 'Hide' : 'Show'} ${revealLabel}`}
        aria-controls={props.id}
        aria-pressed={visible}
        disabled={props.disabled}
        onPointerDown={(event) => event.preventDefault()}
        onClick={() => setRevealed(!visible)}
      >
        {visible ? <EyeOff size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}
      </button>
    </div>
  );
}
