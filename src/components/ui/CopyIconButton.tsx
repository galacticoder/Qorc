import type { ButtonHTMLAttributes } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '../../lib/utils/shared-utils';

interface CopyIconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly copied: boolean;
}

export function CopyIconButton({ copied, className, ...props }: CopyIconButtonProps) {
  return <button type="button" className={cn('qorc-copy-button', copied && 'is-copied', className)} {...props}>
    {copied ? <Check size={17} aria-hidden="true" /> : <Copy size={17} aria-hidden="true" />}
  </button>;
}
