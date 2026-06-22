import React from 'react';
import lightModeLogo from '@/assets/brand/qor-chat-logo-for-light-mode.jpg';
import darkModeLogo from '@/assets/brand/qor-chat-logo-for-dark-mode.jpg';
import { cn } from '@/lib/utils/shared-utils';

interface QorBrandLogoProps {
  readonly className?: string;
  readonly imageClassName?: string;
  readonly ariaHidden?: boolean;
  readonly label?: string;
}

export function QorBrandLogo({
  className,
  imageClassName,
  ariaHidden = true,
  label = 'Qor Chat',
}: QorBrandLogoProps) {
  return (
    <span
      className={cn('qor-brand-logo-switcher', className)}
      aria-hidden={ariaHidden}
      aria-label={ariaHidden ? undefined : label}
      role={ariaHidden ? undefined : 'img'}
    >
      <img
        className={cn('qor-brand-logo-img qor-brand-logo-for-light-mode', imageClassName)}
        src={lightModeLogo}
        alt=""
        draggable={false}
      />
      <img
        className={cn('qor-brand-logo-img qor-brand-logo-for-dark-mode', imageClassName)}
        src={darkModeLogo}
        alt=""
        draggable={false}
      />
    </span>
  );
}
