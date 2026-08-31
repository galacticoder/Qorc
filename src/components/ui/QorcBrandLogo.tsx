import lightModeLogo from '@/assets/brand/qorc-logo-for-light-mode.jpg';
import darkModeLogo from '@/assets/brand/qorc-logo-for-dark-mode.jpg';
import { cn } from '@/lib/utils/shared-utils';

interface QorcBrandLogoProps {
  readonly className?: string;
  readonly imageClassName?: string;
  readonly ariaHidden?: boolean;
  readonly label?: string;
}

export function QorcBrandLogo({
  className,
  imageClassName,
  ariaHidden = true,
  label = 'qorc',
}: QorcBrandLogoProps) {
  return (
    <span
      className={cn('qorc-brand-logo-switcher', className)}
      aria-hidden={ariaHidden}
      aria-label={ariaHidden ? undefined : label}
      role={ariaHidden ? undefined : 'img'}
    >
      <img
        className={cn('qorc-brand-logo-img qorc-brand-logo-for-light-mode', imageClassName)}
        src={lightModeLogo}
        alt=""
        draggable={false}
      />
      <img
        className={cn('qorc-brand-logo-img qorc-brand-logo-for-dark-mode', imageClassName)}
        src={darkModeLogo}
        alt=""
        draggable={false}
      />
    </span>
  );
}
