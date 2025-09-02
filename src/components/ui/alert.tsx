import * as React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: string[]) {
  return twMerge(clsx(inputs));
}

const variantClasses = {
  default: 'bg-gray-100 text-gray-800',
  destructive: 'bg-red-100 text-red-800',
};

interface AlertProps {
  variant?: keyof typeof variantClasses;
  children: React.ReactNode;
  className?: string;
}

export function Alert({ variant = 'default', children, className = '' }: AlertProps) {
  return (
    <div className={cn('p-4 rounded-md', variantClasses[variant], className)}>
      {children}
    </div>
  );
}

interface AlertDescriptionProps {
  children: React.ReactNode;
  className?: string;
}

export function AlertDescription({ children, className = '' }: AlertDescriptionProps) {
  return <p className={cn('text-sm', className)}>{children}</p>;
}