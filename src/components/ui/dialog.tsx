import React, { createContext, useContext, useState, ReactNode } from 'react';

interface DialogContextType {
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
}

const DialogContext = createContext<DialogContextType | undefined>(undefined);

interface DialogProps {
  children: ReactNode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

import { createPortal } from 'react-dom';
import { cn } from '@/lib/utils';

export const Dialog: React.FC<DialogProps> = ({ children, open, onOpenChange }) => {
  const [internalOpen, setInternalOpen] = useState(false);

  const isOpen = open !== undefined ? open : internalOpen;
  const setIsOpen = onOpenChange || setInternalOpen;

  return (
    <DialogContext.Provider value={{ isOpen, setIsOpen }}>
      {children}
    </DialogContext.Provider>
  );
};

export const DialogTrigger: React.FC<{ children: ReactNode; asChild?: boolean }> = ({
  children,
  asChild = false
}) => {
  const context = useContext(DialogContext);
  if (!context) throw new Error('DialogTrigger must be used within Dialog');

  if (asChild && React.isValidElement(children)) {
    return React.cloneElement(children, {
      onClick: (e: React.MouseEvent) => {
        children.props.onClick?.(e);
        context.setIsOpen(true);
      }
    } as any);
  }

  return (
    <button onClick={() => context.setIsOpen(true)}>
      {children}
    </button>
  );
};

export const DialogContent: React.FC<{ children: ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>> = ({ children, className, ...props }) => {
  const context = useContext(DialogContext);
  if (!context) throw new Error('DialogContent must be used within Dialog');

  if (!context.isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="fixed inset-0 bg-black/50"
        onClick={() => context.setIsOpen(false)}
      />
      <div
        className={cn("relative rounded-lg shadow-lg max-w-md w-full mx-4 p-6", className)}
        style={{ backgroundColor: 'var(--color-background)', color: 'var(--color-text-primary)' }}
        {...props}
      >
        {children}
      </div>
    </div>,
    document.body
  );
};

export const DialogHeader: React.FC<{ children: ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>> = ({ children, className, ...props }) => (
  <div className={cn("mb-4", className)} {...props}>
    {children}
  </div>
);

export const DialogTitle: React.FC<{ children: ReactNode; className?: string } & React.HTMLAttributes<HTMLHeadingElement>> = ({ children, className, ...props }) => (
  <h2
    className={cn("text-lg font-semibold", className)}
    style={{ color: 'var(--color-text-primary)' }}
    {...props}
  >
    {children}
  </h2>
);

export const DialogDescription: React.FC<{ children: ReactNode; className?: string } & React.HTMLAttributes<HTMLParagraphElement>> = ({ children, className, ...props }) => (
  <p
    className={cn("text-sm mt-2", className)}
    style={{ color: 'var(--color-text-secondary)' }}
    {...props}
  >
    {children}
  </p>
);

export const DialogFooter: React.FC<{ children: ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>> = ({ children, className, ...props }) => (
  <div className={cn("flex justify-end gap-2 mt-6", className)} {...props}>
    {children}
  </div>
);
