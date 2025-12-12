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
  const [isAnimatingOut, setIsAnimatingOut] = React.useState(false);
  const [isVisible, setIsVisible] = React.useState(false);

  if (!context) throw new Error('DialogContent must be used within Dialog');

  const handleClose = React.useCallback(() => {
    // Just trigger close, the effect handles the animation
    context.setIsOpen(false);
  }, [context]);

  React.useEffect(() => {
    if (context.isOpen) {
      setIsVisible(true);
      setIsAnimatingOut(false);
    } else if (isVisible) {
      setIsAnimatingOut(true);
      const timer = setTimeout(() => {
        setIsVisible(false);
        setIsAnimatingOut(false);
      }, 200);
      return () => clearTimeout(timer);
    }
  }, [context.isOpen, isVisible]);

  if (!isVisible) return null;

  return createPortal(
    <>
      <style>{`
        @keyframes dialogOverlayShow {
          from {
            opacity: 0;
          }
          to {
            opacity: 1;
          }
        }
        
        @keyframes dialogOverlayHide {
          from {
            opacity: 1;
          }
          to {
            opacity: 0;
          }
        }
        
        @keyframes dialogContentShow {
          from {
            opacity: 0;
            transform: scale(0.96);
          }
          to {
            opacity: 1;
            transform: scale(1);
          }
        }
        
        @keyframes dialogContentHide {
          from {
            opacity: 1;
            transform: scale(1);
          }
          to {
            opacity: 0;
            transform: scale(0.96);
          }
        }
        
        .dialog-overlay {
          animation: dialogOverlayShow 200ms cubic-bezier(0.16, 1, 0.3, 1);
        }
        
        .dialog-overlay.closing {
          animation: dialogOverlayHide 200ms cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        
        .dialog-content {
          animation: dialogContentShow 200ms cubic-bezier(0.16, 1, 0.3, 1);
        }
        
        .dialog-content.closing {
          animation: dialogContentHide 200ms cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
      `}</style>
      <div className="fixed inset-0 z-50 flex items-center justify-center">
        <div
          className={`dialog-overlay fixed inset-0 bg-black/50 ${isAnimatingOut ? 'closing' : ''}`}
          onClick={handleClose}
        />
        <div
          className={cn(
            "dialog-content relative rounded-lg shadow-lg max-w-md w-full mx-4 p-6 select-none",
            isAnimatingOut ? 'closing' : '',
            className
          )}
          style={{
            backgroundColor: 'hsl(var(--card))',
            color: 'hsl(var(--card-foreground))',
            ...props.style
          }}
          onClick={(e) => e.stopPropagation()}
          {...props}
        >
          {children}
        </div>
      </div>
    </>,
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
    style={{ color: 'hsl(var(--card-foreground))' }}
    {...props}
  >
    {children}
  </h2>
);

export const DialogDescription: React.FC<{ children: ReactNode; className?: string } & React.HTMLAttributes<HTMLParagraphElement>> = ({ children, className, ...props }) => (
  <p
    className={cn("text-sm mt-2", className)}
    style={{ color: 'hsl(var(--muted-foreground))' }}
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
