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

export const Dialog: React.FC<DialogProps> = ({ children, open, onOpenChange }) => {
  const [internalOpen, setInternalOpen] = useState(false);
  
  const isOpen = open !== undefined ? open : internalOpen;
  const setIsOpen = onOpenChange || setInternalOpen;

  return (
    <DialogContext.Provider value={{ isOpen, setIsOpen }}>
      {children}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div 
            className="fixed inset-0 bg-black/50" 
            onClick={() => setIsOpen(false)}
          />
          <div className="relative bg-white rounded-lg shadow-lg max-w-md w-full mx-4">
            {children}
          </div>
        </div>
      )}
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
      onClick: () => context.setIsOpen(true)
    });
  }
  
  return (
    <button onClick={() => context.setIsOpen(true)}>
      {children}
    </button>
  );
};

export const DialogContent: React.FC<{ children: ReactNode }> = ({ children }) => {
  const context = useContext(DialogContext);
  if (!context) throw new Error('DialogContent must be used within Dialog');
  
  if (!context.isOpen) return null;
  
  return (
    <div className="p-6">
      {children}
    </div>
  );
};

export const DialogHeader: React.FC<{ children: ReactNode }> = ({ children }) => (
  <div className="mb-4">
    {children}
  </div>
);

export const DialogTitle: React.FC<{ children: ReactNode }> = ({ children }) => (
  <h2 className="text-lg font-semibold text-gray-900">
    {children}
  </h2>
);

export const DialogDescription: React.FC<{ children: ReactNode }> = ({ children }) => (
  <p className="text-sm text-gray-600 mt-2">
    {children}
  </p>
);

export const DialogFooter: React.FC<{ children: ReactNode }> = ({ children }) => (
  <div className="flex justify-end gap-2 mt-6">
    {children}
  </div>
);
