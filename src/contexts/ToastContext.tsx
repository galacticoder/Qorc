import React, { createContext, useContext, useRef, ReactNode } from 'react';
import type { Toast } from 'primereact/toast';

interface ToastContextType {
    toastRef: React.RefObject<Toast>;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
    const toastRef = useRef<Toast>(null);

    return (
        <ToastContext.Provider value={{ toastRef }}>
            {children}
        </ToastContext.Provider>
    );
}

export function useToastContext() {
    const context = useContext(ToastContext);
    if (!context) {
        throw new Error('useToastContext must be used within ToastProvider');
    }
    return context;
}
