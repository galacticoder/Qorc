import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { syncEncryptedStorage } from '@/lib/encrypted-storage';

export interface CallLogEntry {
    id: string;
    peerUsername: string;
    type: 'audio' | 'video';
    direction: 'incoming' | 'outgoing';
    status: 'missed' | 'completed' | 'declined';
    startTime: number;
    duration?: number; // in seconds
}

interface CallHistoryContextType {
    logs: CallLogEntry[];
    addCallLog: (entry: Omit<CallLogEntry, 'id'>) => void;
    deleteLog: (id: string) => void;
    clearLogs: () => void;
    isLoading: boolean;
}

const CallHistoryContext = createContext<CallHistoryContextType | undefined>(undefined);

export const useCallHistory = () => {
    const context = useContext(CallHistoryContext);
    if (!context) {
        throw new Error('useCallHistory must be used within a CallHistoryProvider');
    }
    return context;
};

const STORAGE_KEY = 'call_history_v1';

export const CallHistoryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [logs, setLogs] = useState<CallLogEntry[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    // Load logs on mount
    useEffect(() => {
        const loadLogs = () => {
            try {
                const stored = syncEncryptedStorage.getItem(STORAGE_KEY);
                if (stored) {
                    const parsed = JSON.parse(stored);
                    if (Array.isArray(parsed)) {
                        setLogs(parsed);
                    }
                }
            } catch (error) {
                console.error('Failed to load call history:', error);
            } finally {
                setIsLoading(false);
            }
        };

        // Check if storage is ready, otherwise poll briefly or wait for event
        // Since syncEncryptedStorage depends on SecureDB, it might not be ready immediately.
        // We can retry a few times.
        let retries = 0;
        const checkStorage = setInterval(() => {
            const stored = syncEncryptedStorage.getItem(STORAGE_KEY);
            if (stored !== null || retries > 10) {
                loadLogs();
                clearInterval(checkStorage);
            }
            retries++;
        }, 500);

        return () => clearInterval(checkStorage);
    }, []);

    const saveLogs = useCallback((newLogs: CallLogEntry[]) => {
        try {
            syncEncryptedStorage.setItem(STORAGE_KEY, JSON.stringify(newLogs));
        } catch (error) {
            console.error('Failed to save call history:', error);
        }
    }, []);

    const addCallLog = useCallback((entry: Omit<CallLogEntry, 'id'>) => {
        const newEntry: CallLogEntry = {
            ...entry,
            id: crypto.randomUUID(),
        };
        setLogs(prev => {
            const updated = [newEntry, ...prev];
            saveLogs(updated);
            return updated;
        });
    }, [saveLogs]);

    const deleteLog = useCallback((id: string) => {
        setLogs(prev => {
            const updated = prev.filter(log => log.id !== id);
            saveLogs(updated);
            return updated;
        });
    }, [saveLogs]);

    const clearLogs = useCallback(() => {
        setLogs([]);
        saveLogs([]);
    }, [saveLogs]);

    return (
        <CallHistoryContext.Provider value={{ logs, addCallLog, deleteLog, clearLogs, isLoading }}>
            {children}
        </CallHistoryContext.Provider>
    );
};
