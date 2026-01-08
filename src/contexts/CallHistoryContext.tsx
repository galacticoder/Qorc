import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { syncEncryptedStorage } from '../lib/database/encrypted-storage';
import { STORAGE_KEYS } from '../lib/database/storage-keys';

export interface CallLogEntry {
    id: string;
    peerUsername: string;
    type: 'audio' | 'video';
    direction: 'incoming' | 'outgoing';
    status: 'missed' | 'completed' | 'declined';
    startTime: number;
    duration?: number;
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

export const CallHistoryProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [logs, setLogs] = useState<CallLogEntry[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        let mounted = true;

        const init = async () => {
            try {
                await syncEncryptedStorage.waitForInitialization();
                if (!mounted) return;

                const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.CALL_HISTORY);
                if (stored) {
                    const parsed = JSON.parse(stored);
                    if (Array.isArray(parsed)) {
                        setLogs(parsed);
                    }
                }
            } catch (error) {
                console.error('Failed to load call history:', error);
            } finally {
                if (mounted) {
                    setIsLoading(false);
                }
            }
        };

        void init();
        return () => { mounted = false; };
    }, []);

    const saveLogs = useCallback((newLogs: CallLogEntry[]) => {
        try {
            syncEncryptedStorage.setItem(STORAGE_KEYS.CALL_HISTORY, JSON.stringify(newLogs));
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
