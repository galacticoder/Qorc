import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { syncEncryptedStorage } from '../lib/database/encrypted-storage';
import { STORAGE_KEYS } from '../lib/database/storage-keys';
import { isValidCallingUsername } from '../lib/utils/calling-utils';

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
const MAX_CALL_HISTORY_ENTRIES = 500;
const MAX_CALL_DURATION_SECONDS = 30 * 24 * 60 * 60;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isValidCallLogEntry(value: unknown): value is CallLogEntry {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
        return false;
    }
    const entry = value as Record<string, unknown>;
    const keys = Object.keys(entry).sort().join(',');
    if (keys !== 'direction,id,peerUsername,startTime,status,type' &&
        keys !== 'direction,duration,id,peerUsername,startTime,status,type') {
        return false;
    }
    return typeof entry.id === 'string' && UUID_RE.test(entry.id) &&
        typeof entry.peerUsername === 'string' &&
        entry.peerUsername === entry.peerUsername.trim().toLowerCase() &&
        isValidCallingUsername(entry.peerUsername) &&
        (entry.type === 'audio' || entry.type === 'video') &&
        (entry.direction === 'incoming' || entry.direction === 'outgoing') &&
        (entry.status === 'missed' || entry.status === 'completed' || entry.status === 'declined') &&
        Number.isSafeInteger(entry.startTime) &&
        (entry.startTime as number) >= 0 &&
        (entry.startTime as number) <= Date.now() + 5 * 60 * 1000 &&
        (entry.duration === undefined || (
            Number.isSafeInteger(entry.duration) &&
            (entry.duration as number) >= 0 &&
            (entry.duration as number) <= MAX_CALL_DURATION_SECONDS
        ));
}

function parseCallHistory(raw: string | null): CallLogEntry[] {
    if (raw === null) return [];
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value) || value.length > MAX_CALL_HISTORY_ENTRIES || !value.every(isValidCallLogEntry)) {
        throw new Error('Invalid call history');
    }
    return value;
}

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

        const loadForCurrentAccount = () => {
            try {
                const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.CALL_HISTORY);
                setLogs(parseCallHistory(stored));
            } catch {
                setLogs([]);
            }
        };

        const init = async () => {
            try {
                await syncEncryptedStorage.waitForInitialization();
                if (!mounted) return;
                loadForCurrentAccount();
            } catch {
            } finally {
                if (mounted) {
                    setIsLoading(false);
                }
            }
        };

        void init();
        const unsubscribe = syncEncryptedStorage.subscribe(() => {
            if (mounted) loadForCurrentAccount();
        });
        return () => { mounted = false; unsubscribe(); };
    }, []);

    const saveLogs = useCallback((newLogs: CallLogEntry[]) => {
        try {
            syncEncryptedStorage.setItem(
                STORAGE_KEYS.CALL_HISTORY,
                JSON.stringify(newLogs.slice(0, MAX_CALL_HISTORY_ENTRIES))
            );
        } catch {
        }
    }, []);

    const addCallLog = useCallback((entry: Omit<CallLogEntry, 'id'>) => {
        const newEntry: CallLogEntry = {
            ...entry,
            id: crypto.randomUUID(),
        };
        if (!isValidCallLogEntry(newEntry)) return;
        setLogs(prev => {
            const updated = [newEntry, ...prev].slice(0, MAX_CALL_HISTORY_ENTRIES);
            saveLogs(updated);
            return updated;
        });
    }, [saveLogs]);

    const deleteLog = useCallback((id: string) => {
        if (!UUID_RE.test(id)) return;
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
