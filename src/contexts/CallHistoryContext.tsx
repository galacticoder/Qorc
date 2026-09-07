import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { syncEncryptedStorage } from '../lib/database/encrypted-storage';
import { STORAGE_KEYS } from '../lib/database/storage-keys';
import { isValidCallingUsername } from '../lib/utils/calling-utils';
import { CALL_LOG_SEGMENT_SIZE, SEGMENT_UNLOAD_IDLE_MS } from '../lib/constants';

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
    hasMoreLogs: boolean;
    loadMoreLogs: () => void;
    scheduleLogRelease: () => void;
    cancelLogRelease: () => void;
    getAllLogs: () => CallLogEntry[];
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

function readStoredLogs(): CallLogEntry[] {
    return parseCallHistory(syncEncryptedStorage.getItem(STORAGE_KEYS.CALL_HISTORY));
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
    const [totalLogCount, setTotalLogCount] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const loadedCountRef = useRef(0);
    const releaseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    const applyPage = useCallback((all: CallLogEntry[], requestedCount: number) => {
        const size = Math.min(Math.max(requestedCount, CALL_LOG_SEGMENT_SIZE), all.length);
        loadedCountRef.current = size;
        setLogs(all.slice(0, size));
        setTotalLogCount(all.length);
    }, []);

    const cancelLogRelease = useCallback(() => {
        if (releaseTimerRef.current === null) return;
        clearTimeout(releaseTimerRef.current);
        releaseTimerRef.current = null;
    }, []);

    const releaseExtraLogs = useCallback(() => {
        if (loadedCountRef.current <= CALL_LOG_SEGMENT_SIZE) return;
        loadedCountRef.current = CALL_LOG_SEGMENT_SIZE;
        setLogs(prev => (prev.length <= CALL_LOG_SEGMENT_SIZE ? prev : prev.slice(0, CALL_LOG_SEGMENT_SIZE)));
    }, []);

    const scheduleLogRelease = useCallback(() => {
        if (releaseTimerRef.current !== null) return;
        if (loadedCountRef.current <= CALL_LOG_SEGMENT_SIZE) return;
        releaseTimerRef.current = setTimeout(() => {
            releaseTimerRef.current = null;
            releaseExtraLogs();
        }, SEGMENT_UNLOAD_IDLE_MS);
    }, [releaseExtraLogs]);

    const loadMoreLogs = useCallback(() => {
        cancelLogRelease();
        const all = readStoredLogs();
        if (loadedCountRef.current >= all.length) {
            setTotalLogCount(all.length);
            return;
        }
        applyPage(all, loadedCountRef.current + CALL_LOG_SEGMENT_SIZE);
    }, [applyPage, cancelLogRelease]);

    const getAllLogs = useCallback(() => readStoredLogs(), []);

    useEffect(() => {
        let mounted = true;

        const syncFromStorage = () => {
            applyPage(readStoredLogs(), loadedCountRef.current || CALL_LOG_SEGMENT_SIZE);
        };

        const init = async () => {
            try {
                await syncEncryptedStorage.waitForInitialization();
                if (!mounted) return;
                syncFromStorage();
            } catch (error) {
                console.error('[CallHistory] Failed to initialize call history', error);
            } finally {
                if (mounted) {
                    setIsLoading(false);
                }
            }
        };

        void init();
        const unsubscribe = syncEncryptedStorage.subscribe(() => {
            if (mounted) syncFromStorage();
        });
        return () => { mounted = false; unsubscribe(); };
    }, [applyPage]);

    useEffect(() => () => {
        if (releaseTimerRef.current !== null) clearTimeout(releaseTimerRef.current);
        releaseTimerRef.current = null;
    }, []);

    const saveLogs = useCallback((newLogs: CallLogEntry[]) => {
        syncEncryptedStorage.setItem(
            STORAGE_KEYS.CALL_HISTORY,
            JSON.stringify(newLogs.slice(0, MAX_CALL_HISTORY_ENTRIES))
        );
    }, []);

    const addCallLog = useCallback((entry: Omit<CallLogEntry, 'id'>) => {
        const newEntry: CallLogEntry = {
            ...entry,
            id: crypto.randomUUID(),
        };
        if (!isValidCallLogEntry(newEntry)) return;
        const updated = [newEntry, ...readStoredLogs()].slice(0, MAX_CALL_HISTORY_ENTRIES);
        saveLogs(updated);
        applyPage(updated, loadedCountRef.current + 1);
    }, [saveLogs, applyPage]);

    const deleteLog = useCallback((id: string) => {
        if (!UUID_RE.test(id)) return;
        const updated = readStoredLogs().filter(log => log.id !== id);
        saveLogs(updated);
        applyPage(updated, loadedCountRef.current);
    }, [saveLogs, applyPage]);

    const clearLogs = useCallback(() => {
        cancelLogRelease();
        loadedCountRef.current = 0;
        setLogs([]);
        setTotalLogCount(0);
        saveLogs([]);
    }, [saveLogs, cancelLogRelease]);

    return (
        <CallHistoryContext.Provider
            value={{
                logs,
                hasMoreLogs: logs.length < totalLogCount,
                loadMoreLogs,
                scheduleLogRelease,
                cancelLogRelease,
                getAllLogs,
                addCallLog,
                deleteLog,
                clearLogs,
                isLoading,
            }}
        >
            {children}
        </CallHistoryContext.Provider>
    );
};
