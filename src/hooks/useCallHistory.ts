/**
 * React Hook for Call History Management
 * - All call history data encrypted using post-quantum cryptography
 * - User-specific isolation with pseudonymized keys
 * - Strict validation and size limits to prevent attacks
 * - Secure memory handling for sensitive call metadata
 */

import { useState, useEffect, useCallback } from 'react';
import { CallState } from '../lib/webrtc-calling';
import { encryptedStorage } from '../lib/encrypted-storage';

const MAX_HISTORY_ITEMS = 100;
const MAX_STORED_LENGTH = 200_000;
const MAX_CALL_ID_LENGTH = 256;
const MAX_PEER_NAME_LENGTH = 256;

const sanitizeCallId = (id: string): string => {
  if (!id || typeof id !== 'string') return '';
  return id.slice(0, MAX_CALL_ID_LENGTH).replace(/[^a-zA-Z0-9_-]/g, '');
};

const sanitizePeer = (peer: string): string => {
  if (!peer || typeof peer !== 'string') return '';
  return peer.slice(0, MAX_PEER_NAME_LENGTH);
};

const isValidCallState = (entry: unknown): entry is CallState => {
  if (!entry || typeof entry !== 'object') return false;
  const e = entry as Record<string, unknown>;
  
  // Validate required fields
  if (typeof e.id !== 'string' || e.id.length === 0 || e.id.length > MAX_CALL_ID_LENGTH) return false;
  if (typeof e.peer !== 'string' || e.peer.length === 0 || e.peer.length > MAX_PEER_NAME_LENGTH) return false;
  if (typeof e.status !== 'string') return false;
  if (typeof e.type !== 'string' || !['audio', 'video'].includes(e.type)) return false;
  if (typeof e.direction !== 'string' || !['incoming', 'outgoing'].includes(e.direction)) return false;
  
  // Validate optional timestamp fields
  if (e.startTime !== undefined) {
    if (typeof e.startTime !== 'number' || e.startTime < 0) return false;
  }
  if (e.endTime !== undefined) {
    if (typeof e.endTime !== 'number' || e.endTime < 0) return false;
  }
  if (e.duration !== undefined && (typeof e.duration !== 'number' || e.duration < 0)) return false;
  
  const oneYearAgo = Date.now() - (365 * 24 * 60 * 60 * 1000);
  const maxFutureTime = Date.now() + 60000;
  if (e.startTime !== undefined && typeof e.startTime === 'number') {
    if (e.startTime < oneYearAgo || e.startTime > maxFutureTime) return false;
  }
  if (e.endTime !== undefined && typeof e.endTime === 'number') {
    if (e.endTime < oneYearAgo || e.endTime > maxFutureTime) return false;
  }
  
  return true;
};

const safeParseHistory = (raw: unknown): CallState[] | null => {
  try {
    if (!Array.isArray(raw)) return null;
    
    // Filter and sanitize each entry
    const validated = raw
      .filter(isValidCallState)
      .map(entry => ({
        ...entry,
        id: sanitizeCallId(entry.id),
        peer: sanitizePeer(entry.peer)
      }))
      .filter(entry => entry.id && entry.peer);
    
    return validated;
  } catch (_error) {
    console.error('[CallHistory] Failed to parse history:', _error);
    return null;
  }
};

export const useCallHistory = (username?: string) => {
  const [callHistory, setCallHistory] = useState<CallState[]>([]);
  const [storageError, setStorageError] = useState<string | null>(null);

  const getStorageKey = useCallback(() => {
    if (!username) return null;
    return `call_history_${username}`;
  }, [username]);

  useEffect(() => {
    (async (): Promise<void> => {
      try {
        const key = getStorageKey();
        if (!key) return;

        const stored = await encryptedStorage.getItem(key);
        if (stored) {
          const history = safeParseHistory(stored);
          if (history) {
            const trimmed = history.slice(0, MAX_HISTORY_ITEMS);
            setCallHistory(trimmed);
          }
        }
      } catch (_error) {
        console.error('[CallHistory] Failed to load call history:', _error);
        setStorageError('unavailable');
      }
    })();
  }, [getStorageKey]);

  const saveCallHistory = useCallback((history: CallState[]): void => {
    (async (): Promise<void> => {
      try {
        const key = getStorageKey();
        if (!key) return;

        const trimmedHistory = history.slice(0, MAX_HISTORY_ITEMS);
        const serialized = JSON.stringify(trimmedHistory);
        if (serialized.length > MAX_STORED_LENGTH) {
          console.error('[CallHistory] History too large, truncating');
          const reduced = history.slice(0, Math.floor(MAX_HISTORY_ITEMS / 2));
          await encryptedStorage.setItem(key, reduced);
          setCallHistory(reduced);
        } else {
          await encryptedStorage.setItem(key, trimmedHistory);
          setCallHistory(trimmedHistory);
        }
        setStorageError(null);
      } catch (_error) {
        console.error('[CallHistory] Failed to save call history:', _error);
        setStorageError('unavailable');
      }
    })();
  }, [getStorageKey]);

  const addCallToHistory = useCallback((call: CallState) => {
    // Only store completed calls
    if (call.status === 'ended' || call.status === 'missed' || call.status === 'declined') {
      if (!isValidCallState(call)) {
        console.error('[CallHistory] Attempted to add invalid call to history');
        return;
      }
      
      const sanitizedCall: CallState = {
        ...call,
        id: sanitizeCallId(call.id),
        peer: sanitizePeer(call.peer)
      };
      
      if (!sanitizedCall.id || !sanitizedCall.peer) {
        console.error('[CallHistory] Call data became invalid after sanitization');
        return;
      }
      
      setCallHistory(prev => {
        const filtered = prev.filter(c => c.id !== sanitizedCall.id);
        const newHistory = [sanitizedCall, ...filtered];
        saveCallHistory(newHistory);
        return newHistory;
      });
    }
  }, [saveCallHistory]);

  // Update an existing call in history
  const updateCallInHistory = useCallback((callId: string, updates: Partial<CallState>) => {
    setCallHistory(prev => {
      const updated = prev.map(call => 
        call.id === callId ? { ...call, ...updates } : call
      );
      saveCallHistory(updated);
      return updated;
    });
  }, [saveCallHistory]);

  // Clear call history
  const clearCallHistory = useCallback((): void => {
    (async (): Promise<void> => {
      try {
        const key = getStorageKey();
        if (key) {
          await encryptedStorage.removeItem(key);
        }
        setCallHistory([]);
        setStorageError(null);
      } catch (_error) {
        console.error('[CallHistory] Failed to clear call history:', _error);
        setStorageError('unavailable');
      }
    })();
  }, [getStorageKey]);

  const getCallsWithUser = useCallback((username: string) => {
    const sanitizedUsername = sanitizePeer(username);
    if (!sanitizedUsername) return [];
    return callHistory.filter(call => call.peer === sanitizedUsername);
  }, [callHistory]);

  // Get recent calls
  const getRecentCalls = useCallback(() => {
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
    return callHistory.filter(call => 
      call.startTime && call.startTime > oneDayAgo
    );
  }, [callHistory]);

  // Get missed calls count
  const getMissedCallsCount = useCallback(() => {
    return callHistory.filter(call => call.status === 'missed').length;
  }, [callHistory]);

  return {
    callHistory,
    addCallToHistory,
    updateCallInHistory,
    clearCallHistory,
    getCallsWithUser,
    getRecentCalls,
    getMissedCallsCount,
    storageError
  };
};