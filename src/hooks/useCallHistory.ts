/**
 * React Hook for Call History Management
 */

import { useState, useEffect, useCallback } from 'react';
import { CallState } from '../lib/webrtc-calling';

const CALL_HISTORY_KEY = 'secure-chat-call-history';
const MAX_HISTORY_ITEMS = 100;

export const useCallHistory = () => {
  const [callHistory, setCallHistory] = useState<CallState[]>([]);

  // Load call history from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(CALL_HISTORY_KEY);
      if (stored) {
        const history = JSON.parse(stored) as CallState[];
        setCallHistory(history.slice(0, MAX_HISTORY_ITEMS));
      }
    } catch (error) {
      console.error('[CallHistory] Failed to load call history:', error);
    }
  }, []);

  // Save call history to localStorage
  const saveCallHistory = useCallback((history: CallState[]) => {
    try {
      const trimmedHistory = history.slice(0, MAX_HISTORY_ITEMS);
      localStorage.setItem(CALL_HISTORY_KEY, JSON.stringify(trimmedHistory));
      setCallHistory(trimmedHistory);
    } catch (error) {
      console.error('[CallHistory] Failed to save call history:', error);
    }
  }, []);

  // Add a call to history
  const addCallToHistory = useCallback((call: CallState) => {
    if (call.status === 'ended' || call.status === 'missed' || call.status === 'declined') {
      setCallHistory(prev => {
        // Remove any existing entry for this call ID
        const filtered = prev.filter(c => c.id !== call.id);
        // Add the new call at the beginning
        const newHistory = [call, ...filtered];
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
  const clearCallHistory = useCallback(() => {
    try {
      localStorage.removeItem(CALL_HISTORY_KEY);
      setCallHistory([]);
    } catch (error) {
      console.error('[CallHistory] Failed to clear call history:', error);
    }
  }, []);

  // Get calls for a specific user
  const getCallsWithUser = useCallback((username: string) => {
    return callHistory.filter(call => call.peer === username);
  }, [callHistory]);

  // Get recent calls (last 24 hours)
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
    getMissedCallsCount
  };
};