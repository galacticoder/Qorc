/**
 * React Hook for WebRTC Calling Integration
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { WebRTCCallingService, CallState } from '../lib/webrtc-calling';
import type { useAuth } from './useAuth';

const stopMediaStream = (stream: MediaStream | null) => {
  if (!stream) return;

  try {
    const seen = new Set<string>();
    const tracks = typeof stream.getTracks === 'function' ? stream.getTracks() : [];
    tracks.forEach((track) => {
      if (!track || seen.has(track.id)) {
        return;
      }
      seen.add(track.id);
      try {
        if (track.readyState !== 'ended') {
          track.stop();
        }
      } catch { }
    });
  } catch { }
};

const MAX_USERNAME_LENGTH = 120;
const MAX_CALL_ID_LENGTH = 256;

const EVENT_ALLOWED_PAYLOAD_KEYS = new Set(['type', 'peer', 'at', 'callId', 'status', 'startTime', 'endTime', 'durationMs', 'direction', 'isVideo', 'isOutgoing']);

const isValidUsername = (username: string): boolean => {
  if (!username || typeof username !== 'string') return false;
  if (username.length === 0 || username.length > MAX_USERNAME_LENGTH) return false;
  return /^[a-zA-Z0-9._-]+$/.test(username);
};

const isValidCallId = (callId: string): boolean => {
  if (!callId || typeof callId !== 'string') return false;
  if (callId.length === 0 || callId.length > MAX_CALL_ID_LENGTH) return false;
  return /^[a-zA-Z0-9_-]+$/.test(callId);
};

const sanitizeEventDetail = (detail: any): Record<string, unknown> => {
  if (!detail || typeof detail !== 'object') {
    return {};
  }

  const sanitized: Record<string, unknown> = {};
  for (const key of EVENT_ALLOWED_PAYLOAD_KEYS) {
    if (!(key in detail)) {
      continue;
    }
    const value = detail[key];
    if (value === null || value === undefined) {
      continue;
    }
    if (typeof value === 'string') {
      const trimmed = value.slice(0, 256);
      if (key === 'peer' && !isValidUsername(trimmed)) continue;
      if (key === 'callId' && !isValidCallId(trimmed)) continue;
      sanitized[key] = trimmed;
    } else if (typeof value === 'number') {
      if (!Number.isFinite(value)) continue;
      if ((key === 'at' || key === 'startTime' || key === 'endTime' || key === 'durationMs') && value < 0) continue;
      sanitized[key] = value;
    } else if (typeof value === 'boolean') {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

const debounceEventDispatcher = () => {
  const queue = new Map<string, { detail: any; timestamp: number }>();
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let pendingAnimationFrame: number | null = null;

  const flush = () => {
    timeoutId = null;
    if (pendingAnimationFrame !== null) {
      cancelAnimationFrame(pendingAnimationFrame);
      pendingAnimationFrame = null;
    }

    const now = Date.now();
    const entries = Array.from(queue.entries());
    queue.clear();

    pendingAnimationFrame = requestAnimationFrame(() => {
      pendingAnimationFrame = null;
      entries.forEach(([name, { detail, timestamp }]) => {
        if (now - timestamp > 1000) {
          return;
        }
        try {
          window.dispatchEvent(new CustomEvent(name, { detail: sanitizeEventDetail(detail) }));
        } catch { }
      });
    });
  };

  const enqueue = (name: string, detail: any, immediate = false) => {
    if (immediate) {
      try {
        window.dispatchEvent(new CustomEvent(name, { detail: sanitizeEventDetail(detail) }));
      } catch { }
      return;
    }

    queue.set(name, { detail: sanitizeEventDetail(detail), timestamp: Date.now() });
    if (timeoutId === null) {
      timeoutId = setTimeout(flush, 20);
    }
  };

  const cancel = () => {
    if (timeoutId !== null) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
    if (pendingAnimationFrame !== null) {
      cancelAnimationFrame(pendingAnimationFrame);
      pendingAnimationFrame = null;
    }
    queue.clear();
  };

  return { enqueue, cancel };
};

export const useCalling = (authContext: ReturnType<typeof useAuth>) => {
  if (!authContext) {
    throw new Error('[useCalling] Auth context is required');
  }

  const eventDebouncer = useRef(debounceEventDispatcher());
  const localStreamRef = useRef<MediaStream | null>(null);
  const remoteStreamRef = useRef<MediaStream | null>(null);
  const remoteScreenStreamRef = useRef<MediaStream | null>(null);

  const hasBeenAuthenticatedRef = useRef(false);
  const authenticatedUsernameRef = useRef<string>('');

  const { username, loginUsernameRef, isLoggedIn, accountAuthenticated } = authContext;

  const [callingService, setCallingService] = useState<WebRTCCallingService | null>(null);
  const [currentCall, setCurrentCall] = useState<CallState | null>(null);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [remoteScreenStream, setRemoteScreenStream] = useState<MediaStream | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);

  const serviceRef = useRef<WebRTCCallingService | null>(null);
  const everConnectedRef = useRef<Set<string>>(new Set());

  const currentUsername = username || loginUsernameRef?.current || '';
  const isFullyAuthenticated = isLoggedIn && accountAuthenticated;

  useEffect(() => {
    return () => {
      eventDebouncer.current.cancel();
      stopMediaStream(localStreamRef.current);
      stopMediaStream(remoteStreamRef.current);
      stopMediaStream(remoteScreenStreamRef.current);
      try { (window as any).edgeApi?.powerSaveBlockerStop?.(); } catch { }
    };
  }, []);

  useEffect(() => {
    if (serviceRef.current) { return; }
    if (!isValidUsername(currentUsername)) { return; }
    if (!isFullyAuthenticated) { return; }
    if (hasBeenAuthenticatedRef.current && !isFullyAuthenticated) { return; }

    const service = new WebRTCCallingService(currentUsername);
    serviceRef.current = service;

    service.onIncomingCall((call) => {
      setCurrentCall({ ...call });
      eventDebouncer.current.enqueue('ui-call-log', { type: 'incoming', peer: call.peer, at: Date.now(), callId: call.id, isVideo: call.type === 'video', isOutgoing: call.direction === 'outgoing' });
    });

    service.onCallStateChange((call) => {
      const statusDetail = {
        peer: call.peer,
        status: call.status,
        type: call.type,
        direction: call.direction,
        startTime: call.startTime,
        endTime: call.endTime
      };
      const statusNeedsImmediateDispatch = call.status === 'ended' || call.status === 'declined' || call.status === 'missed';
      eventDebouncer.current.enqueue(EventType.UI_CALL_STATUS, statusDetail, statusNeedsImmediateDispatch);

      const wasConnected = everConnectedRef.current.has(call.id);

      if (call.status === 'connecting') {
        try { (window as any).edgeApi?.powerSaveBlockerStart?.(); } catch { }
        eventDebouncer.current.enqueue('ui-call-log', { type: 'started', peer: call.peer, at: Date.now(), callId: call.id, isVideo: call.type === 'video', isOutgoing: call.direction === 'outgoing' });
      } else if (call.status === 'connected') {
        try { everConnectedRef.current.add(call.id); } catch { }
        try { (window as any).edgeApi?.powerSaveBlockerStart?.(); } catch { }
        eventDebouncer.current.enqueue('ui-call-log', { type: 'connected', peer: call.peer, at: Date.now(), callId: call.id, isVideo: call.type === 'video', isOutgoing: call.direction === 'outgoing' });
      }
      if (call.status === 'ended' || call.status === 'declined' || call.status === 'missed') {
        try { (window as any).edgeApi?.powerSaveBlockerStop?.(); } catch { }
        if (call.status === 'ended') {
          if (!wasConnected) {
            if (call.direction === 'incoming') {
              eventDebouncer.current.enqueue('ui-call-log', {
                type: 'missed',
                peer: call.peer,
                at: Date.now(),
                callId: call.id,
                isVideo: call.type === 'video',
                isOutgoing: false
              });
            } else {
              eventDebouncer.current.enqueue('ui-call-log', {
                type: 'ended',
                peer: call.peer,
                at: Date.now(),
                callId: call.id,
                durationMs: 0,
                isVideo: call.type === 'video',
                isOutgoing: true
              });
            }
          } else {
            const durationMs = call.startTime && call.endTime ? (call.endTime - call.startTime) : 0;
            eventDebouncer.current.enqueue('ui-call-ended', {
              peer: call.peer,
              type: call.type,
              startTime: call.startTime,
              endTime: call.endTime,
              durationMs
            });
            eventDebouncer.current.enqueue('ui-call-log', { type: 'ended', peer: call.peer, at: Date.now(), callId: call.id, durationMs, isVideo: call.type === 'video', isOutgoing: call.direction === 'outgoing' });
          }
        }
        if (call.status === 'declined') {
          eventDebouncer.current.enqueue('ui-call-log', { type: 'declined', peer: call.peer, at: Date.now(), callId: call.id, isVideo: call.type === 'video', isOutgoing: call.direction === 'outgoing' });
        }
        if (call.status === 'missed') {
          eventDebouncer.current.enqueue('ui-call-log', { type: 'missed', peer: call.peer, at: Date.now(), callId: call.id, isVideo: call.type === 'video', isOutgoing: call.direction === 'outgoing' });
        }
        unstable_batchedUpdates(() => {
          setCurrentCall(null);
          stopMediaStream(localStreamRef.current);
          stopMediaStream(remoteStreamRef.current);
          stopMediaStream(remoteScreenStreamRef.current);
          localStreamRef.current = null;
          remoteStreamRef.current = null;
          remoteScreenStreamRef.current = null;
          setLocalStream(null);
          setRemoteStream(null);
          setRemoteScreenStream(null);
        });
        try { everConnectedRef.current.delete(call.id); } catch { }
      } else {
        unstable_batchedUpdates(() => {
          setCurrentCall({ ...call });
        });
      }
    });

    service.onLocalStream((stream) => {
      stopMediaStream(localStreamRef.current);
      unstable_batchedUpdates(() => {
        localStreamRef.current = stream;
        setLocalStream(stream);
      });
    });

    service.onRemoteStream((stream) => {
      stopMediaStream(remoteStreamRef.current);
      unstable_batchedUpdates(() => {
        remoteStreamRef.current = stream;
        setRemoteStream(stream);
      });
    });

    service.onRemoteScreenStream((stream) => {
      stopMediaStream(remoteScreenStreamRef.current);
      unstable_batchedUpdates(() => {
        remoteScreenStreamRef.current = stream;
        setRemoteScreenStream(stream);
      });
    });

    const initializeService = async (attempt = 0): Promise<void> => {
      try {
        service.initialize();

        hasBeenAuthenticatedRef.current = true;
        authenticatedUsernameRef.current = currentUsername;

        setCallingService(service);
        setIsInitialized(true);
      } catch (_error) {
        if (attempt < 3) {
          const baseDelay = 500;
          const jitterBytes = await import('../lib/post-quantum-crypto').then(m => m.PostQuantumRandom.randomBytes(1));
          const jitter = jitterBytes[0] % 200;
          const delay = Math.min(5000, baseDelay * Math.pow(2, attempt)) + jitter;
          await new Promise((resolve) => setTimeout(resolve, delay));
          await initializeService(attempt + 1);
          return;
        }
        console.error('[useCalling] Failed to initialize calling service:', _error);
        serviceRef.current = null;
        setCallingService(null);
        setCurrentCall(null);
        setLocalStream(null);
        setRemoteStream(null);
        setRemoteScreenStream(null);
        setIsInitialized(false);
        hasBeenAuthenticatedRef.current = false;
        authenticatedUsernameRef.current = '';
      }
    };

    initializeService();

    return () => {
      if (serviceRef.current) {
        serviceRef.current.destroy();
        serviceRef.current = null;
      }
      setCallingService(null);
      setCurrentCall(null);
      stopMediaStream(localStreamRef.current);
      stopMediaStream(remoteStreamRef.current);
      stopMediaStream(remoteScreenStreamRef.current);
      localStreamRef.current = null;
      remoteStreamRef.current = null;
      remoteScreenStreamRef.current = null;
      setLocalStream(null);
      setRemoteStream(null);
      setRemoteScreenStream(null);
      setIsInitialized(false);
    };
  }, [currentUsername, isFullyAuthenticated]);

  const startCall = useCallback(async (targetUser: string, callType: 'audio' | 'video' = 'audio') => {
    if (!serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    const peer = targetUser.trim();
    if (!isValidUsername(peer)) {
      throw new Error('[useCalling] Invalid target username format');
    }

    if (callType !== 'audio' && callType !== 'video') {
      throw new Error('[useCalling] Invalid call type');
    }

    if (peer === currentUsername) {
      throw new Error('[useCalling] Cannot call yourself');
    }

    try {
      const callId = await serviceRef.current.startCall(peer, callType);
      return callId;
    } catch (_error) {
      console.error('[useCalling] Failed to start call:', _error);
      unstable_batchedUpdates(() => {
        setCurrentCall(null);
        stopMediaStream(localStreamRef.current);
        stopMediaStream(remoteStreamRef.current);
        stopMediaStream(remoteScreenStreamRef.current);
        localStreamRef.current = null;
        remoteStreamRef.current = null;
        remoteScreenStreamRef.current = null;
        setLocalStream(null);
        setRemoteStream(null);
        setRemoteScreenStream(null);
      });
      throw _error;
    }
  }, [currentUsername]);

  const answerCall = useCallback(async (callId: string) => {
    if (!serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    if (!isValidCallId(callId)) {
      throw new Error('[useCalling] Invalid call ID format');
    }

    try {
      await serviceRef.current.answerCall(callId);
    } catch (_error) {
      console.error('[useCalling] Failed to answer call:', _error);
      throw _error;
    }
  }, []);

  const declineCall = useCallback(async (callId: string) => {
    if (!serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    if (!isValidCallId(callId)) {
      throw new Error('[useCalling] Invalid call ID format');
    }

    try {
      await serviceRef.current.declineCall(callId);
    } catch (_error) {
      console.error('[useCalling] Failed to decline call:', _error);
      throw _error;
    }
  }, []);

  const endCall = useCallback(async () => {
    if (!serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    try {
      await serviceRef.current.endCall();
    } catch (_error) {
      console.error('[useCalling] Failed to end call:', _error);
      throw _error;
    }
  }, []);

  const toggleMute = useCallback(() => {
    if (!serviceRef.current) {
      return false;
    }

    const isMuted = serviceRef.current.toggleMute();
    return isMuted;
  }, []);

  const toggleVideo = useCallback(async () => {
    if (!serviceRef.current) {
      return false;
    }

    const isEnabled = await serviceRef.current.toggleVideo();
    return isEnabled;
  }, []);

  const switchCamera = useCallback(async (deviceId: string) => {
    if (!serviceRef.current) {
      return;
    }

    try {
      await serviceRef.current.switchCamera(deviceId);
    } catch (_error) {
      console.error('[useCalling] Failed to switch camera:', _error);
    }
  }, []);

  const switchMicrophone = useCallback(async (deviceId: string) => {
    if (!serviceRef.current) {
      return;
    }

    try {
      await serviceRef.current.switchMicrophone(deviceId);
    } catch (_error) {
      console.error('[useCalling] Failed to switch microphone:', _error);
    }
  }, []);

  const startScreenShare = useCallback(async (selectedSource?: { id: string; name: string; type: 'screen' | 'window' }) => {
    if (!serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    if (selectedSource) {
      if (!selectedSource.id || typeof selectedSource.id !== 'string') {
        throw new Error('[useCalling] Invalid source ID');
      }
      if (!selectedSource.type || !['screen', 'window'].includes(selectedSource.type)) {
        throw new Error('[useCalling] Invalid source type');
      }
    }

    try {
      await serviceRef.current.startScreenShare(selectedSource);
    } catch (_error) {
      console.error('[useCalling] Failed to start screen sharing:', _error);
      throw _error;
    }
  }, []);

  const getAvailableScreenSources = useMemo(() => {
    const electronApi = (window as any).electronAPI;
    const edgeApi = (window as any).edgeApi;
    const isElectron = !!(electronApi || edgeApi);

    if (!isElectron) return undefined;

    return async () => {
      if (!serviceRef.current) {
        throw new Error('[useCalling] Calling service not initialized');
      }

      try {
        return await serviceRef.current.getAvailableScreenSources();
      } catch (_error) {
        console.error('[useCalling] Failed to get screen sources:', _error);
        throw _error;
      }
    };
  }, []);

  const stopScreenShare = useCallback(async () => {
    if (!serviceRef.current) {
      return;
    }

    try {
      await serviceRef.current.stopScreenShare();
    } catch (_error) {
      console.error('[useCalling] Failed to stop screen sharing:', _error);
    }
  }, []);

  const isScreenSharing = callingService?.getScreenSharingStatus() || false;

  return {
    currentCall,
    localStream,
    remoteStream,
    remoteScreenStream,
    peerConnection: callingService?.getPeerConnection() || null,
    isInitialized,
    isScreenSharing,

    startCall,
    answerCall,
    declineCall,
    endCall,
    toggleMute,
    toggleVideo,

    switchCamera,
    switchMicrophone,
    startScreenShare,
    stopScreenShare,
    getAvailableScreenSources,
    callingService
  };
};