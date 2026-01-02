import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { WebRTCCallingService, CallState } from '../../lib/webrtc-calling';
import type { useAuth } from '../auth/useAuth';
import { stopMediaStream, debounceEventDispatcher, isValidCallingUsername } from '../../lib/utils/calling-utils';
import {
  setupIncomingCallCallback,
  setupCallStateChangeCallback,
  setupStreamCallbacks,
  type CallbackRefs,
  type CallbackSetters
} from './callbacks';
import {
  createStartCall,
  createAnswerCall,
  createDeclineCall,
  createEndCall,
  createToggleMute,
  createToggleVideo,
  createSwitchCamera,
  createSwitchMicrophone,
  createStartScreenShare,
  createStopScreenShare,
  createGetAvailableScreenSources,
  type ActionRefs,
  type ActionSetters
} from './actions';

// Hook wiring the WebRTC calling service to the auth context
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

  const callbackRefs: CallbackRefs = {
    localStreamRef,
    remoteStreamRef,
    remoteScreenStreamRef,
    everConnectedRef,
    eventDebouncer
  };

  const callbackSetters: CallbackSetters = {
    setCurrentCall,
    setLocalStream,
    setRemoteStream,
    setRemoteScreenStream
  };

  const actionRefs: ActionRefs = {
    serviceRef,
    localStreamRef,
    remoteStreamRef,
    remoteScreenStreamRef
  };

  const actionSetters: ActionSetters = {
    setCurrentCall,
    setLocalStream,
    setRemoteStream,
    setRemoteScreenStream
  };

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
    if (!isValidCallingUsername(currentUsername)) { return; }
    if (!isFullyAuthenticated) { return; }
    if (hasBeenAuthenticatedRef.current && !isFullyAuthenticated) { return; }

    const service = new WebRTCCallingService(currentUsername);
    serviceRef.current = service;

    setupIncomingCallCallback(service, callbackRefs, callbackSetters);
    setupCallStateChangeCallback(service, callbackRefs, callbackSetters);
    setupStreamCallbacks(service, callbackRefs, callbackSetters);

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
          const { PostQuantumRandom } = await import('../../lib/cryptography/random');
          const jitterBytes = PostQuantumRandom.randomBytes(1);
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

  const startCall = useCallback(
    createStartCall(actionRefs, actionSetters, currentUsername),
    [currentUsername]
  );

  const answerCall = useCallback(createAnswerCall(actionRefs), []);

  const declineCall = useCallback(createDeclineCall(actionRefs), []);

  const endCall = useCallback(createEndCall(actionRefs), []);

  const toggleMute = useCallback(createToggleMute(actionRefs), []);

  const toggleVideo = useCallback(createToggleVideo(actionRefs), []);

  const switchCamera = useCallback(createSwitchCamera(actionRefs), []);

  const switchMicrophone = useCallback(createSwitchMicrophone(actionRefs), []);

  const startScreenShare = useCallback(createStartScreenShare(actionRefs), []);

  const stopScreenShare = useCallback(createStopScreenShare(actionRefs), []);

  const getAvailableScreenSources = useMemo(
    () => createGetAvailableScreenSources(actionRefs),
    []
  );

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
