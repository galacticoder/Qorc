import { useState, useEffect, useCallback, useRef } from 'react';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { PostQuantumRandom } from '../../lib/cryptography/random';
import type { useAuth } from '../auth/useAuth';
import type { PeerCertificateBundle } from '../../lib/types/p2p-types';
import { clearCallMediaState, releaseVisualCanvas, debounceEventDispatcher, isValidCallingUsername } from '../../lib/utils/calling-utils';
import { power } from '../../lib/tauri-bindings';
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
  createSwitchSpeaker,
  createStartScreenShare,
  createStopScreenShare,
  type ActionRefs,
  type ActionSetters
} from './actions';
import { CallState } from '../../lib/types/calling-types';

// Hook wiring the calling service to the auth context
export const useCalling = (
  authContext: ReturnType<typeof useAuth>,
  options: {
    getPeerCertificate: (username: string) => Promise<PeerCertificateBundle | null>;
    checkPeerSession: (username: string) => Promise<void>;
  }
) => {
  if (!authContext) {
    throw new Error('Auth context is required');
  }

  const eventDebouncer = useRef(debounceEventDispatcher());
  const localMediaActiveRef = useRef(false);
  const localVideoCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const localScreenCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const remoteVideoCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const remoteScreenCanvasRef = useRef<HTMLCanvasElement | null>(null);

  const { username, loginUsernameRef, isLoggedIn, accountAuthenticated } = authContext;

  const [callingService, setCallingService] = useState<SecureCallingService | null>(null);
  const [currentCall, setCurrentCall] = useState<CallState | null>(null);
  const [pendingIncomingCalls, setPendingIncomingCalls] = useState<CallState[]>([]);
  const [localMediaActive, setLocalMediaActive] = useState(false);
  const [localVideoCanvas, setLocalVideoCanvas] = useState<HTMLCanvasElement | null>(null);
  const [localScreenCanvas, setLocalScreenCanvas] = useState<HTMLCanvasElement | null>(null);
  const [remoteVideoCanvas, setRemoteVideoCanvas] = useState<HTMLCanvasElement | null>(null);
  const [remoteScreenCanvas, setRemoteScreenCanvas] = useState<HTMLCanvasElement | null>(null);
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);

  const serviceRef = useRef<SecureCallingService | null>(null);
  const everConnectedRef = useRef<Set<string>>(new Set());

  const currentUsername = username || loginUsernameRef?.current || '';
  const isFullyAuthenticated = isLoggedIn && accountAuthenticated;

  const callbackRefs: CallbackRefs = {
    localMediaActiveRef,
    localVideoCanvasRef,
    localScreenCanvasRef,
    remoteVideoCanvasRef,
    remoteScreenCanvasRef,
    everConnectedRef,
    eventDebouncer
  };

  const callbackSetters: CallbackSetters = {
    setCurrentCall,
    setPendingIncomingCalls,
    setLocalMediaActive,
    setLocalVideoCanvas,
    setLocalScreenCanvas,
    setRemoteVideoCanvas,
    setRemoteScreenCanvas
  };

  const actionRefs: ActionRefs = {
    serviceRef,
    localMediaActiveRef,
    localVideoCanvasRef,
    localScreenCanvasRef,
    remoteVideoCanvasRef,
    remoteScreenCanvasRef,
    getPeerCertificate: options.getPeerCertificate,
    checkPeerSession: options.checkPeerSession,
  };

  const actionSetters: ActionSetters = {
    setCurrentCall,
    setLocalMediaActive,
    setLocalVideoCanvas,
    setLocalScreenCanvas,
    setRemoteVideoCanvas,
    setRemoteScreenCanvas
  };

  useEffect(() => {
    return () => {
      eventDebouncer.current.cancel();
      localMediaActiveRef.current = false;
      localVideoCanvasRef.current = null;
      localScreenCanvasRef.current = null;
      releaseVisualCanvas(remoteVideoCanvasRef.current);
      releaseVisualCanvas(remoteScreenCanvasRef.current);
      everConnectedRef.current.clear();
      power.stop().catch(() => { });
    };
  }, []);

  useEffect(() => {
    if (serviceRef.current) { return; }
    if (!isValidCallingUsername(currentUsername)) { return; }
    if (!isFullyAuthenticated) { return; }

    const service = new SecureCallingService(currentUsername);
    serviceRef.current = service;
    let cancelled = false;

    setupIncomingCallCallback(service, callbackRefs, callbackSetters, currentUsername);
    setupCallStateChangeCallback(service, callbackRefs, callbackSetters, currentUsername);
    setupStreamCallbacks(service, callbackRefs, callbackSetters);
    service.onScreenSharingChange(setIsScreenSharing);

    const initializeService = async (attempt = 0): Promise<void> => {
      try {
        await service.initialize();
        if (cancelled || serviceRef.current !== service) return;

        setCallingService(service);
        setIsInitialized(true);
      } catch (_error) {
        if (cancelled) return;
        if (attempt < 3) {
          const baseDelay = 500;
          const jitterBytes = PostQuantumRandom.randomBytes(1);
          const jitter = jitterBytes[0] % 200;
          jitterBytes.fill(0);
          const delay = Math.min(5000, baseDelay * Math.pow(2, attempt)) + jitter;
          await new Promise((resolve) => setTimeout(resolve, delay));
          if (cancelled) return;
          await initializeService(attempt + 1);
          return;
        }
        console.error('Failed to initialize calling service:', _error);
        service.destroy();
        serviceRef.current = null;
        setCallingService(null);
        setCurrentCall(null);
        setPendingIncomingCalls([]);
        setLocalMediaActive(false);
        setLocalVideoCanvas(null);
        setLocalScreenCanvas(null);
        setRemoteVideoCanvas(null);
        setRemoteScreenCanvas(null);
        setIsScreenSharing(false);
        setIsInitialized(false);
      }
    };

    initializeService();

    return () => {
      cancelled = true;
      eventDebouncer.current.cancel();
      service.destroy();
      void power.stop().catch(() => { });
      if (serviceRef.current === service) {
        serviceRef.current = null;
      }
      setCallingService(null);
      setCurrentCall(null);
      setPendingIncomingCalls([]);
      setIsScreenSharing(false);
      clearCallMediaState(callbackRefs, callbackSetters);
      everConnectedRef.current.clear();
      setIsInitialized(false);
    };
  }, [currentUsername, isFullyAuthenticated]);

  const startCall = useCallback(
    createStartCall(actionRefs, actionSetters, currentUsername),
    [currentUsername, options?.getPeerCertificate, options?.checkPeerSession]
  );

  const answerCall = useCallback(
    createAnswerCall(actionRefs, currentUsername),
    [currentUsername, options?.getPeerCertificate, options?.checkPeerSession]
  );

  const declineCall = useCallback(
    createDeclineCall(actionRefs),
    []
  );

  const endCall = useCallback(createEndCall(actionRefs, actionSetters), []);

  const toggleMute = useCallback(createToggleMute(actionRefs), []);

  const toggleVideo = useCallback(createToggleVideo(actionRefs), []);

  const switchCamera = useCallback(createSwitchCamera(actionRefs), []);

  const switchMicrophone = useCallback(createSwitchMicrophone(actionRefs), []);

  const switchSpeaker = useCallback(createSwitchSpeaker(actionRefs), []);

  const startScreenShare = useCallback(createStartScreenShare(actionRefs), []);

  const stopScreenShare = useCallback(createStopScreenShare(actionRefs), []);

  return {
    currentCall,
    pendingIncomingCalls,
    localMediaActive,
    localVideoCanvas,
    localScreenCanvas,
    remoteVideoCanvas,
    remoteScreenCanvas,
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
    switchSpeaker,
    startScreenShare,
    stopScreenShare,
    callingService
  };
};
