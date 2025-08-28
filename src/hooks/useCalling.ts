/**
 * React Hook for WebRTC Calling Integration
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { WebRTCCallingService, CallState } from '../lib/webrtc-calling';
import { useAuth } from './useAuth';

export const useCalling = (authContext?: ReturnType<typeof useAuth>) => {
  const fallbackAuthContext = useAuth();
  
  // Track if we've ever been fully authenticated to prevent re-initialization
  const hasBeenAuthenticatedRef = useRef(false);
  // Store the authenticated username to prevent re-initialization with empty values
  const authenticatedUsernameRef = useRef<string>('');
  // Store the original auth context to prevent switching to fallback
  const originalAuthContextRef = useRef<ReturnType<typeof useAuth> | null>(null);
  
  // Store the first valid auth context we receive and never change it
  if (authContext && authContext.username && authContext.isLoggedIn && !originalAuthContextRef.current) {
    console.log('[useCalling] Storing original auth context for user:', authContext.username);
    originalAuthContextRef.current = authContext;
  }
  
  // Also store fallback context if it has valid authentication and no original context yet
  if (!originalAuthContextRef.current && fallbackAuthContext.username && fallbackAuthContext.isLoggedIn) {
    console.log('[useCalling] Storing fallback auth context as original for user:', fallbackAuthContext.username);
    originalAuthContextRef.current = fallbackAuthContext;
  }
  
  // ALWAYS use the original context once we have it - never switch contexts
  const actualAuthContext: ReturnType<typeof useAuth> = originalAuthContextRef.current || authContext || fallbackAuthContext;
  
  const { username, loginUsernameRef, isLoggedIn, accountAuthenticated } = actualAuthContext;
  
  const [callingService, setCallingService] = useState<WebRTCCallingService | null>(null);
  const [currentCall, setCurrentCall] = useState<CallState | null>(null);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  
  const serviceRef = useRef<WebRTCCallingService | null>(null);
  const stableUsernameRef = useRef<string>('');
  const stableIsLoggedInRef = useRef<boolean>(false);
  const stableAccountAuthenticatedRef = useRef<boolean>(false);

  // Store stable values that never reset once set
  if (username && username.trim() !== '' && !stableUsernameRef.current) {
    stableUsernameRef.current = username;
  }
  if (isLoggedIn && !stableIsLoggedInRef.current) {
    stableIsLoggedInRef.current = isLoggedIn;
  }
  if (accountAuthenticated && !stableAccountAuthenticatedRef.current) {
    stableAccountAuthenticatedRef.current = accountAuthenticated;
  }

  // Use stable values that never reset
  const stableUsername = stableUsernameRef.current || username;
  const stableIsLoggedIn = stableIsLoggedInRef.current || isLoggedIn;
  const stableAccountAuthenticated = stableAccountAuthenticatedRef.current || accountAuthenticated;

  // Initialize calling service after complete authentication
  useEffect(() => {
    // FIRST PRIORITY: If we have a service, preserve it regardless of auth state
    if (serviceRef.current) {
      console.log('[useCalling] Service exists - preserving service regardless of auth state');
      return;
    }

    const currentUsername = stableUsername || loginUsernameRef?.current;
    const hasValidUsername = currentUsername && currentUsername.trim() !== '';
    const isAuthenticated = stableIsLoggedIn && stableAccountAuthenticated; // Require BOTH flags
    
    // ALWAYS log to see what's happening
    console.log('[useCalling] useEffect triggered:', {
      currentUsername,
      hasValidUsername,
      isLoggedIn,
      accountAuthenticated,
      isAuthenticated,
      stableUsername,
      stableIsLoggedIn,
      stableAccountAuthenticated,
      hasExistingService: !!serviceRef.current,
      hasBeenAuthenticated: hasBeenAuthenticatedRef.current,
      authenticatedUsername: authenticatedUsernameRef.current,
      usingOriginalContext: !!originalAuthContextRef.current,
      passedAuthContext: !!authContext,
      fallbackAuthContext: !!fallbackAuthContext
    });
    
    // If we get empty authentication values but we've been authenticated before, ignore this trigger
    if (hasBeenAuthenticatedRef.current && (!hasValidUsername || !isAuthenticated)) {
      console.log('[useCalling] Ignoring authentication reset - service already initialized for:', authenticatedUsernameRef.current);
      return;
    }

    // NEVER clean up service if we have one - only on explicit logout
    // This prevents accidental cleanup during temporary auth resets
    if (!isLoggedIn && !accountAuthenticated && !hasBeenAuthenticatedRef.current && !serviceRef.current) {
      console.log('[useCalling] No service to clean up on logout');
      return;
    }
    
    // Don't initialize if not properly authenticated (but preserve existing service)
    if (!isAuthenticated || !hasValidUsername) {
      return;
    }

    // Initialize if we have complete authentication AND valid username AND no existing service
    // Remove the hasBeenAuthenticatedRef check to allow initialization even after context resets
    if (hasValidUsername && isAuthenticated && !serviceRef.current) {
      console.log('[useCalling] All conditions met - Initializing calling service for user:', currentUsername);
      
      const service = new WebRTCCallingService(currentUsername);
      serviceRef.current = service;

      // Set up callbacks
      service.onIncomingCall((call) => {
        console.log('[useCalling] Incoming call:', call);
        setCurrentCall(call);
      });

      service.onCallStateChange((call) => {
        console.log('[useCalling] Call state changed:', call.status);
        setCurrentCall(call);
      });

      service.onLocalStream((stream) => {
        console.log('[useCalling] Local stream received');
        setLocalStream(stream);
      });

      service.onRemoteStream((stream) => {
        console.log('[useCalling] Remote stream received');
        setRemoteStream(stream);
      });

      // Initialize service immediately (it's synchronous)
      try {
        service.initialize();
        console.log('[useCalling] Calling service initialized successfully');
        
        // Set authentication tracking AFTER successful initialization
        hasBeenAuthenticatedRef.current = true;
        authenticatedUsernameRef.current = currentUsername;
        
        // Update state after successful initialization
        setCallingService(service);
        setIsInitialized(true);
        
        console.log('[useCalling] State updated - service available for calls');
      } catch (error) {
        console.error('[useCalling] Failed to initialize calling service:', error);
        serviceRef.current = null;
        setCallingService(null);
        setIsInitialized(false);
        hasBeenAuthenticatedRef.current = false;
        authenticatedUsernameRef.current = '';
      }
    }
  }, [stableUsername, stableIsLoggedIn, stableAccountAuthenticated]);

  // Start a call
  const startCall = useCallback(async (targetUser: string, callType: 'audio' | 'video' = 'audio') => {
    console.log('[useCalling] startCall called:', {
      targetUser,
      callType,
      hasServiceRef: !!serviceRef.current,
      hasServiceState: !!callingService,
      isInitializedState: isInitialized,
      currentAuthState: {
        username,
        loginUsernameRef: loginUsernameRef?.current,
        isLoggedIn,
        accountAuthenticated,
        hasBeenAuthenticated: hasBeenAuthenticatedRef.current,
        authenticatedUsername: authenticatedUsernameRef.current,
        usingOriginalContext: !!originalAuthContextRef.current
      }
    });

    if (!serviceRef.current) {
      console.log('[useCalling] No calling service available - detailed state:', {
        serviceRef: serviceRef.current,
        callingService,
        isInitialized,
        hasBeenAuthenticatedRef: hasBeenAuthenticatedRef.current,
        authenticatedUsernameRef: authenticatedUsernameRef.current,
        originalAuthContextRef: !!originalAuthContextRef.current
      });
      throw new Error('Calling service not available');
    }

    try {
      const callId = await serviceRef.current.startCall(targetUser, callType);
      console.log('[useCalling] Call started:', callId);
      return callId;
    } catch (error) {
      console.error('[useCalling] Failed to start call:', error);
      throw error;
    }
  }, [callingService, isInitialized]);

  // Answer a call
  const answerCall = useCallback(async (callId: string) => {
    if (!callingService) {
      throw new Error('Calling service not available');
    }

    try {
      await callingService.answerCall(callId);
      console.log('[useCalling] Call answered:', callId);
    } catch (error) {
      console.error('[useCalling] Failed to answer call:', error);
      throw error;
    }
  }, [callingService]);

  // Decline a call
  const declineCall = useCallback(async (callId: string) => {
    if (!callingService) {
      throw new Error('Calling service not available');
    }

    try {
      await callingService.declineCall(callId);
      console.log('[useCalling] Call declined:', callId);
    } catch (error) {
      console.error('[useCalling] Failed to decline call:', error);
      throw error;
    }
  }, [callingService]);

  // End a call
  const endCall = useCallback(async () => {
    if (!callingService) {
      throw new Error('Calling service not available');
    }

    try {
      await callingService.endCall();
      console.log('[useCalling] Call ended');
    } catch (error) {
      console.error('[useCalling] Failed to end call:', error);
      throw error;
    }
  }, [callingService]);

  // Toggle mute
  const toggleMute = useCallback(() => {
    if (!callingService) {
      return false;
    }

    const isMuted = callingService.toggleMute();
    console.log('[useCalling] Mute toggled:', isMuted);
    return isMuted;
  }, [callingService]);

  // Toggle video
  const toggleVideo = useCallback(() => {
    if (!callingService) {
      return false;
    }

    const isEnabled = callingService.toggleVideo();
    console.log('[useCalling] Video toggled:', isEnabled);
    return isEnabled;
  }, [callingService]);

  // Switch camera
  const switchCamera = useCallback(async () => {
    if (!callingService) {
      return;
    }

    try {
      await callingService.switchCamera();
      console.log('[useCalling] Camera switched');
    } catch (error) {
      console.error('[useCalling] Failed to switch camera:', error);
    }
  }, [callingService]);

  return {
    // State
    currentCall,
    localStream,
    remoteStream,
    isInitialized,
    
    // Actions
    startCall,
    answerCall,
    declineCall,
    endCall,
    toggleMute,
    toggleVideo,
    switchCamera,
    
    // Service instance (for advanced usage)
    callingService
  };
};
