import React from 'react';
import { flushSync, unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { clearCallMediaState, isValidCallingUsername, isValidCallId } from '../../lib/utils/calling-utils';
import type { PeerCertificateBundle } from '../../lib/types/p2p-types';
import { preparePeerTransport } from '../../lib/p2p/prepare-peer';
import { toast } from 'sonner';
import { blockingSystem } from '../../lib/blocking/blocking-system';

function callDiagnostic(phase: string, details: Record<string, unknown> = {}): void {
  console.info('[CALL-DIAG]', { phase, ...details });
}

async function validatePeerMaterial(
  refs: ActionRefs,
  peer: string,
  expectedService: SecureCallingService,
  ownerUsername: string
): Promise<void> {
  callDiagnostic('action.peer-material-enter');
  if (refs.serviceRef.current !== expectedService) {
    throw new Error('Calling service not initialized');
  }

  await preparePeerTransport(
    ownerUsername,
    peer,
    refs.getPeerCertificate,
    () => refs.serviceRef.current === expectedService,
  );
  callDiagnostic('action.peer-session-before');
  await refs.checkPeerSession(peer);
  callDiagnostic('action.peer-session-after');
  if (refs.serviceRef.current !== expectedService) {
    throw new Error('Calling account changed while establishing the signaling session');
  }
  callDiagnostic('action.peer-material-complete');
}

export interface ActionRefs {
  serviceRef: React.RefObject<SecureCallingService | null>;
  localMediaActiveRef: React.RefObject<boolean>;
  localVideoCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  localScreenCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  remoteVideoCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  remoteScreenCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  getPeerCertificate: (username: string) => Promise<PeerCertificateBundle | null>;
  checkPeerSession: (username: string) => Promise<void>;
}

export interface ActionSetters {
  setCurrentCall: React.Dispatch<React.SetStateAction<any>>;
  setLocalMediaActive: React.Dispatch<React.SetStateAction<boolean>>;
  setLocalVideoCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
  setLocalScreenCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
  setRemoteVideoCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
  setRemoteScreenCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
}

// Callback for starting a call
export const createStartCall = (
  refs: ActionRefs,
  setters: ActionSetters,
  currentUsername: string
) => {
  return async (targetUser: string, callType: 'audio' | 'video' = 'audio') => {
    const startedAt = performance.now();
    callDiagnostic('action.start-enter', { callType });
    const service = refs.serviceRef.current;
    if (!service) {
      throw new Error('Calling service not initialized');
    }

    if (!window.isSecureContext) {
      toast.error("Security Restriction", {
        description: "Camera/microphone access is blocked because this session is not secure (HTTPS or localhost required)."
      });
      throw new Error('Insecure context');
    }

    const peer = targetUser.trim();
    if (!isValidCallingUsername(peer)) {
      throw new Error('Invalid target username format');
    }

    if (callType !== 'audio' && callType !== 'video') {
      throw new Error('Invalid call type');
    }

    if (peer === currentUsername) {
      throw new Error('Cannot call yourself');
    }
    if (!blockingSystem.isEnforcementReady() || blockingSystem.isBlockedSync(peer)) {
      throw new Error('recipient-blocked');
    }
    callDiagnostic('action.start-validated', {
      callType,
      elapsedMs: Math.round(performance.now() - startedAt),
    });

    try {
      await validatePeerMaterial(refs, peer, service, currentUsername);
      callDiagnostic('action.service-start-before', {
        callType,
        elapsedMs: Math.round(performance.now() - startedAt),
      });

      const callId = await service.startCall(peer, callType);
      callDiagnostic('action.service-start-after', {
        callType,
        elapsedMs: Math.round(performance.now() - startedAt),
      });
      return callId;
    } catch (_error: any) {
      console.error('[CALL-DIAG]', {
        phase: 'action.start-failed',
        callType,
        elapsedMs: Math.round(performance.now() - startedAt),
        errorName: _error instanceof Error ? _error.name : 'UnknownError',
        errorMessage: _error instanceof Error ? _error.message : String(_error),
      });
      if (_error.message === 'arbitration-loss') {
        return '';
      }
      const serviceIsCurrent = refs.serviceRef.current === service;

      if (serviceIsCurrent && _error instanceof Error && _error.name === 'NotAllowedError') {
        toast.error("Permission Denied", {
          description: "Access to camera/microphone was denied. Please check the app and system privacy settings."
        });
      }

      if (serviceIsCurrent) {
        unstable_batchedUpdates(() => {
          setters.setCurrentCall(null);
          clearCallMediaState(refs, setters);
        });
      }
      throw _error;
    }
  };
};

// Callback for answering a call
export const createAnswerCall = (refs: ActionRefs, currentUsername: string) => {
  return async (callId: string, peer?: string) => {
    const service = refs.serviceRef.current;
    if (!service) {
      throw new Error('Calling service not initialized');
    }

    if (!window.isSecureContext) {
      toast.error("Security Restriction", {
        description: "Camera/microphone access is blocked because this session is not secure (HTTPS or localhost required)."
      });
      throw new Error('Insecure context');
    }

    if (!isValidCallId(callId)) {
      throw new Error('Invalid call ID format');
    }

    const incomingCall = service.getCallState(callId);

    try {
      const peerUsername = String(incomingCall?.peer || '').trim();
      if (!isValidCallingUsername(peerUsername)) {
        throw new Error('Missing peer identity for call answer');
      }
      if (peer !== undefined && peer.trim() !== peerUsername) {
        throw new Error('Call answer peer does not match the active call');
      }
      await validatePeerMaterial(refs, peerUsername, service, currentUsername);

      await service.answerCall(callId);
    } catch (_error: any) {
      if (refs.serviceRef.current === service && _error.name === 'NotAllowedError') {
        toast.error("Permission Denied", {
          description: "Could not access camera/microphone. Please check the app and system privacy settings."
        });
      }

      throw _error;
    }
  };
};

// Callback for declining a call
export const createDeclineCall = (refs: ActionRefs) => {
  return async (callId: string) => {
    if (!refs.serviceRef.current) {
      throw new Error('Calling service not initialized');
    }

    if (!isValidCallId(callId)) {
      throw new Error('Invalid call ID format');
    }

    try {
      await refs.serviceRef.current.declineCall(callId);
    } catch (_error) {
      console.error('Failed to decline call:', _error);
      throw _error;
    }
  };
};

// Callback for ending the current call
export const createEndCall = (refs: ActionRefs, setters: ActionSetters) => {
  return async () => {
    const service = refs.serviceRef.current;
    if (!service) {
      throw new Error('Calling service not initialized');
    }

    flushSync(() => {
      setters.setCurrentCall(null);
    });

    try {
      await service.endCall();
    } catch (_error) {
      console.error('Failed to end call:', _error);
      throw _error;
    }
  };
};

// Callback for toggling mute
export const createToggleMute = (refs: ActionRefs) => {
  return async () => {
    if (!refs.serviceRef.current) {
      return false;
    }

    const isMuted = await refs.serviceRef.current.toggleMute();
    return isMuted;
  };
};

// Callback for toggling video
export const createToggleVideo = (refs: ActionRefs) => {
  return async () => {
    if (!refs.serviceRef.current) {
      return false;
    }

    const isEnabled = await refs.serviceRef.current.toggleVideo();
    return isEnabled;
  };
};

// Callback for switching the camera
export const createSwitchCamera = (refs: ActionRefs) => {
  return async (deviceId: string) => {
    if (!refs.serviceRef.current) {
      return;
    }
    await refs.serviceRef.current.switchCamera(deviceId);
  };
};

// Callback for switching the microphone
export const createSwitchMicrophone = (refs: ActionRefs) => {
  return async (deviceId: string) => {
    if (!refs.serviceRef.current) {
      return;
    }

    try {
      await refs.serviceRef.current.switchMicrophone(deviceId);
    } catch (_error) {
      console.error('Failed to switch microphone:', _error);
    }
  };
};

export const createSwitchSpeaker = (refs: ActionRefs) => {
  return async (deviceId: string) => {
    if (!refs.serviceRef.current) {
      return;
    }
    await refs.serviceRef.current.switchSpeaker(deviceId);
  };
};

// Callback for starting screen share
export const createStartScreenShare = (refs: ActionRefs) => {
  return async () => {
    if (!refs.serviceRef.current) {
      throw new Error('Calling service not initialized');
    }

    try {
      await refs.serviceRef.current.startScreenShare();
    } catch (_error: any) {
      console.error('Failed to start screen sharing:', _error);

      if (_error.name === 'NotAllowedError') {
        toast.error("Permission Denied", {
          description: "Access to screen recording was denied or canceled. Please check the app and system privacy settings."
        });
      } else {
        toast.error("Screen Share Failed", {
          description: _error instanceof Error ? _error.message : "Screen capture could not be started."
        });
      }

      throw _error;
    }
  };
};

// Callback for stopping screen share
export const createStopScreenShare = (refs: ActionRefs) => {
  return async () => {
    if (!refs.serviceRef.current) {
      return;
    }

    try {
      await refs.serviceRef.current.stopScreenShare();
    } catch (_error) {
      console.error('Failed to stop screen sharing:', _error);
    }
  };
};
