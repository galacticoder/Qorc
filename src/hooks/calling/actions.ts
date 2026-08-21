import React from 'react';
import { flushSync, unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { clearCallMediaState, isValidCallingUsername, isValidCallId } from '../../lib/utils/calling-utils';
import { isTauri } from '../../lib/tauri-bindings';
import type { PeerCertificateBundle } from '../../lib/types/p2p-types';
import { p2pTransport } from '../../lib/transport/p2p-transport';
import { loadPersistedPeerEndpoint } from '../../lib/p2p/persisted-peer-cert';
import { toast } from 'sonner';
import { blockingSystem } from '../../lib/blocking/blocking-system';

async function ensurePeerMaterial(
  refs: ActionRefs,
  peer: string,
  expectedService: SecureCallingService,
  ownerUsername: string
): Promise<void> {
  if (refs.serviceRef.current !== expectedService) {
    throw new Error('Calling service not initialized');
  }

  if (!refs.getPeerCertificate) throw new Error('Peer certificate resolver unavailable');
  const trustedCert = await refs.getPeerCertificate(peer);
  if (refs.serviceRef.current !== expectedService) {
    throw new Error('Calling account changed while resolving peer identity');
  }
  if (!trustedCert) throw new Error('Trusted peer certificate unavailable');
  await p2pTransport.registerPeerCertificate(peer, trustedCert);
  if (refs.serviceRef.current !== expectedService) {
    throw new Error('Calling account changed while registering peer identity');
  }
  if (!p2pTransport.hasAuthenticatedEndpoint(peer)) {
    const persistedEndpoint = await loadPersistedPeerEndpoint(ownerUsername, peer);
    if (refs.serviceRef.current !== expectedService) {
      throw new Error('Calling account changed while restoring the peer endpoint');
    }
    if (persistedEndpoint) {
      p2pTransport.updateAuthenticatedEndpoint(
        peer,
        persistedEndpoint.endpointUrl,
        persistedEndpoint.signerPublicKeyBase64,
        persistedEndpoint.announcedAt
      );
    }
  }
  if (refs.ensurePeerSession) {
    await refs.ensurePeerSession(peer);
    if (refs.serviceRef.current !== expectedService) {
      throw new Error('Calling account changed while establishing the signaling session');
    }
  }
}

export interface ActionRefs {
  serviceRef: React.RefObject<SecureCallingService | null>;
  localStreamRef: React.RefObject<MediaStream | null>;
  localVideoCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  remoteVideoCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  remoteScreenCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  getPeerCertificate?: (username: string) => Promise<PeerCertificateBundle | null>;
  ensurePeerSession?: (username: string) => Promise<void>;
}

export interface ActionSetters {
  setCurrentCall: React.Dispatch<React.SetStateAction<any>>;
  setLocalStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
  setLocalVideoCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
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

    try {
      await ensurePeerMaterial(refs, peer, service, currentUsername);

      const callId = await service.startCall(peer, callType);
      return callId;
    } catch (_error: any) {
      if (_error.message === 'arbitration-loss') {
        return '';
      }
      const serviceIsCurrent = refs.serviceRef.current === service;

      if (serviceIsCurrent && _error instanceof Error && _error.name === 'NotAllowedError') {
        toast.error("Permission Denied", {
          description: "Access to camera/microphone was denied. Please check your browser permissions in the address bar and system privacy settings."
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

    const currentCall = (service as any).currentCall;

    try {
      const peerUsername = String(currentCall?.peer || '').trim();
      if (!isValidCallingUsername(peerUsername)) {
        throw new Error('Missing peer identity for call answer');
      }
      if (peer !== undefined && peer.trim() !== peerUsername) {
        throw new Error('Call answer peer does not match the active call');
      }
      await ensurePeerMaterial(refs, peerUsername, service, currentUsername);

      await service.answerCall(callId);
    } catch (_error: any) {
      if (refs.serviceRef.current === service && _error.name === 'NotAllowedError') {
        toast.error("Permission Denied", {
          description: "Could not access camera/microphone. Please check your browser and system privacy settings."
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
  return () => {
    if (!refs.serviceRef.current) {
      return false;
    }

    const isMuted = refs.serviceRef.current.toggleMute();
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

// Callback for starting screen share
export const createStartScreenShare = (refs: ActionRefs) => {
  return async (selectedSource?: { id: string; name: string; type: 'screen' | 'window' }) => {
    if (!refs.serviceRef.current) {
      throw new Error('Calling service not initialized');
    }

    try {
      await refs.serviceRef.current.startScreenShare(selectedSource);
    } catch (_error: any) {
      console.error('Failed to start screen sharing:', _error);

      if (_error.name === 'NotAllowedError') {
        toast.error("Permission Denied", {
          description: "Access to screen recording was denied or canceled. Please check your browser and system privacy settings."
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

// Callback for exposing screen sources on desktop
export const createGetAvailableScreenSources = (refs: ActionRefs) => {
  if (!isTauri()) return undefined;

  return async () => {
    if (!refs.serviceRef.current) {
      throw new Error('Calling service not initialized');
    }

    try {
      return await refs.serviceRef.current.getAvailableScreenSources();
    } catch (_error) {
      console.error('Failed to get screen sources:', _error);
      throw _error;
    }
  };
};
