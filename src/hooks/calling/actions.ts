import React from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { isValidCallingUsername, isValidCallId, stopMediaStream } from '../../lib/utils/calling-utils';
import { PostQuantumUtils } from '../../lib/utils/pq-utils';
import { isTauri } from '../../lib/tauri-bindings';
import type { PeerCertificateBundle } from '../../lib/types/p2p-types';
import { p2pTransport } from '../../lib/transport/p2p-transport';
import { normalizeP2PEndpointUrl } from '../../lib/utils/p2p-endpoint';
import { toast } from 'sonner';

type PeerKeysResponse = {
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64?: string;
};

async function ensurePeerMaterial(refs: ActionRefs, peer: string): Promise<void> {
  const service = refs.serviceRef.current;
  if (!service) {
    throw new Error('Calling service not initialized');
  }

  let trustedCert: PeerCertificateBundle | null = null;
  if (refs.getPeerCertificate) {
    trustedCert = await refs.getPeerCertificate(peer);
    if (!trustedCert) {
      throw new Error(`Trusted peer certificate unavailable for ${peer}`);
    }
  }

  if (!service.hasPeerKeys(peer)) {
    if (!refs.getPeerKeys) {
      throw new Error(`No key resolver configured for ${peer}`);
    }

    const keys = await refs.getPeerKeys(peer);
    if (!keys) {
      throw new Error(`No keys available for ${peer}`);
    }

    const peerKeys = {
      username: peer,
      dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(keys.dilithiumPublicBase64),
      kyberPublicKey: PostQuantumUtils.base64ToUint8Array(keys.kyberPublicBase64),
      x25519PublicKey: keys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(keys.x25519PublicBase64) : undefined
    };

    if (trustedCert) {
      if (
        trustedCert.dilithiumPublicKey !== keys.dilithiumPublicBase64 ||
        trustedCert.kyberPublicKey !== keys.kyberPublicBase64 ||
        trustedCert.x25519PublicKey !== keys.x25519PublicBase64
      ) {
        throw new Error(`Peer key material mismatch for ${peer}`);
      }
    }

    if (
      peerKeys.dilithiumPublicKey.length === 0 ||
      peerKeys.kyberPublicKey.length === 0 ||
      !peerKeys.x25519PublicKey ||
      peerKeys.x25519PublicKey.length === 0
    ) {
      throw new Error(`Invalid key material for ${peer}`);
    }

    service.setPeerKeys(peer, peerKeys as any);
  }
  
  if (trustedCert) {
    const kyber = PostQuantumUtils.base64ToUint8Array(trustedCert.kyberPublicKey);
    const dilithium = PostQuantumUtils.base64ToUint8Array(trustedCert.dilithiumPublicKey);
    const x25519 = PostQuantumUtils.base64ToUint8Array(trustedCert.x25519PublicKey);
    if (kyber.length > 0 && dilithium.length > 0 && x25519.length > 0) {
      p2pTransport.registerPeerIdentity(peer, {
        username: peer,
        kyberPublicKey: kyber,
        dilithiumPublicKey: dilithium,
        x25519PublicKey: x25519,
        endpointUrl: normalizeP2PEndpointUrl(trustedCert.p2pEndpointUrl)
      });
    }
  }
}

export interface ActionRefs {
  serviceRef: React.RefObject<SecureCallingService | null>;
  localStreamRef: React.RefObject<MediaStream | null>;
  remoteStreamRef: React.RefObject<MediaStream | null>;
  remoteScreenStreamRef: React.RefObject<MediaStream | null>;
  getPeerKeys?: (username: string) => Promise<PeerKeysResponse | null>;
  getPeerCertificate?: (username: string) => Promise<PeerCertificateBundle | null>;
}

export interface ActionSetters {
  setCurrentCall: React.Dispatch<React.SetStateAction<any>>;
  setLocalStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
  setRemoteStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
  setRemoteScreenStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
}

// Callback for starting a call
export const createStartCall = (
  refs: ActionRefs,
  setters: ActionSetters,
  currentUsername: string
) => {
  return async (targetUser: string, callType: 'audio' | 'video' = 'audio') => {
    if (!refs.serviceRef.current) {
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

    try {
      await ensurePeerMaterial(refs, peer);

      const callId = await refs.serviceRef.current.startCall(peer, callType);
      return callId;
    } catch (_error: any) {
      if (_error.message === 'arbitration-loss') {
        return '';
      }
      console.error('Failed to start call:', _error);

      if (_error instanceof Error && _error.name === 'NotAllowedError') {
        console.warn('Permission denied for camera/microphone. Please check your system privacy settings.');
        toast.error("Permission Denied", {
          description: "Access to camera/microphone was denied. Please check your browser permissions in the address bar and system privacy settings."
        });
      }

      unstable_batchedUpdates(() => {
        setters.setCurrentCall(null);
        stopMediaStream(refs.localStreamRef.current);
        stopMediaStream(refs.remoteStreamRef.current);
        stopMediaStream(refs.remoteScreenStreamRef.current);
        refs.localStreamRef.current = null;
        refs.remoteStreamRef.current = null;
        refs.remoteScreenStreamRef.current = null;
        setters.setLocalStream(null);
        setters.setRemoteStream(null);
        setters.setRemoteScreenStream(null);
      });
      throw _error;
    }
  };
};

// Callback for answering a call
export const createAnswerCall = (refs: ActionRefs) => {
  return async (callId: string, peer?: string) => {
    if (!refs.serviceRef.current) {
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

    const currentCall = (refs.serviceRef.current as any).currentCall;

    try {
      const peerUsername = (peer || currentCall?.peer || '').trim();
      if (!isValidCallingUsername(peerUsername)) {
        throw new Error('Missing peer identity for call answer');
      }
      await ensurePeerMaterial(refs, peerUsername);

      await refs.serviceRef.current.answerCall(callId);
    } catch (_error: any) {
      console.error('Failed to answer call:', _error);

      if (_error.name === 'NotAllowedError') {
        console.warn('Permission denied for camera/microphone during answerCall.');
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
      const service = refs.serviceRef.current;
      if (refs.getPeerKeys) {
        try {
          const currentCall = (service as any).currentCall;
          if (currentCall && currentCall.id === callId && currentCall.peer) {
            const peer = currentCall.peer;
            await ensurePeerMaterial(refs, peer);
          }
        } catch (keyError) {
          console.warn('Failed to fetch keys for decline call:', keyError);
        }
      }

      await refs.serviceRef.current.declineCall(callId);
    } catch (_error) {
      console.error('Failed to decline call:', _error);
      throw _error;
    }
  };
};

// Callback for ending the current call
export const createEndCall = (refs: ActionRefs) => {
  return async () => {
    if (!refs.serviceRef.current) {
      throw new Error('Calling service not initialized');
    }

    try {
      await refs.serviceRef.current.endCall();
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

    try {
      await refs.serviceRef.current.switchCamera(deviceId);
    } catch (_error) {
      console.error('Failed to switch camera:', _error);
    }
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

    if (selectedSource) {
      if (!selectedSource.id || typeof selectedSource.id !== 'string') {
        throw new Error('Invalid source ID');
      }
      if (!selectedSource.type || !['screen', 'window'].includes(selectedSource.type)) {
        throw new Error('Invalid source type');
      }
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
