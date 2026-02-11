import React from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { isValidCallingUsername, isValidCallId, stopMediaStream } from '../../lib/utils/calling-utils';
import { PostQuantumUtils } from '../../lib/utils/pq-utils';
import { isTauri } from '../../lib/tauri-bindings';
import { toast } from 'sonner';

type MediaPermissionResult = {
  granted: boolean;
  audioOnlyFallback: boolean;
};

// Request media permissions
async function requestMediaPermissions(callType: 'audio' | 'video'): Promise<MediaPermissionResult> {
  if (!navigator.mediaDevices?.getUserMedia) {
    console.warn('[requestMediaPermissions] mediaDevices.getUserMedia is not available.');
    return { granted: false, audioOnlyFallback: false };
  }

  const attempts: Array<{ constraints: MediaStreamConstraints; audioOnlyFallback: boolean }> = callType === 'video'
    ? [
      { constraints: { audio: true, video: true }, audioOnlyFallback: false },
      { constraints: { audio: true }, audioOnlyFallback: true }
    ]
    : [{ constraints: { audio: true }, audioOnlyFallback: false }];

  let lastError: any = null;

  for (const attempt of attempts) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia(attempt.constraints);
      stream.getTracks().forEach(track => track.stop());
      return { granted: true, audioOnlyFallback: attempt.audioOnlyFallback };
    } catch (error: any) {
      lastError = error;
      const name = error?.name;

      if (name === 'NotAllowedError' || name === 'SecurityError') {
        return { granted: false, audioOnlyFallback: false };
      }

      const canFallback = name === 'OverconstrainedError'
        || name === 'NotFoundError'
        || name === 'NotReadableError';

      if (!canFallback) {
        break;
      }
    }
  }

  if (lastError) {
    console.warn('[requestMediaPermissions] Failed:', lastError.name, lastError.message);
  }
  return { granted: false, audioOnlyFallback: false };
}

export interface ActionRefs {
  serviceRef: React.RefObject<SecureCallingService | null>;
  localStreamRef: React.RefObject<MediaStream | null>;
  remoteStreamRef: React.RefObject<MediaStream | null>;
  remoteScreenStreamRef: React.RefObject<MediaStream | null>;
  getPeerKeys?: (username: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>;
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

    // Request media permissions before attempting to start call
    const permissionResult = await requestMediaPermissions(callType);
    if (!permissionResult.granted) {
      toast.error("Permission Denied", {
        description: "Access to camera/microphone was denied. Please check your system privacy settings and ensure Qor Chat has permission to access these devices."
      });
      throw new Error('Media permissions denied');
    }
    if (permissionResult.audioOnlyFallback && callType === 'video') {
      toast.warning("Camera Unavailable", {
        description: "Video permission or device was unavailable, starting an audio-only call."
      });
    }

    // Make sure keys are available for peer
    try {
      if (refs.getPeerKeys) {
        try {
          const service = refs.serviceRef.current;
          let hasKeys = false;
          if (service && (service as any).hasPeerKeys) {
            hasKeys = (service as any).hasPeerKeys(peer);
          }

          if (!hasKeys) {
            const keys = await refs.getPeerKeys(peer);
            if (keys) {
              const peerKeys = {
                username: peer,
                dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(keys.dilithiumPublicBase64),
                kyberPublicKey: PostQuantumUtils.base64ToUint8Array(keys.kyberPublicBase64),
                x25519PublicKey: keys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(keys.x25519PublicBase64) : undefined
              };

              if (peerKeys.dilithiumPublicKey.length > 0 && peerKeys.kyberPublicKey.length > 0) {
                refs.serviceRef.current.setPeerKeys(peer, peerKeys as any);
              }
            }
          }
        } catch (keyError) {
          console.warn('Failed to fetch keys for peer call:', keyError);
        }
      }

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

    // Get call type from current call to request permissions
    const currentCall = (refs.serviceRef.current as any).currentCall;
    const callType = currentCall?.type || 'audio';

    // Request media permissions before attempting to answer call
    const permissionResult = await requestMediaPermissions(callType);
    if (!permissionResult.granted) {
      toast.error("Permission Denied", {
        description: "Access to camera/microphone was denied. Please check your system privacy settings and ensure Qor Chat has permission to access these devices."
      });
      throw new Error('Media permissions denied');
    }
    if (permissionResult.audioOnlyFallback && callType === 'video') {
      toast.warning("Camera Unavailable", {
        description: "Video permission or device was unavailable, answering with audio only."
      });
    }

    try {
      if (peer && refs.getPeerKeys) {
        try {
          const service = refs.serviceRef.current;
          let hasKeys = false;
          if (service && (service as any).hasPeerKeys) {
            hasKeys = (service as any).hasPeerKeys(peer);
          }

          if (!hasKeys) {
            const keys = await refs.getPeerKeys(peer);
            if (keys) {
              const peerKeys = {
                username: peer,
                dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(keys.dilithiumPublicBase64),
                kyberPublicKey: PostQuantumUtils.base64ToUint8Array(keys.kyberPublicBase64),
                x25519PublicKey: keys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(keys.x25519PublicBase64) : undefined
              };

              // Validate keys
              if (peerKeys.dilithiumPublicKey.length > 0 && peerKeys.kyberPublicKey.length > 0) {
                refs.serviceRef.current.setPeerKeys(peer, peerKeys as any);
              }
            }
          }
        } catch (keyError) {
          console.warn('Failed to fetch keys for answering call:', keyError);
        }
      }

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

            let hasKeys = false;
            if (service && (service as any).hasPeerKeys) {
              hasKeys = (service as any).hasPeerKeys(peer);
            }

            if (!hasKeys) {
              const keys = await refs.getPeerKeys(peer);

              if (keys) {
                const peerKeys = {
                  username: peer,
                  dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(keys.dilithiumPublicBase64),
                  kyberPublicKey: PostQuantumUtils.base64ToUint8Array(keys.kyberPublicBase64),
                  x25519PublicKey: keys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(keys.x25519PublicBase64) : undefined
                };

                if (peerKeys.dilithiumPublicKey.length > 0 && peerKeys.kyberPublicKey.length > 0) {
                  service.setPeerKeys(peer, peerKeys as any);
                }
              }
            }
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
