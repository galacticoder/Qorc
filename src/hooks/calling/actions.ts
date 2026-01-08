import React from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { isValidCallingUsername, isValidCallId, stopMediaStream } from '../../lib/utils/calling-utils';
import { PostQuantumUtils } from '../../lib/utils/pq-utils';

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
      throw new Error('[useCalling] Calling service not initialized');
    }

    const peer = targetUser.trim();
    if (!isValidCallingUsername(peer)) {
      throw new Error('[useCalling] Invalid target username format');
    }

    if (callType !== 'audio' && callType !== 'video') {
      throw new Error('[useCalling] Invalid call type');
    }

    if (peer === currentUsername) {
      throw new Error('[useCalling] Cannot call yourself');
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
          console.warn('[useCalling] Failed to fetch keys for peer call:', keyError);
        }
      }

      const callId = await refs.serviceRef.current.startCall(peer, callType);
      return callId;
    } catch (_error: any) {
      if (_error.message === 'arbitration-loss') {
        return '';
      }
      console.error('[useCalling] Failed to start call:', _error);
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
      throw new Error('[useCalling] Calling service not initialized');
    }

    if (!isValidCallId(callId)) {
      throw new Error('[useCalling] Invalid call ID format');
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
          console.warn('[useCalling] Failed to fetch keys for answering call:', keyError);
        }
      }

      await refs.serviceRef.current.answerCall(callId);
    } catch (_error) {
      console.error('[useCalling] Failed to answer call:', _error);
      throw _error;
    }
  };
};

// Callback for declining a call
export const createDeclineCall = (refs: ActionRefs) => {
  return async (callId: string) => {
    if (!refs.serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    if (!isValidCallId(callId)) {
      throw new Error('[useCalling] Invalid call ID format');
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
          console.warn('[useCalling] Failed to fetch keys for decline call:', keyError);
        }
      }

      await refs.serviceRef.current.declineCall(callId);
    } catch (_error) {
      console.error('[useCalling] Failed to decline call:', _error);
      throw _error;
    }
  };
};

// Callback for ending the current call
export const createEndCall = (refs: ActionRefs) => {
  return async () => {
    if (!refs.serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    try {
      await refs.serviceRef.current.endCall();
    } catch (_error) {
      console.error('[useCalling] Failed to end call:', _error);
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
      console.error('[useCalling] Failed to switch camera:', _error);
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
      console.error('[useCalling] Failed to switch microphone:', _error);
    }
  };
};

// Callback for starting screen share
export const createStartScreenShare = (refs: ActionRefs) => {
  return async (selectedSource?: { id: string; name: string; type: 'screen' | 'window' }) => {
    if (!refs.serviceRef.current) {
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
      await refs.serviceRef.current.startScreenShare(selectedSource);
    } catch (_error) {
      console.error('[useCalling] Failed to start screen sharing:', _error);
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
      console.error('[useCalling] Failed to stop screen sharing:', _error);
    }
  };
};

// Callback for exposing screen sources on desktop
export const createGetAvailableScreenSources = (refs: ActionRefs) => {
  const electronApi = (window as any).electronAPI;
  const edgeApi = (window as any).edgeApi;
  const isElectron = !!(electronApi || edgeApi);

  if (!isElectron) return undefined;

  return async () => {
    if (!refs.serviceRef.current) {
      throw new Error('[useCalling] Calling service not initialized');
    }

    try {
      return await refs.serviceRef.current.getAvailableScreenSources();
    } catch (_error) {
      console.error('[useCalling] Failed to get screen sources:', _error);
      throw _error;
    }
  };
};
