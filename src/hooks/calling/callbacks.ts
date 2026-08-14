import React from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService, CallState } from '../../lib/transport/secure-calling-service';
import { EventType } from '../../lib/types/event-types';
import { clearCallMediaState, stopMediaStream, EventDebouncer } from '../../lib/utils/calling-utils';
import { notifications, power, tray } from '../../lib/tauri-bindings';
import { toast } from 'sonner';

export interface CallbackRefs {
  localStreamRef: React.RefObject<MediaStream | null>;
  remoteStreamRef: React.RefObject<MediaStream | null>;
  remoteScreenStreamRef: React.RefObject<MediaStream | null>;
  everConnectedRef: React.RefObject<Set<string>>;
  lastCallTypeRef: React.RefObject<Map<string, 'audio' | 'video'>>;
  eventDebouncer: React.RefObject<EventDebouncer>;
}

export interface CallbackSetters {
  setCurrentCall: React.Dispatch<React.SetStateAction<CallState | null>>;
  setLocalStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
  setRemoteStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
  setRemoteScreenStream: React.Dispatch<React.SetStateAction<MediaStream | null>>;
}

// Register the handler for incoming calls
export const setupIncomingCallCallback = (
  service: SecureCallingService,
  refs: CallbackRefs,
  setters: CallbackSetters,
  account: string
) => {
  service.onIncomingCall((call) => {
    setters.setCurrentCall({ ...call });
    if (document.hidden || !document.hasFocus()) {
      void notifications.show().catch(() => { });
      void tray.incrementUnread().catch(() => { });
    }
    refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
      account,
      type: 'incoming',
      peer: call.peer,
      at: Date.now(),
      callId: call.id,
      isVideo: call.type === 'video',
      isOutgoing: call.direction === 'outgoing'
    });
  });
};

// Keep call state updates in sync, emit telemetry, and clean up media when the call changes
export const setupCallStateChangeCallback = (
  service: SecureCallingService,
  refs: CallbackRefs,
  setters: CallbackSetters,
  account: string
) => {
  service.onCallStateChange((call) => {
    const previousType = refs.lastCallTypeRef.current.get(call.id);
    if (previousType && previousType !== call.type && previousType === 'video' && call.type === 'audio') {
      toast.warning('Video unavailable', {
        description: 'This call has switched to audio-only because video could not be started.'
      });
    }
    refs.lastCallTypeRef.current.set(call.id, call.type);

    const statusDetail = {
      account,
      peer: call.peer,
      status: call.status,
      type: call.type,
      direction: call.direction,
      startTime: call.startTime,
      endTime: call.endTime
    };
    const statusNeedsImmediateDispatch = call.status === 'ended' || call.status === 'declined' || call.status === 'missed';
    refs.eventDebouncer.current.enqueue(EventType.UI_CALL_STATUS, statusDetail, statusNeedsImmediateDispatch);

    const wasConnected = refs.everConnectedRef.current.has(call.id);

    if (call.status === 'connecting') {
      power.start().catch(() => { });
      refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
        account,
        type: 'started',
        peer: call.peer,
        at: Date.now(),
        callId: call.id,
        isVideo: call.type === 'video',
        isOutgoing: call.direction === 'outgoing'
      });
    } else if (call.status === 'connected') {
      try { refs.everConnectedRef.current.add(call.id); } catch { }
      power.start().catch(() => { });
      refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
        account,
        type: 'connected',
        peer: call.peer,
        at: Date.now(),
        callId: call.id,
        isVideo: call.type === 'video',
        isOutgoing: call.direction === 'outgoing'
      });
    }

    if (call.status === 'ended' || call.status === 'declined' || call.status === 'missed') {
      power.stop().catch(() => { });

      refs.lastCallTypeRef.current.delete(call.id);

      if (call.status === 'ended') {
        if (!wasConnected) {
          if (call.direction === 'incoming') {
            refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
              account,
              type: 'missed',
              peer: call.peer,
              at: Date.now(),
              callId: call.id,
              isVideo: call.type === 'video',
              isOutgoing: false
            });
          } else {
            refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
              account,
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
          refs.eventDebouncer.current.enqueue(EventType.UI_CALL_ENDED, {
            account,
            peer: call.peer,
            type: call.type,
            startTime: call.startTime,
            endTime: call.endTime,
            durationMs
          });
          refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
            account,
            type: 'ended',
            peer: call.peer,
            at: Date.now(),
            callId: call.id,
            durationMs,
            isVideo: call.type === 'video',
            isOutgoing: call.direction === 'outgoing'
          });
        }
      }

      if (call.status === 'declined') {
        refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
          account,
          type: 'declined',
          peer: call.peer,
          at: Date.now(),
          callId: call.id,
          isVideo: call.type === 'video',
          isOutgoing: call.direction === 'outgoing'
        });
      }

      if (call.status === 'missed') {
        refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
          account,
          type: 'missed',
          peer: call.peer,
          at: Date.now(),
          callId: call.id,
          isVideo: call.type === 'video',
          isOutgoing: call.direction === 'outgoing'
        });
      }

      unstable_batchedUpdates(() => {
        setters.setCurrentCall(null);
        clearCallMediaState(refs, setters);
      });
      try { refs.everConnectedRef.current.delete(call.id); } catch { }
    } else {
      unstable_batchedUpdates(() => {
        setters.setCurrentCall({ ...call });
      });
    }
  });
};

// Track local, remote, and screen share streams
export const setupStreamCallbacks = (
  service: SecureCallingService,
  refs: CallbackRefs,
  setters: CallbackSetters
) => {
  service.onLocalStream((stream) => {
    const previous = refs.localStreamRef.current;
    if (previous && previous !== stream) stopMediaStream(previous);
    unstable_batchedUpdates(() => {
      refs.localStreamRef.current = stream;
      setters.setLocalStream(stream);
    });
  });

  service.onRemoteStream((stream) => {
    const previous = refs.remoteStreamRef.current;
    if (previous && previous !== stream) stopMediaStream(previous);
    unstable_batchedUpdates(() => {
      refs.remoteStreamRef.current = stream;
      setters.setRemoteStream(stream);
    });
  });

  service.onRemoteScreenStream((stream) => {
    const previous = refs.remoteScreenStreamRef.current;
    if (previous && previous !== stream) stopMediaStream(previous);
    unstable_batchedUpdates(() => {
      refs.remoteScreenStreamRef.current = stream;
      setters.setRemoteScreenStream(stream);
    });
  });
};
