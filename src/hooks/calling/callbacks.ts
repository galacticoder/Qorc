import React from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService, CallState } from '../../lib/transport/secure-calling-service';
import { EventType } from '../../lib/types/event-types';
import { stopMediaStream, EventDebouncer } from '../../lib/utils/calling-utils';

export interface CallbackRefs {
  localStreamRef: React.RefObject<MediaStream | null>;
  remoteStreamRef: React.RefObject<MediaStream | null>;
  remoteScreenStreamRef: React.RefObject<MediaStream | null>;
  everConnectedRef: React.RefObject<Set<string>>;
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
  setters: CallbackSetters
) => {
  service.onIncomingCall((call) => {
    setters.setCurrentCall({ ...call });
    refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
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
  setters: CallbackSetters
) => {
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
    refs.eventDebouncer.current.enqueue(EventType.UI_CALL_STATUS, statusDetail, statusNeedsImmediateDispatch);

    const wasConnected = refs.everConnectedRef.current.has(call.id);

    if (call.status === 'connecting') {
      try { (window as any).edgeApi?.powerSaveBlockerStart?.(); } catch { }
      refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
        type: 'started',
        peer: call.peer,
        at: Date.now(),
        callId: call.id,
        isVideo: call.type === 'video',
        isOutgoing: call.direction === 'outgoing'
      });
    } else if (call.status === 'connected') {
      try { refs.everConnectedRef.current.add(call.id); } catch { }
      try { (window as any).edgeApi?.powerSaveBlockerStart?.(); } catch { }
      refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
        type: 'connected',
        peer: call.peer,
        at: Date.now(),
        callId: call.id,
        isVideo: call.type === 'video',
        isOutgoing: call.direction === 'outgoing'
      });
    }

    if (call.status === 'ended' || call.status === 'declined' || call.status === 'missed') {
      try { (window as any).edgeApi?.powerSaveBlockerStop?.(); } catch { }

      if (call.status === 'ended') {
        if (!wasConnected) {
          if (call.direction === 'incoming') {
            refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
              type: 'missed',
              peer: call.peer,
              at: Date.now(),
              callId: call.id,
              isVideo: call.type === 'video',
              isOutgoing: false
            });
          } else {
            refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
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
            peer: call.peer,
            type: call.type,
            startTime: call.startTime,
            endTime: call.endTime,
            durationMs
          });
          refs.eventDebouncer.current.enqueue(EventType.UI_CALL_LOG, {
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
    stopMediaStream(refs.localStreamRef.current);
    unstable_batchedUpdates(() => {
      refs.localStreamRef.current = stream;
      setters.setLocalStream(stream);
    });
  });

  service.onRemoteStream((stream) => {
    stopMediaStream(refs.remoteStreamRef.current);
    unstable_batchedUpdates(() => {
      refs.remoteStreamRef.current = stream;
      setters.setRemoteStream(stream);
    });
  });

  service.onRemoteScreenStream((stream) => {
    stopMediaStream(refs.remoteScreenStreamRef.current);
    unstable_batchedUpdates(() => {
      refs.remoteScreenStreamRef.current = stream;
      setters.setRemoteScreenStream(stream);
    });
  });
};
