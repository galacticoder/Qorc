import React from 'react';
import { unstable_batchedUpdates } from 'react-dom';
import { SecureCallingService } from '../../lib/transport/secure-calling-service';
import { EventType } from '../../lib/types/event-types';
import { clearCallMediaState, releaseVisualCanvas, EventDebouncer } from '../../lib/utils/calling-utils';
import { notifications, power, tray } from '../../lib/tauri-bindings';
import { CallState } from '../../lib/types/calling-types';
import { getNotificationMutes } from '../../lib/ui/notification-preferences';

export interface CallbackRefs {
  localMediaActiveRef: React.RefObject<boolean>;
  localVideoCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  localScreenCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  remoteVideoCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  remoteScreenCanvasRef: React.RefObject<HTMLCanvasElement | null>;
  everConnectedRef: React.RefObject<Set<string>>;
  eventDebouncer: React.RefObject<EventDebouncer>;
}

export interface CallbackSetters {
  setCurrentCall: React.Dispatch<React.SetStateAction<CallState | null>>;
  setPendingIncomingCalls: React.Dispatch<React.SetStateAction<CallState[]>>;
  setLocalMediaActive: React.Dispatch<React.SetStateAction<boolean>>;
  setLocalVideoCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
  setLocalScreenCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
  setRemoteVideoCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
  setRemoteScreenCanvas: React.Dispatch<React.SetStateAction<HTMLCanvasElement | null>>;
}

export const setupIncomingCallCallback = (
  service: SecureCallingService,
  refs: CallbackRefs,
  setters: CallbackSetters,
  account: string
) => {
  service.onIncomingCall((call) => {
    setters.setPendingIncomingCalls(previous => (
      previous.some(candidate => candidate.id === call.id)
        ? previous.map(candidate => candidate.id === call.id ? { ...call } : candidate)
        : [...previous, { ...call }]
    ));
    if (!getNotificationMutes(call.peer).calls && (document.hidden || !document.hasFocus())) {
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

export const setupCallStateChangeCallback = (
  service: SecureCallingService,
  refs: CallbackRefs,
  setters: CallbackSetters,
  account: string
) => {
  service.onCallStateChange((call, isActive) => {
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
    } else if (call.status === 'connected' && isActive) {
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
      if (isActive) power.stop().catch(() => { });

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
        setters.setPendingIncomingCalls(previous => previous.filter(candidate => candidate.id !== call.id));
        if (isActive) {
          setters.setCurrentCall(previous => previous?.id === call.id ? null : previous);
          clearCallMediaState(refs, setters);
        }
      });
      try { refs.everConnectedRef.current.delete(call.id); } catch { }
    } else if (isActive) {
      unstable_batchedUpdates(() => {
        setters.setPendingIncomingCalls(previous => previous.filter(candidate => candidate.id !== call.id));
        setters.setCurrentCall({ ...call });
      });
    } else if (call.direction === 'incoming' && call.status === 'ringing') {
      setters.setPendingIncomingCalls(previous => (
        previous.some(candidate => candidate.id === call.id)
          ? previous.map(candidate => candidate.id === call.id ? { ...call } : candidate)
          : [...previous, { ...call }]
      ));
    }
  });
};

// Track local capture and remote render surfaces
export const setupStreamCallbacks = (
  service: SecureCallingService,
  refs: CallbackRefs,
  setters: CallbackSetters
) => {
  service.onLocalMediaChange((active) => {
    unstable_batchedUpdates(() => {
      refs.localMediaActiveRef.current = active;
      setters.setLocalMediaActive(active);
    });
  });

  service.onLocalVideoCanvas((canvas) => {
    unstable_batchedUpdates(() => {
      refs.localVideoCanvasRef.current = canvas;
      setters.setLocalVideoCanvas(canvas);
    });
  });

  service.onLocalScreenCanvas((canvas) => {
    unstable_batchedUpdates(() => {
      refs.localScreenCanvasRef.current = canvas;
      setters.setLocalScreenCanvas(canvas);
    });
  });

  service.onRemoteVideoCanvas((canvas) => {
    const previous = refs.remoteVideoCanvasRef.current;
    if (previous && previous !== canvas) releaseVisualCanvas(previous);
    unstable_batchedUpdates(() => {
      refs.remoteVideoCanvasRef.current = canvas;
      setters.setRemoteVideoCanvas(canvas);
    });
  });

  service.onRemoteScreenCanvas((canvas) => {
    const previous = refs.remoteScreenCanvasRef.current;
    if (previous && previous !== canvas) releaseVisualCanvas(previous);
    unstable_batchedUpdates(() => {
      refs.remoteScreenCanvasRef.current = canvas;
      setters.setRemoteScreenCanvas(canvas);
    });
  });
};
