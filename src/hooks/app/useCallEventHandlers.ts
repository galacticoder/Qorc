import { useCallback, useEffect, useRef } from 'react';
import { Message } from '../../components/chat/messaging/types';
import { EventType } from '../../lib/types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';
import { truncateUsername } from '../../lib/utils/avatar-utils';
import { resolveDisplayUsername } from '../../lib/database/unified-username-display';
import {
  LOCAL_EVENT_RATE_LIMIT_WINDOW_MS,
  LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS,
} from '../../lib/constants';

interface CallEventHandlersProps {
  stableGetDisplayUsername: (username: string) => Promise<string>;
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  selectedConversation: string | null;
  saveMessageToLocalDB: (message: Message, peer?: string) => Promise<void>;
  startCall: (peer: string, type?: 'audio' | 'video') => Promise<any>;
  callHistory: {
    addCallLog: (log: {
      peerUsername: string;
      type: 'audio' | 'video';
      direction: 'incoming' | 'outgoing';
      status: 'completed' | 'missed' | 'declined';
      startTime: number;
      duration?: number;
    }) => void;
  };
}

export function useCallEventHandlers({
  stableGetDisplayUsername,
  setMessages,
  selectedConversation,
  saveMessageToLocalDB,
  startCall,
  callHistory,
}: CallEventHandlersProps) {
  const uiEventRateRef = useRef({ windowStart: Date.now(), count: 0 });

  const handleCallLog = useCallback(async (e: Event) => {
    try {
      const now = Date.now();
      const bucket = uiEventRateRef.current;
      if (now - bucket.windowStart > LOCAL_EVENT_RATE_LIMIT_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS) {
        return;
      }

      if (!(e instanceof CustomEvent)) return;
      const detail = e.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const peer = (detail as any).peer;
      if (typeof peer !== 'string') return;

      const eventType = (detail as any).type;
      if (typeof eventType !== 'string') return;

      const callId = (detail as any).callId || crypto.randomUUID();
      const at = (detail as any).at || Date.now();
      const durationMs = (detail as any).durationMs || 0;
      const isVideo = (detail as any).isVideo === true;
      const isOutgoing = (detail as any).isOutgoing === true;

      const displayPeerName = truncateUsername(await resolveDisplayUsername(peer, stableGetDisplayUsername));
      const durationSeconds = Math.round(durationMs / 1000);

      const { addCallLog } = callHistory;
      if (['ended', 'missed', 'declined'].includes(eventType)) {
        addCallLog({
          peerUsername: peer,
          type: isVideo ? 'video' : 'audio',
          direction: isOutgoing ? 'outgoing' : 'incoming',
          status: eventType === 'missed' ? 'missed' : eventType === 'declined' ? 'declined' : 'completed',
          startTime: at,
          ...(eventType === 'ended' && durationSeconds > 0 ? { duration: durationSeconds } : {})
        });
      }

      const label = eventType === 'incoming' ? `Incoming call from ${displayPeerName}`
        : eventType === 'connected' ? `Call connected with ${displayPeerName}`
          : eventType === 'started' ? `Calling ${displayPeerName}...`
            : eventType === 'ended' ? `Call with ${displayPeerName} ended`
              : eventType === 'declined' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                : eventType === 'missed' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                  : eventType === 'not-answered' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                    : `Call event: ${eventType}`;

      const shouldHaveActions = ['missed', 'not-answered', 'ended', 'declined'].includes(eventType);
      const actions = shouldHaveActions
        ? [{ label: 'Call back', onClick: () => startCall(peer, 'audio').catch(() => { }) }]
        : undefined;

      const newMessage: Message = {
        id: `call-log-${callId}-${eventType}-${at}`,
        content: JSON.stringify({ label, actionsType: actions ? 'callback' : undefined, isError: eventType === 'missed' }),
        sender: peer,
        recipient: peer,
        timestamp: new Date(at),
        isCurrentUser: false,
        isSystemMessage: true,
        type: 'system'
      } as Message;

      if (peer === selectedConversation) {
        setMessages((prev) => [...prev, newMessage]);
      }
      void saveMessageToLocalDB(newMessage, peer);
    } catch { }
  }, [stableGetDisplayUsername, setMessages, selectedConversation, saveMessageToLocalDB, startCall, callHistory]);

  const handleCallRequest = useCallback((e: Event) => {
    try {
      const now = Date.now();
      const bucket = uiEventRateRef.current;
      if (now - bucket.windowStart > LOCAL_EVENT_RATE_LIMIT_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS) {
        return;
      }

      if (!(e instanceof CustomEvent)) return;
      const detail = e.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const peer = (detail as any).peer;
      if (typeof peer !== 'string') return;

      const requestedType = (detail as any).type;
      const callType = requestedType === 'video' ? 'video' : 'audio';

      startCall(peer, callType).catch(() => { });
    } catch { }
  }, [startCall]);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_LOG, handleCallLog as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_LOG, handleCallLog as EventListener);
  }, [handleCallLog]);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_REQUEST, handleCallRequest as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_REQUEST, handleCallRequest as EventListener);
  }, [handleCallRequest]);
}
