import { useCallback, useEffect, useLayoutEffect, useRef } from 'react';
import { Message } from '../../components/chat/messaging/types';
import { EventType } from '../../lib/types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';
import { truncateUsername } from '../../lib/utils/avatar-utils';
import { isValidCallId, isValidCallingUsername } from '../../lib/utils/calling-utils';
import {
  LOCAL_EVENT_RATE_LIMIT_WINDOW_MS,
  LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS,
} from '../../lib/constants';

interface CallEventHandlersProps {
  currentUsername: string;
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
  currentUsername,
  setMessages,
  selectedConversation,
  saveMessageToLocalDB,
  startCall,
  callHistory,
}: CallEventHandlersProps) {
  const uiEventRateRef = useRef({ windowStart: Date.now(), count: 0 });
  const activeAccountRef = useRef(currentUsername);
  const accountGenerationRef = useRef(0);

  useLayoutEffect(() => {
    if (activeAccountRef.current === currentUsername) return;
    activeAccountRef.current = currentUsername;
    accountGenerationRef.current += 1;
  }, [currentUsername]);

  useEffect(() => {
    uiEventRateRef.current = { windowStart: Date.now(), count: 0 };
  }, [currentUsername]);

  const handleCallLog = useCallback((e: Event) => {
    try {
      const account = currentUsername;
      const generation = accountGenerationRef.current;
      const isCurrent = () => !!account &&
        activeAccountRef.current === account &&
        accountGenerationRef.current === generation;
      if (!isCurrent()) return;
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
      const detailKeys = Object.keys(detail).sort().join(',');
      if (
        detailKeys !== 'account,at,callId,isOutgoing,isVideo,peer,type' &&
        detailKeys !== 'account,at,callId,durationMs,isOutgoing,isVideo,peer,type' &&
        detailKeys !== 'account,at,callId,historyOnly,isOutgoing,isVideo,peer,type'
      ) return;
      if ((detail as any).account !== currentUsername || !currentUsername) return;

      const peer = (detail as any).peer;
      if (typeof peer !== 'string' || peer !== peer.trim().toLowerCase() || !isValidCallingUsername(peer)) return;

      const eventType = (detail as any).type;
      if (!['incoming', 'connected', 'started', 'ended', 'missed', 'declined'].includes(eventType)) return;

      const callId = (detail as any).callId;
      const at = (detail as any).at;
      const durationMs = (detail as any).durationMs ?? 0;
      const isVideo = (detail as any).isVideo;
      const isOutgoing = (detail as any).isOutgoing;
      const historyOnly = (detail as any).historyOnly ?? false;
      if (
        !isValidCallId(callId) ||
        !Number.isSafeInteger(at) || at < 0 || at > now + 5 * 60 * 1000 ||
        !Number.isSafeInteger(durationMs) || durationMs < 0 || durationMs > 30 * 24 * 60 * 60 * 1000 ||
        typeof isVideo !== 'boolean' ||
        typeof isOutgoing !== 'boolean' ||
        typeof historyOnly !== 'boolean'
      ) return;

      const displayPeerName = truncateUsername(peer);
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
      if (historyOnly) return;

      const label = eventType === 'incoming' ? `Incoming call from ${displayPeerName}`
        : eventType === 'connected' ? `Call connected with ${displayPeerName}`
          : eventType === 'started' ? `Calling ${displayPeerName}...`
            : eventType === 'ended' ? `Call with ${displayPeerName} ended`
              : eventType === 'declined' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                : eventType === 'missed' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                  : `Call event: ${eventType}`;

      const shouldHaveActions = ['missed', 'ended', 'declined'].includes(eventType);
      const actions = shouldHaveActions
        ? [{ label: 'Call back', onClick: () => startCall(peer, 'audio').catch(() => { }) }]
        : undefined;

      const newMessage: Message = {
        id: `call-log-${callId}-${eventType}-${at}`,
        content: JSON.stringify({ label, actionsType: actions ? 'callback' : undefined, isError: eventType === 'missed' }),
        sender: peer,
        recipient: currentUsername,
        timestamp: new Date(at),
        isCurrentUser: false,
        isSystemMessage: true,
        type: 'system'
      } as Message;

      if (peer === selectedConversation) {
        setMessages((prev) => isCurrent() ? [...prev, newMessage] : prev);
      }
      if (isCurrent()) void saveMessageToLocalDB(newMessage, peer).catch(() => { });
    } catch { }
  }, [currentUsername, setMessages, selectedConversation, saveMessageToLocalDB, startCall, callHistory]);

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
      if (Object.keys(detail).sort().join(',') !== 'account,peer,type') return;
      if ((detail as any).account !== currentUsername || !currentUsername) return;

      const peer = (detail as any).peer;
      if (typeof peer !== 'string' || peer !== peer.trim().toLowerCase() || !isValidCallingUsername(peer)) return;

      const requestedType = (detail as any).type;
      if (requestedType !== 'audio' && requestedType !== 'video') return;
      const callType = requestedType;

      startCall(peer, callType).catch(() => { });
    } catch { }
  }, [startCall, currentUsername]);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_LOG, handleCallLog as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_LOG, handleCallLog as EventListener);
  }, [handleCallLog]);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_REQUEST, handleCallRequest as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_REQUEST, handleCallRequest as EventListener);
  }, [handleCallRequest]);
}
