import React, { useEffect } from 'react';
import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';

interface UseP2PSignalHandlersProps {
  p2pMessaging?: unknown;
}

export function useP2PSignalHandlers({ p2pMessaging: _p2pMessaging }: UseP2PSignalHandlersProps) {
  // Handle outgoing P2P session reset requests
  useEffect(() => {
    const handler = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const to: string = d?.to;
        const reason: string | undefined = d?.reason;
        const recipientInboxId: string | undefined = d?.recipientInboxId || d?.inboxId;
        const destinationRouteId: string | undefined = d?.destinationRouteId || d?.routeId;
        const destinationMailboxLookupId: string | undefined = d?.destinationMailboxLookupId || d?.mailboxLookupId;
        if (!to) return;

        try {
          await unifiedSignalTransport.send(
            to,
            { reason },
            SignalType.SESSION_RESET_REQUEST,
            recipientInboxId || destinationRouteId ? { recipientInboxId, destinationRouteId, destinationMailboxLookupId } : undefined
          );
        } catch { }
      } catch { }
    };

    try { window.addEventListener(EventType.P2P_SESSION_RESET_SEND, handler as EventListener); } catch { }
    return () => { try { window.removeEventListener(EventType.P2P_SESSION_RESET_SEND, handler as EventListener); } catch { } };
  }, []);

  // Handle outgoing P2P call signals
  useEffect(() => {
    const handler = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const to: string = d?.to;
        const signalObj: any = d?.signal;
        const requestId: string = d?.requestId || '';
        if (!to || !signalObj) return;

        let success = false;
        try {
          try {
            const result = await unifiedSignalTransport.send(to, signalObj, SignalType.CALL_SIGNAL);
            success = result.success;
          } catch { }
        } catch { }

        try {
          window.dispatchEvent(new CustomEvent(EventType.P2P_CALL_SIGNAL_RESULT, { detail: { requestId, success } }));
        } catch { }
      } catch { }
    };

    try { window.addEventListener(EventType.P2P_CALL_SIGNAL_SEND, handler as EventListener); } catch { }
    return () => { try { window.removeEventListener(EventType.P2P_CALL_SIGNAL_SEND, handler as EventListener); } catch { } };
  }, []);
}
