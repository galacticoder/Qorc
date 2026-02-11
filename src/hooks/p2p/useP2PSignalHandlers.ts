import React, { useEffect } from 'react';
import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';

interface UseP2PSignalHandlersProps {
  p2pMessaging: {
    isPeerConnected: (peer: string) => boolean;
    connectToPeer: (peer: string) => Promise<void>;
  };
}

export function useP2PSignalHandlers({ p2pMessaging }: UseP2PSignalHandlersProps) {
  // Handle outgoing P2P session reset requests
  useEffect(() => {
    const handler = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const to: string = d?.to;
        const reason: string | undefined = d?.reason;
        const destinationInbox: string | undefined = d?.destinationInbox || d?.inboxId;
        if (!to) return;

        try {
          if (!p2pMessaging.isPeerConnected(to)) {
            try { await p2pMessaging.connectToPeer(to); } catch { }
            await (p2pMessaging as any).waitForPeerConnection?.(to, 5000).catch(() => { });
          }
          await unifiedSignalTransport.send(
            to,
            { reason },
            SignalType.SESSION_RESET_REQUEST,
            destinationInbox ? { destinationInbox } : undefined
          );
        } catch { }
      } catch { }
    };

    try { window.addEventListener(EventType.P2P_SESSION_RESET_SEND, handler as EventListener); } catch { }
    return () => { try { window.removeEventListener(EventType.P2P_SESSION_RESET_SEND, handler as EventListener); } catch { } };
  }, [p2pMessaging]);

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
          if (!p2pMessaging.isPeerConnected(to)) {
            try { await p2pMessaging.connectToPeer(to); } catch { }
            try { await (p2pMessaging as any).waitForPeerConnection?.(to, 2000); } catch { }
          }

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
  }, [p2pMessaging]);
}
