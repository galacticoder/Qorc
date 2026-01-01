import React, { useEffect } from 'react';
import { EventType } from '../../lib/event-types';
import { SignalType } from '../../lib/signal-types';

interface UseP2PSignalHandlersProps {
  p2pMessaging: {
    isPeerConnected: (peer: string) => boolean;
    connectToPeer: (peer: string) => Promise<void>;
    p2pServiceRef?: React.RefObject<any>;
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
        if (!to) return;

        try {
          if (!p2pMessaging.isPeerConnected(to)) {
            try { await p2pMessaging.connectToPeer(to); } catch { }
            await (p2pMessaging as any).waitForPeerConnection?.(to, 5000).catch(() => { });
          }
          await (p2pMessaging as any)?.p2pServiceRef?.current?.sendMessage?.(to, { kind: SignalType.SESSION_RESET_REQUEST, reason }, 'signal');
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

          const svc: any = (window as any).p2pService || (p2pMessaging as any)?.p2pServiceRef?.current || null;
          if (svc && typeof svc.sendMessage === 'function') {
            try {
              await svc.sendMessage(to, { kind: EventType.CALL_SIGNAL, signal: signalObj }, 'signal');
              success = true;
            } catch {
              // Wait for PQ establishment and retry
              await new Promise<void>((resolve) => {
                let settled = false;
                const t = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
                const on = (ev: Event) => {
                  const p = (ev as CustomEvent).detail?.peer;
                  if (p === to) { if (!settled) { settled = true; clearTimeout(t); } resolve(); }
                };
                window.addEventListener(EventType.P2P_PQ_ESTABLISHED, on as EventListener, { once: true });
              });
              try {
                await svc.sendMessage(to, { kind: EventType.CALL_SIGNAL, signal: signalObj }, 'signal');
                success = true;
              } catch { }
            }
          }
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
