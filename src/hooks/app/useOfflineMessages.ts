import { useEffect, useRef } from 'react';
import { EventType } from '../../lib/types/event-types';
import { globalSpoolPirQueue } from '../../lib/websocket/global-spool-pir-handler';

interface OfflineMessagesProps {
  encryptedHandlerRef: React.RefObject<(msg: any) => Promise<void>>;
  hybridKeysRef: React.RefObject<any>;
  isReady: boolean;
}

export function useOfflineMessages({
  encryptedHandlerRef,
  hybridKeysRef: _hybridKeysRef,
  isReady,
}: OfflineMessagesProps) {
  const offlineCallbackSetRef = useRef(false);
  const isReadyRef = useRef(isReady);

  useEffect(() => {
    isReadyRef.current = isReady;
  }, [isReady]);

  useEffect(() => {
    if (offlineCallbackSetRef.current) return;
    offlineCallbackSetRef.current = true;

    try {
      globalSpoolPirQueue.setIncomingCandidateCallback(async (msg: any) => {
        if (!isReadyRef.current) {
          console.warn('[SPOOL] candidate dropped: app not ready');
          return;
        }
        await encryptedHandlerRef.current(msg);
      });
    } catch { }
  }, []);

  useEffect(() => {
    const startLoop = () => {
      if (!isReadyRef.current) {
        console.log('[SPOOL] startLoop skipped: app not ready');
        try {
          globalSpoolPirQueue.stopDeliveryLoop();
        } catch { }
        return;
      }
      console.log('[SPOOL] startLoop: (re)arming delivery loop');
      try {
        globalSpoolPirQueue.stopDeliveryLoop();
        globalSpoolPirQueue.startDeliveryLoop();
      } catch { }
    };

    if (isReady) {
      startLoop();
    } else {
      try {
        globalSpoolPirQueue.stopDeliveryLoop();
      } catch { }
    }
    window.addEventListener(EventType.WS_RECONNECTED, startLoop);
    window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, startLoop);
    return () => {
      try {
        globalSpoolPirQueue.stopDeliveryLoop();
      } catch { }
      window.removeEventListener(EventType.WS_RECONNECTED, startLoop);
      window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, startLoop);
    };
  }, [isReady]);
}
