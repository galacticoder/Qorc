import { useEffect, useLayoutEffect, useRef } from 'react';
import { EventType } from '../../lib/types/event-types';
import { keyTransparencyClient } from '../../lib/key-transparency/client';
import { taggedLaneRetriever } from '../../lib/spool/tagged-lane-retriever';

// Offline retrieval
interface OfflineMessagesProps {
  encryptedHandlerRef: React.RefObject<(msg: any) => Promise<boolean>>;
  hybridKeysRef: React.RefObject<any>;
  isReady: boolean;
  username?: string | null;
}

export function useOfflineMessages({
  encryptedHandlerRef,
  hybridKeysRef,
  isReady,
  username,
}: OfflineMessagesProps) {
  const isReadyRef = useRef(isReady);

  useLayoutEffect(() => {
    isReadyRef.current = isReady;
  }, [isReady]);

  useEffect(() => {
    const startTaggedLane = () => {
      if (
        !username ||
        !isReadyRef.current ||
        keyTransparencyClient.isSecurityIncidentActive()
      ) {
        try { taggedLaneRetriever.stop(); } catch { }
        return;
      }
      try {
        taggedLaneRetriever.configure(
          username,
          async (msg) => {
            if (hybridKeysRef.current?.native !== true) return false;
            return (await encryptedHandlerRef.current(msg)) !== false;
          }
        );
        taggedLaneRetriever.start();
      } catch { }
    };

    if (isReady) {
      startTaggedLane();
    } else {
      try { taggedLaneRetriever.stop(); } catch { }
    }
    window.addEventListener(EventType.WS_RECONNECTED, startTaggedLane);
    window.addEventListener(EventType.PQ_SESSION_ESTABLISHED, startTaggedLane);
    window.addEventListener(EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT, startTaggedLane);
    return () => {
      try { taggedLaneRetriever.stop(); } catch { }
      window.removeEventListener(EventType.WS_RECONNECTED, startTaggedLane);
      window.removeEventListener(EventType.PQ_SESSION_ESTABLISHED, startTaggedLane);
      window.removeEventListener(EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT, startTaggedLane);
    };
  }, [isReady, username, encryptedHandlerRef, hybridKeysRef]);
}
