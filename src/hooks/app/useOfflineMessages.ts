import { useEffect, useRef } from 'react';
import { offlineMessageQueue } from '../../lib/websocket/offline-message-handler';
import { EventType } from '../../lib/types/event-types';

interface OfflineMessagesProps {
  encryptedHandlerRef: React.RefObject<(msg: any) => Promise<void>>;
  hybridKeysRef: React.RefObject<any>;
}

export function useOfflineMessages({
  encryptedHandlerRef,
  hybridKeysRef,
}: OfflineMessagesProps) {
  const offlineCallbackSetRef = useRef(false);
  useEffect(() => {
    if (offlineCallbackSetRef.current) return;
    offlineCallbackSetRef.current = true;

    try {
      offlineMessageQueue.setIncomingOfflineEncryptedMessageCallback(async (msg: any) => {
        await encryptedHandlerRef.current(msg);
      });
    } catch { }
  }, []);

  useEffect(() => {
    const applyKey = () => {
      const kyberSecret = hybridKeysRef?.current?.kyber?.secretKey;
      if (kyberSecret && kyberSecret instanceof Uint8Array) {
        try {
          offlineMessageQueue.setDecryptionKey(kyberSecret);
        } catch { }
      } else {
        try {
          offlineMessageQueue.clearDecryptionKey();
        } catch { }
      }
    };

    applyKey();

    const onKeysUpdated = () => applyKey();
    try {
      window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
      } catch { }
    };
  }, [hybridKeysRef.current]);
}
