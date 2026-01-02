import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import websocketClient from '../../lib/websocket';
import type { FailedDeliveryReceipt, HybridKeys, UserWithHybridKeys } from '../../lib/types/message-handling-types';
import { DELIVERY_RECEIPT_PREFIX } from '@/lib/constants';

// Create delivery receipt payload
export const createDeliveryReceiptPayload = (
  messageId: string,
  fromUsername: string,
  toUsername: string
): Record<string, unknown> => ({
  messageId: `${DELIVERY_RECEIPT_PREFIX}-${messageId}`,
  from: fromUsername,
  to: toUsername,
  content: SignalType.DELIVERY_RECEIPT,
  timestamp: Date.now(),
  messageType: SignalType.SIGNAL_PROTOCOL,
  signalType: SignalType.SIGNAL_PROTOCOL,
  protocolType: SignalType.SIGNAL,
  type: SignalType.DELIVERY_RECEIPT
});

// Send encrypted delivery receipt
export const sendEncryptedDeliveryReceipt = async (
  currentUser: string,
  senderUsername: string,
  messageId: string,
  kyber: string | null,
  hybrid: HybridKeys | null,
  failedDeliveryReceiptsRef: React.RefObject<Map<string, FailedDeliveryReceipt>>
): Promise<boolean> => {
  if (!hybrid || !hybrid.dilithiumPublicBase64) {
    return false;
  }

  try {
    const deliveryReceiptData = createDeliveryReceiptPayload(messageId, currentUser, senderUsername);

    let encryptedMessage = await (window as any).edgeApi?.encrypt?.({
      fromUsername: currentUser,
      toUsername: senderUsername,
      plaintext: JSON.stringify(deliveryReceiptData),
      recipientKyberPublicKey: kyber,
      recipientHybridKeys: hybrid || undefined
    });

    if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
      const errMsg = String(encryptedMessage?.error || '');
      if (/session|no valid sessions|no session|invalid whisper message|decryption failed/i.test(errMsg)) {
        const quickWait = new Promise<void>((resolve) => {
          let settled = false;
          const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
          const onReady = (evt: Event) => {
            const d = (evt as CustomEvent).detail;
            if (d?.peer === senderUsername) {
              if (!settled) { settled = true; clearTimeout(timeout); }
              resolve();
            }
          };
          window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, onReady as EventListener, { once: true });
        });
        try { await websocketClient.sendSecureControlMessage({ type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, username: senderUsername }); } catch { }
        await quickWait;
        try {
          encryptedMessage = await (window as any).edgeApi?.encrypt?.({
            fromUsername: currentUser,
            toUsername: senderUsername,
            plaintext: JSON.stringify(deliveryReceiptData),
            recipientKyberPublicKey: kyber,
            recipientHybridKeys: hybrid || undefined
          });
        } catch { }
      }

      if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
        const receiptKey = `${senderUsername}:${messageId}`;
        const existing = failedDeliveryReceiptsRef.current.get(receiptKey);
        const attempts = (existing?.attempts || 0) + 1;
        if (attempts <= 3) {
          failedDeliveryReceiptsRef.current.set(receiptKey, {
            messageId,
            peerUsername: senderUsername,
            timestamp: Date.now(),
            attempts
          });
        }
        return false;
      }
    }

    const deliveryReceiptPayload = {
      type: SignalType.ENCRYPTED_MESSAGE,
      to: senderUsername,
      encryptedPayload: encryptedMessage.encryptedPayload
    };

    websocketClient.send(JSON.stringify(deliveryReceiptPayload));

    const receiptKey = `${senderUsername}:${messageId}`;
    failedDeliveryReceiptsRef.current.delete(receiptKey);
    return true;
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Failed to send delivery receipt:', _error);
    const receiptKey = `${senderUsername}:${messageId}`;
    const existing = failedDeliveryReceiptsRef.current.get(receiptKey);
    const attempts = (existing?.attempts || 0) + 1;
    if (attempts <= 3) {
      failedDeliveryReceiptsRef.current.set(receiptKey, {
        messageId,
        peerUsername: senderUsername,
        timestamp: Date.now(),
        attempts
      });
    }
    return false;
  }
};

// Retry failed delivery receipts for a peer
export const retryFailedDeliveryReceipts = async (
  peerUsername: string,
  failedDeliveryReceiptsRef: React.RefObject<Map<string, FailedDeliveryReceipt>>,
  getKeysOnDemand: (() => Promise<any>) | undefined,
  usersRef: React.RefObject<UserWithHybridKeys[]> | undefined,
  loginUsernameRef: React.RefObject<string>
): Promise<void> => {
  const receiptsToRetry: Array<{ key: string; data: FailedDeliveryReceipt }> = [];
  for (const [key, data] of failedDeliveryReceiptsRef.current.entries()) {
    if (data.peerUsername === peerUsername) {
      receiptsToRetry.push({ key, data });
    }
  }

  if (receiptsToRetry.length === 0) return;

  const keys = await getKeysOnDemand?.();
  if (!keys?.kyber?.publicKeyBase64 || !keys?.dilithium?.secretKey) return;

  const user = usersRef?.current?.find?.((u: any) => u.username === peerUsername);
  if (!user?.hybridPublicKeys) return;

  const hybrid = user.hybridPublicKeys;
  const kyber = hybrid?.kyberPublicBase64;

  for (const { key, data } of receiptsToRetry) {
    try {
      const deliveryReceiptData = createDeliveryReceiptPayload(data.messageId, loginUsernameRef.current || '', peerUsername);

      const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
        fromUsername: loginUsernameRef.current,
        toUsername: peerUsername,
        plaintext: JSON.stringify(deliveryReceiptData),
        recipientKyberPublicKey: kyber,
        recipientHybridKeys: hybrid
      });

      if (encryptedMessage?.success && encryptedMessage?.encryptedPayload) {
        const deliveryReceiptPayload = {
          type: SignalType.ENCRYPTED_MESSAGE,
          to: peerUsername,
          encryptedPayload: encryptedMessage.encryptedPayload
        };
        websocketClient.send(JSON.stringify(deliveryReceiptPayload));
        failedDeliveryReceiptsRef.current.delete(key);
      } else {
        data.attempts++;
        if (data.attempts > 3) {
          failedDeliveryReceiptsRef.current.delete(key);
        } else {
          failedDeliveryReceiptsRef.current.set(key, data);
        }
      }
    } catch (_error) {
      console.error(`[EncryptedMessageHandler] Failed to retry delivery receipt:`, _error);
      data.attempts++;
      if (data.attempts > 3) {
        failedDeliveryReceiptsRef.current.delete(key);
      } else {
        failedDeliveryReceiptsRef.current.set(key, data);
      }
    }

    await new Promise(resolve => setTimeout(resolve, 100));
  }
};
