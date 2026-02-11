import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import type { FailedDeliveryReceipt, HybridKeys, UserWithHybridKeys } from '../../lib/types/message-handling-types';
import { DELIVERY_RECEIPT_PREFIX } from '@/lib/constants';

// Create delivery receipt payload
export const createDeliveryReceiptPayload = (
  messageId: string,
  fromUsername: string,
  toUsername: string
): Record<string, unknown> => ({
  messageId: `${DELIVERY_RECEIPT_PREFIX}${messageId}`,
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
  try {
    const deliveryReceiptData = createDeliveryReceiptPayload(messageId, currentUser, senderUsername);

    const result = await unifiedSignalTransport.send(
      senderUsername,
      deliveryReceiptData,
      SignalType.DELIVERY_RECEIPT
    );

    if (result.success) {
      const receiptKey = `${senderUsername}:${messageId}`;
      failedDeliveryReceiptsRef.current.delete(receiptKey);
      return true;
    } else {
      throw new Error(result.error || 'Transport send failed');
    }
  } catch (_error: any) {
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
  usersRef: React.RefObject<UserWithHybridKeys[]> | undefined,
  loginUsernameRef: React.RefObject<string>,
  resolvePeerInboxId?: (peer: string) => Promise<string | null>
): Promise<void> => {
  const receiptsToRetry: Array<{ key: string; data: FailedDeliveryReceipt }> = [];
  for (const [key, data] of failedDeliveryReceiptsRef.current.entries()) {
    if (data.peerUsername === peerUsername) {
      receiptsToRetry.push({ key, data });
    }
  }

  if (receiptsToRetry.length === 0) return;

  for (const { key, data } of receiptsToRetry) {
    try {
      const peer = (usersRef?.current as any[])?.find(u => u.username === peerUsername);
      let destinationInbox = peer?.inboxId || peer?.hybridPublicKeys?.inboxId;

      if (!destinationInbox && resolvePeerInboxId) {
        try {
          destinationInbox = await resolvePeerInboxId(peerUsername);
        } catch { }
      }

      if (!destinationInbox) {
        console.warn('[Receipts] Cannot retry receipt without inboxId', peerUsername);
        continue;
      }

      const deliveryReceiptData = createDeliveryReceiptPayload(data.messageId, loginUsernameRef.current || '', peerUsername);

      const result = await unifiedSignalTransport.send(
        peerUsername,
        deliveryReceiptData,
        SignalType.DELIVERY_RECEIPT,
        { destinationInbox }
      );

      if (result.success) {
        failedDeliveryReceiptsRef.current.delete(key);
      } else {
        throw new Error(result.error);
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
