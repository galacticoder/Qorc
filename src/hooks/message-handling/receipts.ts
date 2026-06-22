import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import type { FailedDeliveryReceipt, HybridKeys, UserWithHybridKeys } from '../../lib/types/message-handling-types';
import { DELIVERY_RECEIPT_PREFIX } from '@/lib/constants';
import { receiptBatcher } from './receipt-batcher';

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
  _currentUser: string,
  senderUsername: string,
  messageId: string,
  _kyber: string | null,
  _hybrid: HybridKeys | null,
  failedDeliveryReceiptsRef: React.RefObject<Map<string, FailedDeliveryReceipt>>
): Promise<boolean> => {
  receiptBatcher.queueDelivery(senderUsername, messageId);
  failedDeliveryReceiptsRef.current?.delete(`${senderUsername}:${messageId}`);
  return true;
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

  // Route retries through same per peer batcher so they coalesce into one signed message
  for (const { key, data } of receiptsToRetry) {
    receiptBatcher.queueDelivery(peerUsername, data.messageId);
    failedDeliveryReceiptsRef.current.delete(key);
  }
};
