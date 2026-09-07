import { FILE_TRANSPORT_ACK_CHUNK_INTERVAL, FILE_TRANSPORT_ACK_MAX_INTERVAL_MS } from '../../lib/constants';
import type { ExtendedFileState } from '../../lib/types/file-types';

export function shouldQueueFileTransportAck(
  entry: ExtendedFileState,
  chunkIndex: number,
  now: number,
  force = false,
): boolean {
  if (entry.transportAckCanceled) return false;
  if (entry.transportAckedIndices?.has(chunkIndex) && !force) return false;
  const checkpoint = entry.transportAckCheckpoint;
  if (
    !force &&
    checkpoint &&
    entry.receivedCount < entry.totalChunks &&
    entry.receivedCount - checkpoint.receivedCount < FILE_TRANSPORT_ACK_CHUNK_INTERVAL &&
    now >= checkpoint.queuedAt &&
    now - checkpoint.queuedAt < FILE_TRANSPORT_ACK_MAX_INTERVAL_MS
  ) return false;
  entry.transportAckCheckpoint = { receivedCount: entry.receivedCount, queuedAt: now };
  return true;
}
