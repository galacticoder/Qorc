import { SignalType } from '../types/signal-types';

export function createPeerSignalSender(options: {
  isCurrent: () => boolean;
  isPeerConnected: (peer: string) => boolean;
  connectToPeer: (peer: string) => Promise<void>;
  sendMessage: (peer: string, payload: any, signal?: AbortSignal) => Promise<void>;
}) {
  return async (to: string, payload: any, type?: SignalType, signal?: AbortSignal): Promise<void> => {
    const assertCurrent = () => {
      signal?.throwIfAborted();
      if (!options.isCurrent()) throw new Error('P2P service changed during account transition');
    };
    assertCurrent();
    if (!options.isPeerConnected(to)) {
      if (type === SignalType.CALL_SIGNAL) {
        void options.connectToPeer(to).catch(() => {});
        throw new Error('P2P connection not ready for live call signaling');
      }
      await options.connectToPeer(to);
      assertCurrent();
      if (!options.isPeerConnected(to)) throw new Error('P2P connection not ready');
    }
    assertCurrent();
    await options.sendMessage(to, payload, signal);
  };
}
