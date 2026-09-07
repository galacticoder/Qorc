import type { SignalType } from '../types/signal-types';
import { isLiveOnlySignalType } from './unified-signal-transport';

const COLD_SEND_P2P_DIAL_BUDGET_MS = 3000;

export function createPeerSignalSender(options: {
  isCurrent: () => boolean;
  isPeerConnected: (peer: string) => boolean;
  connectToPeer: (peer: string) => Promise<void>;
  sendMessage: (peer: string, payload: any) => Promise<void>;
}) {
  return async (to: string, payload: any, type: SignalType): Promise<void> => {
    const assertCurrent = () => {
      if (!options.isCurrent()) throw new Error('P2P service changed during account transition');
    };
    assertCurrent();
    if (!options.isPeerConnected(to)) {
      const dial = options.connectToPeer(to);
      if (!isLiveOnlySignalType(type)) {
        let deadline: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            dial,
            new Promise<void>((resolve) => {
              deadline = setTimeout(resolve, COLD_SEND_P2P_DIAL_BUDGET_MS);
            }),
          ]);
        } finally {
          if (deadline !== undefined) clearTimeout(deadline);
        }
      } else {
        void dial.catch(() => { });
      }
      assertCurrent();
      if (!options.isPeerConnected(to)) throw new Error('P2P connection not ready');
    }
    assertCurrent();
    await options.sendMessage(to, payload);
  };
}
