export function createPeerSignalSender(options: {
  isCurrent: () => boolean;
  isPeerConnected: (peer: string) => boolean;
  connectToPeer: (peer: string) => Promise<void>;
  sendMessage: (peer: string, payload: any) => Promise<void>;
}) {
  return async (to: string, payload: any): Promise<void> => {
    const assertCurrent = () => {
      if (!options.isCurrent()) throw new Error('P2P service changed during account transition');
    };
    assertCurrent();
    if (!options.isPeerConnected(to)) {
      await options.connectToPeer(to);
      assertCurrent();
      if (!options.isPeerConnected(to)) throw new Error('P2P connection not ready');
    }
    assertCurrent();
    await options.sendMessage(to, payload);
  };
}
