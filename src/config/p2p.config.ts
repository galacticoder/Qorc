export interface P2PConfig {
  features: {
    typingIndicators: boolean;
    reactions: boolean;
    textMessages: boolean;
    fileTransfers: boolean;
  };
}

export const p2pConfig: P2PConfig = {
  get features() {
    return {
      typingIndicators: true,
      reactions: true,
      textMessages: true,
      fileTransfers: true,
    } as P2PConfig['features'];
  }
} as unknown as P2PConfig;

export function getSignalingServerUrl(serverUrl: string): string {
  try {
    const base = new URL(serverUrl);
    const isSecure = base.protocol === 'https:' || base.protocol === 'wss:';
    const wsProto = isSecure ? 'wss:' : 'ws:';
    return `${wsProto}//${base.host}/p2p-signaling`;
  } catch {
    return '';
  }
}

