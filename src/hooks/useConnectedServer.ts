import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import websocketClient from '../lib/websocket/websocket';
import { websocket } from '../lib/tauri-bindings';
import { normalizeToWss } from '../lib/servers/server-address';
import type { SavedServer } from '../lib/servers/saved-servers';

const connectedEpoch = (): number | null => websocketClient.isConnectedToServer() &&
  websocketClient.isPQSessionEstablished() ? websocketClient.captureConnectionPrivacyEpoch() : null;

export interface ConnectedServer extends SavedServer {
  readonly identity: { fingerprint: string; serverId: string | null } | null;
  readonly signedName: string | null;
}

export function useConnectedServer(enabled: boolean): ConnectedServer | null {
  const subscribe = useCallback((onChange: () => void) => enabled
    ? websocketClient.subscribeConnectionState(onChange)
    : () => { }, [enabled]);
  const epoch = useSyncExternalStore(subscribe, connectedEpoch, () => null);
  const [server, setServer] = useState<{ epoch: number; value: ConnectedServer } | null>(null);

  useEffect(() => {
    if (!enabled || epoch === null) {
      setServer(null);
      return;
    }
    let cancelled = false;
    
    void Promise.all([websocket.getServerUrl(), websocket.getState()]).then(([url, state]) => {
      if (cancelled || connectedEpoch() !== epoch) return;
      const normalized = normalizeToWss(url || '');
      const profile = websocketClient.getServerProfile();
      setServer(state.connected && state.connectionToken === epoch && normalized
        ? { epoch, value: { url: normalized, name: profile?.name || new URL(normalized).host, icon: profile?.icon ?? null,
          signedName: profile?.name ?? null, identity: websocketClient.getConnectedServerIdentity() } }
        : null);
    }).catch(() => { if (!cancelled) setServer(null); });
    return () => { cancelled = true; };
  }, [enabled, epoch]);

  return enabled && epoch !== null && server?.epoch === epoch ? server.value : null;
}
