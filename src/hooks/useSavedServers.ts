import { useEffect, useSyncExternalStore } from 'react';
import { savedServers } from '../lib/servers/saved-servers';

export function useSavedServers() {
  const snapshot = useSyncExternalStore(savedServers.subscribe, savedServers.getSnapshot);
  useEffect(() => {
    void savedServers.load().catch(() => undefined);
  }, []);
  return snapshot;
}
