import { useSyncExternalStore } from 'react';
import { startupConnection, type StartupConnectionState } from '../../lib/transport/startup-connection';

export function useStartupConnection(): StartupConnectionState {
  return useSyncExternalStore(
    (onChange) => startupConnection.subscribe(onChange),
    () => startupConnection.getState(),
    () => startupConnection.getState(),
  );
}
