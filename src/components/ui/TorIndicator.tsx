import { useState, useEffect } from 'react';
import { cn } from '@/lib/utils/shared-utils';
import { torNetworkManager } from '@/lib/transport/tor-network';
import { TorConnectionStats } from '@/lib/types/tor-types';

export function TorIndicator() {
  const [stats, setStats] = useState<TorConnectionStats>(torNetworkManager.getStats());
  const isSupported = torNetworkManager.isSupported();
  const isConnected = isSupported && stats.isConnected;

  useEffect(() => {
    let mounted = true;

    const handleStatsChange = (newStats: TorConnectionStats) => {
      if (mounted) setStats(newStats);
    };
    setStats(torNetworkManager.getStats());

    void torNetworkManager.syncWithDaemon().then(() => {
      if (mounted) setStats(torNetworkManager.getStats());
    }).catch(() => { });

    torNetworkManager.onStatsChange(handleStatsChange);
    return () => {
      mounted = false;
      torNetworkManager.offStatsChange(handleStatsChange);
    };
  }, []);

  if (!isSupported) {
    return null;
  }

  const statusLabel = !isSupported
    ? 'Unavailable'
    : isConnected
      ? 'Connected'
      : stats.bootstrapProgress && stats.bootstrapProgress < 100
        ? `Bootstrapping ${stats.bootstrapProgress}%`
        : 'Disconnected';

  return (
    <span
      className={cn('qorc-tor-badge', !isConnected && 'is-off')}
      role="status"
      aria-label={`Tor ${statusLabel}`}
      title={`Tor ${statusLabel}`}
    >
      Tor
    </span>
  );
}
