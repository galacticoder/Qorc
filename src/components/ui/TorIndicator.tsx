import React, { useState, useEffect } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Shield, RotateCw } from 'lucide-react';
import { cn } from '@/lib/utils/shared-utils';
import { torNetworkManager } from '@/lib/transport/tor-network';
import { TorConnectionStats } from '@/lib/types/tor-types';

interface TorIndicatorProps {
  readonly variant?: 'default' | 'login' | 'signup';
}

export function TorIndicator({ variant = 'default' }: TorIndicatorProps) {
  const [stats, setStats] = useState<TorConnectionStats>(torNetworkManager.getStats());
  const [isRotating, setIsRotating] = useState(false);
  const authPrefix = variant === 'login' || variant === 'signup' ? variant : null;
  const isSupported = torNetworkManager.isSupported();
  const isConnected = isSupported && stats.isConnected;

  useEffect(() => {
    let mounted = true;

    const handleStatsChange = (newStats: TorConnectionStats) => {
      if (!mounted) return;
      setStats(newStats);
      if (newStats.lastCircuitRotation > stats.lastCircuitRotation) {
        setIsRotating(false);
      }
    };
    setStats(torNetworkManager.getStats());

    torNetworkManager.onStatsChange(handleStatsChange);
    return () => {
      mounted = false;
      torNetworkManager.offStatsChange(handleStatsChange);
    };
  }, [stats.lastCircuitRotation]);

  const handleRotateCircuit = async () => {
    setIsRotating(true);
    setTimeout(async () => {
      try {
        await torNetworkManager.rotateCircuit();
      } catch {
        setIsRotating(false);
      }
      setStats(torNetworkManager.getStats());
      if (torNetworkManager.getStats().lastCircuitRotation === stats.lastCircuitRotation) {
      }
    }, 0);
  };

  const formatTime = (timestamp: number) => {
    if (!timestamp) return 'Never';
    const diff = Date.now() - timestamp;
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
  };

  if (!isSupported && !authPrefix) {
    return null;
  }

  const formattedLatency = stats.averageLatency ? `${Math.round(stats.averageLatency)} ms` : 'N/A';
  const statusLabel = !isSupported
    ? 'Unavailable'
    : isConnected
      ? 'Connected'
      : stats.bootstrapProgress && stats.bootstrapProgress < 100
        ? `Bootstrapping ${stats.bootstrapProgress}%`
        : 'Disconnected';

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn(authPrefix ? `${authPrefix}-screen-tor` : "qor-tor-trigger", !isConnected && "is-off")}
          aria-label="Tor status"
        >
          {authPrefix ? (
            <>
              <Shield aria-hidden="true" />
              <span>Tor</span>
            </>
          ) : (
          <span className={cn("qor-tor-badge", !isConnected && "is-off")}>
            <Shield className="h-3 w-3" aria-hidden="true" />
            <span>Tor</span>
          </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="qor-tor-popover w-80 select-none"
        side="bottom"
        align={authPrefix ? "end" : "start"}
        sideOffset={8}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-600" />
              <span className="font-semibold">Tor Network</span>
            </div>
            <Badge 
              variant={isConnected ? 'default' : 'secondary'} 
              className={isConnected ? 'bg-green-600 hover:bg-[#3b8e3f]' : 'bg-gray-600 hover:bg-[#657389]'}
            >
              {statusLabel}
            </Badge>
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="font-medium">Circuit Rotations</div>
              <div className="text-muted-foreground">{stats.circuitCount}</div>
            </div>
            <div>
              <div className="font-medium">Last Rotation</div>
              <div className="text-muted-foreground">{formatTime(stats.lastCircuitRotation)}</div>
            </div>
            <div>
              <div className="font-medium">Average Latency</div>
              <div className="text-muted-foreground">{formattedLatency}</div>
            </div>
            <div>
              <div className="font-medium">Circuit Health</div>
              <div className="text-muted-foreground capitalize">{stats.circuitHealth}</div>
            </div>
          </div>

          {isConnected && (
            <Button
              onClick={handleRotateCircuit}
              disabled={isRotating}
              size="sm"
              variant="outline"
              className="w-full flex items-center gap-2"
            >
              <RotateCw className={`h-4 w-4 ${isRotating ? 'animate-spin' : ''}`} />
              {isRotating ? 'Rotating...' : 'Rotate Circuit'}
            </Button>
          )}

          <div className="text-xs text-muted-foreground">
            Tor routing keeps your IP hidden from the relay destination.
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
