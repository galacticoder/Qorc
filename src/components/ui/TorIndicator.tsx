import React, { useState, useEffect } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Shield, RotateCw } from 'lucide-react';
import { torNetworkManager, TorConnectionStats } from '@/lib/tor-network';

export function TorIndicator() {
  const [stats, setStats] = useState<TorConnectionStats>(torNetworkManager.getStats());
  const [isRotating, setIsRotating] = useState(false);

  useEffect(() => {
    const updateStats = () => setStats(torNetworkManager.getStats());
    updateStats();
    const interval = setInterval(updateStats, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleConnectionChange = () => setStats(torNetworkManager.getStats());
    torNetworkManager.onConnectionChange(handleConnectionChange);

    // Automatic circuit rotation
    const rotationIntervalMs = 5 * 60 * 1000; // 5 minutes
    const rotationInterval = setInterval(async () => {
      if (torNetworkManager.isConnected()) {
        setIsRotating(true);
        await torNetworkManager.rotateCircuit();
        setIsRotating(false);
        setStats(torNetworkManager.getStats());
      }
    }, rotationIntervalMs);

    return () => {
      torNetworkManager.offConnectionChange(handleConnectionChange);
      clearInterval(rotationInterval);
    };
  }, []);

  const handleRotateCircuit = async () => {
    setIsRotating(true);
    await torNetworkManager.rotateCircuit();
    setIsRotating(false);
    setStats(torNetworkManager.getStats());
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

  if (!torNetworkManager.isSupported()) {
    return null;
  }

  const formattedLatency = stats.averageLatency ? `${Math.round(stats.averageLatency)} ms` : 'N/A';

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 px-2 select-none">
          <Badge
            variant={stats.isConnected ? 'default' : 'secondary'}
            className={`flex items-center gap-1 ${stats.isConnected ? 'bg-green-600 hover:bg-green-700' : 'bg-gray-600'}`}
          >
            <Shield className="h-3 w-3" />
            <span className="hidden sm:inline">Tor</span>
          </Badge>
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 select-none" align="end">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-600" />
              <span className="font-semibold">Tor Network</span>
            </div>
            <Badge variant={stats.isConnected ? 'default' : 'secondary'} className={stats.isConnected ? 'bg-green-600' : ''}>
              {stats.isConnected ? 'Connected' : 'Disconnected'}
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

          {stats.isConnected && (
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