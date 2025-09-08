import React, { useState, useEffect } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Shield, Eye, EyeOff, RotateCcw } from 'lucide-react';
import { torNetworkManager, TorConnectionStats } from '@/lib/tor-network';

export function TorIndicator() {
  const [stats, setStats] = useState<TorConnectionStats>({
    isConnected: false,
    circuitCount: 0,
    lastCircuitRotation: 0,
    connectionAttempts: 0,
    failedConnections: 0,
    bytesTransmitted: 0,
    bytesReceived: 0,
  });
  
  const [isRotating, setIsRotating] = useState(false);

  // Update stats periodically
  useEffect(() => {
    const updateStats = () => {
      setStats(torNetworkManager.getStats());
    };

    updateStats();
    const interval = setInterval(updateStats, 3000);
    return () => clearInterval(interval);
  }, []);

  // Listen for connection changes
  useEffect(() => {
    const handleConnectionChange = () => {
      setStats(torNetworkManager.getStats());
    };

    torNetworkManager.onConnectionChange(handleConnectionChange);
    return () => torNetworkManager.offConnectionChange(handleConnectionChange);
  }, []);

  const handleRotateCircuit = async () => {
    setIsRotating(true);
    await torNetworkManager.rotateCircuit();
    setIsRotating(false);
  };

  const formatTime = (timestamp: number) => {
    if (timestamp === 0) return 'Never';
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
  };

  // Only show indicator if Tor is supported in this environment
  if (!torNetworkManager.isSupported()) {
    return null;
  }

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 px-2">
          <Badge 
            variant={stats.isConnected ? 'default' : 'secondary'} 
            className={`flex items-center gap-1 ${stats.isConnected ? 'bg-green-600 hover:bg-green-700' : 'bg-gray-600'}`}
          >
            <Shield className="h-3 w-3" />
            <span className="hidden sm:inline">Tor</span>
          </Badge>
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80" align="end">
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

          <div className="text-sm text-muted-foreground">
            Your connection is being routed through the Tor network for enhanced anonymity.
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
          </div>

          {stats.isConnected && (
            <Button 
              onClick={handleRotateCircuit}
              disabled={isRotating}
              size="sm"
              variant="outline"
              className="w-full flex items-center gap-2"
            >
              <RotateCcw className={`h-4 w-4 ${isRotating ? 'animate-spin' : ''}`} />
              {isRotating ? 'Rotating...' : 'Rotate Circuit'}
            </Button>
          )}

          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Eye className="h-3 w-3" />
            <span>Your IP address and location are hidden</span>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}