import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Shield, AlertTriangle, CheckCircle, RotateCcw, Settings } from 'lucide-react';
import { torNetworkManager, TorConfig, TorConnectionStats } from '@/lib/tor-network';

export function TorSettings() {
  const [config, setConfig] = useState<TorConfig>({
    enabled: false,
    socksPort: 9050,
    controlPort: 9051,
    host: '127.0.0.1',
    circuitRotationInterval: 10,
    maxRetries: 3,
    connectionTimeout: 30000,
  });
  
  const [stats, setStats] = useState<TorConnectionStats>({
    isConnected: false,
    circuitCount: 0,
    lastCircuitRotation: 0,
    connectionAttempts: 0,
    failedConnections: 0,
    bytesTransmitted: 0,
    bytesReceived: 0,
  });
  
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string>('');

  // Update stats periodically
  useEffect(() => {
    const updateStats = () => {
      setStats(torNetworkManager.getStats());
    };

    updateStats();
    const interval = setInterval(updateStats, 5000);
    return () => clearInterval(interval);
  }, []);

  // Listen for connection changes
  useEffect(() => {
    const handleConnectionChange = (connected: boolean) => {
      setStats(torNetworkManager.getStats());
      if (!connected && config.enabled) {
        setError('Lost connection to Tor network');
      } else {
        setError('');
      }
    };

    torNetworkManager.onConnectionChange(handleConnectionChange);
    return () => torNetworkManager.offConnectionChange(handleConnectionChange);
  }, [config.enabled]);

  const handleConfigChange = (key: keyof TorConfig, value: any) => {
    setConfig(prev => ({ ...prev, [key]: value }));
  };

  const handleConnect = async () => {
    setIsConnecting(true);
    setError('');
    
    try {
      torNetworkManager.updateConfig(config);
      const success = await torNetworkManager.initialize();
      
      if (!success) {
        setError('Failed to connect to Tor network. Make sure Tor is running on your system.');
      }
    } catch (err) {
      setError(`Connection failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    await torNetworkManager.shutdown();
    setStats(torNetworkManager.getStats());
  };

  const handleRotateCircuit = async () => {
    const success = await torNetworkManager.rotateCircuit();
    if (!success) {
      setError('Failed to rotate Tor circuit');
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatTime = (timestamp: number) => {
    if (timestamp === 0) return 'Never';
    return new Date(timestamp).toLocaleTimeString();
  };

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            <CardTitle>Tor Network Status</CardTitle>
            <Badge variant={stats.isConnected ? 'default' : 'secondary'} className={stats.isConnected ? 'bg-green-600' : ''}>
              {stats.isConnected ? 'Connected' : 'Disconnected'}
            </Badge>
          </div>
          <CardDescription>
            Anonymous network routing through the Tor network
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {!config.enabled && (
            <Alert>
              <Shield className="h-4 w-4" />
              <AlertDescription>
                Tor networking is disabled. Enable it below to route connections through the Tor network for enhanced anonymity.
              </AlertDescription>
            </Alert>
          )}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1">
              <Label className="text-sm text-muted-foreground">Connection Attempts</Label>
              <div className="text-2xl font-bold">{stats.connectionAttempts}</div>
            </div>
            <div className="space-y-1">
              <Label className="text-sm text-muted-foreground">Failed Connections</Label>
              <div className="text-2xl font-bold text-red-600">{stats.failedConnections}</div>
            </div>
            <div className="space-y-1">
              <Label className="text-sm text-muted-foreground">Circuit Rotations</Label>
              <div className="text-2xl font-bold">{stats.circuitCount}</div>
            </div>
            <div className="space-y-1">
              <Label className="text-sm text-muted-foreground">Last Rotation</Label>
              <div className="text-sm font-medium">{formatTime(stats.lastCircuitRotation)}</div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label className="text-sm text-muted-foreground">Data Transmitted</Label>
              <div className="text-lg font-semibold">{formatBytes(stats.bytesTransmitted)}</div>
            </div>
            <div className="space-y-1">
              <Label className="text-sm text-muted-foreground">Data Received</Label>
              <div className="text-lg font-semibold">{formatBytes(stats.bytesReceived)}</div>
            </div>
          </div>

          <div className="flex gap-2">
            {!stats.isConnected ? (
              <Button 
                onClick={handleConnect} 
                disabled={isConnecting || !config.enabled}
                className="flex items-center gap-2"
              >
                <Shield className="h-4 w-4" />
                {isConnecting ? 'Connecting...' : 'Connect to Tor'}
              </Button>
            ) : (
              <>
                <Button 
                  onClick={handleDisconnect}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <Shield className="h-4 w-4" />
                  Disconnect
                </Button>
                <Button 
                  onClick={handleRotateCircuit}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <RotateCcw className="h-4 w-4" />
                  Rotate Circuit
                </Button>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            <CardTitle>Tor Configuration</CardTitle>
          </div>
          <CardDescription>
            Configure Tor network settings and connection parameters
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Tor Network</Label>
              <div className="text-sm text-muted-foreground">
                Route all connections through the Tor network for anonymity
              </div>
            </div>
            <Switch
              checked={config.enabled}
              onCheckedChange={(checked) => handleConfigChange('enabled', checked)}
            />
          </div>

          {config.enabled && (
            <div className="space-y-4 pt-4 border-t">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="socksPort">SOCKS Port</Label>
                  <Input
                    id="socksPort"
                    type="number"
                    value={config.socksPort}
                    onChange={(e) => handleConfigChange('socksPort', parseInt(e.target.value))}
                    placeholder="9050"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="controlPort">Control Port</Label>
                  <Input
                    id="controlPort"
                    type="number"
                    value={config.controlPort}
                    onChange={(e) => handleConfigChange('controlPort', parseInt(e.target.value))}
                    placeholder="9051"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="host">Tor Host</Label>
                <Input
                  id="host"
                  value={config.host}
                  onChange={(e) => handleConfigChange('host', e.target.value)}
                  placeholder="127.0.0.1"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="circuitRotation">Circuit Rotation (minutes)</Label>
                  <Input
                    id="circuitRotation"
                    type="number"
                    value={config.circuitRotationInterval}
                    onChange={(e) => handleConfigChange('circuitRotationInterval', parseInt(e.target.value))}
                    placeholder="10"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="timeout">Connection Timeout (ms)</Label>
                  <Input
                    id="timeout"
                    type="number"
                    value={config.connectionTimeout}
                    onChange={(e) => handleConfigChange('connectionTimeout', parseInt(e.target.value))}
                    placeholder="30000"
                  />
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Security Notice */}
      <Alert>
        <CheckCircle className="h-4 w-4" />
        <AlertDescription>
          <strong>Security Notice:</strong> Tor provides network-level anonymity by routing your traffic through multiple encrypted relays. 
          Make sure you have Tor installed and running on your system. Your end-to-end encryption and post-quantum security remain active with Tor.
        </AlertDescription>
      </Alert>
    </div>
  );
}