import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Label } from '../../components/ui/label';
import { Switch } from '../../components/ui/switch';
import { Alert, AlertDescription } from '../../components/ui/alert';
import { torNetworkManager, TorConfig, TorConnectionStats } from '../../lib/tor-network';

export function TorSettings() {
  const [config, setConfig] = useState<TorConfig>({
    enabled: false,
    socksPort: 9150,
    controlPort: 9051,
    host: '127.0.0.1',
    circuitRotationInterval: 10,
    maxRetries: 3,
    connectionTimeout: 30000,
  });
  const [stats, setStats] = useState<TorConnectionStats>(torNetworkManager.getStats());
  const [isConnecting, setIsConnecting] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  const [isRotating, setIsRotating] = useState(false);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const handleStatsChange = (newStats: TorConnectionStats) => {
      setStats(newStats);
      if (!newStats.isConnected && config.enabled) {
        setError('Lost connection to Tor network');
      } else {
        setError('');
      }
    };

    setStats(torNetworkManager.getStats());
    torNetworkManager.onStatsChange(handleStatsChange);
    return () => torNetworkManager.offStatsChange(handleStatsChange);
  }, [config.enabled]);

  const handleConfigChange = (key: keyof TorConfig, value: any) => setConfig(prev => ({ ...prev, [key]: value }));

  const handleConnect = async () => {
    setIsConnecting(true);
    setError('');
    try {
      torNetworkManager.updateConfig(config);
      const success = await torNetworkManager.initialize();
      if (!success) setError('Failed to connect to Tor network. Ensure Tor is running.');
    } catch (_err) {
      setError(`Connection failed: ${_err instanceof Error ? _err.message : 'Unknown error'}`);
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (isDisconnecting) return;
    setIsDisconnecting(true);
    try {
      await torNetworkManager.shutdown();
      setStats(torNetworkManager.getStats());
    } finally {
      setIsDisconnecting(false);
    }
  };

  const handleRotateCircuit = async () => {
    if (isRotating) return;
    setIsRotating(true);
    try {
      const success = await torNetworkManager.rotateCircuit();
      if (!success) setError('Failed to rotate Tor circuit');
    } finally {
      setTimeout(() => setIsRotating(false), 1000);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatTime = (timestamp: number) => (timestamp === 0 ? 'Never' : new Date(timestamp).toLocaleTimeString());

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Tor Network Status</CardTitle>
            <div className="text-sm text-muted-foreground">{stats.isConnected ? 'Connected' : 'Disconnected'}</div>
          </div>
          <CardDescription>Anonymous network routing through Tor.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {!config.enabled && (
            <Alert>
              <AlertDescription>Tor networking is disabled. Enable it below to route connections through Tor.</AlertDescription>
            </Alert>
          )}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1"><Label className="text-sm text-muted-foreground">Connection Attempts</Label><div className="text-2xl font-bold">{stats.connectionAttempts}</div></div>
            <div className="space-y-1"><Label className="text-sm text-muted-foreground">Failed Connections</Label><div className="text-2xl font-bold text-red-600">{stats.failedConnections}</div></div>
            <div className="space-y-1"><Label className="text-sm text-muted-foreground">Circuit Rotations</Label><div className="text-2xl font-bold">{stats.circuitCount}</div></div>
            <div className="space-y-1"><Label className="text-sm text-muted-foreground">Last Rotation</Label><div className="text-sm font-medium">{formatTime(stats.lastCircuitRotation)}</div></div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1"><Label className="text-sm text-muted-foreground">Data Transmitted</Label><div className="text-lg font-semibold">{formatBytes(stats.bytesTransmitted)}</div></div>
            <div className="space-y-1"><Label className="text-sm text-muted-foreground">Data Received</Label><div className="text-lg font-semibold">{formatBytes(stats.bytesReceived)}</div></div>
          </div>

          <div className="flex gap-2">
            {!stats.isConnected ? (
              <Button onClick={handleConnect} disabled={isConnecting || !config.enabled}>
                {isConnecting ? 'Connecting…' : 'Connect to Tor'}
              </Button>
            ) : (
              <>
                <Button onClick={handleDisconnect} disabled={isDisconnecting} variant="outline">
                  {isDisconnecting ? 'Disconnecting…' : 'Disconnect'}
                </Button>
                <Button onClick={handleRotateCircuit} disabled={isRotating} variant="outline">
                  {isRotating ? 'Rotating…' : 'Rotate Circuit'}
                </Button>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Tor Configuration</CardTitle>
          <CardDescription>Configure Tor network settings.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Tor Network</Label>
              <div className="text-sm text-muted-foreground">Route connections through Tor.</div>
            </div>
            <Switch checked={config.enabled} onCheckedChange={(checked) => handleConfigChange('enabled', checked)} />
          </div>

          {config.enabled && (
            <div className="space-y-4 pt-4 border-t">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2"><Label htmlFor="socksPort">SOCKS Port</Label><Input id="socksPort" type="number" value={config.socksPort} onChange={(e) => handleConfigChange('socksPort', parseInt(e.target.value))} placeholder="9150" /></div>
                <div className="space-y-2"><Label htmlFor="controlPort">Control Port</Label><Input id="controlPort" type="number" value={config.controlPort} onChange={(e) => handleConfigChange('controlPort', parseInt(e.target.value))} placeholder="9051" /></div>
              </div>
              <div className="space-y-2"><Label htmlFor="host">Tor Host</Label><Input id="host" value={config.host} onChange={(e) => handleConfigChange('host', e.target.value)} placeholder="127.0.0.1" /></div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2"><Label htmlFor="circuitRotation">Circuit Rotation (minutes)</Label><Input id="circuitRotation" type="number" value={config.circuitRotationInterval} onChange={(e) => handleConfigChange('circuitRotationInterval', parseInt(e.target.value))} placeholder="10" /></div>
                <div className="space-y-2"><Label htmlFor="timeout">Connection Timeout (ms)</Label><Input id="timeout" type="number" value={config.connectionTimeout} onChange={(e) => handleConfigChange('connectionTimeout', parseInt(e.target.value))} placeholder="30000" /></div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Alert>
        <AlertDescription>Tor routes traffic through multiple encrypted relays. Ensure Tor is installed and running.</AlertDescription>
      </Alert>
    </div>
  );
}