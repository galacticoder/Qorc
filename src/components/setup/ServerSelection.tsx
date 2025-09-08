import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Globe, Server, Wifi, Info, CheckCircle, AlertTriangle } from 'lucide-react';

interface ServerSelectionProps {
  onServerSelected?: (serverUrl: string) => void;
  defaultTunnelUrl?: string;
}

export function ServerSelection({ onServerSelected, defaultTunnelUrl }: ServerSelectionProps) {
  const [customServerUrl, setCustomServerUrl] = useState('');
  const [selectedOption, setSelectedOption] = useState<'tunnel' | 'custom'>('tunnel');
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'success' | 'failed'>('idle');

  // Auto-detect if we have a tunnel URL, otherwise default to custom
  useEffect(() => {
    if (defaultTunnelUrl) {
      setSelectedOption('tunnel');
    } else {
      setSelectedOption('custom');
    }
  }, [defaultTunnelUrl]);

  const handleConnect = async () => {
    setIsConnecting(true);
    setConnectionStatus('testing');

    let serverUrl = '';
    
    try {
      switch (selectedOption) {
        case 'tunnel':
          if (!defaultTunnelUrl) {
            throw new Error('No tunnel URL available');
          }
          serverUrl = defaultTunnelUrl.replace('https://', 'wss://');
          break;
        case 'custom':
          if (!customServerUrl.trim()) {
            throw new Error('Please enter a server URL');
          }
          // Ensure it's a secure websocket URL (always use wss://)
          serverUrl = customServerUrl.trim();
          if (serverUrl.startsWith('http://')) {
            // Upgrade insecure HTTP to secure WebSocket
            serverUrl = serverUrl.replace('http://', 'wss://');
          } else if (serverUrl.startsWith('https://')) {
            serverUrl = serverUrl.replace('https://', 'wss://');
          } else if (serverUrl.startsWith('ws://')) {
            // Upgrade insecure WebSocket to secure WebSocket
            serverUrl = serverUrl.replace('ws://', 'wss://');
          } else if (!serverUrl.startsWith('wss://')) {
            serverUrl = 'wss://' + serverUrl;
          }
          break;
      }

      // Test connection briefly (skip for localhost in development due to self-signed certs)
      if (serverUrl.includes('localhost') || serverUrl.includes('127.0.0.1')) {
        console.log('[SERVER-SELECTION] Skipping connection test for localhost (development mode)');
        // Simulate a brief delay to show the testing state
        await new Promise(resolve => setTimeout(resolve, 1000));
      } else {
        await new Promise((resolve, reject) => {
          const testWs = new WebSocket(serverUrl);
          const timeout = setTimeout(() => {
            testWs.close();
            reject(new Error('Connection timeout'));
          }, 5000);

          testWs.onopen = () => {
            clearTimeout(timeout);
            testWs.close();
            resolve(true);
          };

          testWs.onerror = (event) => {
            clearTimeout(timeout);
            console.error('[SERVER-SELECTION] WebSocket error:', event);
            reject(new Error('Connection failed'));
          };
        });
      }

      setConnectionStatus('success');
      setTimeout(() => {
        onServerSelected?.(serverUrl);
      }, 1000);

    } catch (error) {
      console.error('[SERVER-SELECTION] Connection test failed:', error);
      setConnectionStatus('failed');
      setTimeout(() => {
        setConnectionStatus('idle');
      }, 3000);
    } finally {
      setIsConnecting(false);
    }
  };

  const getStatusColor = () => {
    switch (connectionStatus) {
      case 'testing': return 'secondary';
      case 'success': return 'default';
      case 'failed': return 'destructive';
      default: return 'outline';
    }
  };

  const getStatusText = () => {
    switch (connectionStatus) {
      case 'testing': return 'Testing...';
      case 'success': return 'Connected';
      case 'failed': return 'Failed';
      default: return 'Ready';
    }
  };

  return (
    <div className="space-y-6">
      {/* Main Selection Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Select Chat Server</CardTitle>
              <CardDescription>
                Choose which server to connect to for encrypted messaging
              </CardDescription>
            </div>
            <Badge variant={getStatusColor()}>
              {getStatusText()}
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Connection Status */}
          {connectionStatus === 'failed' && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                Failed to connect to the selected server. Please check the URL and try again.
              </AlertDescription>
            </Alert>
          )}

          {connectionStatus === 'success' && (
            <Alert>
              <CheckCircle className="h-4 w-4" />
              <AlertDescription>
                Connection successful! Proceeding to login...
              </AlertDescription>
            </Alert>
          )}

          {/* Server Options */}
          <div className="space-y-4">
            {/* Tunnel Option */}
            {defaultTunnelUrl && (
              <div
                className={`p-4 border rounded-lg cursor-pointer transition-all ${
                  selectedOption === 'tunnel'
                    ? 'border-primary bg-primary/5 ring-2 ring-primary/20'
                    : 'border-border hover:border-primary/50'
                }`}
                onClick={() => setSelectedOption('tunnel')}
              >
                <div className="flex items-start gap-3">
                  <div className="flex items-center gap-2">
                    <input
                      type="radio"
                      name="server-option"
                      checked={selectedOption === 'tunnel'}
                      onChange={() => setSelectedOption('tunnel')}
                      className="mt-1"
                    />
                    <Globe className="h-5 w-5 text-blue-600" />
                  </div>
                  <div className="flex-1">
                    <div className="font-medium text-base">Public Server (Recommended)</div>
                    <div className="text-sm text-muted-foreground mb-2">
                      Connect through Cloudflare tunnel with DDoS protection
                    </div>
                    <div className="text-xs font-mono bg-muted p-2 rounded break-all">
                      {defaultTunnelUrl}
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <CheckCircle className="h-3 w-3 text-green-600" />
                        DDoS Protected
                      </span>
                      <span className="flex items-center gap-1">
                        <CheckCircle className="h-3 w-3 text-green-600" />
                        Always Available
                      </span>
                      <span className="flex items-center gap-1">
                        <CheckCircle className="h-3 w-3 text-green-600" />
                        Global Access
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}


            {/* Custom Option */}
            <div
              className={`p-4 border rounded-lg cursor-pointer transition-all ${
                selectedOption === 'custom'
                  ? 'border-primary bg-primary/5 ring-2 ring-primary/20'
                  : 'border-border hover:border-primary/50'
              }`}
              onClick={() => setSelectedOption('custom')}
            >
              <div className="flex items-start gap-3">
                <div className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="server-option"
                    checked={selectedOption === 'custom'}
                    onChange={() => setSelectedOption('custom')}
                    className="mt-1"
                  />
                  <Wifi className="h-5 w-5 text-purple-600" />
                </div>
                <div className="flex-1 space-y-3">
                  <div>
                    <div className="font-medium text-base">Custom Server</div>
                    <div className="text-sm text-muted-foreground">
                      Connect to any end2end chat server by URL
                    </div>
                  </div>
                  
                  {selectedOption === 'custom' && (
                    <div className="space-y-2">
                      <Label htmlFor="custom-url" className="text-sm font-medium">
                        Server URL
                      </Label>
                      <Input
                        id="custom-url"
                        placeholder="wss://your-server.example.com or localhost:8443"
                        value={customServerUrl}
                        onChange={(e) => setCustomServerUrl(e.target.value)}
                        className="font-mono text-sm"
                      />
                      <div className="text-xs text-muted-foreground">
                        Enter the domain, IP address, or full WebSocket URL (supports localhost and remote servers)
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Connect Button */}
          <Button
            onClick={handleConnect}
            disabled={isConnecting || (selectedOption === 'custom' && !customServerUrl.trim())}
            className="w-full flex items-center gap-2"
            size="lg"
          >
            {isConnecting ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Testing Connection...
              </>
            ) : (
              <>
                <CheckCircle className="h-4 w-4" />
                Connect to Server
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Information Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Connection Options Explained</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm">
            <div className="flex items-start gap-3">
              <Globe className="h-4 w-4 mt-0.5 text-blue-500" />
              <div>
                <div className="font-medium">Public Server</div>
                <div className="text-muted-foreground">
                  Uses your Cloudflare tunnel URL for global access with DDoS protection.
                  Anyone can connect to your server using this URL.
                </div>
              </div>
            </div>
            
            <div className="flex items-start gap-3">
              <Wifi className="h-4 w-4 mt-0.5 text-purple-500" />
              <div>
                <div className="font-medium">Custom Server</div>
                <div className="text-muted-foreground">
                  Connect to any end2end chat server by entering its URL.
                  Supports local servers (localhost), remote servers, and IP addresses.
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
