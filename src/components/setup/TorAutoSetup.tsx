import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Download, Settings, Play, CheckCircle, AlertTriangle, Loader2, Info } from 'lucide-react';
import { getTorAutoSetup, TorSetupStatus } from '@/lib/tor-auto-setup';
import { TorVerification } from './TorVerification';

interface TorAutoSetupProps {
  onComplete?: (success: boolean) => void;
  autoStart?: boolean;
}

export function TorAutoSetup({ onComplete }: TorAutoSetupProps) {
  const [status, setStatus] = useState<TorSetupStatus>({
    isInstalled: false,
    isConfigured: false,
    isRunning: false,
    setupProgress: 0,
    currentStep: 'Ready to setup'
  });
  
  const [isSetupRunning, setIsSetupRunning] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showVerification, setShowVerification] = useState(false);

  // Bridge configuration state
  const [enableBridges, setEnableBridges] = useState(false);
  const [transport, setTransport] = useState<'obfs4' | 'snowflake'>('obfs4');
  const [bridgesText, setBridgesText] = useState('');
  const [obfs4ProxyPath, setObfs4ProxyPath] = useState('');

  // Check initial status and refresh from Electron API
  useEffect(() => {
    const loadInitialStatus = async () => {
      const initialStatus = await getTorAutoSetup().refreshStatus();
      setStatus(initialStatus);
    };
    loadInitialStatus();
  }, []);

  // Prevent body scrolling when verification modal is open
  useEffect(() => {
    if (showVerification) {
      document.body.style.overflow = 'hidden';
      return () => {
        document.body.style.overflow = 'unset';
      };
    }
  }, [showVerification]);

  const handleAutoSetup = async () => {
    console.log('[TOR-SETUP-UI] Starting auto setup...');
    setIsSetupRunning(true);

    // Clear any previous errors when starting setup
    setStatus(prev => ({
      ...prev,
      error: undefined
    }));

    try {
      console.log('[TOR-SETUP-UI] Calling torAutoSetup.autoSetup()...');
      const bridges = bridgesText
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 0);

      const success = await getTorAutoSetup().autoSetup({
        autoStart: true,
        enableBridges,
        transport,
        bridges,
        obfs4ProxyPath: obfs4ProxyPath || undefined,
        onProgress: (newStatus) => {
          console.log('[TOR-SETUP-UI] Progress update:', newStatus);
          setStatus(prevStatus => ({
            ...prevStatus,
            ...newStatus,
            error: newStatus.error || undefined
          }));
        }
      });

      console.log('[TOR-SETUP-UI] Setup completed, success:', success);

      // Don't auto-navigate - let user click Continue button

    } catch (error) {
      console.error('[TOR-SETUP-UI] Setup failed:', error);
      setStatus(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Setup failed',
        setupProgress: 0
      }));
    } finally {
      setIsSetupRunning(false);
    }
  };


  const getStatusColor = () => {
    if (status.setupProgress === 100 && !isSetupRunning) return 'default';
    if (isSetupRunning || (status.setupProgress > 0 && status.setupProgress < 100)) return 'secondary';
    if (status.error && !isSetupRunning) return 'destructive';
    return 'outline';
  };

  const getStatusText = () => {
    if (status.setupProgress === 100 && !isSetupRunning) return 'Complete';
    if (isSetupRunning || (status.setupProgress > 0 && status.setupProgress < 100)) return 'Setting Up...';
    if (status.error && !isSetupRunning) return 'Setup Failed';
    return 'Not Configured';
  };

  return (
    <div className="space-y-6">
      {/* Main Setup Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Tor Network Setup</CardTitle>
              <CardDescription>
                Automatic installation and configuration of Tor for anonymous networking
              </CardDescription>
            </div>
            <Badge variant={getStatusColor()}>
              {getStatusText()}
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Error Display - Only show if not currently setting up */}
          {status.error && !isSetupRunning && status.setupProgress === 0 && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Setup Error:</strong> {status.error}
              </AlertDescription>
            </Alert>
          )}

          {/* Progress Display */}
          {(isSetupRunning || status.setupProgress > 0) && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>{status.currentStep}</span>
                <span>{status.setupProgress}%</span>
              </div>
              <Progress value={status.setupProgress} className="w-full" />
            </div>
          )}

          {/* Status Information */}
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${status.isInstalled ? 'bg-green-500' : 'bg-gray-300'}`} />
              <span>Installed</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${status.isConfigured ? 'bg-green-500' : 'bg-gray-300'}`} />
              <span>Configured</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${status.isRunning ? 'bg-green-500' : 'bg-gray-300'}`} />
              <span>Running</span>
            </div>
          </div>

          {/* Setup Buttons */}
          {status.setupProgress !== 100 && (
            <div className="space-y-3">
              <Button
                onClick={handleAutoSetup}
                disabled={isSetupRunning}
                className="w-full flex items-center gap-2"
                size="lg"
              >
                {isSetupRunning ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Setting up Tor...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4" />
                    Auto-Setup Tor Network
                  </>
                )}
              </Button>

            </div>
          )}

          {/* Success Message */}
          {status.setupProgress === 100 && !isSetupRunning && (
            <div className="space-y-3">
              <Alert>
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Setup Complete!</strong> Tor is now installed, configured, and running.
                  Your connections will be automatically routed through the Tor network for enhanced privacy.
                </AlertDescription>
              </Alert>

              <Button
                onClick={() => onComplete && onComplete(true)}
                className="w-full"
                size="lg"
              >
                Continue to Server Selection
              </Button>

              <Button
                onClick={() => setShowVerification(true)}
                variant="outline"
                className="w-full flex items-center gap-2"
              >
                <Info className="h-4 w-4" />
                Verify Tor is Really Working
              </Button>
            </div>
          )}

          {/* Advanced Options Toggle */}
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full"
          >
            <Settings className="h-4 w-4 mr-2" />
            {showAdvanced ? 'Hide' : 'Show'} Advanced Options
          </Button>

          {/* Advanced Options */}
          {showAdvanced && (
            <div className="space-y-4 p-4 border rounded-lg bg-gray-50">
              <h4 className="font-semibold text-sm">Advanced Configuration</h4>
              
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Tor Version:</span>
                  <span className="font-mono">{status.version || 'Not detected'}</span>
                </div>
                
                <div className="flex justify-between">
                  <span>SOCKS Port:</span>
                  <span className="font-mono">{status.socksPort || 'Not detected'}</span>
                </div>
                
                <div className="flex justify-between">
                  <span>Control Port:</span>
                  <span className="font-mono">{status.controlPort || 'Not detected'}</span>
                </div>
              </div>

              {/* Bridges Configuration */}
              <div className="space-y-3 p-3 bg-white rounded-md border">
                <div className="flex items-center justify-between">
                  <Label htmlFor="enableBridges" className="text-sm font-medium">Use Bridges (for censored networks)</Label>
                  <input
                    id="enableBridges"
                    type="checkbox"
                    className="h-4 w-4"
                    checked={enableBridges}
                    onChange={(e) => setEnableBridges(e.target.checked)}
                  />
                </div>

                {enableBridges && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <Label htmlFor="transport" className="text-sm">Transport</Label>
                        <select
                          id="transport"
                          className="border rounded px-2 py-1 text-sm w-full bg-white"
                          value={transport}
                          onChange={(e) => setTransport((e.target.value as 'obfs4' | 'snowflake'))}
                        >
                          <option value="obfs4">obfs4 (recommended)</option>
                          <option value="snowflake">snowflake</option>
                        </select>
                      </div>

                      {transport === 'obfs4' && (
                        <div className="space-y-1">
                          <Label htmlFor="obfs4path" className="text-sm">obfs4proxy path (optional)</Label>
                          <Input
                            id="obfs4path"
                            placeholder="e.g. /usr/bin/obfs4proxy"
                            value={obfs4ProxyPath}
                            onChange={(e) => setObfs4ProxyPath(e.target.value)}
                          />
                          <div className="text-xs text-gray-500">Leave empty if obfs4proxy is in PATH</div>
                        </div>
                      )}
                    </div>

                    <div className="space-y-1">
                      <Label htmlFor="bridges" className="text-sm">Bridge lines</Label>
                      <Textarea
                        id="bridges"
                        placeholder="Paste your Bridge lines here (one per line).\nExample: obfs4 1.2.3.4:9001 0123456789ABCDEF cert=... iat-mode=0"
                        value={bridgesText}
                        onChange={(e) => setBridgesText(e.target.value)}
                        className="min-h-[120px]"
                      />
                      <div className="text-xs text-gray-500">
                        Get bridges at https://bridges.torproject.org/ or via email to bridges@torproject.org from a Riseup or Gmail address.
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={async () => {
                    await getTorAutoSetup().stopTor();
                    const newStatus = await getTorAutoSetup().refreshStatus();
                    setStatus({
                      ...newStatus,
                      setupProgress: 0,
                      currentStep: 'Ready to setup'
                    });
                  }}
                  disabled={!status.isRunning}
                >
                  Stop Tor
                </Button>
                
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={async () => {
                    await getTorAutoSetup().uninstallTor();
                    const newStatus = await getTorAutoSetup().refreshStatus();
                    setStatus({
                      ...newStatus,
                      setupProgress: 0,
                      currentStep: 'Ready to setup'
                    });
                  }}
                  disabled={isSetupRunning}
                >
                  Uninstall
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Information Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">What happens during setup?</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm">
            <div className="flex items-start gap-3">
              <Download className="h-4 w-4 mt-0.5 text-blue-500" />
              <div>
                <div className="font-medium">Download Tor</div>
                <div className="text-muted-foreground">
                  Downloads the latest Tor binary for your operating system
                </div>
              </div>
            </div>
            
            <div className="flex items-start gap-3">
              <Settings className="h-4 w-4 mt-0.5 text-green-500" />
              <div>
                <div className="font-medium">Configure Settings</div>
                <div className="text-muted-foreground">
                  Creates optimal configuration for secure anonymous networking
                </div>
              </div>
            </div>
            
            <div className="flex items-start gap-3">
              <Play className="h-4 w-4 mt-0.5 text-purple-500" />
              <div>
                <div className="font-medium">Start Service</div>
                <div className="text-muted-foreground">
                  Launches Tor and establishes connection to the network
                </div>
              </div>
            </div>
            
            <div className="flex items-start gap-3">
              <CheckCircle className="h-4 w-4 mt-0.5 text-green-500" />
              <div>
                <div className="font-medium">Verify Connection</div>
                <div className="text-muted-foreground">
                  Tests the connection to ensure everything is working properly
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tor Verification Modal */}
      {showVerification && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 overflow-hidden"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setShowVerification(false);
            }
          }}
          style={{ 
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            overflowY: 'hidden'
          }}
        >
          <div className="max-h-[90vh] overflow-y-auto scrollbar-hide">
            <TorVerification onClose={() => setShowVerification(false)} />
          </div>
        </div>
      )}
    </div>
  );
}