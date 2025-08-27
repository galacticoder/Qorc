import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Shield, Download, Settings, Play, CheckCircle, AlertTriangle, Loader2, Info } from 'lucide-react';
import { torAutoSetup, TorSetupStatus } from '@/lib/tor-auto-setup';
import { TorVerification } from './TorVerification';

interface TorAutoSetupProps {
  onSetupComplete?: (success: boolean) => void;
  autoStart?: boolean;
}

export function TorAutoSetup({ onSetupComplete, autoStart = true }: TorAutoSetupProps) {
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

  // Check initial status
  useEffect(() => {
    const initialStatus = torAutoSetup.getStatus();
    setStatus(initialStatus);
  }, []);

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
      const success = await torAutoSetup.autoSetup({
        autoStart: true,
        enableBridges: false,
        onProgress: (newStatus) => {
          console.log('[TOR-SETUP-UI] Progress update:', newStatus);
          // If the new status contains an error, it should be preserved.
          // Otherwise, we can clear any previous error.
          setStatus(prevStatus => ({
            ...prevStatus,
            ...newStatus,
            error: newStatus.error || undefined
          }));
        }
      });

      console.log('[TOR-SETUP-UI] Setup completed, success:', success);

      if (onSetupComplete) {
        onSetupComplete(success);
      }

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

  const getStatusIcon = () => {
    if (status.error) {
      return <AlertTriangle className="h-5 w-5 text-red-500" />;
    }
    
    if (status.setupProgress === 100) {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    }
    
    if (isSetupRunning) {
      return <Loader2 className="h-5 w-5 animate-spin text-blue-500" />;
    }
    
    return <Shield className="h-5 w-5 text-gray-500" />;
  };

  const getStatusColor = () => {
    // Prioritize active setup over error state
    if (isSetupRunning || status.setupProgress > 0) return 'secondary';
    if (status.setupProgress === 100) return 'default';
    if (status.error && !isSetupRunning) return 'destructive';
    return 'outline';
  };

  const getStatusText = () => {
    // Prioritize active setup over error state
    if (isSetupRunning || status.setupProgress > 0) return 'Setting Up...';
    if (status.setupProgress === 100) return 'Ready';
    if (status.error && !isSetupRunning) return 'Setup Failed';
    return 'Not Configured';
  };

  return (
    <div className="space-y-6">
      {/* Main Setup Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {getStatusIcon()}
              <div>
                <CardTitle>Tor Network Setup</CardTitle>
                <CardDescription>
                  Automatic installation and configuration of Tor for anonymous networking
                </CardDescription>
              </div>
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

              {/* Skip Button - only show if there's an error or user wants to skip */}
              {(status.error || !isSetupRunning) && (
                <Button
                  onClick={() => {
                    localStorage.setItem('tor_setup_skipped', 'true');
                    onSetupComplete && onSetupComplete(false);
                  }}
                  variant="outline"
                  className="w-full"
                  disabled={isSetupRunning}
                >
                  Skip Tor Setup (Continue Without Tor)
                </Button>
              )}
            </div>
          )}

          {/* Success Message */}
          {status.setupProgress === 100 && !status.error && (
            <div className="space-y-3">
              <Alert>
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Setup Complete!</strong> Tor is now installed, configured, and running.
                  Your connections will be automatically routed through the Tor network for enhanced privacy.
                </AlertDescription>
              </Alert>

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
                  <span className="font-mono">9050</span>
                </div>
                
                <div className="flex justify-between">
                  <span>Control Port:</span>
                  <span className="font-mono">9051</span>
                </div>
              </div>

              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => torAutoSetup.stopTor()}
                  disabled={!status.isRunning}
                >
                  Stop Tor
                </Button>
                
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => torAutoSetup.uninstallTor()}
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
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <TorVerification onClose={() => setShowVerification(false)} />
        </div>
      )}
    </div>
  );
}
