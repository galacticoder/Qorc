import { useEffect, useMemo, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { TorVerification } from './TorVerification';
import { getTorAutoSetup, TorSetupStatus } from '@/lib/tor-auto-setup';
import { torNetworkManager } from '@/lib/tor-network';

interface ConnectSetupProps {
  onComplete?: (serverUrl: string) => Promise<void> | void;
  initialServerUrl?: string;
}

export function ConnectSetup({ onComplete, initialServerUrl = '' }: ConnectSetupProps) {
  // Tor setup state
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

  // Server selection state
  const [selectedOption, setSelectedOption] = useState<'tunnel' | 'custom'>('custom');
  const [customServerUrl, setCustomServerUrl] = useState('');
  const [defaultServerUrl, setDefaultServerUrl] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testStatus, setTestStatus] = useState<string>('');
  const [testError, setTestError] = useState<string>('');
  const [isContinuing, setIsContinuing] = useState(false);

  // Advanced Tor config
  const [enableBridges, setEnableBridges] = useState(false);
  const [transport, setTransport] = useState<'obfs4' | 'snowflake'>('obfs4');
  const [bridgesText, setBridgesText] = useState('');
  const [obfs4ProxyPath, setObfs4ProxyPath] = useState('');

  // Prefill defaults on mount
  useEffect(() => {
    (async () => {
      try {
        // Tor status
        const initialStatus = await getTorAutoSetup().refreshStatus();
        setStatus(initialStatus);

        const stored = await (window as any).edgeApi?.getServerUrl?.();
        const storedUrl = typeof stored?.serverUrl === 'string' ? stored.serverUrl : '';
        const envUrl = (import.meta as any)?.env?.VITE_WS_URL || '';
        let preferred = initialServerUrl || '';
        if (!preferred) {
          try {
            const storedHost = storedUrl ? new URL(storedUrl).hostname : '';
            const envHost = envUrl ? new URL(envUrl).hostname : '';
            if (envHost && (storedHost === 'localhost' || storedHost === '127.0.0.1' || storedHost === '::1')) {
              preferred = envUrl || storedUrl || '';
            } else {
              preferred = storedUrl || envUrl || '';
            }
          } catch {
            preferred = storedUrl || envUrl || '';
          }
        }
        if (preferred) {
          setCustomServerUrl(preferred);
        }
        setSelectedOption('custom');
      } catch {}
    })();
  }, [initialServerUrl]);

  // Prevent background scroll when verification modal open
  useEffect(() => {
    if (!showVerification) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, [showVerification]);

  const normalizeToWss = (value: string): string => {
    let v = (value || '').trim();
    if (!v) return '';
    if (!/^wss:\/\//i.test(v)) {
      if (/^https?:\/\//i.test(v)) v = v.replace(/^https?:\/\//i, 'wss://');
      else if (/^ws:\/\//i.test(v)) v = v.replace(/^ws:\/\//i, 'wss://');
      else v = 'wss://' + v;
    }
    try {
      const u = new URL(v);
      if (u.protocol !== 'wss:') throw new Error('Invalid scheme');
      if (!u.hostname || u.hostname.length > 253) throw new Error('Invalid host');
      return u.toString();
    } catch {
      return '';
    }
  };

  const chosenServerUrl = useMemo(() => {
    return normalizeToWss(customServerUrl);
  }, [customServerUrl]);

  const canContinue = status.isRunning && !!chosenServerUrl && !isSetupRunning && !isTesting && !isContinuing;

  const handleAutoSetup = async () => {
    setIsSetupRunning(true);
    setStatus(prev => ({ ...prev, error: undefined }));
    try {
      const bridges = bridgesText.split('\n').map(l => l.trim()).filter(Boolean);
      const success = await getTorAutoSetup().autoSetup({
        autoStart: true,
        enableBridges,
        transport,
        bridges,
        obfs4ProxyPath: obfs4ProxyPath || undefined,
        onProgress: (newStatus) => {
          setStatus(prevStatus => ({ ...prevStatus, ...newStatus, error: newStatus.error || undefined }));
        }
      });
      if (success) {
        const refreshed = await getTorAutoSetup().refreshStatus();
        setStatus(refreshed);
      }
    } catch (_error) {
      console.error('[ConnectSetup] Auto-setup failed:', _error);
      setStatus(prev => ({ ...prev, error: _error instanceof Error ? _error.message : 'Setup failed', setupProgress: 0 }));
    } finally {
      setIsSetupRunning(false);
    }
  };

  const testConnection = async (url: string, timeoutMs = 12000): Promise<void> => {
    const edgeApi: any = (window as any).edgeApi;
    if (!edgeApi?.wsProbeConnect) {
      console.error('[ConnectSetup] wsProbeConnect not available on edgeApi');
      throw new Error('Electron WebSocket probe is required');
    }
    const res = await edgeApi.wsProbeConnect(url, timeoutMs);
    if (!res || res.success === false) {
      console.error('[ConnectSetup] WebSocket probe failed', {
        url,
        timeoutMs,
        result: res
      });
      throw new Error(res?.error || 'Connection failed');
    }
  };

  const ensureTorInitialized = async (): Promise<boolean> => {
    try {
      // Notify Electron main process that Tor setup is complete
      await (window as any).electronAPI?.torSetupComplete?.();
    } catch {}
    try {
      torNetworkManager.updateConfig({ enabled: true });
      const ok = await torNetworkManager.initialize();
      return !!ok;
    } catch { return false; }
  };

  const humanizeConnectionError = (err: unknown): string => {
    const raw = (err instanceof Error ? err.message : (typeof err === 'string' ? err : '')) || '';
    const code = (err as any)?.code ? String((err as any).code) : '';
    const text = `${code} ${raw}`.toLowerCase();

    // DNS issues
    if (text.includes('eai_again')) return 'Temporary DNS issue resolving the server name. Check your internet connection or try again in a moment.';
    if (text.includes('enotfound') || text.includes('eai_noname') || text.includes('getaddrinfo')) return 'Couldn’t find the server. Check the URL (wss://) and spelling.';

    // Connectivity
    if (text.includes('econnrefused') || text.includes('connection refused')) return 'The server refused the connection. The server may be down or blocking connections.';
    if (text.includes('etimedout') || text.includes('timeout')) return 'The connection timed out. Check your network, firewall, or try again.';

    // TLS/cert
    if (text.includes('self signed') || text.includes('certificate') || text.includes('err_ssl') || text.includes('cert_')) return 'Secure connection failed: the server’s TLS certificate is not trusted. Use a valid certificate or trust your self-signed cert.';
    if (text.includes('tls') && text.includes('handshake')) return 'Secure connection failed during TLS handshake.';

    // HTTP gateways
    if (text.includes(' 401') || text.includes('unauthorized')) return 'Unauthorized. The server requires authentication.';
    if (text.includes(' 403') || text.includes('forbidden')) return 'Forbidden. Access to the server is blocked.';
    if (text.includes(' 502') || text.includes(' 503') || text.includes(' 504')) return 'Server is temporarily unavailable. Please try again later.';

    // Fallback
    return 'Failed to connect to the server. Please verify the URL (wss://) and try again.';
  };

  const handleContinue = async () => {
    if (!canContinue) return;
    setIsContinuing(true);
    setTestStatus('');
    setTestError('');
    try {
      // Ensure Tor ready in network manager
      const torReady = await ensureTorInitialized();
      if (!torReady) {
        setTestError('Tor verification failed. Please retry.');
        setIsContinuing(false);
        return;
      }

      const serverUrl = chosenServerUrl;
      if (!serverUrl) {
        setTestError('Invalid server URL. Please enter a valid wss:// URL.');
        setIsContinuing(false);
        return;
      }

      // Probe connection first for quick feedback
      setIsTesting(true);
      setTestStatus('Testing connection...');
      await testConnection(serverUrl);
      setIsTesting(false);
      setTestStatus('Connected');

      // Persist server URL
      try {
        const electronAPI = (window as any).electronAPI;
        if (electronAPI && electronAPI.setServerUrl) {
          await electronAPI.setServerUrl(serverUrl);
        } else {
          const edgeApi = (window as any).edgeApi;
          if (edgeApi && edgeApi.setServerUrl) {
            await edgeApi.setServerUrl(serverUrl);
          }
        }
      } catch {}

      // Let parent continue flow (e.g., wsConnect + navigate)
      await (onComplete?.(serverUrl));
    } catch (_error) {
      console.error('[ConnectSetup] handleContinue error', _error);
      setIsTesting(false);
      const friendly = humanizeConnectionError(_error);
      setTestError(friendly);
    } finally {
      setIsContinuing(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Connect</CardTitle>
              <CardDescription>Set up Tor and select your server. Continue when both are ready.</CardDescription>
            </div>
            {testStatus && !testError && (
              <div className="text-sm text-muted-foreground">{testStatus}</div>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-8">
          {testError && (
            <Alert variant="destructive">
              <AlertDescription>
                <strong>Connection Error:</strong> {testError}
              </AlertDescription>
            </Alert>
          )}
          {/* Tor Setup Section */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="font-medium">Tor Setup</div>
              <div className="text-sm text-muted-foreground">
                {isSetupRunning ? 'Setting up…' : (status.setupProgress === 100 ? 'Complete' : (status.error ? 'Failed' : 'Not configured'))}
              </div>
            </div>

            {status.error && !isSetupRunning && status.setupProgress === 0 && (
              <Alert variant="destructive">
                <AlertDescription>
                  <strong>Setup Error:</strong> {status.error}
                </AlertDescription>
              </Alert>
            )}

            {(isSetupRunning || status.setupProgress > 0) && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>{status.currentStep}</span>
                  <span>{status.setupProgress}%</span>
                </div>
                <Progress value={status.setupProgress} className="w-full" />
              </div>
            )}

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

            {status.setupProgress !== 100 && (
              <div className="space-y-3">
                <Button onClick={handleAutoSetup} disabled={isSetupRunning} className="w-full" size="lg">
                  {isSetupRunning ? 'Setting up…' : 'Auto-Setup Tor'}
                </Button>
              </div>
            )}

            {status.setupProgress === 100 && !isSetupRunning && (
              <div className="flex gap-2">
                <Button onClick={() => setShowVerification(true)} variant="outline" className="w-full">
                  Verify Tor
                </Button>
              </div>
            )}

            <Button variant="ghost" size="sm" onClick={() => setShowAdvanced(!showAdvanced)} className="w-full">
              {showAdvanced ? 'Hide' : 'Show'} Advanced Options
            </Button>

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

                <div className="space-y-3 p-3 bg-white rounded-md border">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="enableBridges" className="text-sm font-medium">Use Bridges</Label>
                    <input id="enableBridges" type="checkbox" className="h-4 w-4" checked={enableBridges} onChange={(e) => setEnableBridges(e.target.checked)} />
                  </div>

                  {enableBridges && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <Label htmlFor="transport" className="text-sm">Transport</Label>
                          <select id="transport" className="border rounded px-2 py-1 text-sm w-full bg-white" value={transport} onChange={(e) => setTransport((e.target.value as 'obfs4' | 'snowflake'))}>
                            <option value="obfs4">obfs4</option>
                            <option value="snowflake">snowflake</option>
                          </select>
                        </div>
                        {transport === 'obfs4' && (
                          <div className="space-y-1">
                            <Label htmlFor="obfs4path" className="text-sm">obfs4proxy path (optional)</Label>
                            <Input id="obfs4path" placeholder="e.g. /usr/bin/obfs4proxy" value={obfs4ProxyPath} onChange={(e) => setObfs4ProxyPath(e.target.value)} />
                          </div>
                        )}
                      </div>

                      <div className="space-y-1">
                        <Label htmlFor="bridges" className="text-sm">Bridge lines</Label>
                        <Textarea id="bridges" placeholder="One per line" value={bridgesText} onChange={(e) => setBridgesText(e.target.value)} className="min-h-[120px]" />
                      </div>
                    </div>
                  )}

                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={async () => {
                      await getTorAutoSetup().stopTor();
                      const newStatus = await getTorAutoSetup().refreshStatus();
                      setStatus({ ...newStatus, setupProgress: 0, currentStep: 'Ready to setup' });
                    }} disabled={!status.isRunning}>Stop Tor</Button>

                    <Button variant="outline" size="sm" onClick={async () => {
                      await getTorAutoSetup().uninstallTor();
                      const newStatus = await getTorAutoSetup().refreshStatus();
                      setStatus({ ...newStatus, setupProgress: 0, currentStep: 'Ready to setup' });
                    }} disabled={isSetupRunning}>Uninstall</Button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Server Selection Section */}
          <div className="space-y-4">
            <div className="font-medium">Server Selection</div>

            <div className="space-y-4">

              <div
                className={`p-4 border rounded-lg transition-all border-primary bg-primary/5 ring-1 ring-primary/20`}
              >
                <div className="flex items-start gap-3">
                  <div className="flex-1 space-y-3">
                    <div>
                      <div className="font-medium text-base">Custom server</div>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="custom-url" className="text-sm font-medium">Server URL</Label>
                      <Input
                        id="custom-url"
                        placeholder="wss://your-server.example.com"
                        value={customServerUrl}
                        onChange={(e) => setCustomServerUrl(e.target.value)}
                        className="font-mono text-sm"
                      />
                      <div className="text-xs text-muted-foreground">Only secure WebSocket (wss://) is allowed.</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Unified Continue Button */}
          <div>
            <Button
              onClick={handleContinue}
              disabled={!canContinue}
              className="w-full"
              size="lg"
            >
              {isContinuing || isTesting ? 'Continuing…' : 'Continue'}
            </Button>
            {!status.isRunning && (
              <div className="mt-2 text-xs text-muted-foreground text-center">Start or complete Tor setup to continue.</div>
            )}
            {status.isRunning && !chosenServerUrl && (
              <div className="mt-2 text-xs text-muted-foreground text-center">Select or enter a server to continue.</div>
            )}
          </div>
        </CardContent>
      </Card>

      {showVerification && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 overflow-hidden" onClick={(e) => { if (e.target === e.currentTarget) setShowVerification(false); }}>
          <div className="max-h-[90vh] overflow-y-auto">
            <TorVerification onClose={() => setShowVerification(false)} />
          </div>
        </div>
      )}
    </div>
  );
}
