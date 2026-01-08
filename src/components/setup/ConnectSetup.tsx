import { useEffect, useMemo, useState, useRef } from 'react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Textarea } from '../ui/textarea';
import { getTorAutoSetup, TorSetupStatus } from '../../lib/tor-auto-setup';
import { torNetworkManager } from '../../lib/tor-network';
import { ShieldCheck, Server, Settings, ChevronDown, ChevronUp, RefreshCw, Loader2 } from 'lucide-react';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../ui/collapsible';
import { toast } from 'sonner';

interface ConnectSetupProps {
  onComplete?: (serverUrl: string) => Promise<void> | void;
  initialServerUrl?: string;
}

export function ConnectSetup({ onComplete, initialServerUrl = '' }: ConnectSetupProps) {
  const [status, setStatus] = useState<TorSetupStatus>({
    isInstalled: false,
    isConfigured: false,
    isRunning: false,
    setupProgress: 0,
    currentStep: 'Ready to setup'
  });
  const [isSetupRunning, setIsSetupRunning] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Server selection state
  const [customServerUrl, setCustomServerUrl] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testStatus, setTestStatus] = useState<string>('');
  const [testError, setTestError] = useState<string>('');
  const [isContinuing, setIsContinuing] = useState(false);

  // Advanced Tor config
  const [enableBridges, setEnableBridges] = useState(false);
  const [transport, setTransport] = useState<'obfs4' | 'snowflake'>('obfs4');
  const [bridgesText, setBridgesText] = useState('');
  const bridgesTextRef = useRef('');

  const debounce = <T extends (...args: any[]) => void>(fn: T, wait: number) => {
    let timeout: ReturnType<typeof setTimeout> | null = null;
    return (...args: Parameters<T>) => {
      if (timeout) clearTimeout(timeout);
      timeout = setTimeout(() => {
        timeout = null;
        fn(...args);
      }, wait);
    };
  };

  const debouncedSetBridges = useMemo(
    () => debounce((value: string) => {
      setBridgesText(value);
      setEnableBridges(!!value.trim());
    }, 150),
    []
  );

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
      } catch { }
    })();
  }, [initialServerUrl]);

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
        onProgress: (newStatus) => {
          setStatus(prevStatus => ({ ...prevStatus, ...newStatus, error: newStatus.error || undefined }));
        }
      });
      if (success) {
        const refreshed = await getTorAutoSetup().refreshStatus();
        setStatus(refreshed);

        torNetworkManager.updateConfig({
          enabled: true,
          socksPort: refreshed.socksPort,
          controlPort: refreshed.controlPort
        });
        await torNetworkManager.initialize();
        (window as any).__TOR_MODE__ = true;

        try {
          await (window as any).electronAPI?.torSetupComplete?.();
        } catch (e) {
          console.warn('[ConnectSetup] Failed to notify Electron of Tor completion:', e);
        }
      }
    } catch (_error) {
      console.error('[ConnectSetup] Auto-setup failed:', _error);
      const errorMsg = _error instanceof Error ? _error.message : 'Setup failed';
      setStatus(prev => ({ ...prev, error: errorMsg, setupProgress: 0 }));
      toast.error(`Tor setup failed: ${errorMsg}`);
    } finally {
      setIsSetupRunning(false);
    }
  };

  const testConnection = async (url: string, timeoutMs = 15000): Promise<void> => {
    const edgeApi: any = (window as any).edgeApi;
    if (!edgeApi?.wsProbeConnect) {
      console.error('[ConnectSetup] wsProbeConnect not available on edgeApi');
      throw new Error('Electron WebSocket probe is required');
    }
    const res = await edgeApi.wsProbeConnect(url, timeoutMs);
    if (!res || res.success === false) {
      throw new Error(res?.error || 'Connection failed');
    }
  };

  const ensureTorInitialized = async (): Promise<boolean> => {
    try {
      const currentStatus = await getTorAutoSetup().refreshStatus();

      torNetworkManager.updateConfig({
        enabled: true,
        socksPort: currentStatus.socksPort || 9150,
        controlPort: currentStatus.controlPort || 9151
      });

      const ok = await torNetworkManager.initialize();

      if (ok) {
        try {
          const edgeApi = (window as any).edgeApi;
          if (edgeApi?.torSetupComplete) {
            await edgeApi.torSetupComplete();
          } else {
            await (window as any).electronAPI?.torSetupComplete?.();
          }
        } catch (e) {
          console.warn('[ConnectSetup] Failed to notify backend after init:', e);
        }
      }

      return !!ok;
    } catch {
      return false;
    }
  };

  const humanizeConnectionError = (err: unknown): string => {
    const raw = (err instanceof Error ? err.message : (typeof err === 'string' ? err : '')) || '';
    const code = (err as any)?.code ? String((err as any).code) : '';
    const text = `${code} ${raw}`.toLowerCase();

    // DNS issues
    if (text.includes('eai_again')) return 'Temporary DNS issue. Check internet connection.';
    if (text.includes('enotfound') || text.includes('eai_noname') || text.includes('getaddrinfo')) return 'Server not found. Check the URL.';

    // Connectivity
    if (text.includes('econnrefused') || text.includes('connection refused')) return 'Connection refused. Server may be down.';
    if (text.includes('etimedout') || text.includes('timeout')) return 'Connection timed out. Check network/firewall.';

    // TLS/cert
    if (text.includes('self signed') || text.includes('certificate') || text.includes('err_ssl') || text.includes('cert_')) return 'Untrusted certificate.';
    if (text.includes('tls') && text.includes('handshake')) return 'TLS handshake failed.';

    // HTTP gateways
    if (text.includes(' 401') || text.includes('unauthorized')) return 'Unauthorized.';
    if (text.includes(' 403') || text.includes('forbidden')) return 'Forbidden.';
    if (text.includes(' 502') || text.includes(' 503') || text.includes(' 504')) return 'Server unavailable.';

    // Fallback
    return 'Failed to connect. Verify URL.';
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
        toast.error('Tor verification failed. Please retry.');
        setIsContinuing(false);
        return;
      }

      const serverUrl = chosenServerUrl;
      if (!serverUrl) {
        toast.error('Invalid server URL.');
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
      } catch { }

      await (onComplete?.(serverUrl));
    } catch (_error) {
      console.error('[ConnectSetup] handleContinue error', _error);
      setIsTesting(false);
      const friendly = humanizeConnectionError(_error);
      toast.error(friendly);
    } finally {
      setIsContinuing(false);
    }
  };

  return (
    <div className="relative flex flex-col items-center justify-center min-h-[80vh] p-6 overflow-hidden select-none">
      {/* Background Effects */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-primary/10 rounded-full blur-3xl opacity-50 pointer-events-none animate-pulse" />
      <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-blue-500/10 rounded-full blur-3xl opacity-30 pointer-events-none" />

      <div className="relative w-full max-w-md space-y-8 z-10">
        {/* Header */}
        <div className="text-center space-y-2 animate-in slide-in-from-bottom-4 fade-in duration-700">
          <div className="mx-auto w-20 h-20 rounded-3xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center mb-6 ring-1 ring-white/10 shadow-2xl shadow-primary/20 backdrop-blur-xl">
            <ShieldCheck className="w-10 h-10 text-primary drop-shadow-[0_0_15px_rgba(124,58,237,0.5)]" />
          </div>
          <h1
            className="text-4xl font-bold tracking-tight"
            style={{ color: document.documentElement.classList.contains('dark') ? '#ffffff' : '#000000' }}
          >
            Secure Connect
          </h1>
          <p
            className="text-lg font-light"
            style={{ color: document.documentElement.classList.contains('dark') ? '#9ca3af' : '#6b7280' }}
          >
            Establish a private, encrypted connection
          </p>
        </div>

        {/* Tor Status Section */}
        <div className="space-y-4 animate-in slide-in-from-bottom-8 fade-in duration-700 delay-100">
          <div className="group p-5 rounded-2xl bg-card/30 border border-white/10 hover:border-primary/30 hover:bg-card/50 transition-all duration-500 backdrop-blur-md shadow-lg">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <span className="font-medium text-lg">Tor Network</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="text-sm font-medium text-muted-foreground">
                  {(status.isRunning && !isSetupRunning) ? 'Active' : 'Inactive'}
                </div>
                {status.isRunning && status.version && status.version !== 'unknown' && (
                  <span className="text-xs font-bold text-muted-foreground/70 animate-in fade-in-0 duration-300">v{status.version}</span>
                )}
              </div>
            </div>

            {/* Setup Button */}
            {(!status.isRunning || isSetupRunning) && (
              <Button
                onClick={handleAutoSetup}
                disabled={isSetupRunning}
                className="w-full bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 hover:border-primary/40 transition-all"
                variant="outline"
              >
                <RefreshCw className={`w-4 h-4 mr-2 ${isSetupRunning ? 'animate-spin' : ''}`} />
                {isSetupRunning ? status.currentStep : 'Initialize Tor'}
              </Button>
            )}


            {/* Advanced Options */}
            <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced} className="mt-3">
              <CollapsibleTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="w-full h-9 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  disabled={isSetupRunning}
                >
                  <Settings className="w-3.5 h-3.5 mr-2" />
                  Advanced Configuration
                  {showAdvanced ? <ChevronUp className="w-3.5 h-3.5 ml-auto" /> : <ChevronDown className="w-3.5 h-3.5 ml-auto" />}
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent
                className="overflow-hidden transition-all duration-200 ease-in-out data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:animate-in data-[state=open]:fade-in-0"
              >
                <div className="space-y-4 pt-4">
                  {/* Bridge Transport Selection */}
                  <div className="space-y-2">
                    <Label htmlFor="transport" className="text-sm font-medium">Bridge Transport</Label>
                    <select
                      id="transport"
                      className="w-full h-10 rounded-lg border border-input bg-background px-3 text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-all"
                      value={transport}
                      onChange={(e) => {
                        setTransport(e.target.value as 'obfs4' | 'snowflake');
                      }}
                    >
                      <option value="obfs4">obfs4 (Standard)</option>
                      <option value="snowflake">snowflake (Resilient)</option>
                    </select>
                  </div>

                  {/* Bridge Lines */}
                  <div className="space-y-2 pl-4 border-l-2 border-primary/30">
                    <Label htmlFor="bridges" className="text-sm font-medium">Bridge Lines</Label>
                    <Textarea
                      id="bridges"
                      placeholder="Paste bridge lines here..."
                      onChange={(e) => {
                        bridgesTextRef.current = e.target.value;
                        debouncedSetBridges(e.target.value);
                      }}
                      defaultValue={bridgesText}
                      className="min-h-[100px] text-sm font-mono resize-none bg-background border-input focus:border-primary/50 focus:ring-2 focus:ring-primary/20 transition-all rounded-lg"
                    />
                  </div>

                  {/* Stop Tor Button */}
                  <Button
                    variant="destructive"
                    size="sm"
                    className="w-full h-9 text-sm"
                    onClick={async () => {
                      await getTorAutoSetup().stopTor();
                      const newStatus = await getTorAutoSetup().refreshStatus();
                      setStatus({ ...newStatus, setupProgress: 0, currentStep: 'Ready to setup' });
                    }}
                    disabled={!status.isRunning || isSetupRunning}
                  >
                    Stop Tor
                  </Button>
                </div>
              </CollapsibleContent>
            </Collapsible>
          </div>
        </div>

        {/* Server Connection */}
        <div className="space-y-6 animate-in slide-in-from-bottom-8 fade-in duration-700 delay-200">
          <div className="space-y-3">
            <Label htmlFor="server-url" className="text-sm font-medium flex items-center gap-2 ml-1 text-muted-foreground">
              <Server className="w-4 h-4" />
              Server Address
            </Label>
            <div className="relative group">
              <div className="absolute -inset-0.5 bg-gradient-to-r from-primary/50 to-primary/40 rounded-lg blur opacity-0 group-hover:opacity-50 transition duration-500" />
              <Input
                id="server-url"
                placeholder="wss://your-server"
                value={customServerUrl}
                onChange={(e) => setCustomServerUrl(e.target.value)}
                className="relative h-14 font-mono text-sm bg-background/80 border-white/10 focus:border-primary/50 focus:ring-2 focus:ring-primary/20 transition-all rounded-lg shadow-sm"
                disabled={!status.isRunning}
              />
            </div>
            {!status.isRunning && (
              <p className="text-xs text-muted-foreground ml-1 opacity-70">Initialize Tor to connect to a server.</p>
            )}

            {(testStatus || testError) && (
              <div className="text-xs ml-1 space-y-1">
                {testStatus && (
                  <div className="text-muted-foreground">{testStatus}</div>
                )}
                {testError && (
                  <div className="text-red-600 dark:text-red-400">{testError}</div>
                )}
              </div>
            )}
          </div>

          <Button
            onClick={handleContinue}
            disabled={!canContinue}
            className="w-full h-14 text-base font-semibold transition-all shadow-xl shadow-primary/20 hover:shadow-primary/40 hover:scale-[1.02] active:scale-[0.98] bg-primary hover:bg-primary/90 border-0"
            size="lg"
          >
            {isContinuing || isTesting ? (
              <>
                <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                {isTesting ? 'Testing Connection...' : 'Connecting...'}
              </>
            ) : (
              'Connect to Server'
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
