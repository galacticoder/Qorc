import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { getTorAutoSetup } from '../../lib/transport/tor-auto-setup';
import type { TorSetupStatus } from '../../lib/types/tor-types';
import { torNetworkManager } from '../../lib/transport/tor-network';
import { toast } from 'sonner';
import { websocket, storage } from '../../lib/tauri-bindings';
import { ThemeToggleButton } from '../ui/ThemeToggleButton';

interface ConnectSetupProps {
  onComplete?: (serverUrl: string) => Promise<void> | void;
  onDisconnect?: () => Promise<void> | void;
  initialServerUrl?: string;
  isConnected?: boolean;
}

type SymbolKind = 'lock' | 'eye' | 'government';

const AUTO_START_KEY = 'qor_tor_auto_start_v1';
const AUTO_CONNECT_KEY = 'qor_tor_auto_connect_v1';
const BRIDGES_ENABLED_KEY = 'qor_tor_bridges_enabled_v1';
const BRIDGE_TRANSPORT_KEY = 'qor_tor_bridge_transport_v1';
const BRIDGE_LINES_KEY = 'qor_tor_bridge_lines_v1';

const readBooleanPreference = async (key: string): Promise<boolean> => {
  try {
    const value = await storage.get(key);
    if (value !== null) return value === 'true' || value === '1';
  } catch { }

  try {
    const value = localStorage.getItem(key);
    return value === 'true' || value === '1';
  } catch {
    return false;
  }
};

const writeBooleanPreference = async (key: string, value: boolean): Promise<void> => {
  try {
    await storage.set(key, value ? 'true' : 'false');
  } catch {
    try {
      localStorage.setItem(key, value ? 'true' : 'false');
    } catch { }
  }
};

const readStringPreference = async (key: string): Promise<string> => {
  try {
    const value = await storage.get(key);
    if (value !== null) return value;
  } catch { }

  try {
    return localStorage.getItem(key) || '';
  } catch {
    return '';
  }
};

const writeStringPreference = async (key: string, value: string): Promise<void> => {
  try {
    await storage.set(key, value);
  } catch {
    try {
      localStorage.setItem(key, value);
    } catch { }
  }
};

const setupSymbols: readonly Readonly<{
  icon: SymbolKind;
  x: string;
  y: string;
  s: string;
  r: string;
  o: string;
}>[] = [
  { icon: 'lock', x: '7%', y: '18%', s: '42px', r: '-11deg', o: '.2' },
  { icon: 'eye', x: '14%', y: '8%', s: '34px', r: '19deg', o: '.13' },
  { icon: 'government', x: '23%', y: '9%', s: '48px', r: '-15deg', o: '.15' },
  { icon: 'lock', x: '32%', y: '3%', s: '32px', r: '10deg', o: '.14' },
  { icon: 'eye', x: '50%', y: '1%', s: '44px', r: '-8deg', o: '.11' },
  { icon: 'lock', x: '68%', y: '4%', s: '38px', r: '18deg', o: '.13' },
  { icon: 'government', x: '77%', y: '9%', s: '54px', r: '-12deg', o: '.14' },
  { icon: 'eye', x: '88%', y: '8%', s: '34px', r: '9deg', o: '.16' },
  { icon: 'government', x: '4%', y: '32%', s: '58px', r: '8deg', o: '.15' },
  { icon: 'lock', x: '16%', y: '30%', s: '36px', r: '-22deg', o: '.18' },
  { icon: 'eye', x: '22%', y: '25%', s: '40px', r: '14deg', o: '.13' },
  { icon: 'eye', x: '76%', y: '25%', s: '42px', r: '-18deg', o: '.14' },
  { icon: 'lock', x: '82%', y: '31%', s: '40px', r: '20deg', o: '.18' },
  { icon: 'government', x: '93%', y: '34%', s: '52px', r: '-9deg', o: '.13' },
  { icon: 'eye', x: '8%', y: '48%', s: '46px', r: '16deg', o: '.14' },
  { icon: 'lock', x: '17%', y: '51%', s: '35px', r: '-7deg', o: '.17' },
  { icon: 'lock', x: '83%', y: '49%', s: '35px', r: '12deg', o: '.15' },
  { icon: 'eye', x: '91%', y: '53%', s: '43px', r: '-21deg', o: '.16' },
  { icon: 'lock', x: '3%', y: '69%', s: '38px', r: '-13deg', o: '.16' },
  { icon: 'government', x: '14%', y: '74%', s: '56px', r: '8deg', o: '.15' },
  { icon: 'eye', x: '22%', y: '75%', s: '39px', r: '22deg', o: '.15' },
  { icon: 'eye', x: '76%', y: '74%', s: '48px', r: '13deg', o: '.18' },
  { icon: 'lock', x: '84%', y: '72%', s: '35px', r: '-22deg', o: '.16' },
  { icon: 'government', x: '93%', y: '76%', s: '60px', r: '-14deg', o: '.13' },
  { icon: 'eye', x: '9%', y: '90%', s: '33px', r: '11deg', o: '.15' },
  { icon: 'lock', x: '21%', y: '88%', s: '42px', r: '-16deg', o: '.13' },
  { icon: 'government', x: '31%', y: '94%', s: '50px', r: '7deg', o: '.12' },
  { icon: 'lock', x: '49%', y: '99%', s: '36px', r: '-10deg', o: '.14' },
  { icon: 'lock', x: '66%', y: '93%', s: '43px', r: '18deg', o: '.13' },
  { icon: 'government', x: '76%', y: '91%', s: '58px', r: '-8deg', o: '.12' },
  { icon: 'eye', x: '89%', y: '89%', s: '34px', r: '15deg', o: '.16' },
];

const LockSymbol = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2" fill="none" stroke="currentColor" strokeWidth="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke="currentColor" strokeWidth="2" />
    <circle cx="12" cy="16" r="1" fill="currentColor" />
  </svg>
);

const EyeSymbol = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" strokeWidth="2" />
  </svg>
);

const GovernmentSymbol = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M3 10h18L12 4 3 10Z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    <path d="M5 10v8M9 10v8M15 10v8M19 10v8M3 20h18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
  </svg>
);

const RefreshIcon = ({ spinning = false }: { spinning?: boolean }) => (
  <svg className={spinning ? 'tor-flat-spin' : undefined} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M21 12a9 9 0 1 1-2.64-6.36" />
    <path d="M21 3v6h-6" />
  </svg>
);

const BridgeIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    <rect x="4" y="11" width="16" height="10" rx="2" />
  </svg>
);

const ClockRefreshIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M12 5v7l4 2" />
    <path d="M21 12a9 9 0 1 1-3-6.7" />
    <path d="M21 3v5h-5" />
  </svg>
);

const CheckIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M20 6 9 17l-5-5" />
  </svg>
);

const renderSymbolIcon = (icon: SymbolKind) => {
  if (icon === 'lock') return <LockSymbol />;
  if (icon === 'eye') return <EyeSymbol />;
  return <GovernmentSymbol />;
};

export function ConnectSetup({ onComplete, onDisconnect, initialServerUrl = '', isConnected = false }: ConnectSetupProps) {
  const [status, setStatus] = useState<TorSetupStatus>({
    isInstalled: false,
    isConfigured: false,
    isRunning: false,
    isBootstrapped: false,
    setupProgress: 0,
    currentStep: 'Ready to setup'
  });
  const [isSetupRunning, setIsSetupRunning] = useState(false);
  const [enableBridges, setEnableBridges] = useState(false);
  const [autoStartEnabled, setAutoStartEnabled] = useState(false);
  const [autoConnectEnabled, setAutoConnectEnabled] = useState(false);
  const [customServerUrl, setCustomServerUrl] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testStatus, setTestStatus] = useState<string>('');
  const [testError, setTestError] = useState<string>('');
  const [isContinuing, setIsContinuing] = useState(false);
  const [transport, setTransport] = useState<'obfs4' | 'snowflake'>('obfs4');
  const [bridgesText, setBridgesText] = useState('');
  const [preferencesReady, setPreferencesReady] = useState(false);
  const continueInFlightRef = useRef(false);
  const autoStartTriggeredRef = useRef(false);
  const autoConnectAttemptRef = useRef<string | null>(null);

  useEffect(() => {
    (async () => {
      const [savedAutoStart, savedAutoConnect, savedBridgeEnabled, savedBridgeTransport, savedBridgeLines] = await Promise.all([
        readBooleanPreference(AUTO_START_KEY),
        readBooleanPreference(AUTO_CONNECT_KEY),
        readBooleanPreference(BRIDGES_ENABLED_KEY),
        readStringPreference(BRIDGE_TRANSPORT_KEY),
        readStringPreference(BRIDGE_LINES_KEY),
      ]);

      try {
        const initialStatus = await getTorAutoSetup().refreshStatus();
        setStatus(initialStatus);
        if (initialStatus.isRunning) {
          torNetworkManager.updateConfig({
            enabled: true,
            socksPort: initialStatus.socksPort || 9150,
            controlPort: initialStatus.controlPort || 9151
          });
          void torNetworkManager.syncWithDaemon();
        }

        const storedUrl = await websocket.getServerUrl();
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

      setAutoStartEnabled(savedAutoStart);
      setAutoConnectEnabled(savedAutoStart && savedAutoConnect);
      setEnableBridges(savedBridgeEnabled);
      setTransport(savedBridgeTransport === 'snowflake' ? 'snowflake' : 'obfs4');
      setBridgesText(savedBridgeLines);
      setPreferencesReady(true);
    })();
  }, [initialServerUrl]);

  useEffect(() => {
    if (!status.isRunning || status.isBootstrapped || isSetupRunning) {
      return;
    }

    const timer = window.setInterval(async () => {
      try {
        const refreshed = await getTorAutoSetup().refreshStatus();
        setStatus(refreshed);
        if (refreshed.isBootstrapped) {
          torNetworkManager.updateConfig({
            enabled: true,
            socksPort: refreshed.socksPort || 9150,
            controlPort: refreshed.controlPort || 9151
          });
          await torNetworkManager.syncWithDaemon();
        }
      } catch { }
    }, 2000);

    return () => window.clearInterval(timer);
  }, [status.isRunning, status.isBootstrapped, isSetupRunning]);

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

  const chosenServerUrl = useMemo(() => normalizeToWss(customServerUrl), [customServerUrl]);
  const torReady = Boolean((status.isRunning && status.isBootstrapped) || isConnected);
  const torStarting = Boolean(isSetupRunning || (status.isRunning && !status.isBootstrapped));
  const meterProgress = torReady
    ? 100
    : Math.max(16, Math.min(99, status.bootstrapProgress || status.setupProgress || 16));
  const canContinue = torReady && !!chosenServerUrl && !isSetupRunning && !isTesting && !isContinuing && !isConnected;
  const canDisconnect = isConnected && !isSetupRunning && !isTesting && !isContinuing;
  const canStopTor = status.isRunning && !isSetupRunning && !isTesting && !isContinuing && !isConnected;
  const serverLocked = !torReady || isConnected;

  const handleAutoSetup = async () => {
    setIsSetupRunning(true);
    setStatus(prev => ({ ...prev, error: undefined }));
    setTestError('');
    try {
      const beforeSetup = await getTorAutoSetup().refreshStatus();
      if (beforeSetup.isRunning && !beforeSetup.isBootstrapped) {
        setStatus(prev => ({
          ...prev,
          setupProgress: Math.max(prev.setupProgress || 0, 5),
          currentStep: 'Restarting Tor...'
        }));
        await getTorAutoSetup().stopTor();
        await torNetworkManager.shutdown();
      }

      const bridges = bridgesText.split('\n').map(l => l.trim()).filter(Boolean);
      void writeBooleanPreference(BRIDGES_ENABLED_KEY, enableBridges);
      void writeStringPreference(BRIDGE_TRANSPORT_KEY, transport);
      void writeStringPreference(BRIDGE_LINES_KEY, bridgesText);
      const success = await getTorAutoSetup().autoSetup({
        autoStart: true,
        enableBridges,
        allowBridgeFallback: true,
        transport,
        bridges,
        onProgress: (newStatus) => {
          setStatus(prevStatus => ({ ...prevStatus, ...newStatus, error: newStatus.error || undefined }));
        }
      });
      if (success) {
        let refreshed = await getTorAutoSetup().refreshStatus();
        let attempts = 0;
        while (!refreshed.isBootstrapped && attempts < 30 && refreshed.isRunning) {
          await new Promise(r => setTimeout(r, 2000));
          refreshed = await getTorAutoSetup().refreshStatus();
          setStatus(refreshed);
          attempts++;
        }

        setStatus(refreshed);

        torNetworkManager.updateConfig({
          enabled: true,
          socksPort: refreshed.socksPort,
          controlPort: refreshed.controlPort
        });
        const ready = await torNetworkManager.syncWithDaemon() || await torNetworkManager.initialize();
        await websocket.setTorReady(ready, refreshed.socksPort);
        (window as any).__TOR_MODE__ = ready;
        if (!ready) {
          setStatus(prev => ({ ...prev, error: 'Tor started but did not finish bootstrapping. Check your internet connection and retry.' }));
        }
      } else {
        const refreshed = await getTorAutoSetup().refreshStatus();
        setStatus(refreshed);
        await torNetworkManager.syncWithDaemon();
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

  const handleStopTor = async () => {
    if (!canStopTor) return;
    setIsSetupRunning(true);
    setTestStatus('');
    setTestError('');
    try {
      await getTorAutoSetup().stopTor();
      await torNetworkManager.shutdown();
      await websocket.setTorReady(false).catch(() => { });
      (window as any).__TOR_MODE__ = false;
      const newStatus = await getTorAutoSetup().refreshStatus();
      setStatus({ ...newStatus, setupProgress: 0, currentStep: 'Ready to setup' });
    } catch (_error) {
      const friendly = _error instanceof Error ? _error.message : 'Failed to stop Tor.';
      setTestError(friendly);
      toast.error(friendly);
    } finally {
      setIsSetupRunning(false);
    }
  };

  const isRecoverableConnectionStall = (value: unknown): boolean => {
    const text = value instanceof Error ? value.message : String(value || '');
    const normalized = text.toLowerCase();
    return normalized.includes('connection in progress')
      || normalized.includes('connection attempt cancelled')
      || normalized.includes('websocket upgrade timeout')
      || normalized.includes('websocket probe timeout')
      || normalized.includes('connection timeout');
  };

  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  const testConnection = async (url: string, timeoutMs = 45000): Promise<void> => {
    const runProbe = () => websocket.probeConnect(url, timeoutMs);
    let res = await runProbe();
    if ((!res || res.success === false) && isRecoverableConnectionStall(res?.error)) {
      setTestStatus('Resetting stale connection...');
      if (!isConnected) {
        await websocket.disconnect().catch(() => { });
      }
      await sleep(350);
      res = await runProbe();
    }
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

      const ok = await torNetworkManager.syncWithDaemon() || await torNetworkManager.initialize();
      const refreshed = await getTorAutoSetup().refreshStatus();
      setStatus(refreshed);

      if (ok && refreshed.isBootstrapped) {
        await websocket.setTorReady(true, refreshed.socksPort);
        return true;
      }

      await websocket.setTorReady(false);
      return false;
    } catch {
      return false;
    }
  };

  const humanizeConnectionError = (err: unknown): string => {
    const raw = (err instanceof Error ? err.message : (typeof err === 'string' ? err : '')) || '';
    const code = (err as any)?.code ? String((err as any).code) : '';
    const text = `${code} ${raw}`.toLowerCase();

    if (text.includes('eai_again')) return 'Temporary DNS issue. Check internet connection.';
    if (text.includes('enotfound') || text.includes('eai_noname') || text.includes('getaddrinfo')) return 'Server not found. Check the URL.';
    if (text.includes('connection in progress')) return 'Connection is still resetting. Try again in a moment.';
    if (text.includes('connection attempt cancelled')) return 'Connection reset. Try again in a moment.';
    if (text.includes('econnrefused') || text.includes('connection refused')) return 'Connection refused. Server may be down.';
    if (text.includes('etimedout') || text.includes('timeout')) return 'Connection timed out. Check network/firewall.';
    if (text.includes('self signed') || text.includes('certificate') || text.includes('err_ssl') || text.includes('cert_')) return 'Untrusted certificate.';
    if (text.includes('tls') && text.includes('handshake')) return 'TLS handshake failed.';
    if (text.includes(' 401') || text.includes('unauthorized')) return 'Unauthorized.';
    if (text.includes(' 403') || text.includes('forbidden')) return 'Forbidden.';
    if (text.includes(' 502') || text.includes(' 503') || text.includes(' 504')) return 'Server unavailable.';

    return 'Failed to connect. Verify URL.';
  };

  const handleContinue = async () => {
    if (!canContinue || continueInFlightRef.current) return;
    continueInFlightRef.current = true;
    setIsContinuing(true);
    setTestStatus('');
    setTestError('');
    try {
      const ready = await ensureTorInitialized();
      if (!ready) {
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

      setIsTesting(true);
      setTestStatus('Testing connection...');
      await testConnection(serverUrl);
      setIsTesting(false);
      setTestStatus('Connected');

      try {
        await websocket.setServerUrl(serverUrl);
      } catch { }

      await (onComplete?.(serverUrl));
    } catch (_error) {
      console.error('[ConnectSetup] handleContinue error', _error);
      const friendly = humanizeConnectionError(_error);
      setTestError(friendly);
      if (isRecoverableConnectionStall(_error) && !isConnected) {
        await websocket.disconnect().catch(() => { });
      }
      toast.error(friendly);
    } finally {
      setIsTesting(false);
      setIsContinuing(false);
      continueInFlightRef.current = false;
    }
  };

  const handleDisconnect = async () => {
    if (!canDisconnect) return;
    setIsContinuing(true);
    setTestStatus('');
    setTestError('');
    autoConnectAttemptRef.current = chosenServerUrl || null;
    setAutoConnectEnabled(false);
    await writeBooleanPreference(AUTO_CONNECT_KEY, false);
    try {
      await onDisconnect?.();
      setTestStatus('Disconnected');
    } catch (_error) {
      console.error('[ConnectSetup] handleDisconnect error', _error);
      const friendly = _error instanceof Error ? _error.message : 'Failed to disconnect.';
      setTestError(friendly);
      toast.error(friendly);
    } finally {
      setIsContinuing(false);
    }
  };

  const initTorText = isSetupRunning
    ? (status.currentStep || 'Starting Tor')
    : (status.isRunning && !status.isBootstrapped)
      ? `Restart Tor (${status.bootstrapProgress || 0}%)`
      : status.isRunning
        ? 'Restart Tor'
        : 'Initialize Tor';
  const connectText = isConnected
    ? (isContinuing ? 'Disconnecting...' : 'Disconnect')
    : isContinuing || isTesting
      ? (isTesting ? 'Testing Connection...' : 'Connecting...')
      : 'Connect to Server';

  useEffect(() => {
    if (!preferencesReady) return;
    void writeBooleanPreference(AUTO_START_KEY, autoStartEnabled);
    if (!autoStartEnabled && autoConnectEnabled) {
      setAutoConnectEnabled(false);
      autoConnectAttemptRef.current = null;
    }
  }, [preferencesReady, autoStartEnabled, autoConnectEnabled]);

  useEffect(() => {
    if (!preferencesReady) return;
    void writeBooleanPreference(AUTO_CONNECT_KEY, autoStartEnabled && autoConnectEnabled);
  }, [preferencesReady, autoStartEnabled, autoConnectEnabled]);

  useEffect(() => {
    if (!preferencesReady) return;
    void writeBooleanPreference(BRIDGES_ENABLED_KEY, enableBridges);
    void writeStringPreference(BRIDGE_TRANSPORT_KEY, transport);
    void writeStringPreference(BRIDGE_LINES_KEY, bridgesText);
  }, [preferencesReady, enableBridges, transport, bridgesText]);

  useEffect(() => {
    if (!preferencesReady) return;
    if (!autoStartEnabled || autoStartTriggeredRef.current) return;
    if (isConnected || status.isRunning || isSetupRunning || isTesting || isContinuing) return;

    autoStartTriggeredRef.current = true;
    void handleAutoSetup();
  }, [preferencesReady, autoStartEnabled, isConnected, status.isRunning, isSetupRunning, isTesting, isContinuing]);

  useEffect(() => {
    if (!preferencesReady) return;
    if (!autoStartEnabled || !autoConnectEnabled || !canContinue || !chosenServerUrl) return;
    if (autoConnectAttemptRef.current === chosenServerUrl) return;

    autoConnectAttemptRef.current = chosenServerUrl;
    void handleContinue();
  }, [preferencesReady, autoStartEnabled, autoConnectEnabled, canContinue, chosenServerUrl]);

  return (
    <section className="screen screen-setup">
      <div className="tor-flat">
        <ThemeToggleButton className="auth-theme-toggle" />
        <div className="setup-tor-backdrop" aria-hidden="true">
          <div className="setup-protection-field">
            {setupSymbols.map((symbol, index) => (
              <span
                className="setup-symbol"
                key={`${symbol.icon}-${index}`}
                style={{
                  '--x': symbol.x,
                  '--y': symbol.y,
                  '--s': symbol.s,
                  '--r': symbol.r,
                  '--o': symbol.o,
                } as CSSProperties}
              >
                {renderSymbolIcon(symbol.icon)}
              </span>
            ))}
          </div>
        </div>

        <main className={`tor-flat-shell ${torReady ? 'tor-ready' : ''}`} id="setupConsole">
          <header className="tor-flat-intro">
            <div className="tor-flat-copy">
              <h1>Qor setup</h1>
              <p />
              <span>Start the local Tor runtime, choose a bridge transport when needed, then connect Qor through the private server route.</span>
            </div>
          </header>

          <div className="tor-flat-status">
            <span className="tor-flat-kicker">Tor setup</span>
            <span className="tor-flat-pill" aria-label={torReady ? 'Tor on' : torStarting ? 'Tor starting' : 'Tor off'}>Tor</span>
            <div className="tor-flat-meter" aria-hidden="true">
              <span style={{ width: `${meterProgress}%` }} />
            </div>
            <div className="tor-flat-steps">
              <span className={status.isRunning ? 'active' : undefined}>{status.isRunning ? 'Daemon online' : 'Daemon offline'}</span>
              <span className={torReady ? 'active' : undefined}>{torReady ? 'Circuit bootstrapped' : 'Circuit not bootstrapped'}</span>
              <span className={isConnected ? 'active' : torReady ? 'active' : undefined}>{isConnected ? 'Server connected' : torReady ? 'Server probe unlocked' : 'Server probe locked'}</span>
            </div>
          </div>

          <div className="tor-flat-row">
            <div className="tor-flat-label">
              <strong>Runtime</strong>
              <span>Start Tor locally.</span>
            </div>
            <div className="tor-flat-controls">
              <div className={`tor-flat-bridges ${enableBridges ? 'enabled' : ''}`}>
                <div className="tor-flat-actions">
                  <div className="tor-action-pill">
                    <button className="tor-flat-btn" type="button" onClick={handleAutoSetup} disabled={isSetupRunning || isTesting || isContinuing || isConnected}>
                      <RefreshIcon spinning={torStarting} />
                      <span>{initTorText}</span>
                    </button>
                    <button className="tor-flat-btn secondary" type="button" onClick={handleStopTor} disabled={!canStopTor}>Stop Tor</button>
                  </div>
                  <button
                    className="tor-flat-bridges-toggle"
                    type="button"
                    onClick={() => setEnableBridges(prev => !prev)}
                    aria-pressed={enableBridges}
                    disabled={isSetupRunning}
                  >
                    <BridgeIcon />
                    <span>{enableBridges ? 'Bridges enabled' : 'Enable bridges'}</span>
                  </button>
                  <button
                    className={`tor-flat-auto-toggle ${autoStartEnabled ? 'enabled' : ''}`}
                    type="button"
                    aria-pressed={autoStartEnabled}
                    onClick={() => {
                      setAutoStartEnabled(prev => {
                        const next = !prev;
                        if (next) {
                          autoStartTriggeredRef.current = false;
                        } else {
                          setAutoConnectEnabled(false);
                          autoConnectAttemptRef.current = null;
                        }
                        return next;
                      });
                    }}
                    disabled={isSetupRunning}
                  >
                    <ClockRefreshIcon />
                    <span>{autoStartEnabled ? 'Auto start on' : 'Auto start Tor'}</span>
                  </button>
                </div>
                <div className="tor-flat-bridges-content">
                  <div className="tor-flat-field">
                    <label htmlFor="transport">Bridge transport</label>
                    <select
                      className="tor-flat-select"
                      id="transport"
                      value={transport}
                      onChange={(event) => setTransport(event.target.value as 'obfs4' | 'snowflake')}
                      disabled={isSetupRunning}
                    >
                      <option value="obfs4">obfs4 (Standard)</option>
                      <option value="snowflake">snowflake (Resilient)</option>
                    </select>
                  </div>
                  <div className="tor-flat-field">
                    <label htmlFor="bridges">Bridge lines</label>
                    <textarea
                      className="tor-flat-textarea"
                      id="bridges"
                      placeholder="Paste bridge lines here..."
                      value={bridgesText}
                      onChange={(event) => setBridgesText(event.target.value)}
                      disabled={isSetupRunning}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="tor-flat-row">
            <div className="tor-flat-label">
              <strong>Server</strong>
              <span>Enter the relay address after Tor is active, then test the connection.</span>
            </div>
            <div className="tor-flat-stack">
              <div className="tor-flat-field">
                <label htmlFor="server-url">Address</label>
                <input
                  className="tor-flat-input"
                  id="server-url"
                  placeholder="wss://your-server"
                  value={customServerUrl}
                  onChange={(event) => {
                    autoConnectAttemptRef.current = null;
                    setCustomServerUrl(event.target.value);
                  }}
                  disabled={serverLocked}
                />
              </div>
              {(testError || status.error) && (
                <div className="tor-flat-feedback" aria-live="polite">
                  {testError && <p className="is-error">{testError}</p>}
                  {status.error && <p className="is-error">{status.error}</p>}
                </div>
              )}
              <div className="tor-server-actions">
                <button
                  className={`tor-flat-btn ${isConnected ? 'danger' : ''}`}
                  type="button"
                  onClick={isConnected ? handleDisconnect : handleContinue}
                  disabled={isConnected ? !canDisconnect : !canContinue}
                >
                  {(isContinuing || isTesting) && <span className="tor-flat-spinner" aria-hidden="true" />}
                  {connectText}
                </button>
                <button
                  className={`tor-flat-auto-toggle ${autoConnectEnabled ? 'enabled' : ''}`}
                  type="button"
                  aria-pressed={autoConnectEnabled}
                  onClick={() => {
                    setAutoConnectEnabled(prev => {
                      const next = !prev;
                      if (next) autoConnectAttemptRef.current = null;
                      return next;
                    });
                  }}
                  disabled={!autoStartEnabled || !torReady || isConnected || !chosenServerUrl}
                >
                  <CheckIcon />
                  <span>{autoConnectEnabled ? 'Auto connect on' : 'Auto connect'}</span>
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </section>
  );
}
