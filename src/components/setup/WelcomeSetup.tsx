import { useCallback, useEffect, useRef, useState } from 'react';
import { QorcBrandLogo } from '../ui/QorcBrandLogo';
import { ThemeToggleButton } from '../ui/ThemeToggleButton';
import { useStartupConnection } from '../../hooks/app/useStartupConnection';
import {
  humanizeConnectionError,
  loadTorPreferences,
  normalizeToWss,
  saveTorPreferences,
  startupConnection,
} from '../../lib/transport/startup-connection';
import { torNetworkManager } from '../../lib/transport/tor-network';

interface WelcomeSetupProps {
  readonly onConnected: (serverUrl: string) => void;
  readonly onCancel?: () => void;
  readonly initialServerUrl?: string;
}

const ChevronIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m6 9 6 6 6-6" />
  </svg>
);

const RestartIcon = ({ spinning = false }: { spinning?: boolean }) => (
  <svg className={spinning ? 'welcome-spin' : undefined} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M21 12a9 9 0 1 1-2.64-6.36" />
    <path d="M21 3v6h-6" />
  </svg>
);

export function WelcomeSetup({ onConnected, onCancel, initialServerUrl = '' }: WelcomeSetupProps) {
  const startup = useStartupConnection();
  const [serverUrl, setServerUrl] = useState(initialServerUrl);
  const [enableBridges, setEnableBridges] = useState(false);
  const [transport, setTransport] = useState<'obfs4' | 'snowflake'>('obfs4');
  const [bridgeLines, setBridgeLines] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isRestartingTor, setIsRestartingTor] = useState(false);
  const [error, setError] = useState('');
  const mountedRef = useRef(true);
  const torSupported = torNetworkManager.isSupported();

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void loadTorPreferences().then((preferences) => {
      if (cancelled) return;
      setEnableBridges(preferences.enableBridges);
      setTransport(preferences.transport);
      setBridgeLines(preferences.bridgeLines);
    });
    return () => { cancelled = true; };
  }, []);

  const handleSubmit = useCallback(async (event: React.FormEvent) => {
    event.preventDefault();
    if (isConnecting || isRestartingTor) return;

    const normalized = normalizeToWss(serverUrl);
    if (!normalized) {
      setError('Enter a valid server address, for example wss://example.onion');
      return;
    }

    setIsConnecting(true);
    setError('');
    try {
      await saveTorPreferences({ enableBridges, transport, bridgeLines });
      await startupConnection.setServerUrl(normalized);
      await startupConnection.checkConnected();
      if (!mountedRef.current) return;
      if (startupConnection.getState().phase !== 'ready') {
        setError(startupConnection.getState().error || 'Could not reach the server.');
        return;
      }
      onConnected(normalized);
    } catch (err) {
      if (!mountedRef.current) return;
      setError(startupConnection.getState().error || humanizeConnectionError(err));
    } finally {
      if (mountedRef.current) setIsConnecting(false);
    }
  }, [serverUrl, enableBridges, transport, bridgeLines, isConnecting, isRestartingTor, onConnected]);

  const handleRestartTor = useCallback(async () => {
    if (isRestartingTor || isConnecting) return;
    setIsRestartingTor(true);
    setError('');
    try {
      await saveTorPreferences({ enableBridges, transport, bridgeLines });
      const ready = await startupConnection.restartTor();
      if (!mountedRef.current) return;
      if (!ready) setError('Tor did not finish bootstrapping. Try enabling bridges.');
    } catch (err) {
      if (mountedRef.current) setError(humanizeConnectionError(err));
    } finally {
      if (mountedRef.current) setIsRestartingTor(false);
    }
  }, [enableBridges, transport, bridgeLines, isConnecting, isRestartingTor]);

  const busy = isConnecting || isRestartingTor;
  const torStep = (startup.step || 'Starting Tor').replace(/\s*\(\d+%\)\s*$/, '');
  const submitLabel = !isConnecting
    ? 'Connect'
    : startup.phase === 'tor'
      ? `${torStep}${startup.torProgress ? ` (${startup.torProgress}%)` : ''}`
      : startup.step || 'Connecting';

  return (
    <section className="screen screen-welcome">
      <div className="welcome-scene">
        <header className="welcome-topbar">
          <div className="login-screen-brand" aria-label="Qorc">
            <QorcBrandLogo className="login-brand-mark" imageClassName="login-brand-logo" />
            <span className="login-brand-name">Qorc</span>
          </div>
        </header>

        <ThemeToggleButton className="auth-theme-toggle" />
        {onCancel && (
          <button
            type="button"
            className="welcome-auth-back"
            onClick={onCancel}
            disabled={busy}
          >
            Sign in / Sign up
          </button>
        )}

        <main className="welcome-simple" aria-label="Choose a server">
          <header className="welcome-simple-head">
            <h1>Choose a server</h1>
          </header>

          <form
            onSubmit={handleSubmit}
            className={`login-simple-form${busy ? ' is-submitting' : ''}`}
            aria-busy={busy}
          >
            <div className="login-simple-field">
              <label htmlFor="welcome-server-url">Server address</label>
              <input
                className="login-simple-input"
                id="welcome-server-url"
                placeholder="wss://your-server"
                value={serverUrl}
                onChange={(event) => {
                  setServerUrl(event.target.value);
                  if (error) setError('');
                }}
                disabled={busy}
                autoFocus
                spellCheck={false}
                autoComplete="off"
              />
            </div>

            {error && startup.phase !== 'failed' && (
              <p className="auth-simple-message">{error}</p>
            )}

            <button
              type="submit"
              className="login-simple-submit"
              disabled={busy || !serverUrl.trim()}
            >
              {submitLabel}
            </button>
          </form>

          <div className={`welcome-advanced${advancedOpen ? ' is-open' : ''}`}>
            <button
              type="button"
              className="welcome-advanced-toggle"
              onClick={() => setAdvancedOpen((open) => !open)}
              aria-expanded={advancedOpen}
              aria-controls="welcome-advanced-panel"
            >
              <span>Tor settings</span>
              <ChevronIcon />
            </button>

            <div className="welcome-advanced-panel" id="welcome-advanced-panel" hidden={!advancedOpen}>
              <p className="welcome-advanced-note">
                Tor starts automatically. Use bridges only when your network blocks Tor.
              </p>

              <button
                type="button"
                className={`welcome-toggle${enableBridges ? ' is-on' : ''}`}
                aria-pressed={enableBridges}
                onClick={() => setEnableBridges((value) => !value)}
                disabled={busy}
              >
                <span>Use bridges</span>
                <span className="welcome-toggle-switch" aria-hidden="true">
                  <span className="welcome-toggle-dot" />
                </span>
              </button>

              {enableBridges && (
                <>
                  <div className="login-simple-field">
                    <label htmlFor="welcome-transport">Bridge transport</label>
                    <select
                      className="welcome-select"
                      id="welcome-transport"
                      value={transport}
                      onChange={(event) => setTransport(event.target.value as 'obfs4' | 'snowflake')}
                      disabled={busy}
                    >
                      <option value="obfs4">obfs4 (standard)</option>
                      <option value="snowflake">snowflake (resilient)</option>
                    </select>
                  </div>

                  <div className="login-simple-field">
                    <label htmlFor="welcome-bridges">Bridge lines</label>
                    <textarea
                      className="welcome-textarea"
                      id="welcome-bridges"
                      placeholder="Paste bridge lines here, one per line"
                      value={bridgeLines}
                      onChange={(event) => setBridgeLines(event.target.value)}
                      disabled={busy}
                      spellCheck={false}
                    />
                  </div>
                </>
              )}

              <button
                type="button"
                className="welcome-secondary"
                onClick={handleRestartTor}
                disabled={busy || !torSupported}
              >
                <RestartIcon spinning={isRestartingTor} />
                <span>{isRestartingTor ? 'Restarting Tor' : 'Restart Tor'}</span>
              </button>
            </div>
          </div>

        </main>
      </div>
    </section>
  );
}
