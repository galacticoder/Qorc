import { useCallback, useEffect, useRef, useState } from 'react';
import { QorcBrandLogo } from '../ui/QorcBrandLogo';
import { ThemeToggleButton } from '../ui/ThemeToggleButton';
import { Server } from 'lucide-react';
import { SavedServersDialog } from '../servers/SavedServersDialog';
import { AppSelect } from '../ui/AppSelect';
import { useStartupConnection } from '../../hooks/app/useStartupConnection';
import {
  humanizeConnectionError,
  loadTorPreferences,
  normalizeToWss,
  saveTorPreferences,
  startupConnection,
} from '../../lib/transport/startup-connection';

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

export function WelcomeSetup({ onConnected, onCancel, initialServerUrl = '' }: WelcomeSetupProps) {
  const startup = useStartupConnection();
  const [serverUrl, setServerUrl] = useState(initialServerUrl);
  const [enableBridges, setEnableBridges] = useState(false);
  const [transport, setTransport] = useState<'obfs4' | 'snowflake'>('obfs4');
  const [bridgeLines, setBridgeLines] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [savedServersOpen, setSavedServersOpen] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState('');
  const mountedRef = useRef(true);

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
    if (isConnecting) return;

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
  }, [serverUrl, enableBridges, transport, bridgeLines, isConnecting, onConnected]);
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
            disabled={isConnecting}
          >
            Sign in / Sign up
          </button>
        )}

        <main className="welcome-simple" aria-label="Connect to a server">
          <header className="welcome-simple-head">
            <h1>Connect to a server</h1>
          </header>

          <form
            onSubmit={handleSubmit}
            className={`login-simple-form${isConnecting ? ' is-submitting' : ''}`}
            aria-busy={isConnecting}
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
                disabled={isConnecting}
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
              disabled={isConnecting || !serverUrl.trim()}
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
                disabled={isConnecting}
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
                    <AppSelect
                      className="welcome-select"
                      id="welcome-transport"
                      label="Bridge transport"
                      value={transport}
                      onValueChange={(value) => setTransport(value as 'obfs4' | 'snowflake')}
                      disabled={isConnecting}
                      options={[
                        { value: 'obfs4', label: 'obfs4 (standard)' },
                        { value: 'snowflake', label: 'snowflake (resilient)' },
                      ]}
                    />
                  </div>

                  <div className="login-simple-field">
                    <label htmlFor="welcome-bridges">Bridge lines</label>
                    <textarea
                      className="welcome-textarea"
                      id="welcome-bridges"
                      placeholder="Paste bridge lines here, one per line"
                      value={bridgeLines}
                      onChange={(event) => setBridgeLines(event.target.value)}
                      disabled={isConnecting}
                      spellCheck={false}
                    />
                  </div>
                </>
              )}

            </div>
          </div>

          <div className="welcome-advanced">
            <button
              type="button"
              className="welcome-advanced-toggle"
              onClick={() => setSavedServersOpen(true)}
              aria-haspopup="dialog"
            >
              <span>Saved servers</span>
              <Server size={17} aria-hidden="true" />
            </button>
          </div>

        </main>
        <SavedServersDialog open={savedServersOpen} onOpenChange={setSavedServersOpen} selectedUrl={serverUrl} disabled={isConnecting} onSelect={(server) => { setServerUrl(server.url); setError(''); }} />
      </div>
    </section>
  );
}
