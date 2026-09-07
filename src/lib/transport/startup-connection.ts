import { getTorAutoSetup } from './tor-auto-setup';
import { torNetworkManager } from './tor-network';
import { websocket, storage, anonymousHttp } from '../tauri-bindings';
import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';

export type StartupPhase = 'idle' | 'tor' | 'server' | 'ready' | 'failed';
export type StartupFailureTarget = 'tor' | 'server' | null;

export interface StartupConnectionState {
  readonly phase: StartupPhase;
  readonly torProgress: number;
  readonly step: string;
  readonly error: string;
  readonly serverUrl: string;
  readonly failureTarget: StartupFailureTarget;
}

export interface TorPreferences {
  enableBridges: boolean;
  transport: 'obfs4' | 'snowflake';
  bridgeLines: string;
}

const CONNECT_ATTEMPTS = 2;
const RETRY_DELAY_MS = 2500;

export function normalizeToWss(value: string): string {
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
}

export function humanizeConnectionError(err: unknown): string {
  const raw = (err instanceof Error ? err.message : (typeof err === 'string' ? err : '')) || '';
  const code = (err as any)?.code ? String((err as any).code) : '';
  const text = `${code} ${raw}`.toLowerCase();

  if (text.includes('eai_again')) return 'Temporary DNS issue. Check your internet connection.';
  if (text.includes('enotfound') || text.includes('eai_noname') || text.includes('getaddrinfo')) return 'Server not found. Check the address.';
  if (text.includes('connection in progress')) return 'Connection is still resetting. Try again in a moment.';
  if (text.includes('connection attempt cancelled')) return 'Connection reset. Try again in a moment.';
  if (text.includes('econnrefused') || text.includes('connection refused')) return 'Connection refused. The server may be down.';
  if (text.includes('etimedout') || text.includes('timeout')) return 'Connection timed out. Check your network or firewall.';
  if (text.includes('self signed') || text.includes('certificate') || text.includes('err_ssl') || text.includes('cert_')) return 'Untrusted certificate.';
  if (text.includes('tls') && text.includes('handshake')) return 'TLS handshake failed.';
  if (text.includes(' 401') || text.includes('unauthorized')) return 'Unauthorized.';
  if (text.includes(' 403') || text.includes('forbidden')) return 'Forbidden.';
  if (text.includes(' 502') || text.includes(' 503') || text.includes(' 504')) return 'Server unavailable.';

  return 'Could not reach the server.';
}

const readBooleanPreference = async (key: string): Promise<boolean> => {
  const value = await storage.get(key);
  if (value === null) return false;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`Stored boolean preference '${key}' is invalid`);
};

const readStringPreference = async (key: string): Promise<string> => {
  return (await storage.get(key)) ?? '';
};

const writeBooleanPreference = async (key: string, value: boolean): Promise<void> => {
  const serialized = value ? 'true' : 'false';
  if (!await storage.set(key, serialized) || await storage.get(key) !== serialized) {
    throw new Error(`Boolean preference '${key}' could not be verified`);
  }
};

const writeStringPreference = async (key: string, value: string): Promise<void> => {
  if (!await storage.set(key, value) || await storage.get(key) !== value) {
    throw new Error(`String preference '${key}' could not be verified`);
  }
};

export async function loadTorPreferences(): Promise<TorPreferences> {
  const [enableBridges, transport, bridgeLines] = await Promise.all([
    readBooleanPreference(STORAGE_KEYS.TOR_BRIDGES_ENABLED),
    readStringPreference(STORAGE_KEYS.TOR_BRIDGE_TRANSPORT),
    readStringPreference(STORAGE_KEYS.TOR_BRIDGE_LINES),
  ]);
  if (transport !== '' && transport !== 'obfs4' && transport !== 'snowflake') {
    throw new Error('Stored Tor bridge transport is invalid');
  }
  return { enableBridges, transport: transport || 'obfs4', bridgeLines };
}

export async function saveTorPreferences(preferences: TorPreferences): Promise<void> {
  await Promise.all([
    writeBooleanPreference(STORAGE_KEYS.TOR_BRIDGES_ENABLED, preferences.enableBridges),
    writeStringPreference(STORAGE_KEYS.TOR_BRIDGE_TRANSPORT, preferences.transport),
    writeStringPreference(STORAGE_KEYS.TOR_BRIDGE_LINES, preferences.bridgeLines),
  ]);
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

class StartupConnection {
  private state: StartupConnectionState = {
    phase: 'idle',
    torProgress: 0,
    step: '',
    error: '',
    serverUrl: '',
    failureTarget: null,
  };

  private readonly listeners = new Set<(state: StartupConnectionState) => void>();
  private inFlight: Promise<void> | null = null;
  private torInFlight: Promise<boolean> | null = null;
  private generation = 0;
  private watchdog: ReturnType<typeof setInterval> | null = null;
  private diagnosticSequence = 0;
  private diagnosticStartedAt = Date.now();

  private diagnostic(
    phase: string,
    details: Record<string, unknown> = {},
    level: 'info' | 'warn' | 'error' = 'info'
  ): void {
    const entry = {
      sequence: ++this.diagnosticSequence,
      phase: `startup.${phase}`,
      elapsedMs: Date.now() - this.diagnosticStartedAt,
      generation: this.generation,
      uiPhase: this.state.phase,
      ...details,
    };
    if (level === 'error') {
      console.error('[WS-CONNECT-DIAG]', entry);
    } else if (level === 'warn') {
      console.warn('[WS-CONNECT-DIAG]', entry);
    } else {
      console.info('[WS-CONNECT-DIAG]', entry);
    }
  }

  getState(): StartupConnectionState {
    return this.state;
  }

  subscribe(listener: (state: StartupConnectionState) => void): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  private update(patch: Partial<StartupConnectionState>): void {
    const next = { ...this.state, ...patch };
    if (
      next.phase === this.state.phase &&
      next.torProgress === this.state.torProgress &&
      next.step === this.state.step &&
      next.error === this.state.error &&
      next.serverUrl === this.state.serverUrl &&
      next.failureTarget === this.state.failureTarget
    ) {
      return;
    }
    this.state = next;
    if (next.phase === 'ready') this.stopWatchdog();
    for (const listener of this.listeners) {
      try { listener(next); } catch { }
    }
  }

  private startWatchdog(): void {
    if (this.watchdog) return;
    this.watchdog = setInterval(() => {
      if (this.state.phase === 'ready') {
        this.stopWatchdog();
        return;
      }
      if (websocketClient.isConnectedToServer() && this.isTorRouteReady()) {
        this.update({ phase: 'ready', step: '', error: '', failureTarget: null });
      }
    }, 1500);
  }

  private stopWatchdog(): void {
    if (!this.watchdog) return;
    clearInterval(this.watchdog);
    this.watchdog = null;
  }

  private isTorRouteReady(): boolean {
    return torNetworkManager.isConnected() && torNetworkManager.isBootstrapped();
  }

  async loadConfiguredServerUrl(): Promise<string> {
    const stored = await websocket.getServerUrl();
    const normalized = normalizeToWss(stored || '');
    if (stored && !normalized) throw new Error('Stored server URL is invalid');
    if (normalized) this.update({ serverUrl: normalized });
    return normalized;
  }

  async setServerUrl(url: string): Promise<string> {
    const normalized = normalizeToWss(url);
    if (!normalized) throw new Error('Enter a valid server address.');
    this.generation += 1;
    this.inFlight = null;
    if (normalized !== this.state.serverUrl || websocketClient.isConnectedToServer()) {
      await websocketClient.close();
    }
    await websocket.setServerUrl(normalized);
    this.update({ serverUrl: normalized, phase: 'idle', error: '', step: '', failureTarget: null });
    return normalized;
  }

  async validateTor(): Promise<boolean> {
    if (this.torInFlight) return this.torInFlight;

    const run = (async (): Promise<boolean> => {
      this.update({
        phase: this.state.phase === 'ready' ? 'ready' : 'tor',
        step: 'Starting Tor',
        error: '',
        failureTarget: null,
      });

      const current = await getTorAutoSetup().refreshStatus();
      if (current.isRunning && current.isBootstrapped) {
        torNetworkManager.updateConfig({
          enabled: true,
          socksPort: current.socksPort,
          controlPort: current.controlPort,
        });
        const synced = await torNetworkManager.syncWithDaemon() && this.isTorRouteReady();
        this.update({ torProgress: 100, step: 'Tor ready' });
        return synced;
      }

      if (current.isRunning && !current.isBootstrapped) {
        await getTorAutoSetup().stopTor().catch(() => false);
        await torNetworkManager.shutdown().catch(() => { });
      }

      const preferences = await loadTorPreferences();
      const bridges = preferences.bridgeLines.split('\n').map(line => line.trim()).filter(Boolean);

      const started = await getTorAutoSetup().autoSetup({
        autoStart: true,
        enableBridges: preferences.enableBridges,
        transport: preferences.transport,
        bridges,
        onProgress: (status) => {
          this.update({
            torProgress: status.bootstrapProgress || status.setupProgress || 0,
            step: status.currentStep || 'Starting Tor',
          });
        },
      });

      const refreshed = await getTorAutoSetup().refreshStatus();
      torNetworkManager.updateConfig({
        enabled: true,
        socksPort: refreshed.socksPort,
        controlPort: refreshed.controlPort,
      });
      const ready = started
        && refreshed.isRunning
        && refreshed.isBootstrapped
        && await torNetworkManager.syncWithDaemon()
        && this.isTorRouteReady();
      this.update({
        torProgress: ready ? 100 : (refreshed.bootstrapProgress || 0),
        step: ready ? 'Tor ready' : (refreshed.error || 'Tor could not finish bootstrapping'),
      });
      return ready;
    })().finally(() => {
      this.torInFlight = null;
    });

    this.torInFlight = run;
    return run;
  }

  async checkConnected(): Promise<void> {
    this.diagnostic('check-requested', {
      websocketReady: websocketClient.isConnectedToServer(),
      torRouteReady: this.isTorRouteReady(),
      hasInFlightOperation: !!this.inFlight,
    });
    if (websocketClient.isConnectedToServer() && this.isTorRouteReady()) {
      this.update({ phase: 'ready', error: '', step: '', failureTarget: null });
      this.diagnostic('already-ready');
      return;
    }
    if (this.inFlight) {
      this.diagnostic('join-existing-operation');
      return this.inFlight;
    }

    this.startWatchdog();
    const generation = ++this.generation;
    this.diagnosticStartedAt = Date.now();
    this.diagnostic('operation-start');
    const run = (async (): Promise<void> => {
      const serverUrl = this.state.serverUrl || await this.loadConfiguredServerUrl();
      if (!serverUrl) {
        this.update({ phase: 'idle', step: '', error: '', failureTarget: null });
        this.diagnostic('server-not-configured', {}, 'warn');
        throw new Error('No server selected');
      }

      let torReady = false;
      try {
        this.diagnostic('tor-check-begin');
        torReady = await this.validateTor();
        this.diagnostic('tor-check-complete', { torReady });
      } catch (error) {
        if (this.generation !== generation) return;
        this.diagnostic('tor-check-failed', {
          errorName: error instanceof Error ? error.name : 'UnknownError',
          errorMessage: error instanceof Error ? error.message : String(error),
        }, 'error');
        const message = 'Tor could not connect. Check your network or bridge settings.';
        this.update({ phase: 'failed', error: message, step: '', failureTarget: 'tor' });
        throw error instanceof Error ? error : new Error(message);
      }
      if (this.generation !== generation) return;
      if (!torReady) {
        const message = this.state.step || 'Tor could not connect. Check your network or bridge settings.';
        this.update({ phase: 'failed', error: message, step: '', failureTarget: 'tor' });
        throw new Error(message);
      }

      if (!this.isTorRouteReady()) {
        const message = 'Tor could not connect. Check your network or bridge settings.';
        this.update({ phase: 'failed', error: message, step: '', failureTarget: 'tor' });
        throw new Error(message);
      }

      if (websocketClient.isConnectedToServer()) {
        this.update({ phase: 'ready', step: '', error: '', failureTarget: null });
        this.diagnostic('became-ready-before-server-dial');
        return;
      }

      let lastError: unknown = null;
      for (let attempt = 1; attempt <= CONNECT_ATTEMPTS; attempt++) {
        if (this.generation !== generation) return;
        this.update({ phase: 'server', step: 'Connecting to server...', error: '', failureTarget: null });
        const attemptStartedAt = Date.now();
        this.diagnostic('server-attempt-begin', { attempt, attemptLimit: CONNECT_ATTEMPTS });

        try {
          await websocketClient.connect({ autoReconnectOnFailure: false });
          if (this.generation !== generation) return;
          this.diagnostic('server-attempt-ready', {
            attempt,
            durationMs: Date.now() - attemptStartedAt,
          });
          this.update({ phase: 'ready', step: '', error: '', failureTarget: null });
          void anonymousHttp.prewarm().catch(() => { });
          return;
        } catch (error) {
          lastError = error;
          if (this.generation !== generation) return;
          this.diagnostic('server-attempt-failed', {
            attempt,
            durationMs: Date.now() - attemptStartedAt,
            errorName: error instanceof Error ? error.name : 'UnknownError',
            errorMessage: error instanceof Error ? error.message : String(error),
          }, 'error');
          if (attempt < CONNECT_ATTEMPTS) {
            this.update({ step: 'Retrying connection...' });
            this.diagnostic('server-retry-delay', {
              attempt,
              delayMs: RETRY_DELAY_MS,
            }, 'warn');
            await delay(RETRY_DELAY_MS);
          }
        }
      }

      if (this.generation !== generation) return;
      const message = humanizeConnectionError(lastError);
      this.diagnostic('operation-failed', {
        errorName: lastError instanceof Error ? lastError.name : 'UnknownError',
        errorMessage: lastError instanceof Error ? lastError.message : String(lastError),
      }, 'error');
      this.update({ phase: 'failed', error: message, step: '', failureTarget: 'server' });
      throw lastError instanceof Error ? lastError : new Error(message);
    })().finally(() => {
      if (this.inFlight === run) this.inFlight = null;
      this.diagnostic('operation-finished', {
        operationWasCurrent: this.generation === generation,
      });
    });

    this.inFlight = run;
    return run;
  }

  async prepareRecoveryTransport(): Promise<void> {
    const torReady = await this.validateTor();
    if (!torReady) {
      throw new Error(this.state.step || 'Tor could not connect.');
    }
    void anonymousHttp.prewarm().catch(() => { });
  }

  async restartTor(): Promise<boolean> {
    this.generation += 1;
    this.inFlight = null;
    this.torInFlight = null;
    this.update({ phase: 'tor', torProgress: 0, step: 'Restarting Tor', error: '', failureTarget: null });
    await getTorAutoSetup().stopTor().catch(() => false);
    await torNetworkManager.shutdown().catch(() => { });
    try {
      const ready = await this.validateTor();
      if (!ready) {
        const message = this.state.step || 'Tor could not connect. Check your network or bridge settings.';
        this.update({ phase: 'failed', error: message, step: '', failureTarget: 'tor' });
      }
      return ready;
    } catch {
      const message = 'Tor could not connect. Check your network or bridge settings.';
      this.update({ phase: 'failed', error: message, step: '', failureTarget: 'tor' });
      return false;
    }
  }

  async retry(): Promise<void> {
    this.generation += 1;
    this.inFlight = null;
    this.torInFlight = null;
    this.update({ phase: 'idle', error: '', step: '', failureTarget: null });
    return this.checkConnected();
  }

  reset(): void {
    this.generation += 1;
    this.inFlight = null;
    this.stopWatchdog();
    this.update({ phase: 'idle', error: '', step: '', serverUrl: '', failureTarget: null });
  }
}

export const startupConnection = new StartupConnection();
