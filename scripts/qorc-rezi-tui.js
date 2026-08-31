import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const requireFromServer = createRequire(new URL('../server/package.json', import.meta.url));
const coreModuleUrl = pathToFileURL(requireFromServer.resolve('@rezi-ui/core')).href;
const nodeModuleUrl = pathToFileURL(requireFromServer.resolve('@rezi-ui/node')).href;
const { darkTheme, extendTheme, rgb, truncateMiddle, ui } = await import(coreModuleUrl);
const { createNodeApp } = await import(nodeModuleUrl);

const COLOR = Object.freeze({
  background: rgb(8, 8, 11),
  surface: rgb(15, 15, 19),
  surfaceRaised: rgb(20, 20, 26),
  border: rgb(47, 46, 58),
  borderStrong: rgb(76, 73, 91),
  text: rgb(238, 238, 244),
  secondary: rgb(170, 168, 182),
  muted: rgb(111, 108, 124),
  purple: rgb(116, 86, 241),
  cyan: rgb(74, 192, 211),
  green: rgb(91, 202, 144),
  yellow: rgb(237, 181, 76),
  red: rgb(238, 92, 107),
});

const qorcTheme = extendTheme(darkTheme, {
  name: 'qorc',
  colors: {
    bg: {
      base: COLOR.background,
      elevated: COLOR.surface,
      overlay: COLOR.surfaceRaised,
      subtle: rgb(12, 12, 16),
    },
    fg: {
      primary: COLOR.text,
      secondary: COLOR.secondary,
      muted: COLOR.muted,
      inverse: COLOR.background,
    },
    accent: {
      primary: COLOR.purple,
      secondary: COLOR.cyan,
      tertiary: rgb(155, 128, 255),
    },
    success: COLOR.green,
    warning: COLOR.yellow,
    error: COLOR.red,
    info: COLOR.cyan,
    focus: { ring: COLOR.purple, bg: COLOR.surfaceRaised },
    selected: { bg: rgb(41, 32, 77), fg: COLOR.text },
    disabled: { fg: COLOR.muted, bg: COLOR.surface },
    border: {
      subtle: COLOR.border,
      default: COLOR.borderStrong,
      strong: rgb(103, 99, 121),
    },
  },
  widget: {
    logs: {
      trace: COLOR.muted,
      debug: COLOR.secondary,
      info: COLOR.text,
      warn: COLOR.yellow,
      error: COLOR.red,
    },
    chart: {
      primary: COLOR.purple,
      accent: COLOR.cyan,
      muted: COLOR.muted,
      success: COLOR.green,
      warning: COLOR.yellow,
      danger: COLOR.red,
    },
  },
});

const ANSI = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))/g;
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

export function cleanTerminalText(value) {
  return String(value ?? '')
    .replace(ANSI, '')
    .replace(CONTROL, '')
    .replace(/\t/g, '  ');
}

export function logEntry(line, sequence, fallbackSource) {
  const message = cleanTerminalText(line).trimEnd();
  const sourceMatch = message.match(/^\s*\[([^\]]+)]\s*/);
  const source = sourceMatch?.[1]?.slice(0, 18) || fallbackSource;
  const normalized = sourceMatch ? message.slice(sourceMatch[0].length) : message;
  const level = /\b(error|fatal|panic|failed|failure)\b/i.test(message)
    ? 'error'
    : /\b(warn|warning|stale|degraded)\b/i.test(message)
      ? 'warn'
      : /\b(debug|trace)\b/i.test(message)
        ? 'debug'
        : 'info';
  const timestampMatch = message.match(/\b(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\b/);
  const parsedTimestamp = timestampMatch ? Date.parse(timestampMatch[1]) : NaN;
  return Object.freeze({
    id: `${fallbackSource}-${sequence}`,
    timestamp: Number.isFinite(parsedTimestamp) ? parsedTimestamp : Date.now(),
    level,
    source,
    message: normalized || message,
  });
}

function toneForState(state) {
  if (['healthy', 'registered', 'valid', 'live', 'standalone'].includes(state)) return 'success';
  if (['starting', 'checking', 'pending', 'stale'].includes(state)) return 'warning';
  if (['degraded', 'missing', 'expired', 'unavailable', 'corrupt'].includes(state)) return 'error';
  return 'default';
}

function stateBadge(label, state) {
  if (!label) return null;
  const variant = toneForState(state);
  return ui.badge(label, { variant: variant === 'default' ? 'default' : variant });
}

function overviewBand(title, groups) {
  return ui.box({
    title: ` ${title.toUpperCase()} `,
    border: 'rounded',
    borderStyle: { fg: COLOR.borderStrong },
    style: { bg: COLOR.surface },
    height: 7,
    p: 0,
    overflow: 'hidden',
  }, [ui.row({ width: 'full', height: 'full', gap: 0 }, groups)]);
}

function groupCell(label, children, options = {}) {
  return ui.column({
    flex: options.flex ?? 1,
    flexBasis: 0,
    flexShrink: 1,
    height: 'full',
    px: 1,
    gap: 0,
    style: { bg: options.raised ? COLOR.surfaceRaised : COLOR.surface },
    overflow: 'hidden',
  }, [
    ui.text(label.toUpperCase(), { style: { fg: options.color ?? COLOR.muted, bold: true } }),
    ...children,
  ]);
}

function signalRow(label, value, state = 'neutral') {
  const signalColor = state === 'good'
    ? COLOR.green
    : state === 'warn'
      ? COLOR.yellow
      : state === 'bad'
        ? COLOR.red
        : COLOR.cyan;
  return ui.row({ width: 'full', gap: 1, align: 'center' }, [
    ui.text('●', { style: { fg: signalColor } }),
    ui.text(label, { style: { fg: COLOR.secondary, bold: true }, maxWidth: 10 }),
    ui.box({
      border: 'none',
      flex: 1,
      minWidth: 0,
      overflow: 'hidden',
    }, [ui.text(truncateMiddle(String(value ?? '—'), 16), {
      style: { fg: COLOR.text },
      textOverflow: 'middle',
      maxWidth: 'full',
    })]),
  ]);
}

function detailPair(leftLabel, leftValue, rightLabel, rightValue) {
  return ui.row({ width: 'full', gap: 1 }, [
    ui.text(leftLabel.toUpperCase(), { style: { fg: COLOR.muted, bold: true } }),
    ui.text(String(leftValue), { style: { fg: COLOR.text, bold: true } }),
    ui.text('·', { style: { fg: COLOR.borderStrong } }),
    ui.text(rightLabel.toUpperCase(), { style: { fg: COLOR.muted, bold: true } }),
    ui.text(String(rightValue), { style: { fg: COLOR.text, bold: true }, textOverflow: 'ellipsis' }),
  ]);
}

function compactEndpoint(value) {
  return String(value ?? '—')
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .replace(/^\/\//, '');
}

function resourceBlock(label, rawValue, color) {
  const numeric = Number.parseFloat(rawValue);
  const value = Number.isFinite(numeric) ? Math.max(0, Math.min(100, numeric)) : 0;
  return ui.column({ flex: 1, minWidth: 8, gap: 0, overflow: 'hidden' }, [
    ui.text(label.toUpperCase(), { style: { fg: COLOR.muted, bold: true } }),
    ui.text(Number.isFinite(numeric) ? `${numeric.toFixed(1)}%` : '—', {
      style: { fg: color, bold: true },
    }),
    ui.gauge(value / 100, {
      width: 'full',
      variant: 'compact',
      thresholds: [
        { value: 0.7, variant: 'warning' },
        { value: 0.9, variant: 'error' },
      ],
    }),
  ]);
}

function header(kind, identity, right) {
  return ui.box({
    border: 'rounded',
    borderStyle: { fg: COLOR.borderStrong },
    style: { bg: COLOR.surfaceRaised },
    height: 4,
    px: 1,
  }, [
    ui.row({ width: 'full', height: 'full', align: 'center', justify: 'between' }, [
      ui.column({ gap: 0 }, [
        ui.text(kind, { style: { fg: COLOR.text, bold: true } }),
        ui.text(identity, { style: { fg: COLOR.muted }, textOverflow: 'middle', maxWidth: 42 }),
      ]),
      ui.row({ gap: 1, align: 'center' }, right.filter(Boolean)),
    ]),
  ]);
}

function controlButton(id, key, label, onPress, intent = 'secondary') {
  const tone = intent === 'danger' ? 'danger' : (intent === 'primary' ? 'primary' : 'default');
  return ui.button({
    id,
    label: `${key}  ${label}`,
    onPress,
    intent,
    dsVariant: 'soft',
    dsTone: tone,
    dsSize: 'sm',
    px: 1,
    focusConfig: { indicator: 'background' },
  });
}

function footerControls(prefix, actions, includeCommand = false) {
  const controls = [];
  if (includeCommand) {
    controls.push(controlButton(`${prefix}-command`, '/', 'Command', actions.openCommand, 'primary'));
  }
  controls.push(
    controlButton(`${prefix}-older`, '↑', 'Older', actions.older),
    controlButton(`${prefix}-newer`, '↓', 'Newer', actions.newer),
    controlButton(`${prefix}-latest`, 'G', 'Latest', actions.latest),
    controlButton(`${prefix}-stop`, 'Q', prefix === 'server' ? 'Stop server' : 'Stop balancer', actions.stop, 'danger'),
  );
  return ui.box({
    border: 'none',
    style: { bg: COLOR.background },
    height: 3,
  }, [ui.row({ gap: 1, align: 'center', justify: 'center', wrap: true }, controls)]);
}

function logsPanel(state, actions) {
  const title = state.followLogs ? ' ACTIVITY ' : ' ACTIVITY · PAUSED ';
  return ui.box({
    title,
    border: 'rounded',
    borderStyle: { fg: state.followLogs ? COLOR.border : COLOR.yellow },
    style: { bg: COLOR.background },
    p: 0,
    flex: 1,
    minHeight: 5,
    overflow: 'hidden',
  }, [
    ui.logsConsole({
      id: `${state.kind}-activity`,
      entries: state.logs,
      scrollTop: state.logScroll,
      autoScroll: state.followLogs,
      onScroll: actions.setLogScroll,
      showTimestamps: true,
      showSource: true,
      scrollbarVariant: 'thin',
      scrollbarStyle: { fg: COLOR.purple },
      focusedStyle: { fg: COLOR.purple },
      width: 'full',
      height: 'full',
      flex: 1,
    }),
  ]);
}

function serverView(state, actions) {
  const warning = state.status === 'healthy' ? null : stateBadge(state.statusLabel, state.status);
  const clusterState = ['registered', 'standalone'].includes(state.registration)
    ? 'good'
    : ['checking', 'pending'].includes(state.registration) ? 'warn' : 'bad';
  const tlsState = state.tlsState === 'valid'
    ? 'good'
    : state.tlsState === 'checking' ? 'warn' : 'bad';
  const redisState = state.redisState === 'live'
    ? 'good'
    : ['checking', 'stale'].includes(state.redisState) ? 'warn' : 'bad';
  const overview = overviewBand('Server control plane', [
    groupCell('HTTPS listener', [
      ui.text(state.endpoint, {
        style: { fg: COLOR.cyan, bold: true },
        textOverflow: 'middle',
        maxWidth: 'full',
      }),
      ui.text('TLS ingress', { style: { fg: COLOR.secondary } }),
      ui.text(`${state.uptime} · PID ${state.pid}`, {
        style: { fg: COLOR.text, bold: true },
        textOverflow: 'ellipsis',
        maxWidth: 'full',
      }),
    ], { flex: 0.85 }),
    groupCell('Resource load', [
      ui.row({ gap: 2, width: 'full' }, [
        resourceBlock('CPU', state.cpu, COLOR.purple),
        resourceBlock('Memory', state.mem, COLOR.cyan),
      ]),
    ], { flex: 1.05, raised: true, color: COLOR.purple }),
    groupCell('Dependencies', [
      signalRow('Cluster', `${state.registrationLabel} · ${String(state.heartbeat).replace(/ ago$/, '')}`, clusterState),
      signalRow('TLS', String(state.tlsLabel).replace(/^TLS\s*/i, ''), tlsState),
      signalRow('Redis', compactEndpoint(state.redis), redisState),
      signalRow('Postgres', compactEndpoint(state.database)),
    ], { flex: 1.6 }),
  ]);

  return ui.page({
    id: 'qorc-server-tui',
    p: 1,
    gap: 1,
    header: header('SERVER', state.serverId, [warning, ui.text(`PID ${state.pid}`, { style: { fg: COLOR.muted } })]),
    body: ui.column({ gap: 1, width: 'full', height: 'full' }, [
      overview,
      logsPanel(state, actions),
    ]),
    footer: footerControls('server', actions),
  });
}

function loadBalancerView(state, actions) {
  const warning = state.dataState === 'live'
    ? null
    : stateBadge(state.dataLabel, state.dataState);
  const serverCount = state.servers == null ? '—' : String(state.servers);
  const poolNames = state.serverList.length
    ? state.serverList.slice(0, 3).map((server) => server.id || 'server').join(' · ')
    : 'Waiting for registrations';
  const redisState = state.dataState === 'live'
    ? 'good'
    : state.dataState === 'stale' || state.dataState === 'connecting' ? 'warn' : 'bad';
  const overview = overviewBand('Edge routing plane', [
    groupCell('Routing', [
      ui.richText([
        { text: serverCount, style: { fg: COLOR.green, bold: true } },
        { text: ` ACTIVE ${state.servers === 1 ? 'BACKEND' : 'BACKENDS'}`, style: { fg: COLOR.text, bold: true } },
      ]),
      signalRow('HTTPS', `:${state.httpsPort}`, 'good'),
      detailPair('PID', state.pid, 'Stats', `:${state.statsPort}`),
      ui.text(poolNames, { style: { fg: COLOR.secondary }, textOverflow: 'ellipsis', maxWidth: 'full' }),
    ], { flex: 0.9 }),
    groupCell('Resource load', [
      ui.row({ gap: 2, width: 'full' }, [
        resourceBlock('CPU', state.cpu, COLOR.purple),
        resourceBlock('Memory', state.mem, COLOR.cyan),
      ]),
    ], { flex: 1.05, raised: true, color: COLOR.purple }),
    groupCell('Edge services', [
      signalRow('Tor', state.onionUrl || 'Waiting for publication', state.onionUrl ? 'good' : 'warn'),
      signalRow('Redis', state.dataLabel, redisState),
      signalRow('HAProxy', `Admin :${state.statsPort}`, 'good'),
      signalRow('Discovery', state.heartbeatWindow, state.dataState === 'live' ? 'good' : redisState),
    ], { flex: 1.55 }),
  ]);

  const bodyChildren = [overview, logsPanel(state, actions)];
  if (state.commandOpen) {
    const suggestions = ['/help', '/reload', '/servers', '/clear', '/quit']
      .filter((command) => command.startsWith(state.commandInput || '/'))
      .slice(0, 4)
      .join('   ');
    bodyChildren.push(ui.focusTrap({
      id: 'balancer-command-trap',
      active: true,
      initialFocus: 'balancer-command-input',
      returnFocusTo: 'balancer-command',
    }, [
      ui.box({
        id: 'balancer-command-panel',
        title: ' COMMAND ',
        border: 'rounded',
        borderStyle: { fg: COLOR.purple },
        style: { bg: COLOR.surfaceRaised },
        px: 1,
        height: 5,
        gap: 0,
      }, [
        ui.row({ width: 'full', gap: 1, align: 'center' }, [
          ui.box({ border: 'none', flex: 1 }, [
            ui.input({
              id: 'balancer-command-input',
              value: state.commandInput,
              placeholder: '/help',
              onInput: actions.setCommandInput,
              dsSize: 'md',
            }),
          ]),
          ui.button({
            id: 'balancer-command-run',
            label: 'Enter  Run',
            onPress: actions.submitCommand,
            intent: 'primary',
            dsSize: 'sm',
          }),
          ui.button({
            id: 'balancer-command-cancel',
            label: 'Esc  Close',
            onPress: actions.closeCommand,
            intent: 'secondary',
            dsSize: 'sm',
          }),
        ]),
        ui.text(suggestions || 'No matching command', {
          style: { fg: COLOR.muted },
          textOverflow: 'ellipsis',
        }),
      ]),
    ]));
  }

  return ui.page({
    id: 'qorc-load-balancer-tui',
    p: 1,
    gap: 1,
    header: header('LOAD BALANCER', `${serverCount} active ${state.servers === 1 ? 'backend' : 'backends'}`, [
      warning,
      ui.text(`PID ${state.pid}`, { style: { fg: COLOR.muted } }),
    ]),
    body: ui.column({ gap: 1, width: 'full', height: 'full' }, bodyChildren),
    footer: footerControls('balancer', actions, true),
  });
}

function createDashboard(kind, initialState, externalActions) {
  let commandValue = '/';
  const app = createNodeApp({
    initialState: {
      ...initialState,
      kind,
      logs: initialState.logs || [],
      logScroll: initialState.logScroll || 0,
      followLogs: initialState.followLogs !== false,
      commandOpen: false,
      commandInput: '/',
    },
    theme: qorcTheme,
    config: {
      fpsCap: 30,
      executionMode: 'auto',
      screen: { mode: 'alt' },
      rootPadding: 0,
    },
  });

  const setLogScroll = (next) => {
    app.update((state) => ({
      ...state,
      logScroll: Math.max(0, next),
      followLogs: next >= Math.max(
        0,
        state.logs.length - Math.max(1, app.measureElement(`${kind}-activity`)?.h || 1)
      ),
    }));
  };
  const moveLogs = (delta) => {
    app.update((state) => {
      const viewportHeight = Math.max(1, app.measureElement(`${kind}-activity`)?.h || 1);
      const maxScroll = Math.max(0, state.logs.length - viewportHeight);
      const base = state.followLogs ? maxScroll : state.logScroll;
      const next = Math.max(0, Math.min(maxScroll, base + delta));
      return { ...state, logScroll: next, followLogs: next >= maxScroll };
    });
  };
  const latest = () => app.update((state) => ({
    ...state,
    logScroll: state.logs.length,
    followLogs: true,
  }));
  const openCommand = () => {
    commandValue = '/';
    app.update((state) => ({ ...state, commandOpen: true, commandInput: commandValue }));
  };
  const closeCommand = () => {
    commandValue = '/';
    app.update((state) => ({ ...state, commandOpen: false, commandInput: commandValue }));
  };
  const submitCommand = () => {
    const command = commandValue;
    commandValue = '/';
    app.update((state) => ({ ...state, commandOpen: false, commandInput: commandValue }));
    if (command.trim()) void externalActions.submitCommand?.(command);
  };
  const recallHistory = (direction) => {
    app.update((state) => {
      commandValue = externalActions.recallHistory?.(direction, state.commandInput) || state.commandInput;
      return { ...state, commandInput: commandValue };
    });
  };
  const actions = Object.freeze({
    older: () => moveLogs(-1),
    newer: () => moveLogs(1),
    pageOlder: () => moveLogs(-10),
    pageNewer: () => moveLogs(10),
    latest,
    setLogScroll,
    stop: externalActions.stop,
    openCommand,
    closeCommand,
    setCommandInput: (value) => {
      commandValue = value;
      app.update((state) => ({ ...state, commandInput: value }));
    },
    submitCommand,
  });

  app.view((state) => kind === 'server' ? serverView(state, actions) : loadBalancerView(state, actions));
  app.keys({
    q: { description: 'Stop', when: ({ state }) => !state.commandOpen, handler: externalActions.stop },
    'shift+q': { description: 'Stop', when: ({ state }) => !state.commandOpen, handler: externalActions.stop },
    'ctrl+c': {
      description: 'Close command or stop',
      handler: ({ state }) => state.commandOpen ? closeCommand() : externalActions.stop(),
    },
    up: {
      priority: 100,
      description: 'Older activity or previous command',
      handler: ({ state }) => state.commandOpen ? recallHistory(-1) : actions.older(),
    },
    k: { description: 'Older activity', when: ({ state }) => !state.commandOpen, handler: actions.older },
    down: {
      priority: 100,
      description: 'Newer activity or next command',
      handler: ({ state }) => state.commandOpen ? recallHistory(1) : actions.newer(),
    },
    j: { description: 'Newer activity', when: ({ state }) => !state.commandOpen, handler: actions.newer },
    pageup: { description: 'Older activity page', when: ({ state }) => !state.commandOpen, handler: actions.pageOlder },
    'ctrl+u': { description: 'Older activity page', when: ({ state }) => !state.commandOpen, handler: actions.pageOlder },
    pagedown: { description: 'Newer activity page', when: ({ state }) => !state.commandOpen, handler: actions.pageNewer },
    'ctrl+d': { description: 'Newer activity page', when: ({ state }) => !state.commandOpen, handler: actions.pageNewer },
    g: { description: 'Oldest activity', when: ({ state }) => !state.commandOpen, handler: () => setLogScroll(0) },
    home: { description: 'Oldest activity', when: ({ state }) => !state.commandOpen, handler: () => setLogScroll(0) },
    'shift+g': { description: 'Latest activity', when: ({ state }) => !state.commandOpen, handler: latest },
    end: { description: 'Latest activity', when: ({ state }) => !state.commandOpen, handler: latest },
    '/': { description: 'Open command', when: ({ state }) => kind === 'balancer' && !state.commandOpen, handler: openCommand },
    ':': { description: 'Open command', when: ({ state }) => kind === 'balancer' && !state.commandOpen, handler: openCommand },
    escape: { description: 'Close command', when: ({ state }) => state.commandOpen, handler: closeCommand },
    enter: { priority: 100, description: 'Run command', when: ({ state }) => state.commandOpen, handler: submitCommand },
  });

  return Object.freeze({
    start: () => app.start(),
    async stop() {
      await app.stop();
      app.dispose();
    },
    update(next) {
      app.update((state) => {
        const merged = { ...state, ...next };
        if (state.followLogs && next.logs) {
          merged.logScroll = next.logs.length;
          merged.followLogs = true;
        }
        return merged;
      });
    },
    app,
  });
}

export function createServerDashboard(initialState, actions) {
  return createDashboard('server', initialState, actions);
}

export function createLoadBalancerDashboard(initialState, actions) {
  return createDashboard('balancer', initialState, actions);
}

export const __test = Object.freeze({
  COLOR,
  qorcTheme,
  serverView,
  loadBalancerView,
});
