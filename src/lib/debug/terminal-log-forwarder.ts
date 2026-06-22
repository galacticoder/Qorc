// Forwards selected webview console lines into the Rust terminal

import { invoke } from '@tauri-apps/api/core';

const TRACKED_PREFIXES = [
  '[MSG-', '[P2P-',
  '[SecureP2PService]', '[EncryptedMessageHandler]', '[P2PConnection]', '[P2PStream]',
  '[UnifiedTransport]', '[P2PTransport]',
  '[WebSocket]', '[DELIVERY]', '[SPOOL]', '[AVATAR]',
  '[OPRF-DISCOVERY]',
  '[SecureCall]',
];

let installed = false;

function stringifyArg(arg: unknown): string {
  if (typeof arg === 'string') return arg;
  if (arg instanceof Error) return arg.message;
  try {
    return JSON.stringify(arg);
  } catch {
    return String(arg);
  }
}

export function installTerminalLogForwarder(): void {
  if (installed) return;
  installed = true;

  const wrap = (
    level: 'info' | 'warn' | 'error',
    original: (...args: any[]) => void
  ) => {
    return (...args: any[]) => {
      original(...args);
      try {
        const first = args[0];
        if (typeof first !== 'string') return;
        if (!TRACKED_PREFIXES.some((p) => first.startsWith(p))) return;
        const line = args.map(stringifyArg).join(' ').slice(0, 4000);
        void invoke('frontend_log', { level, line }).catch(() => { });
      } catch {
      }
    };
  };

  /* eslint-disable no-console */
  console.log = wrap('info', console.log.bind(console));
  console.warn = wrap('warn', console.warn.bind(console));
  console.error = wrap('error', console.error.bind(console));
  /* eslint-enable no-console */
}
