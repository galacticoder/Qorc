import { invoke } from '@tauri-apps/api/core';

type ForwardedConsoleLevel = 'LOG' | 'INFO' | 'WARN' | 'ERROR';

const MAX_LINE_CHARS = 32 * 1024;
const MAX_PENDING_LINES = 1_000;
const MAX_BATCH_LINES = 32;
const FLUSH_INTERVAL_MS = 100;

const pending: string[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;
let flushing = false;
let installed = false;

function serializeArgument(value: unknown): string {
    if (typeof value === 'string') return value;
    if (typeof value === 'undefined') return 'undefined';
    if (typeof value === 'bigint') return `${value.toString()}n`;
    if (typeof value === 'symbol' || typeof value === 'function') return String(value);
    const seen = new WeakSet<object>();
    try {
        const encoded = JSON.stringify(value, (_key, current: unknown) => {
            if (typeof current === 'bigint') return `${current.toString()}n`;
            if (current instanceof Error) {
                return {
                    name: current.name,
                    message: current.message,
                    stack: current.stack,
                    cause: 'cause' in current
                        ? (current as Error & { cause?: unknown }).cause
                        : undefined,
                };
            }
            if (current instanceof Uint8Array) return `[Uint8Array ${current.byteLength} bytes]`;
            if (current instanceof ArrayBuffer) return `[ArrayBuffer ${current.byteLength} bytes]`;
            if (current instanceof Map) return Object.fromEntries(current);
            if (current instanceof Set) return Array.from(current);
            if (current && typeof current === 'object') {
                if (seen.has(current)) return '[Circular]';
                seen.add(current);
            }
            return current;
        });
        return typeof encoded === 'string' ? encoded : String(value);
    } catch {
        try {
            return String(value);
        } catch {
            return '[Unserializable]';
        }
    }
}

function makeLine(level: ForwardedConsoleLevel, args: readonly unknown[]): string {
    const body = args.map(serializeArgument).join(' ');
    const line = `[${new Date().toISOString()}] [${level}] ${body}`
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n');
    if (line.length <= MAX_LINE_CHARS) return line;
    return `${line.slice(0, MAX_LINE_CHARS)} [truncated]`;
}

function scheduleFlush(delay = FLUSH_INTERVAL_MS): void {
    if (flushTimer !== null || flushing || pending.length === 0) return;
    flushTimer = setTimeout(() => {
        flushTimer = null;
        void flush();
    }, delay);
}

async function flush(): Promise<void> {
    if (flushing || pending.length === 0) return;
    flushing = true;
    const entries = pending.splice(0, MAX_BATCH_LINES);
    let failed = false;
    try {
        await invoke<boolean>('forward_client_logs', { entries });
    } catch {
        failed = true;
        pending.unshift(...entries);
        if (pending.length > MAX_PENDING_LINES) pending.splice(0, pending.length - MAX_PENDING_LINES);
    } finally {
        flushing = false;
        if (pending.length > 0) {
            scheduleFlush(failed ? 1_000 : pending.length >= MAX_BATCH_LINES ? 0 : FLUSH_INTERVAL_MS);
        }
    }
}

function enqueue(level: ForwardedConsoleLevel, args: readonly unknown[]): void {
    pending.push(makeLine(level, args));
    if (pending.length > MAX_PENDING_LINES) pending.splice(0, pending.length - MAX_PENDING_LINES);
    if (pending.length >= MAX_BATCH_LINES) {
        if (flushTimer !== null) clearTimeout(flushTimer);
        flushTimer = null;
        void flush();
        return;
    }
    scheduleFlush();
}

export function installClientLogForwarding(): void {
    if (installed) return;
    installed = true;
    const methods: Array<[keyof Pick<Console, 'log' | 'info' | 'warn' | 'error'>, ForwardedConsoleLevel]> = [
        ['log', 'LOG'],
        ['info', 'INFO'],
        ['warn', 'WARN'],
        ['error', 'ERROR'],
    ];
    for (const [method, level] of methods) {
        const original = console[method].bind(console);
        console[method] = (...args: unknown[]) => {
            original(...args);
            if (args[0] === '[CALL-DIAG]' || args[0] === '[WS-CONNECT-DIAG]') {
                const entry = makeLine(level, args);
                void invoke<boolean>('forward_client_logs', { entries: [entry] })
                    .catch(() => enqueue(level, args));
                return;
            }
            enqueue(level, args);
        };
    }
    window.addEventListener('error', event => {
        enqueue('ERROR', ['[UNHANDLED-ERROR]', event.error ?? event.message]);
        void flush();
    });
    window.addEventListener('unhandledrejection', event => {
        enqueue('ERROR', ['[UNHANDLED-REJECTION]', event.reason]);
        void flush();
    });
    window.addEventListener('pagehide', () => { void flush(); });
    enqueue('INFO', ['[LOG-FORWARDING] initialized']);
}

installClientLogForwarding();
