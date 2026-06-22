import fs from 'fs';
import path from 'path';
import { logger as defaultLogger } from '../crypto/crypto-logger.js';

const DEFAULT_INTERVAL_MS = 60_000;
const MIN_INTERVAL_MS = 5_000;
const MAX_INTERVAL_MS = 10 * 60_000;
const TOP_TYPE_LIMIT = 8;
const TYPE_BUCKET_LIMIT = 32;
const IDLE_CLEANUP_DELAY_MS = envInt('RUNTIME_IDLE_CLEANUP_DELAY_MS', 30_000, 0, 60 * 60_000);
const IDLE_CLEANUP_ENABLED = envBool('RUNTIME_IDLE_CLEANUP_ENABLED', true);
const IDLE_GC_ENABLED = envBool('RUNTIME_IDLE_GC_ENABLED', true);
const DIAGNOSTIC_LOG_ENABLED = envBool('RUNTIME_DIAGNOSTIC_LOG_ENABLED', true);
const DIAGNOSTIC_LOG_DIR = process.env.RUNTIME_DIAGNOSTIC_LOG_DIR || 'logs';
const DIAGNOSTIC_LOG_FILE = process.env.RUNTIME_DIAGNOSTIC_LOG_FILE || '';

function envBool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return !['0', 'false', 'off', 'no'].includes(String(raw).trim().toLowerCase());
}

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function mb(bytes) {
  return Math.round(((Number(bytes) || 0) / 1024 / 1024) * 10) / 10;
}

function runTimestamp() {
  return new Date()
    .toISOString()
    .replace(/[:.]/g, '-');
}

function resolveDiagnosticLogPath() {
  const explicitPath = String(DIAGNOSTIC_LOG_FILE || '').trim();
  if (explicitPath) {
    return path.resolve(explicitPath);
  }
  return path.resolve(
    DIAGNOSTIC_LOG_DIR,
    `server-runtime-diagnostics-${runTimestamp()}-${process.pid}.jsonl`
  );
}

function jsonSafeReplacer(_key, value) {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack
    };
  }
  if (value instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(value))) {
    return Buffer.from(value).toString('base64');
  }
  return value;
}

function createDiagnosticLogWriter(logger) {
  if (!DIAGNOSTIC_LOG_ENABLED) {
    return {
      filePath: null,
      write: () => {},
      close: () => {}
    };
  }

  const filePath = resolveDiagnosticLogPath();
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const stream = fs.createWriteStream(filePath, { flags: 'a' });
    stream.on('error', (error) => {
      logger.error('[RUNTIME] Diagnostic log file write failed', {
        filePath,
        error: error?.message || String(error)
      });
    });
    return {
      filePath,
      write(entry) {
        try {
          stream.write(`${JSON.stringify(entry, jsonSafeReplacer)}\n`);
        } catch (error) {
          logger.error('[RUNTIME] Diagnostic log serialization failed', {
            filePath,
            error: error?.message || String(error)
          });
        }
      },
      close() {
        stream.end();
      }
    };
  } catch (error) {
    logger.error('[RUNTIME] Diagnostic log file unavailable', {
      filePath,
      error: error?.message || String(error)
    });
    return {
      filePath: null,
      write: () => {},
      close: () => {}
    };
  }
}

function safeType(type) {
  if (typeof type !== 'string' || type.length === 0) return 'unknown';
  if (type.length > 80) return 'oversized-type';
  return type.replace(/[^a-zA-Z0-9:_-]/g, '_');
}

function createWindowStats() {
  return {
    frames: 0,
    bytes: 0,
    largeFrames: 0,
    largestBytes: 0,
    types: new Map()
  };
}

const counters = {
  ingress: createWindowStats(),
  inner: createWindowStats(),
  egress: createWindowStats(),
  broadcasts: {
    attempts: 0,
    delivered: 0,
    skippedBackpressure: 0,
    skippedSuspended: 0,
    skippedNotReady: 0
  }
};

function addType(map, type, bytes) {
  const key = safeType(type);
  const bucket = map.has(key) || map.size < TYPE_BUCKET_LIMIT ? key : 'other';
  const current = map.get(bucket) || { count: 0, bytes: 0 };
  current.count += 1;
  current.bytes += Number(bytes) || 0;
  map.set(bucket, current);
}

function recordWindowStat(stats, bytes, type, largeThreshold) {
  const n = Math.max(0, Number(bytes) || 0);
  stats.frames += 1;
  stats.bytes += n;
  stats.largestBytes = Math.max(stats.largestBytes, n);
  if (n > largeThreshold) stats.largeFrames += 1;
  addType(stats.types, type, n);
}

export function recordWsIngress(bytes, type = 'unknown') {
  recordWindowStat(counters.ingress, bytes, type, 64 * 1024);
}

export function recordWsInnerMessage(type, bytes = 0) {
  recordWindowStat(counters.inner, bytes, type, 64 * 1024);
}

export function recordWsEgress(bytes, type = 'unknown') {
  recordWindowStat(counters.egress, bytes, type, 64 * 1024);
}

export function recordLocalBroadcast(stats = {}) {
  counters.broadcasts.attempts += Number(stats.attempts || 0);
  counters.broadcasts.delivered += Number(stats.delivered || 0);
  counters.broadcasts.skippedBackpressure += Number(stats.skippedBackpressure || 0);
  counters.broadcasts.skippedSuspended += Number(stats.skippedSuspended || 0);
  counters.broadcasts.skippedNotReady += Number(stats.skippedNotReady || 0);
}

function topTypes(map) {
  return Array.from(map.entries())
    .sort((a, b) => b[1].bytes - a[1].bytes)
    .slice(0, TOP_TYPE_LIMIT)
    .map(([type, value]) => ({
      type,
      count: value.count,
      mb: mb(value.bytes)
    }));
}

function snapshotWindowStats(stats) {
  return {
    frames: stats.frames,
    mb: mb(stats.bytes),
    largeFrames: stats.largeFrames,
    largestMb: mb(stats.largestBytes),
    topTypes: topTypes(stats.types)
  };
}

function resetWindowStats(stats) {
  stats.frames = 0;
  stats.bytes = 0;
  stats.largeFrames = 0;
  stats.largestBytes = 0;
  stats.types.clear();
}

function snapshotBroadcastStats() {
  return { ...counters.broadcasts };
}

function resetBroadcastStats() {
  counters.broadcasts.attempts = 0;
  counters.broadcasts.delivered = 0;
  counters.broadcasts.skippedBackpressure = 0;
  counters.broadcasts.skippedSuspended = 0;
  counters.broadcasts.skippedNotReady = 0;
}

function snapshotWebSocketState(wss) {
  const clients = Array.from(wss?.clients || []);
  let open = 0;
  let bufferedBytes = 0;
  let maxBufferedBytes = 0;
  for (const ws of clients) {
    if (ws?.readyState === 1) open += 1;
    const buffered = Math.max(0, Number(ws?.bufferedAmount || 0));
    bufferedBytes += buffered;
    maxBufferedBytes = Math.max(maxBufferedBytes, buffered);
  }
  return {
    clients: clients.length,
    open,
    bufferedMb: mb(bufferedBytes),
    maxBufferedMb: mb(maxBufferedBytes)
  };
}

export function getRuntimeSnapshot(wss = null) {
  const memory = process.memoryUsage();
  return {
    uptimeSec: Math.round(process.uptime()),
    memory: {
      rssMb: mb(memory.rss),
      heapUsedMb: mb(memory.heapUsed),
      heapTotalMb: mb(memory.heapTotal),
      externalMb: mb(memory.external),
      arrayBuffersMb: mb(memory.arrayBuffers)
    },
    ws: snapshotWebSocketState(wss),
    window: {
      ingress: snapshotWindowStats(counters.ingress),
      inner: snapshotWindowStats(counters.inner),
      egress: snapshotWindowStats(counters.egress),
      broadcasts: snapshotBroadcastStats()
    }
  };
}

function snapshotMemory() {
  const memory = process.memoryUsage();
  return {
    rssMb: mb(memory.rss),
    heapUsedMb: mb(memory.heapUsed),
    heapTotalMb: mb(memory.heapTotal),
    externalMb: mb(memory.external),
    arrayBuffersMb: mb(memory.arrayBuffers)
  };
}

function resetRuntimeWindow() {
  resetWindowStats(counters.ingress);
  resetWindowStats(counters.inner);
  resetWindowStats(counters.egress);
  resetBroadcastStats();
}

export function startRuntimeMonitor({ getWss, logger = defaultLogger, getDiagnostics, onIdleCleanup } = {}) {
  if (!envBool('RUNTIME_MONITOR_ENABLED', true)) {
    return () => {};
  }

  const intervalMs = envInt('RUNTIME_MONITOR_INTERVAL_MS', DEFAULT_INTERVAL_MS, MIN_INTERVAL_MS, MAX_INTERVAL_MS);
  let idleSince = null;
  let cleanupInFlight = false;
  let cleanupRuns = 0;
  const diagnosticLog = createDiagnosticLogWriter(logger);

  const maybeRunIdleCleanup = async (snapshot) => {
    const now = Date.now();
    if (!IDLE_CLEANUP_ENABLED || snapshot?.ws?.open !== 0) {
      idleSince = null;
      return;
    }
    if (!idleSince) idleSince = now;
    const idleMs = now - idleSince;
    if (idleMs < IDLE_CLEANUP_DELAY_MS || cleanupInFlight) return;

    cleanupInFlight = true;
    const before = snapshotMemory();
    try {
      const cleanup = typeof onIdleCleanup === 'function'
        ? await onIdleCleanup({ idleMs, snapshot })
        : {};
      let gcRan = false;
      if (IDLE_GC_ENABLED && typeof global.gc === 'function') {
        global.gc();
        gcRan = true;
      }
      const after = snapshotMemory();
      cleanupRuns += 1;
      const event = {
        idleMs,
        cleanupRuns,
        cleanup,
        gc: {
          enabled: IDLE_GC_ENABLED,
          available: typeof global.gc === 'function',
          ran: gcRan
        },
        memoryBefore: before,
        memoryAfter: after
      };
      logger.warn('[RUNTIME] Idle cleanup completed', event);
      diagnosticLog.write({
        ts: new Date().toISOString(),
        level: 'warn',
        event: 'runtime-idle-cleanup-completed',
        ...event
      });
    } catch (error) {
      const event = {
        idleMs,
        error: error?.message || String(error)
      };
      logger.error('[RUNTIME] Idle cleanup failed', event);
      diagnosticLog.write({
        ts: new Date().toISOString(),
        level: 'error',
        event: 'runtime-idle-cleanup-failed',
        ...event
      });
    } finally {
      cleanupInFlight = false;
      idleSince = Date.now();
    }
  };

  const emit = () => {
    void (async () => {
      const snapshot = getRuntimeSnapshot(typeof getWss === 'function' ? getWss() : null);
      let diagnostics = {};
      if (typeof getDiagnostics === 'function') {
        try {
          diagnostics = await getDiagnostics();
        } catch (error) {
          diagnostics = { error: error?.message || String(error) };
        }
      }
      const event = {
        intervalMs,
        ...snapshot,
        diagnostics
      };
      logger.warn('[RUNTIME] Memory and websocket usage', event);
      diagnosticLog.write({
        ts: new Date().toISOString(),
        level: 'warn',
        event: 'runtime-memory-websocket-usage',
        ...event
      });
      resetRuntimeWindow();
      await maybeRunIdleCleanup(snapshot);
    })();
  };

  const timer = setInterval(emit, intervalMs);
  timer.unref?.();

  logger.warn('[RUNTIME] Runtime monitor started', {
    intervalMs,
    diagnosticLogFile: diagnosticLog.filePath
  });
  diagnosticLog.write({
    ts: new Date().toISOString(),
    level: 'warn',
    event: 'runtime-monitor-started',
    intervalMs,
    diagnosticLogFile: diagnosticLog.filePath
  });
  return () => {
    clearInterval(timer);
    logger.warn('[RUNTIME] Runtime monitor stopped', {
      diagnosticLogFile: diagnosticLog.filePath
    });
    diagnosticLog.write({
      ts: new Date().toISOString(),
      level: 'warn',
      event: 'runtime-monitor-stopped',
      diagnosticLogFile: diagnosticLog.filePath
    });
    diagnosticLog.close();
  };
}
