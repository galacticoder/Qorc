import fs from 'node:fs/promises';
import path from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import { monitorEventLoopDelay, performance } from 'node:perf_hooks';

const SNAPSHOT_INTERVAL_MS = 2_000;
const OPERATION_WINDOW_MS = 60_000;
const OPERATION_SAMPLE_LIMIT = 8_192;
const TELEMETRY_PATH = process.env.QORC_SERVER_TELEMETRY_PATH || '/app/logs/server-telemetry.json';
const startedAt = Date.now();
const operationSamples = [];
const storageSamples = { postgres: [], redis: [] };
const errorCategories = new Map();
const eventLoopHistogram = monitorEventLoopDelay({ resolution: 20 });
const storageTelemetryContext = new AsyncLocalStorage();

let operationTotal = 0;
let frameTotal = 0;
let processedBytesTotal = 0;
let errorTotal = 0;
let deliveryRetryTotal = 0;
let deliveryExpiredTotal = 0;
let deliveryProvider = null;
let runtimeProvider = null;
let snapshotTimer = null;
let snapshotInFlight = null;
let previousEventLoopUtilization = performance.eventLoopUtilization();
let originalConsoleError = null;

function percentile(sorted, value) {
  if (sorted.length === 0) return 0;
  const position = Math.min(sorted.length - 1, Math.max(0, Math.ceil((value / 100) * sorted.length) - 1));
  return sorted[position];
}

function rounded(value, digits = 2) {
  if (!Number.isFinite(value)) return 0;
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function errorCategory(firstArgument) {
  if (typeof firstArgument !== 'string') return 'server';
  const match = /^\[([A-Za-z0-9_-]{1,40})\]/.exec(firstArgument.trim());
  return match ? match[1].toLowerCase() : 'server';
}

function pruneOperationSamples(now = Date.now()) {
  while (operationSamples.length > 0 && now - operationSamples[0].at > OPERATION_WINDOW_MS) {
    operationSamples.shift();
  }
  if (operationSamples.length > OPERATION_SAMPLE_LIMIT) {
    operationSamples.splice(0, operationSamples.length - OPERATION_SAMPLE_LIMIT);
  }
}

function pruneTimedSamples(samples, now = Date.now()) {
  while (samples.length > 0 && now - samples[0].at > OPERATION_WINDOW_MS) samples.shift();
  if (samples.length > OPERATION_SAMPLE_LIMIT) samples.splice(0, samples.length - OPERATION_SAMPLE_LIMIT);
}

function latencySummary(samples, now) {
  pruneTimedSamples(samples, now);
  const durations = samples.map((entry) => entry.duration).sort((left, right) => left - right);
  return {
    p50: rounded(percentile(durations, 50)),
    p95: rounded(percentile(durations, 95)),
    p99: rounded(percentile(durations, 99)),
    samples: durations.length
  };
}

export function recordServerOperation(durationMs, { frame = false, bytes = 0 } = {}) {
  const duration = Number(durationMs);
  if (Number.isFinite(duration) && duration >= 0) {
    operationSamples.push({ at: Date.now(), duration });
    pruneOperationSamples();
  }
  operationTotal += 1;
  if (frame) frameTotal += 1;
  if (Number.isFinite(bytes) && bytes > 0) processedBytesTotal += Math.trunc(bytes);
}

export function recordServerError(category = 'server', count = 1) {
  const normalized = typeof category === 'string' && /^[a-z0-9_-]{1,40}$/i.test(category)
    ? category.toLowerCase()
    : 'server';
  const amount = Number.isSafeInteger(count) && count > 0 ? count : 1;
  errorTotal += amount;
  errorCategories.set(normalized, (errorCategories.get(normalized) || 0) + amount);
}

export function recordStorageOperation(storage, durationMs, failed = false) {
  if (storageTelemetryContext.getStore() === false) return;
  if (storage !== 'postgres' && storage !== 'redis') return;
  const duration = Number(durationMs);
  if (Number.isFinite(duration) && duration >= 0) {
    storageSamples[storage].push({ at: Date.now(), duration });
    pruneTimedSamples(storageSamples[storage]);
  }
  if (failed) recordServerError(storage);
}

export function withoutStorageTelemetry(operation) {
  return storageTelemetryContext.run(false, operation);
}

export function recordDeliveryRetry(count = 1) {
  if (Number.isSafeInteger(count) && count > 0) deliveryRetryTotal += count;
}

export function recordDeliveryExpired(count = 1) {
  if (Number.isSafeInteger(count) && count > 0) deliveryExpiredTotal += count;
}

export function setDeliveryTelemetryProvider(provider) {
  deliveryProvider = typeof provider === 'function' ? provider : null;
}

export function setRuntimeTelemetryProvider(provider) {
  runtimeProvider = typeof provider === 'function' ? provider : null;
}

async function deliverySnapshot() {
  if (!deliveryProvider) return null;
  try {
    return await deliveryProvider();
  } catch {
    return null;
  }
}

async function runtimeSnapshot() {
  if (!runtimeProvider) return null;
  try {
    return await runtimeProvider();
  } catch {
    return null;
  }
}

async function writeSnapshot() {
  const now = Date.now();
  pruneOperationSamples(now);
  const durations = operationSamples.map((entry) => entry.duration).sort((left, right) => left - right);
  const utilization = performance.eventLoopUtilization(previousEventLoopUtilization);
  previousEventLoopUtilization = performance.eventLoopUtilization();
  const histogramHasData = Number.isFinite(eventLoopHistogram.mean);
  const snapshot = {
    version: 1,
    timestamp: now,
    startedAt,
    operationLatencyMs: {
      p50: rounded(percentile(durations, 50)),
      p95: rounded(percentile(durations, 95)),
      p99: rounded(percentile(durations, 99)),
      samples: durations.length
    },
    storageLatencyMs: {
      postgres: latencySummary(storageSamples.postgres, now),
      redis: latencySummary(storageSamples.redis, now)
    },
    eventLoop: {
      utilization: rounded(utilization.utilization * 100),
      p50Ms: histogramHasData ? rounded(eventLoopHistogram.percentile(50) / 1_000_000) : 0,
      p99Ms: histogramHasData ? rounded(eventLoopHistogram.percentile(99) / 1_000_000) : 0
    },
    counters: {
      operations: operationTotal,
      frames: frameTotal,
      processedBytes: processedBytesTotal,
      errors: errorTotal,
      deliveryRetries: deliveryRetryTotal,
      deliveryExpired: deliveryExpiredTotal
    },
    errors: Object.fromEntries([...errorCategories.entries()].sort(([left], [right]) => left.localeCompare(right))),
    delivery: await deliverySnapshot(),
    runtime: await runtimeSnapshot()
  };
  eventLoopHistogram.reset();
  const temporary = `${TELEMETRY_PATH}.tmp`;
  await fs.mkdir(path.dirname(TELEMETRY_PATH), { recursive: true });
  await fs.writeFile(temporary, `${JSON.stringify(snapshot)}\n`, { mode: 0o600 });
  await fs.rename(temporary, TELEMETRY_PATH);
}

function queueSnapshot() {
  if (snapshotInFlight) return snapshotInFlight;
  snapshotInFlight = writeSnapshot()
    .catch(() => {})
    .finally(() => { snapshotInFlight = null; });
  return snapshotInFlight;
}

export function startServerTelemetry() {
  if (snapshotTimer) return;
  eventLoopHistogram.enable();
  if (!originalConsoleError) {
    originalConsoleError = console.error;
    console.error = (...arguments_) => {
      recordServerError(errorCategory(arguments_[0]));
      originalConsoleError.apply(console, arguments_);
    };
  }
  void queueSnapshot();
  snapshotTimer = setInterval(() => void queueSnapshot(), SNAPSHOT_INTERVAL_MS);
  snapshotTimer.unref?.();
}

export async function stopServerTelemetry() {
  if (snapshotTimer) {
    clearInterval(snapshotTimer);
    snapshotTimer = null;
  }
  eventLoopHistogram.disable();
  if (snapshotInFlight) await snapshotInFlight;
  await queueSnapshot();
  if (originalConsoleError) {
    console.error = originalConsoleError;
    originalConsoleError = null;
  }
}
