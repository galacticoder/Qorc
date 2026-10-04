import assert from 'node:assert/strict';
import fs from 'node:fs';
import test, { before, after } from 'node:test';
import { createServer } from 'vite';

let loader;
let DiscoveryTransferDiagnostics;
before(async () => {
  loader = await createServer({
    configFile: false, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true, watch: { ignored: ['**/src-tauri/target/**', '**/node_modules/**'] } },
    optimizeDeps: { noDiscovery: true },
  });
  ({ DiscoveryTransferDiagnostics } = await loader.ssrLoadModule('/src/lib/transport/discovery-transfer-diagnostics.ts'));
});
after(async () => { await loader?.close(); });

function fixture(t) {
  t.mock.timers.enable({ apis: ['setInterval'] });
  let now = 0;
  const logs = [];
  t.mock.method(performance, 'now', () => now);
  t.mock.method(console, 'info', (tag, data) => {
    assert.equal(tag, '[DISCOVERY-PERF]');
    logs.push(JSON.parse(data));
  });
  return {
    logs,
    advance(ms) {
      while (ms > 0) {
        const step = Math.min(ms, 1000);
        now += step;
        t.mock.timers.tick(step);
        ms -= step;
      }
    },
    block(ms) { now += ms; },
  };
}

test('discovery diagnostics separate queue, setup, body and verification time', (t) => {
  const f = fixture(t);
  const trace = new DiscoveryTransferDiagnostics(1024 * 1024);
  f.advance(10);
  trace.phase('discovery-queue');
  f.advance(2000);
  trace.phase('key-exchange');
  f.advance(100);
  trace.phase('admission-pow');
  f.advance(500);
  trace.phase('request-encryption');
  f.advance(100);
  trace.phase('connecting-upload-waiting-headers');
  f.advance(5000);
  trace.progress(0);
  f.advance(1000);
  trace.progress(256 * 1024);
  f.advance(3000);
  trace.progress(1024 * 1024);
  trace.phase('response-authentication');
  f.advance(100);
  trace.phase('response-decryption');
  f.advance(150);
  trace.phase('response-parse');
  f.advance(40);
  trace.finish('success');
  const summary = f.logs.at(-1);
  assert.equal(summary.elapsedMs, 12000);
  assert.equal(summary.phasesMs['discovery-queue'], 2000);
  assert.equal(summary.phasesMs['admission-pow'], 500);
  assert.equal(summary.bodyMs, 4000);
  assert.equal(summary.firstBodyByteMs, 1000);
  assert.equal(summary.averageKiBps, 256);
  assert.equal(summary.maxNoProgressMs, 3000);
  assert.equal(summary.dominantStage, 'beforeHeaders');
  assert.match(summary.nextCheck, /cannot be separated/);
  const count = f.logs.length;
  f.advance(60_000);
  trace.finish('error');
  trace.progress(1);
  assert.equal(f.logs.length, count);
});

test('an idle body produces zero-speed progress and a cancellation summary', (t) => {
  const f = fixture(t);
  const trace = new DiscoveryTransferDiagnostics(8912896);
  trace.phase('connecting-upload-waiting-headers');
  trace.progress(0);
  f.advance(15_000);
  assert.equal(f.logs.at(-1).event, 'progress');
  assert.equal(f.logs.at(-1).windowKiBps, 0);
  assert.equal(f.logs.at(-1).estimatedRemainingSeconds, null);
  assert.equal(f.logs.at(-1).noProgressMs, 15_000);
  f.advance(15_000);
  trace.finish('cancelled');
  assert.equal(f.logs.at(-1).outcome, 'cancelled');
  assert.equal(f.logs.at(-1).dominantStage, 'download');
  assert.equal(f.logs.at(-1).maxNoProgressMs, 30_000);
  assert.equal(f.logs.at(-1).firstBodyByteMs, null);
});

test('queue and frontend stalls are distinguished from network speed', (t) => {
  const f = fixture(t);
  const trace = new DiscoveryTransferDiagnostics(1024);
  trace.phase('bulk-queue');
  f.advance(30_000);
  trace.phase('response-decryption');
  f.block(20_000);
  trace.finish('error');
  const summary = f.logs.at(-1);
  assert.equal(summary.dominantStage, 'queue');
  assert.equal(summary.maxTimerDelayMs, 5000);
  assert.equal(summary.bodyMs, 0);
  assert.equal(summary.averageKiBps, null);
});

test('completed bodies do not accumulate idle time during response verification', (t) => {
  const f = fixture(t);
  const trace = new DiscoveryTransferDiagnostics(1024);
  trace.progress(0);
  f.advance(1000);
  trace.progress(1024);
  trace.phase('response-decryption');
  f.advance(60_000);
  trace.finish('success');
  const summary = f.logs.at(-1);
  assert.equal(summary.bodyMs, 1000);
  assert.equal(summary.noProgressMs, 0);
  assert.equal(summary.maxNoProgressMs, 1000);
  assert.equal(summary.dominantStage, 'clientVerification');
});

test('diagnostic correlation is local IPC only, not an anonymous HTTP header', () => {
  const native = fs.readFileSync('src-tauri/src/commands/discovery.rs', 'utf8');
  const sender = native.slice(native.indexOf('async fn send_anonymous_request('), native.indexOf('async fn wait_for_bootstrap('));
  assert.doesNotMatch(sender, /x-qorc-transfer-diagnostic|diagnosticId/);
  assert.match(native, /get\("x-qorc-transfer-diagnostic"\)/);
  const diagnostics = fs.readFileSync('src/lib/transport/discovery-transfer-diagnostics.ts', 'utf8');
  assert.doesNotMatch(diagnostics, /serverUrl|bucketId|username|fingerprint|requestId|localStorage/);
});
