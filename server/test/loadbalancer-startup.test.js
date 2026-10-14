import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsAsync from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import ts from 'typescript';
import * as infrastructure from '../config/infrastructure.js';
import { readProcessIdFileSnapshot } from '../utils/process-identity.js';
import { HAProxyConfigGenerator } from '../load-balancer/haproxy-config-generator.js';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const keys = { CLUSTER_SERVERS: 'servers', LB_ONION_ADDRESS: 'onion', LB_HTTPS_PORT: 'https-port' };

test('both bundled edge runtimes contain the authenticated current Tor source and publication patch', () => {
  const metadata = JSON.parse(fs.readFileSync(path.join(repo, 'docker/tor/manifest.json'), 'utf8'));
  const dockerfile = fs.readFileSync(path.join(repo, 'docker/Dockerfile.loadbalancer'), 'utf8');
  const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  assert.equal(digest(fs.readFileSync(path.join(repo, 'docker/tor', metadata.patch))), metadata.patch_sha256);
  assert.match(dockerfile, new RegExp(`org\\.qorc\\.tor\\.version="${metadata.version.replaceAll('.', '\\.')}"`));
  assert.ok(dockerfile.includes(`org.qorc.tor.source-sha256="${metadata.source_sha256}"`));
  assert.ok(dockerfile.includes(`org.qorc.tor.patch-sha256="${metadata.patch_sha256}"`));
  for (const [architecture, target, machine] of [['amd64', 'x86_64', 62], ['arm64', 'arm64', 183]]) {
    const archive = path.join(repo, `docker/edge-runtime/qorc-edge-runtime-linux-${target}-v1.tar.gz`);
    const expected = dockerfile.match(new RegExp(`${architecture}\\) archive=[^;]+; expected=([a-f0-9]{64})`))?.[1];
    assert.equal(digest(fs.readFileSync(archive)), expected);
    const manifest = JSON.parse(execFileSync('tar', ['-xzOf', archive, 'qorc-edge/manifest.json'], { encoding: 'utf8' }));
    assert.equal(manifest.target, `linux-${target}-glibc-2.35`);
    assert.equal(manifest.tor.version, metadata.version);
    assert.equal(manifest.tor.source_sha256, metadata.source_sha256);
    assert.equal(manifest.tor.patch_sha256, metadata.patch_sha256);
    const binary = execFileSync('tar', ['-xzOf', archive, 'qorc-edge/tor/tor'], { maxBuffer: 32 * 1024 * 1024 });
    assert.equal(binary.readUInt16LE(18), machine);
    assert.equal(digest(binary), manifest.tor.binary_sha256);
    assert.equal(manifest.files['tor/tor'], manifest.tor.binary_sha256);
  }
});

test('generated proxy health checks tolerate transient work and re-resolve Docker backends', () => {
  const generator = new HAProxyConfigGenerator({
    listenPort: 8443, statsPort: 8404, tlsCertPath: '/fixture/certs',
    statsUsername: 'fixture', statsPassword: 'fixture-password-123456', statsBindAddress: '127.0.0.1',
  });
  generator.addBackend({ name: 'server-main', host: 'server', port: 3000 });
  const config = generator.generateConfig();
  assert.match(config, /timeout check\s+10s/);
  assert.equal((config.match(/check inter 2s fall 3 rise 2/g) || []).length, 2);
  assert.match(config, /resolvers qorc_backends\n\s+parse-resolv-conf/);
  assert.match(config, /hold valid 5s/);
  assert.equal((config.match(/resolvers qorc_backends resolve-prefer ipv4 init-addr none/g) || []).length, 2);
  assert.equal((config.match(/verify required/g) || []).length, 2);
});

test('headless load-balancer startup never opens the terminal renderer and propagates its mode', () => {
  const source = fs.readFileSync(path.join(repo, 'scripts/start-loadbalancer.cjs'), 'utf8');
  const expression = source.match(/NO_GUI:\s*([^,]+),\s*HAPROXY_HTTPS_PORT:/)?.[1];
  assert.ok(expression);
  const headless = new Function('process', `return (${expression});`);
  for (const [flag, stdin, stdout, expected] of [
    ['false', false, false, true], ['false', true, false, true],
    ['false', false, true, true], ['true', true, true, true], ['false', true, true, false],
  ]) {
    assert.equal(headless({ env: { NO_GUI: flag }, stdin: { isTTY: stdin }, stdout: { isTTY: stdout } }), expected);
  }
  assert.match(source, /NO_GUI:\s*String\(CONFIG\.NO_GUI\)/);
  assert.match(source, /await ui\.start\(\);\s*\} catch \(error\) \{\s*child\.kill\('SIGTERM'\)/);
});

function load(relativePath, mocks, processMock, clock = Date, schedule = setTimeout) {
  const filename = path.join(repo, relativePath);
  const source = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    fileName: filename,
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
    transformers: { before: [context => {
      const visit = node => {
        if (ts.isMetaProperty(node)) return ts.factory.createObjectLiteralExpression([
          ts.factory.createPropertyAssignment('url', ts.factory.createStringLiteral(pathToFileURL(filename).href)),
        ]);
        return ts.visitEachChild(node, visit, context);
      };
      return node => ts.visitNode(node, visit);
    }] },
  }).outputText;
  const module = { exports: {} };
  new Function('require', 'module', 'exports', 'process', 'console', 'Date', 'setTimeout', source)(
    id => {
      if (Object.hasOwn(mocks, id)) return mocks[id];
      throw new Error(`Unmocked dependency: ${id}`);
    }, module, module.exports, processMock, { log() {}, info() {}, warn() {}, error() {} }, clock, schedule,
  );
  return module.exports;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function torFixture(context, { clock = Date, schedule = setTimeout, failSpawn = false, onSpawn, readSnapshot } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-lb-tor-'));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const live = new Set();
  const children = [];
  const signals = [];
  let snapshot;
  let removed = 0;
  const processMock = {
    argv: ['node', '/unit-test.js'], env: {},
    kill(pid, signal) { signals.push([pid, signal]); live.delete(pid); },
  };
  const spawn = (_binary, _args, options) => {
    const child = new EventEmitter();
    Object.assign(child, {
      pid: 10_000 + children.length, exitCode: null, signalCode: null, killed: false,
      unref() {},
      kill(signal) {
        if (child.exitCode !== null || child.signalCode !== null) return false;
        child.killed = true;
        child.signalCode = signal;
        live.delete(child.pid);
        queueMicrotask(() => child.emit('exit', null, signal));
        return true;
      },
    });
    children.push(child);
    live.add(child.pid);
    options.signal.addEventListener('abort', () => {
      child.kill('SIGTERM');
      child.emit('error', Object.assign(new Error('Aborted'), { code: 'ABORT_ERR' }));
    }, { once: true });
    queueMicrotask(() => {
      if (failSpawn) {
        live.delete(child.pid);
        child.emit('error', new Error('spawn failed'));
      } else {
        child.emit('spawn');
        onSpawn?.(directory);
      }
    });
    return child;
  };
  const { TorManager } = load('server/load-balancer/tor-manager.js', {
    child_process: { spawn, execFileSync() {} }, 'fs/promises': fsAsync,
    fs, path, url: { fileURLToPath },
    '../config/infrastructure.js': infrastructure,
    './onion-health.js': {},
    '../utils/process-identity.js': {
      processMatchesExecutable: async pid => live.has(pid),
      readProcessIdFileSnapshot: async () => {
        if (readSnapshot) return readSnapshot(path.join(directory, 'tor.pid'));
        if (snapshot !== undefined) return snapshot;
        const pidFile = path.join(directory, 'tor.pid');
        return fs.existsSync(pidFile) ? { pid: Number(fs.readFileSync(pidFile, 'utf8').trim()) } : null;
      },
      removeUnchangedProcessIdFile: async () => {
        removed++;
        snapshot = undefined;
        const pidFile = path.join(directory, 'tor.pid');
        if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
        return true;
      },
    },
  }, processMock, clock, schedule);
  const manager = new TorManager();
  manager.dataDir = directory;
  manager.hiddenServiceDir = path.join(directory, 'hidden_service');
  manager.torrcPath = path.join(directory, 'torrc');
  manager.pidPath = path.join(directory, 'tor.pid');
  manager.logPath = path.join(directory, 'tor.log');
  manager.hsLogPath = path.join(directory, 'tor-hs.log');
  manager.proxyPath = path.join(directory, 'health-proxy.sock');
  manager.checkInterval = 0;
  manager.getTorBinary = async () => manager.getTorBinaryPath();
  manager.probeReachability = async () => true;
  fs.mkdirSync(manager.hiddenServiceDir, { mode: 0o700 });
  fs.writeFileSync(path.join(manager.hiddenServiceDir, 'hostname'), `${'a'.repeat(56)}.onion\n`);
  fs.writeFileSync(path.join(manager.hiddenServiceDir, 'hs_ed25519_secret_key'), 'preserved-identity');
  fs.writeFileSync(path.join(directory, 'state'), 'preserved-guards');
  fs.writeFileSync(manager.logPath, '');
  fs.writeFileSync(manager.hsLogPath, '');
  return {
    manager, children, signals, live,
    setSnapshot(value) { snapshot = value; },
    get removed() { return removed; },
    bootstrap() { fs.appendFileSync(manager.logPath, 'Bootstrapped 100% (done): Done\n'); },
    current() { fs.appendFileSync(manager.hsLogPath, 'QORC_HS_DESC_READY current\n'); },
    next() { fs.appendFileSync(manager.hsLogPath, 'QORC_HS_DESC_READY next\n'); },
  };
}

test('an exited Tor process cannot regain readiness from its outstanding health probe', async context => {
  const fixture = torFixture(context);
  const { manager } = fixture;
  await manager.start(8443);
  const probe = deferred();
  manager.probeReachability = () => probe.promise;
  manager.checkReachability('a'.repeat(56) + '.onion');
  const completion = manager.healthProbePromise;
  const child = manager.torProcess;
  fixture.live.delete(child.pid);
  child.exitCode = 1;
  child.emit('exit', 1, null);
  probe.resolve(true);
  await completion;
  assert.equal(manager.isPublished(), false);
  assert.equal(manager.lastReachableAt, 0);
  assert.equal(manager.healthProbePromise, null);
});

test('Tor launch returns while publication is pending and requires both fresh descriptors', async context => {
  const fixture = torFixture(context);
  const { manager } = fixture;
  assert.equal(await manager.start(8443), true);
  assert.equal(manager.isRunningState, true);
  assert.equal(await manager.isRunning(), true);
  assert.equal(fs.readFileSync(manager.pidPath, 'utf8'), `${manager.torProcess.pid}\n`);
  assert.equal(fs.statSync(manager.pidPath).mode & 0o777, 0o600);
  assert.equal(manager.isPublished(), false);
  fixture.bootstrap();
  fixture.current();
  await manager.monitor(8443);
  assert.equal(manager.isPublished(), false);
  assert.equal(fixture.children.length, 1);
  fixture.next();
  await manager.monitor(8443);
  await manager.healthProbePromise;
  assert.equal(manager.isPublished(), true);
  await manager.stop();
});

test('stale startup and publication markers cannot authorize a new Tor process', async context => {
  const fixture = torFixture(context);
  fixture.bootstrap();
  fixture.current();
  fixture.next();
  await fixture.manager.start(8443);
  await fixture.manager.monitor(8443);
  assert.equal(fixture.manager.isBootstrappedState, false);
  assert.equal(fixture.manager.isPublished(), false);
  fixture.bootstrap();
  fixture.current();
  await fixture.manager.monitor(8443);
  assert.equal(fixture.manager.isPublished(), false);
  await fixture.manager.stop();
});

test('an existing owned Tor process is replaced instead of trusting old readiness', async context => {
  const fixture = torFixture(context);
  fixture.live.add(9_999);
  fixture.setSnapshot({ pid: 9_999 });
  fixture.bootstrap();
  fixture.current();
  fixture.next();
  await fixture.manager.monitor(8443);
  assert.deepEqual(fixture.signals, [[9_999, 'SIGTERM']]);
  assert.equal(fixture.removed, 1);
  assert.equal(fixture.children.length, 1);
  assert.equal(fixture.manager.isPublished(), false);
  await fixture.manager.stop();
});

test('observed publication survives bounded log-window growth without dropping readiness', async context => {
  const fixture = torFixture(context);
  await fixture.manager.start(8443);
  fixture.bootstrap();
  fixture.current();
  await fixture.manager.monitor(8443);
  fs.appendFileSync(fixture.manager.hsLogPath, 'unrelated Tor activity\n'.repeat(20_000));
  fixture.next();
  await fixture.manager.monitor(8443);
  await fixture.manager.healthProbePromise;
  assert.equal(fixture.manager.isPublished(), true);
  await fixture.manager.stop();
});

test('a stalled publication restarts Tor within its budget without deleting identity or guards', async context => {
  const fixture = torFixture(context);
  await fixture.manager.start(8443);
  fixture.bootstrap();
  fixture.current();
  fixture.manager.startedAt = Date.now() - infrastructure.TOR_PUBLICATION_TIMEOUT_MS - 1;
  await fixture.manager.monitor(8443);
  assert.equal(fixture.children.length, 2);
  assert.equal(fixture.children[0].signalCode, 'SIGTERM');
  assert.equal(fixture.manager.isPublished(), false);
  assert.equal(fixture.manager.publicationState.current, false);
  assert.equal(fs.readFileSync(path.join(fixture.manager.hiddenServiceDir, 'hs_ed25519_secret_key'), 'utf8'), 'preserved-identity');
  assert.equal(fs.readFileSync(path.join(fixture.manager.dataDir, 'state'), 'utf8'), 'preserved-guards');
  fixture.bootstrap();
  fixture.next();
  await fixture.manager.monitor(8443);
  assert.equal(fixture.manager.isPublished(), false);
  await fixture.manager.stop();
});

test('a stalled bootstrap is bounded and process death immediately revokes readiness', async context => {
  const fixture = torFixture(context);
  await fixture.manager.start(8443);
  fixture.manager.startedAt = Date.now() - infrastructure.TOR_BOOTSTRAP_TIMEOUT_MS - 1;
  await fixture.manager.monitor(8443);
  assert.equal(fixture.children.length, 2);
  fixture.bootstrap(); fixture.current(); fixture.next();
  await fixture.manager.monitor(8443);
  await fixture.manager.healthProbePromise;
  assert.equal(fixture.manager.isPublished(), true);
  fixture.children[1].kill('SIGTERM');
  await Promise.resolve();
  assert.equal(fixture.manager.isPublished(), false);
  await fixture.manager.monitor(8443);
  assert.equal(fixture.children.length, 3);
  assert.equal(fixture.manager.isPublished(), false);
  await fixture.manager.stop();
});

test('Tor launch is single-flight and cancellation prevents a late spawn', async context => {
  const fixture = torFixture(context);
  const validation = deferred();
  fixture.manager.validateConfig = () => validation.promise;
  const first = fixture.manager.start(8443);
  assert.equal(fixture.manager.start(8443), first);
  const stopping = fixture.manager.stop();
  assert.equal(fixture.manager.stop(), stopping);
  validation.resolve();
  assert.equal(await first, false);
  await stopping;
  assert.equal(fixture.children.length, 0);
  assert.equal(await fixture.manager.start(8443), false);
});

test('descriptor acknowledgments cannot advertise an onion before its pinned HTTPS probe succeeds', async context => {
  const fixture = torFixture(context);
  const probe = deferred();
  fixture.manager.probeReachability = () => probe.promise;
  await fixture.manager.start(8443);
  fixture.bootstrap(); fixture.current(); fixture.next();
  await fixture.manager.monitor(8443);
  assert.equal(fixture.manager.isPublished(), false);
  assert.ok(fixture.manager.healthProbePromise);
  probe.resolve(true);
  await fixture.manager.healthProbePromise;
  assert.equal(fixture.manager.isPublished(), true);
  await fixture.manager.stop();
});

test('a formerly reachable onion is withdrawn and recovered without clearing its identity or guards', async context => {
  let now = 1_000_000;
  const fixture = torFixture(context, { clock: { now: () => now } });
  await fixture.manager.start(8443);
  fixture.bootstrap(); fixture.current(); fixture.next();
  await fixture.manager.monitor(8443);
  await fixture.manager.healthProbePromise;
  assert.equal(fixture.manager.isPublished(), true);
  fixture.manager.probeReachability = async () => false;
  now += infrastructure.TOR_HEALTH_CHECK_INTERVAL_MS;
  await fixture.manager.monitor(8443);
  await fixture.manager.healthProbePromise;
  assert.equal(fixture.manager.isPublished(), false);
  now += infrastructure.TOR_PUBLICATION_TIMEOUT_MS;
  await fixture.manager.monitor(8443);
  assert.equal(fixture.children.length, 2);
  assert.equal(fs.readFileSync(path.join(fixture.manager.hiddenServiceDir, 'hs_ed25519_secret_key'), 'utf8'), 'preserved-identity');
  assert.equal(fs.readFileSync(path.join(fixture.manager.dataDir, 'state'), 'utf8'), 'preserved-guards');
  await fixture.manager.stop();
});

test('an expired health lease or a late successful probe cannot retain stale readiness', async context => {
  let now = 1_000_000;
  const fixture = torFixture(context, { clock: { now: () => now } });
  await fixture.manager.start(8443);
  fixture.bootstrap(); fixture.current(); fixture.next();
  await fixture.manager.monitor(8443);
  await fixture.manager.healthProbePromise;
  now += infrastructure.TOR_HEALTH_LEASE_MS;
  assert.equal(fixture.manager.isPublished(), false);
  const probe = deferred();
  fixture.manager.probeReachability = () => probe.promise;
  await fixture.manager.monitor(8443);
  const pending = fixture.manager.healthProbePromise;
  await fixture.manager.stop();
  probe.resolve(true);
  await pending;
  assert.equal(fixture.manager.isPublished(), false);
});

test('spawn errors reject startup and a pending publication does not block shutdown', async context => {
  const failed = torFixture(context, { failSpawn: true });
  await assert.rejects(failed.manager.start(8443), /spawn failed/);
  assert.equal(failed.manager.isPublished(), false);
  await failed.manager.stop();
  const fixture = torFixture(context);
  await fixture.manager.start(8443);
  await fixture.manager.stop();
  assert.equal(fixture.children[0].signalCode, 'SIGTERM');
  assert.equal(fixture.manager.isPublished(), false);
  assert.equal(await fixture.manager.isRunning(), false);
});

test('shutdown has a deadline and never signals a foreign PID', async context => {
  let now = 1_000_000;
  const fixture = torFixture(context, { clock: { now: () => now }, schedule: callback => { now += 100; queueMicrotask(callback); } });
  fixture.setSnapshot({ pid: 5_555 });
  await fixture.manager.stopProcess();
  assert.equal(fixture.signals.length, 0);
  fixture.live.add(6_666);
  fixture.setSnapshot({ pid: 6_666 });
  fixture.signals.push = () => {};
  fixture.live.delete = () => false;
  await assert.rejects(fixture.manager.stopProcess(), /shutdown deadline/);
});

test('an old process owner cannot signal or remove the replacement PID file', async context => {
  const fixture = torFixture(context);
  await fixture.manager.start(8443);
  fixture.setSnapshot({ pid: 77_777 });
  fixture.live.add(77_777);
  await fixture.manager.stop();
  assert.equal(fixture.live.has(77_777), true);
  assert.equal(fixture.signals.length, 0);
  assert.equal(fixture.removed, 0);
});

test('PID symlinks fail closed without spawning or modifying their target', async context => {
  const fixture = torFixture(context, { readSnapshot: readProcessIdFileSnapshot });
  const target = path.join(fixture.manager.dataDir, 'not-a-pid-file');
  fs.writeFileSync(target, 'untouched', { mode: 0o600 });
  fs.symlinkSync(target, fixture.manager.pidPath);
  await assert.rejects(fixture.manager.start(8443), /ELOOP/);
  assert.equal(fixture.children.length, 0);
  assert.equal(fs.readFileSync(target, 'utf8'), 'untouched');
  await assert.rejects(fixture.manager.stop(), /ELOOP/);
});

test('a PID-file race cannot overwrite the replacement record or leave the spawned child running', async context => {
  const fixture = torFixture(context, {
    onSpawn: directory => fs.writeFileSync(path.join(directory, 'tor.pid'), '77777\n', { mode: 0o600 }),
  });
  await assert.rejects(fixture.manager.start(8443), /EEXIST/);
  await fixture.manager.stop();
  assert.equal(fixture.children[0].signalCode, 'SIGTERM');
  assert.equal(fs.readFileSync(fixture.manager.pidPath, 'utf8'), '77777\n');
  assert.equal(fixture.manager.isPublished(), false);
});

function balancerFixture(tor = null) {
  const processMock = Object.assign(new EventEmitter(), {
    env: { HAPROXY_HTTPS_PORT: '8443', HAPROXY_STATS_PORT: '8404', NO_GUI: 'false' },
    argv: ['node', '/unit-test.js'], pid: 100,
  });
  const exits = [];
  processMock.exit = code => exits.push(code);
  const redis = new Map();
  const operations = [];
  const counts = { start: 0, reload: 0, haproxyStop: 0, torStop: 0, commandStop: 0, release: 0, config: 0 };
  let interval = null;
  class HAProxyManager {
    isRunning = false;
    async refreshRunningState() { return this.isRunning; }
    async start() { counts.start++; this.isRunning = true; }
    async reload() { counts.reload++; }
    async stop() { counts.haproxyStop++; this.isRunning = false; }
  }
  class TorManager {
    isRunningState = false;
    published = false;
    async monitor() { this.isRunningState = true; }
    async getOnionAddress() { return `${'a'.repeat(56)}.onion`; }
    isPublished() { return this.published; }
    async stop() { counts.torStop++; this.published = false; this.isRunningState = false; }
  }
  class LBCommandListener {
    async setup() {
      assert.equal(processMock.listenerCount('SIGTERM'), 1);
      assert.equal(processMock.listenerCount('SIGINT'), 1);
    }
    async stop() { counts.commandStop++; }
  }
  const client = {
    async set(key, value) { operations.push(['set', key, value]); redis.set(key, value); },
    async del(key) { operations.push(['del', key]); redis.delete(key); },
  };
  const { AutoLoadBalancer } = load('server/load-balancer/auto-loadbalancer.js', {
    '../session/redis-client.js': { withRedisClient: callback => callback(client) },
    './haproxy-config-generator.js': { HAProxyConfigGenerator: class {}, parseHAProxyPort: value => Number(value) },
    './haproxy-manager.js': { HAProxyManager }, './tor-manager.js': { TorManager },
    './lb-command-listener.js': { LBCommandListener },
    'fs/promises': fsAsync, fs, path, url: { fileURLToPath },
    '../config/infrastructure.js': infrastructure, '../config/redis-keys.js': { REDIS_KEYS: keys },
    '../utils/process-identity.js': {}, '../utils/process-lock.js': {},
    '../utils/safe-url.js': { safeServiceEndpointForDisplay: () => 'Redis' },
    '../cluster/server-record.js': {},
  }, processMock);
  const manager = new AutoLoadBalancer();
  if (tor) manager.torManager = tor;
  manager.acquireLock = async () => true;
  manager.releaseLock = async () => { counts.release++; };
  let servers = [{ serverId: 'server-main', host: 'server', port: 3000 }];
  manager.getActiveServers = async () => servers;
  manager.generateHAProxyConfig = async () => { counts.config++; };
  const originalSetInterval = globalThis.setInterval;
  const originalClearInterval = globalThis.clearInterval;
  return {
    manager, processMock, redis, operations, counts, exits,
    setServers(value) { servers = value; },
    async start() {
      globalThis.setInterval = callback => { interval = callback; return 42; };
      globalThis.clearInterval = () => { interval = null; };
      try { await manager.start(); }
      finally { globalThis.setInterval = originalSetInterval; globalThis.clearInterval = originalClearInterval; }
    },
    tick() { interval?.(); },
  };
}

test('backend monitoring starts before Tor publication and readiness stays fail-closed', async context => {
  const fixture = torFixture(context);
  const balancer = balancerFixture(fixture.manager);
  await balancer.start();
  assert.equal(balancer.manager.monitorInterval, 42);
  assert.equal(balancer.counts.start, 1);
  assert.equal(balancer.redis.has(keys.LB_ONION_ADDRESS), false);
  balancer.setServers([{ serverId: 'new-server', host: 'server-two', port: 3000 }]);
  fixture.bootstrap(); fixture.current();
  await balancer.manager.monitor();
  assert.equal(balancer.counts.reload, 1);
  assert.equal(balancer.redis.has(keys.LB_ONION_ADDRESS), false);
  fixture.next();
  await balancer.manager.monitor();
  assert.equal(balancer.redis.get(keys.LB_ONION_ADDRESS), `https://${'a'.repeat(56)}.onion`);
  await balancer.manager.stop();
  assert.equal(balancer.redis.has(keys.LB_ONION_ADDRESS), false);
  assert.deepEqual(balancer.exits, [0]);
});

test('monitor cycles share one operation and stop prevents a delayed backend start', async () => {
  const balancer = balancerFixture();
  const lookup = deferred();
  balancer.manager.getActiveServers = () => lookup.promise;
  const cycle = balancer.manager.monitor();
  assert.equal(balancer.manager.monitor(), cycle);
  const stopping = balancer.manager.stop();
  assert.equal(balancer.manager.stop(), stopping);
  lookup.resolve([{ serverId: 'server-main', host: 'server', port: 3000 }]);
  await Promise.all([cycle, stopping]);
  assert.equal(balancer.counts.start, 0);
  assert.equal(balancer.counts.torStop, 1);
  assert.equal(balancer.counts.release, 1);
  assert.deepEqual(balancer.exits, [0]);
});

test('an HAProxy death restarts its runtime even when cluster hostnames have not changed', async () => {
  const balancer = balancerFixture();
  await balancer.start();
  assert.equal(balancer.counts.start, 1);
  balancer.manager.haproxyManager.isRunning = false;
  await balancer.manager.monitor();
  assert.equal(balancer.counts.start, 2);
  assert.equal(balancer.counts.config, 2);
  await balancer.manager.stop();
});

test('an empty cluster never advertises its onion and still replaces stale initial proxy configuration', async () => {
  const balancer = balancerFixture();
  balancer.setServers([]);
  balancer.manager.torManager.published = true;
  await balancer.start();
  assert.equal(balancer.counts.config, 1);
  assert.equal(balancer.redis.has(keys.LB_ONION_ADDRESS), false);
  await balancer.manager.stop();
});

test('SIGTERM works while publication is pending and cannot resurrect either service', async () => {
  const balancer = balancerFixture();
  await balancer.start();
  balancer.processMock.emit('SIGTERM');
  await balancer.manager.stopPromise;
  await balancer.manager.monitor();
  assert.equal(balancer.counts.haproxyStop, 1);
  assert.equal(balancer.counts.torStop, 1);
  assert.equal(balancer.counts.commandStop, 1);
  assert.equal(balancer.processMock.listenerCount('SIGTERM'), 0);
  assert.equal(balancer.manager.monitorInterval, null);
  assert.deepEqual(balancer.exits, [0]);
});

test('a cleanup failure does not skip other services, lock release, or onion withdrawal', async () => {
  const balancer = balancerFixture();
  await balancer.start();
  balancer.redis.set(keys.LB_ONION_ADDRESS, 'stale-onion');
  balancer.manager.torManager.stop = async () => { throw new Error('Tor cleanup failed'); };
  await balancer.manager.stop();
  assert.equal(balancer.counts.commandStop, 1);
  assert.equal(balancer.counts.haproxyStop, 1);
  assert.equal(balancer.counts.release, 1);
  assert.equal(balancer.redis.has(keys.LB_ONION_ADDRESS), false);
  assert.deepEqual(balancer.exits, [1]);
});
