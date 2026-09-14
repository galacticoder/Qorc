import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners, once } from 'node:events';
import { createServer as createHttpServer, get } from 'node:http';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test, { before, after } from 'node:test';
import { createServer } from 'vite';
import ts from 'typescript';
import { writeAnonymousResponse } from '../routes/anonymous-response-writer.js';
import * as anonymousHttpLayout from '../../shared/anonymous-http-layout.js';
import {
  ANONYMOUS_HEADER_TIMEOUT_MS,
  ANONYMOUS_IDLE_TIMEOUT_MS,
  ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
  DISCOVERY_LOOKUP_TIMEOUT_MS,
  anonymousBodyTimeoutMs,
  isAnonymousResponseTimestampValid,
} from '../../shared/anonymous-transfer-policy.js';

let loader;
let AnonymousRequestLane;
let runAnonymousRequestBatch;
let progressModule;
let AnonymousServerTrust;

before(async () => {
  loader = await createServer({
    configFile: false, root: process.cwd(), appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true, watch: { ignored: ['**/src-tauri/target/**', '**/node_modules/**', '**/dist/**'] } },
    optimizeDeps: { noDiscovery: true }, resolve: { alias: { '@': path.join(process.cwd(), 'src') } },
  });
  ({ AnonymousRequestLane, runAnonymousRequestBatch } = await loader.ssrLoadModule('/src/lib/transport/anonymous-request-lane.ts'));
  progressModule = await loader.ssrLoadModule('/src/lib/discovery/progress.ts');
  ({ AnonymousServerTrust } = await loader.ssrLoadModule('/src/lib/transport/anonymous-server-trust.ts'));
});
after(async () => { await loader?.close(); });

async function flush() {
  for (let index = 0; index < 12; index += 1) await Promise.resolve();
}

class SlowResponse extends EventEmitter {
  destroyed = false;
  writableFinished = false;
  bytes = 0;
  timeout = 0;
  callbacks = [];
  constructor(delay = 2000) { super(); this.delay = delay; }
  setTimeout(timeout) { this.timeout = timeout; return this; }
  write(chunk, callback) {
    this.callbacks.push(setTimeout(() => {
      this.bytes += chunk.length;
      callback();
    }, this.delay));
    return false;
  }
  end(callback) {
    this.writableFinished = true;
    this.emit('finish');
    callback();
  }
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    for (const timer of this.callbacks) clearTimeout(timer);
    this.emit('close');
  }
}

test('fixed discovery padding is unchanged and transfer budgets cover its actual size', () => {
  assert.equal(ANONYMOUS_DISCOVERY_RESPONSE_BYTES * 4, 34 * 1024 * 1024);
  assert.equal(anonymousBodyTimeoutMs(ANONYMOUS_DISCOVERY_RESPONSE_BYTES), 724_000);
  assert.equal(anonymousBodyTimeoutMs(64 * 1024), 300_000);
  assert.equal(anonymousBodyTimeoutMs(512 * 1024), 300_000);
  assert.ok(ANONYMOUS_HEADER_TIMEOUT_MS + anonymousBodyTimeoutMs(ANONYMOUS_DISCOVERY_RESPONSE_BYTES) < DISCOVERY_LOOKUP_TIMEOUT_MS);
  assert.throws(() => anonymousBodyTimeoutMs(ANONYMOUS_DISCOVERY_RESPONSE_BYTES + 1));
  assert.throws(() => anonymousBodyTimeoutMs(-1));
});

test('a progressing padded response completes after the former three-minute cutoff', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const response = new SlowResponse(500);
  const result = writeAnonymousResponse(response, Buffer.alloc(ANONYMOUS_DISCOVERY_RESPONSE_BYTES));
  for (let index = 0; index < ANONYMOUS_DISCOVERY_RESPONSE_BYTES / (16 * 1024); index += 1) {
    t.mock.timers.tick(500);
    await flush();
  }
  assert.equal(await result, true);
  assert.equal(response.bytes, ANONYMOUS_DISCOVERY_RESPONSE_BYTES);
  assert.equal(response.destroyed, false);
  assert.equal(response.timeout, ANONYMOUS_IDLE_TIMEOUT_MS);
  assert.equal(response.listenerCount('close'), 0);
  assert.equal(response.listenerCount('error'), 0);
});

test('partial TLS-sized writes count as progress before a full 64 KiB has drained', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const response = new SlowResponse();
  const write = response.write.bind(response);
  response.write = (chunk, callback) => {
    response.delay = chunk.length / (16 * 1024) * 20_000;
    return write(chunk, callback);
  };
  const result = writeAnonymousResponse(response, Buffer.alloc(64 * 1024), { idleTimeoutMs: 60_000 });
  for (let index = 0; index < 4; index += 1) {
    t.mock.timers.tick(20_000);
    await flush();
  }
  assert.equal(await result, true);
  assert.equal(response.bytes, 64 * 1024);
  assert.equal(response.destroyed, false);
  assert.equal(response.listenerCount('close'), 0);
});

test('an idle response fails promptly and reports partial byte counts', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const logs = [];
  t.mock.method(console, 'warn', (...args) => logs.push(args));
  const response = new SlowResponse(ANONYMOUS_IDLE_TIMEOUT_MS + 30_000);
  const result = writeAnonymousResponse(response, Buffer.alloc(ANONYMOUS_DISCOVERY_RESPONSE_BYTES));
  t.mock.timers.tick(ANONYMOUS_IDLE_TIMEOUT_MS);
  assert.equal(await result, false);
  assert.equal(response.destroyed, true);
  assert.equal(logs[0][1].reason, 'write-idle-timeout');
  assert.equal(logs[0][1].writtenBytes, 0);
  assert.equal(response.listenerCount('close'), 0);
});

test('a discovery response resumes after a Tor stall near the end of its body', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const response = new SlowResponse();
  const write = response.write.bind(response);
  response.write = (chunk, callback) => {
    response.delay = response.bytes === 8_192_000 ? 127_000 : 80;
    return write(chunk, callback);
  };
  const result = writeAnonymousResponse(response, Buffer.alloc(ANONYMOUS_DISCOVERY_RESPONSE_BYTES));
  for (let index = 0; index < ANONYMOUS_DISCOVERY_RESPONSE_BYTES / (16 * 1024); index += 1) {
    t.mock.timers.tick(response.delay);
    await flush();
  }
  assert.equal(await result, true);
  assert.equal(response.bytes, ANONYMOUS_DISCOVERY_RESPONSE_BYTES);
  assert.equal(response.destroyed, false);
});

test('a trickling peer cannot retain a response indefinitely', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const logs = [];
  t.mock.method(console, 'warn', (...args) => logs.push(args));
  const response = new SlowResponse(ANONYMOUS_IDLE_TIMEOUT_MS - 1000);
  const result = writeAnonymousResponse(response, Buffer.alloc(ANONYMOUS_DISCOVERY_RESPONSE_BYTES));
  for (let index = 0; index < 5; index += 1) {
    t.mock.timers.tick(ANONYMOUS_IDLE_TIMEOUT_MS - 1000);
    await flush();
  }
  assert.equal(await result, false);
  assert.equal(response.destroyed, true);
  assert.equal(logs[0][1].reason, 'transfer-deadline');
});

test('a closed response releases the writer without waiting for its deadline', async (t) => {
  t.mock.method(console, 'warn', () => {});
  const response = new SlowResponse(60_000);
  const result = writeAnonymousResponse(response, Buffer.alloc(64 * 1024));
  response.destroy();
  assert.equal(await result, false);
  assert.equal(response.listenerCount('close'), 0);
});

test('the actual HTTP writer delivers every padded byte without changing the body', async (t) => {
  const body = randomBytes(ANONYMOUS_DISCOVERY_RESPONSE_BYTES);
  let delivery;
  const server = createHttpServer((request, response) => {
    response.setHeader('Content-Length', String(body.length));
    response.setTimeout(120_000);
    delivery = writeAnonymousResponse(response, body);
    assert.equal(response.socket.timeout, ANONYMOUS_IDLE_TIMEOUT_MS);
  });
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const response = await new Promise((resolve, reject) => {
    get(`http://127.0.0.1:${server.address().port}/`, resolve).once('error', reject);
  });
  const chunks = [];
  for await (const chunk of response) chunks.push(chunk);
  assert.deepEqual(Buffer.concat(chunks), body);
  assert.equal(await delivery, true);
});

test('a real HTTP client disconnect cancels a partially written response', async (t) => {
  t.mock.method(console, 'warn', () => {});
  let completeDelivery;
  const delivery = new Promise((resolve) => { completeDelivery = resolve; });
  const server = createHttpServer((request, response) => {
    void writeAnonymousResponse(response, Buffer.alloc(ANONYMOUS_DISCOVERY_RESPONSE_BYTES)).then(completeDelivery);
  });
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const response = await new Promise((resolve, reject) => {
    get(`http://127.0.0.1:${server.address().port}/`, resolve).once('error', reject);
  });
  response.destroy();
  assert.equal(await delivery, false);
});

test('queued requests abort immediately without taking a later lane slot', async () => {
  const lane = new AnonymousRequestLane(1, 2, 5000);
  const release = await lane.acquire();
  const controller = new AbortController();
  const failure = assert.rejects(lane.acquire(controller.signal), { name: 'AbortError' });
  controller.abort();
  await failure;
  assert.equal(lane.waiters.length, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  release();
  assert.equal(lane.active, 0);
});

test('an abort racing a slot grant releases the reserved slot exactly once', async () => {
  const lane = new AnonymousRequestLane(1, 2, 5000);
  const release = await lane.acquire();
  const controller = new AbortController();
  const failure = assert.rejects(lane.acquire(controller.signal), { name: 'AbortError' });
  release();
  controller.abort();
  await failure;
  release();
  assert.equal(lane.active, 0);
});

function bulkTransportPolicy() {
  const file = 'src/lib/transport/pq-anonymous-http.ts';
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const names = new Set([
    'MAX_CONCURRENT_REQUESTS', 'MAX_QUEUED_REQUESTS', 'QUEUE_TIMEOUT_MS', 'OPERATION_POLICY',
    'primaryRequestLane', 'discoveryRequestLane', 'bulkRequestLane',
  ]);
  const declarations = ast.statements.filter((node) => (
    ts.isVariableStatement(node) && names.has(node.declarationList.declarations[0].name.getText(ast))
  )).map((node) => node.getText(ast));
  const policy = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name.text === 'isBulkTransportOperation');
  const code = ts.transpileModule([
    ...declarations, policy.getText(ast),
    'return { primaryRequestLane, discoveryRequestLane, bulkRequestLane, isBulkTransportOperation, OPERATION_POLICY };',
  ].join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const audiences = Object.fromEntries([
    'AVATAR_BLOB_GET', 'AVATAR_BLOB_PUT', 'AVATAR_POOL', 'DISCOVERY_BUCKET', 'DISCOVERY_MANIFEST',
    'KEY_TRANSPARENCY_APPEND', 'KEY_TRANSPARENCY_SYNC', 'OPRF_EVALUATE', 'SPOOL_PIR', 'SPOOL_TAG_INDEX',
  ].map((name) => [`${name}_AUDIENCE`, name]));
  const dependencies = {
    ...anonymousHttpLayout,
    ...audiences, AnonymousRequestLane, DISCOVERY_LOOKUP_TIMEOUT_MS,
    ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
    KEY_TRANSPARENCY_SYNC_RESPONSE_BYTES: 2 * 1024 * 1024,
    KEY_TRANSPARENCY_SYNC_RESPONSE_CLASS: 7,
  };
  return new Function(...Object.keys(dependencies), code)(...Object.values(dependencies));
}

test('bulk discovery never uses the interactive Tor lane or takes the last bulk slot', async () => {
  const policy = bulkTransportPolicy();
  const { primaryRequestLane: primary, discoveryRequestLane: discovery, bulkRequestLane: bulk } = policy;
  assert.equal(policy.isBulkTransportOperation('DISCOVERY_BUCKET'), true);
  assert.equal(policy.isBulkTransportOperation('SPOOL_PIR'), true);
  assert.equal(policy.isBulkTransportOperation('KEY_TRANSPARENCY_SYNC'), true);
  assert.equal(policy.isBulkTransportOperation('OPRF_EVALUATE'), false);
  assert.equal(policy.isBulkTransportOperation('DISCOVERY_MANIFEST'), false);
  assert.equal(policy.OPERATION_POLICY.DISCOVERY_BUCKET.responseBytes, ANONYMOUS_DISCOVERY_RESPONSE_BYTES);
  const releases = [];
  for (let index = 0; index < 2; index += 1) releases.push(await discovery.acquire(), await bulk.acquire());
  assert.equal(primary.active, 0);
  const releasePir = await bulk.acquire();
  const releaseControl = await primary.acquire();
  assert.equal(bulk.active, 3);
  assert.equal(primary.active, 1);
  releaseControl();
  releasePir();
  for (const release of releases) release();
  assert.equal(primary.active, 0);
  assert.equal(bulk.active, 0);
  assert.equal(discovery.active, 0);
});

test('one failed bucket cancels and drains its siblings before returning', async () => {
  let cancelled = 0;
  const pending = (signal) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => { cancelled += 1; reject(new Error('cancelled')); }, { once: true });
  });
  await assert.rejects(runAnonymousRequestBatch([
    async () => { throw new Error('body read failed'); }, pending, pending, pending,
  ]), { message: 'body read failed' });
  assert.equal(cancelled, 3);
});

test('a cancelled lookup starts no bucket requests', async () => {
  let sent = 0;
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runAnonymousRequestBatch([async () => { sent += 1; }], controller.signal), { name: 'AbortError' });
  assert.equal(sent, 0);
});

test('authenticated response timestamps are bounded by the actual request lifetime', () => {
  const start = 1_770_000_000_000;
  const end = start + 7 * 60_000;
  assert.equal(isAnonymousResponseTimestampValid(start + 5000, start, end, 300_000), true);
  assert.equal(isAnonymousResponseTimestampValid(start - 300_001, start, end, 300_000), false);
  assert.equal(isAnonymousResponseTimestampValid(end + 300_001, start, end, 300_000), false);
  assert.equal(isAnonymousResponseTimestampValid(start, start, null, 300_000), false);
  assert.equal(isAnonymousResponseTimestampValid(start, start, start + DISCOVERY_LOOKUP_TIMEOUT_MS + 1, 300_000), false);
});

test('aborting the client binding invokes native cancellation with the same request id', async () => {
  const source = fs.readFileSync('src/lib/tauri-bindings.ts', 'utf8');
  const ast = ts.createSourceFile('bindings.ts', source, ts.ScriptTarget.Latest, true);
  let initializer;
  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'anonymousHttp') initializer = node.initializer.getText(ast);
    ts.forEachChild(node, visit);
  }
  visit(ast);
  const compiled = ts.transpileModule(`const binding = ${initializer};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  let sentId;
  let rejectFetch;
  let cancelledId;
  const invoke = (command, args, options) => {
    if (command === 'anonymous_api_fetch') {
      sentId = options.headers['x-qorc-anonymous-request-id'];
      assert.equal(options.headers['x-qorc-anonymous-response-bytes'], String(ANONYMOUS_DISCOVERY_RESPONSE_BYTES));
      return new Promise((_, reject) => { rejectFetch = reject; });
    }
    assert.equal(command, 'cancel_anonymous_api_fetch');
    cancelledId = args.requestId;
    rejectFetch(new Error('anonymous request cancelled'));
    return Promise.resolve();
  };
  const binding = new Function('invoke', 'PROTOCOL_KEYS', `${compiled}; return binding;`)(invoke, { EXPECTED_SERVER_HEADER: 'expected-server' });
  const controller = new AbortController();
  const failure = assert.rejects(binding.fetch(new Uint8Array(64 * 1024), 'wss://example.test', {
    responseBytes: ANONYMOUS_DISCOVERY_RESPONSE_BYTES, signal: controller.signal,
  }), { message: 'anonymous request cancelled' });
  controller.abort();
  await failure;
  assert.equal(cancelledId, sentId);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('discovery progress counts bytes across all four buckets, then switches to verification', () => {
  const values = [];
  const update = progressModule.createBucketProgress(4, 100, (value) => values.push(value));
  assert.equal(values.at(-1).phase, 'preparing');
  update(0, 100);
  assert.deepEqual(values.at(-1), { phase: 'downloading', receivedBytes: 100, totalBytes: 400 });
  update(1, 40);
  update(2, 20);
  assert.equal(values.at(-1).receivedBytes, 160);
  const count = values.length;
  for (const [index, bytes] of [[-1, 10], [4, 50], [2, 19], [2, NaN], [2, 101]]) update(index, bytes);
  assert.equal(values.length, count);
  update(3, 100);
  update(2, 100);
  update(1, 100);
  assert.deepEqual(values.at(-1), { phase: 'verifying', receivedBytes: 400, totalBytes: 400 });
});

test('joining a running lookup receives its current progress and detaches on completion', async () => {
  const { DiscoveryProgressStream, trackDiscoveryProgress, observeDiscoveryProgress } = progressModule;
  const stream = new DiscoveryProgressStream();
  let complete;
  const operation = new Promise((resolve) => { complete = resolve; });
  trackDiscoveryProgress(operation, stream);
  const first = [];
  const firstResult = observeDiscoveryProgress(operation, (value) => first.push(value));
  stream.report({ phase: 'downloading', receivedBytes: 25, totalBytes: 100 });
  const second = [];
  const secondResult = observeDiscoveryProgress(operation, (value) => second.push(value));
  assert.equal(second[0].receivedBytes, 25);
  complete('found');
  assert.deepEqual(await Promise.all([firstResult, secondResult]), ['found', 'found']);
  stream.report({ phase: 'downloading', receivedBytes: 80, totalBytes: 100 });
  assert.equal(first.at(-1).receivedBytes, 25);
  assert.equal(second.at(-1).receivedBytes, 25);
});

test('failed discovery progress observers detach without leaking into another lookup', async () => {
  const { DiscoveryProgressStream, trackDiscoveryProgress, observeDiscoveryProgress } = progressModule;
  const first = new DiscoveryProgressStream();
  const second = new DiscoveryProgressStream();
  const values = [];
  const operation = Promise.reject(new Error('failed'));
  trackDiscoveryProgress(operation, first);
  await assert.rejects(observeDiscoveryProgress(operation, (value) => values.push(value)), /failed/);
  first.report({ phase: 'downloading', receivedBytes: 40, totalBytes: 100 });
  second.report({ phase: 'verifying', receivedBytes: 100, totalBytes: 100 });
  assert.equal(values.length, 1);
});

test('native progress stays request-local, validates byte bounds, and ignores late events', async () => {
  const source = fs.readFileSync('src/lib/tauri-bindings.ts', 'utf8');
  const ast = ts.createSourceFile('bindings.ts', source, ts.ScriptTarget.Latest, true);
  let initializer;
  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'anonymousHttp') initializer = node.initializer.getText(ast);
    ts.forEachChild(node, visit);
  }
  visit(ast);
  const compiled = ts.transpileModule(`const binding = ${initializer};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const channels = [];
  class Channel {
    constructor(onmessage) { this.onmessage = onmessage; this.id = channels.length; channels.push(this); }
    serialize() { return `__CHANNEL__:${this.id}`; }
  }
  const completed = [];
  const invoke = (command, body, options) => {
    assert.equal(command, 'anonymous_api_fetch');
    assert.equal(options.headers['x-qorc-anonymous-progress'], `__CHANNEL__:${completed.length}`);
    return new Promise((resolve) => completed.push(resolve));
  };
  const binding = new Function('invoke', 'PROTOCOL_KEYS', 'Channel', 'SERIALIZE_TO_IPC_FN', `${compiled}; return binding;`)(
    invoke, { EXPECTED_SERVER_HEADER: 'expected-server' }, Channel, 'serialize',
  );
  const values = [[], []];
  const requests = values.map((list) => binding.fetch(new Uint8Array(64 * 1024), 'wss://example.test', {
    responseBytes: ANONYMOUS_DISCOVERY_RESPONSE_BYTES, onProgress: (bytes) => list.push(bytes),
  }));
  const send = (index, receivedBytes, totalBytes = ANONYMOUS_DISCOVERY_RESPONSE_BYTES) => channels[index].onmessage({ receivedBytes, totalBytes });
  send(0, 100);
  send(1, 200);
  send(0, 99);
  send(0, NaN);
  send(0, ANONYMOUS_DISCOVERY_RESPONSE_BYTES + 1);
  send(0, 500, 10);
  assert.deepEqual(values, [[100], [200]]);
  completed.forEach((resolve) => resolve(new ArrayBuffer(0)));
  await Promise.all(requests);
  send(0, 800);
  assert.deepEqual(values[0], [100]);
});

function loadFunction(file, name, dependencies) {
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const node = ast.statements.find((entry) => ts.isFunctionDeclaration(entry) && entry.name?.text === name);
  assert.ok(node, `${name} must exist`);
  const compiled = ts.transpileModule(node.getText(ast).replace(/^export /, ''), {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  return new Function(...Object.keys(dependencies), `${compiled}; return ${name};`)(...Object.values(dependencies));
}

function trustFixture(t) {
  let elapsed = 0;
  const trust = new AnonymousServerTrust(() => elapsed);
  const material = {
    fingerprint: 'a'.repeat(64),
    kyberPublicKey: new Uint8Array([1, 2]),
    dilithiumPublicKey: new Uint8Array([3, 4]),
    x25519PublicKey: new Uint8Array([5, 6]),
  };
  trust.authenticate(material, 1_800_000_000_000);
  t.after(() => trust.invalidate());
  return { trust, material, advance: (ms) => { elapsed += ms; } };
}

test('anonymous server identity and response clock survive a same-server reconnect', (t) => {
  const f = trustFixture(t);
  const request = f.trust.capture();
  const requestedAt = request.now();
  f.advance(350_000);
  assert.equal(request.signal.aborted, false);
  assert.equal(request.now(), requestedAt + 350_000);
  f.trust.authenticate(f.material, requestedAt + 355_000);
  assert.equal(f.trust.identity(), request.signal);
  assert.equal(request.now(), requestedAt + 350_000);
  assert.deepEqual(request.material.kyberPublicKey, new Uint8Array([1, 2]));
});

test('anonymous time advances monotonically even if the wall clock changes', (t) => {
  const f = trustFixture(t);
  const request = f.trust.capture();
  const start = request.now();
  t.mock.method(Date, 'now', () => 0);
  f.advance(5000);
  assert.equal(request.now(), start + 5000);
  assert.equal(f.trust.now(), start + 5000);
});

test('anonymous trust expires without a live authenticated connection', (t) => {
  const f = trustFixture(t);
  const request = f.trust.capture();
  f.advance(DISCOVERY_LOOKUP_TIMEOUT_MS);
  assert.equal(f.trust.capture(), null);
  assert.equal(request.signal.aborted, true);
  f.trust.authenticate(f.material, request.now());
  assert.notEqual(f.trust.identity(), request.signal);
  assert.equal(request.signal.aborted, true);
});

test('expired trust actively aborts requests without another caller polling it', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = trustFixture(t);
  const identity = f.trust.identity();
  t.mock.timers.tick(DISCOVERY_LOOKUP_TIMEOUT_MS);
  assert.equal(identity.aborted, true);
  assert.equal(f.trust.capture(), null);
});

test('server-key replacement and explicit privacy boundaries revoke old requests permanently', (t) => {
  const f = trustFixture(t);
  const first = f.trust.capture();
  f.trust.authenticate({ ...f.material, fingerprint: 'b'.repeat(64) }, first.now());
  assert.equal(first.signal.aborted, true);
  const second = f.trust.capture();
  f.trust.invalidate();
  assert.equal(second.signal.aborted, true);
  assert.equal(f.trust.capture(), null);
  f.trust.authenticate(f.material, first.now());
  assert.notEqual(f.trust.identity(), first.signal);
  assert.notEqual(f.trust.identity(), second.signal);
});

function requestFixture(t) {
  const f = trustFixture(t);
  const primary = new AnonymousRequestLane(1, 4, 5000);
  let serverContext = { serverUrl: 'wss://test.onion', serverScope: 'a'.repeat(64) };
  let captured;
  const executions = [];
  const fetch = loadFunction('src/lib/transport/pq-anonymous-http.ts', 'anonymousHttpFetch', {
    websocketClient: { captureAnonymousHttpContext: () => (captured = f.trust.capture()) },
    DISCOVERY_LOOKUP_TIMEOUT_MS,
    DISCOVERY_BUCKET_AUDIENCE: 'bucket',
    discoveryRequestLane: new AnonymousRequestLane(4, 4, 5000),
    primaryRequestLane: primary,
    bulkRequestLane: primary,
    isBulkTransportOperation: () => false,
    captureCurrentServerContext: async () => ({ ...serverContext }),
    assertCurrentServerContext: async (context) => {
      assert.deepEqual(context, serverContext, 'server identity must remain unchanged');
    },
    executeAnonymousHttpRequest: (_operation, _body, _context, authentication, signal) => new Promise((resolve, reject) => {
      const abort = () => reject(new DOMException('cancelled', 'AbortError'));
      signal.addEventListener('abort', abort, { once: true });
      executions.push({ authentication, signal, complete() { signal.removeEventListener('abort', abort); resolve('verified'); } });
    }),
  });
  return { ...f, fetch, primary, executions, context: () => serverContext, captured: () => captured,
    changeServer: () => { serverContext = { ...serverContext, serverScope: 'b'.repeat(64) }; } };
}

test('in-flight anonymous HTTP requests complete through a same-server reconnect', async (t) => {
  const f = requestFixture(t);
  const operation = f.fetch('bucket', {}, f.context().serverUrl);
  await flush();
  assert.equal(f.executions.length, 1);
  const identity = f.executions[0].authentication.signal;
  f.advance(350_000);
  f.trust.authenticate(f.material, f.trust.now());
  assert.equal(f.executions[0].signal.aborted, false);
  f.executions[0].complete();
  assert.equal(await operation, 'verified');
  assert.equal(f.primary.active, 0);
  assert.equal(getEventListeners(identity, 'abort').length, 0);
  assert.ok(f.captured().material.kyberPublicKey.every((byte) => byte === 0));
});

test('logout cancels in-flight anonymous requests and releases their lane', async (t) => {
  const f = requestFixture(t);
  const operation = f.fetch('bucket', {}, f.context().serverUrl);
  const failed = assert.rejects(operation, { name: 'AbortError' });
  await flush();
  f.trust.invalidate();
  await failed;
  assert.equal(f.executions[0].signal.aborted, true);
  assert.equal(f.primary.active, 0);
});

test('a privacy boundary cancels queued anonymous requests before they can send', async (t) => {
  const f = requestFixture(t);
  const release = await f.primary.acquire();
  const failed = assert.rejects(f.fetch('bucket', {}, f.context().serverUrl), { name: 'AbortError' });
  await flush();
  f.trust.invalidate();
  await failed;
  release();
  assert.equal(f.executions.length, 0);
  assert.equal(f.primary.active, 0);
  assert.equal(f.primary.waiters.length, 0);
});

test('changing the pinned server while queued prevents sending to a new identity', async (t) => {
  const f = requestFixture(t);
  const release = await f.primary.acquire();
  const failed = assert.rejects(f.fetch('bucket', {}, f.context().serverUrl), /server identity/);
  await flush();
  f.changeServer();
  release();
  await failed;
  assert.equal(f.executions.length, 0);
  assert.equal(f.primary.active, 0);
});

test('caller cancellation also cancels an anonymous request after reconnect', async (t) => {
  const f = requestFixture(t);
  const controller = new AbortController();
  const failed = assert.rejects(f.fetch('bucket', {}, f.context().serverUrl, { signal: controller.signal }), { name: 'AbortError' });
  await flush();
  f.trust.authenticate(f.material, f.trust.now());
  controller.abort();
  await failed;
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  assert.equal(f.primary.active, 0);
});

test('the 512 KiB response continues progressing beyond the former 92-second deadline', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const response = new SlowResponse(7_000);
  const result = writeAnonymousResponse(response, Buffer.alloc(512 * 1024));
  for (let index = 0; index < 32; index += 1) {
    t.mock.timers.tick(7_000);
    await flush();
  }
  assert.equal(await result, true);
  assert.equal(response.bytes, 512 * 1024);
  assert.equal(response.destroyed, false);
});

test('an already destroyed response is not written or reported as another delivery failure', async (t) => {
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args));
  const response = new SlowResponse();
  response.destroy();
  assert.equal(await writeAnonymousResponse(response, Buffer.alloc(64 * 1024)), false);
  assert.equal(response.callbacks.length, 0);
  assert.equal(warnings.length, 0);
});

test('aborted HTTP uploads do not allocate an opaque error or attempt a reply', async () => {
  const logs = [];
  let sent = 0;
  const handler = loadFunction('server/routes/pq-anonymous-http.js', 'handlePqAnonymousHttpParseError', {
    REQUEST_BODY_PARSE_TYPES: new Set(['entity.parse.failed']),
    logAnonymousRejection: (reason) => logs.push(reason),
    sendOpaqueFailure: async () => { sent += 1; },
  });
  for (const [error, request, response] of [
    [{ type: 'request.aborted' }, {}, {}],
    [{}, { aborted: true }, {}],
    [{}, {}, { destroyed: true }],
  ]) {
    let destroyed = false;
    await handler(error, request, { ...response, destroy() { destroyed = true; } });
    assert.equal(destroyed, true);
  }
  assert.equal(sent, 0);
  assert.equal(logs.length, 0);
  await handler({ type: 'entity.parse.failed' }, {}, {});
  assert.equal(sent, 1);
  assert.deepEqual(logs, ['request-body-parse:entity.parse.failed']);
});

test('the actual discovery lookup retains its three completed buckets across a socket reset', async (t) => {
  const f = trustFixture(t);
  const owner = new AbortController();
  const source = fs.readFileSync('src/hooks/discovery/useDiscovery.ts', 'utf8');
  const ast = ts.createSourceFile('useDiscovery.ts', source, ts.ScriptTarget.Latest, true);
  let callback;
  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'findUser') {
      callback = node.initializer.arguments[0].getText(ast);
    }
    ts.forEachChild(node, visit);
  }
  visit(ast);
  assert.ok(callback);
  const events = new EventTarget();
  let connected = true;
  let finishBuckets;
  let downloadSignal;
  let reportBytes;
  let requestedBatches = 0;
  let verified = 0;
  const dependencies = {
    ownerScope: 'owner',
    ownerAbortControllerRef: { current: owner },
    activeOwnerScopeRef: { current: 'owner' },
    effectiveHandle: 'self',
    websocketClient: {
      captureAnonymousHttpIdentity: () => f.trust.identity(),
      isAnonymousHttpIdentityCurrent: (identity) => identity !== null && !identity.aborted && identity === f.trust.identity(),
    },
    shouldAttemptDiscovery: () => true,
    getDiscoveryHandle: (handle) => handle,
    isDiscoveryTransportReady: () => connected,
    waitForOprfState: async () => ({ publicKey: 'a'.repeat(64), epoch: 1 }),
    scopedDiscoveryCacheKey: (...parts) => parts.join(':'),
    discoveryResultCache: new Map(),
    findUserCache: new Map(),
    findUserInFlightLock: new Map(),
    forceRefreshFindUserCache: new Map(),
    discoveryNetworkFetchAt: new Map(),
    FORCED_REFETCH_MIN_INTERVAL_MS: 1000,
    DISCOVERY_LOOKUP_MAX_IN_FLIGHT: 2,
    DISCOVERY_TIMEOUT_CACHE_TTL_MS: 1000,
    DISCOVERY_LOOKUP_TIMEOUT_MS,
    ...progressModule,
    getDiscoveryTokensForEpochs: async () => new Map([[1, { token: 'a'.repeat(64), encryptionKey: new Uint8Array(32) }]]),
    findDiscoveryBlobsInBuckets: async (_tokens, signal, report) => {
      requestedBatches += 1;
      downloadSignal = signal;
      reportBytes = progressModule.createBucketProgress(4, 100, report);
      reportBytes(0, 100);
      reportBytes(1, 100);
      reportBytes(2, 100);
      return new Promise((resolve) => { finishBuckets = resolve; });
    },
    finalizeDiscoverySnapshotResult: async (_cache, _target, _blobs, _keys, _negative, monitor, current) => {
      assert.equal(current(), true);
      assert.equal(monitor, true);
      verified += 1;
      return { found: true };
    },
    noteDiscoveryNetworkFetch: () => {},
    window: events,
  };
  const compiled = ts.transpileModule(`const lookup = ${callback};`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const lookup = new Function(...Object.keys(dependencies), `${compiled}; return lookup;`)(...Object.values(dependencies));
  const progress = [];
  const request = lookup('peer', { forceRefresh: true, onProgress: (value) => progress.push(value) });
  await flush();
  assert.equal(progress.at(-1).receivedBytes, 300);
  connected = false;
  events.dispatchEvent(new Event('__ws_connection_error'));
  assert.equal(downloadSignal.aborted, false);
  f.advance(350_000);
  assert.equal(progress.at(-1).receivedBytes, 300);
  reportBytes(3, 100);
  finishBuckets({ blobs: ['encrypted'], context: {} });
  assert.deepEqual(await request, { found: true });
  assert.equal(verified, 1);
  assert.equal(requestedBatches, 1);
  assert.equal(progress.at(-1).receivedBytes, 400);
  assert.equal(getEventListeners(f.trust.identity(), 'abort').length, 0);
  assert.equal(getEventListeners(owner.signal, 'abort').length, 0);
});

test('an anonymous trust snapshot must match every currently pinned server key before sending', async () => {
  const encode = (bytes) => Buffer.from(bytes).toString('base64');
  const material = {
    kyberPublicKey: new Uint8Array([1]),
    dilithiumPublicKey: new Uint8Array([2]),
    x25519PublicKey: new Uint8Array([3]),
  };
  let pins = {
    kyberPublicBase64: encode(material.kyberPublicKey),
    dilithiumPublicBase64: encode(material.dilithiumPublicKey),
    x25519PublicBase64: encode(material.x25519PublicKey),
  };
  const capture = loadFunction('src/lib/security/local-account-scope.ts', 'captureCurrentServerContext', {
    websocket: { getServerUrl: async () => 'wss://test.onion' },
    PinnedServer: { load: async () => pins },
    validateServerUrl: (url) => url,
    Base64: { arrayBufferToBase64: encode },
    digestScope: () => 'a'.repeat(64),
    STORAGE_KEY_DOMAINS: { LOCAL_SERVER_SCOPE: 'scope' },
  });
  assert.equal((await capture(material)).serverUrl, 'wss://test.onion');
  for (const field of Object.keys(pins)) {
    const previous = pins;
    pins = { ...pins, [field]: encode(new Uint8Array([4])) };
    await assert.rejects(capture(material), /no longer matches its pin/);
    pins = previous;
  }
});
