import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { downloadRuntimePackage } = require('../../scripts/download-runtime-package.cjs');

function fixture(t, responses, validate = file => fs.readFileSync(file, 'utf8') === 'verified package') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-package-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const destination = path.join(root, 'runtime.deb');
  const requests = [];
  const waits = [];
  const messages = [];
  const run = () => downloadRuntimePackage({ url: 'https://packages.example/runtime.deb', destination, validate }, {
    async fetch(url, options) {
      requests.push({ url, options });
      const response = responses[requests.length - 1];
      if (response instanceof Error) throw response;
      return response;
    },
    async wait(ms) { waits.push(ms); },
    log(message) { messages.push(message); }
  });
  return { root, destination, requests, waits, messages, run };
}

function socketError() {
  const cause = Object.assign(new Error('other side closed'), { code: 'UND_ERR_SOCKET' });
  return new TypeError('fetch failed', { cause });
}

test('verified downloads are atomically published without leftover partial files', async t => {
  const setup = fixture(t, [new Response('verified package')]);
  await setup.run();
  assert.equal(fs.readFileSync(setup.destination, 'utf8'), 'verified package');
  assert.deepEqual(fs.readdirSync(setup.root), ['runtime.deb']);
  assert.equal(setup.requests.length, 1);
  assert.ok(setup.requests[0].options.signal.aborted);
});

test('a transient fetch failure retries the same URL and reports its cause', async t => {
  const setup = fixture(t, [socketError(), new Response('verified package')]);
  await setup.run();
  assert.deepEqual(setup.waits, [1000]);
  assert.equal(setup.requests[0].url, setup.requests[1].url);
  assert.notEqual(setup.requests[0].options.signal, setup.requests[1].options.signal);
  assert.match(setup.messages[0], /UND_ERR_SOCKET: other side closed/);
  assert.equal(fs.readFileSync(setup.destination, 'utf8'), 'verified package');
});

test('transient HTTP errors retry with bounded backoff', async t => {
  const setup = fixture(t, [new Response('', { status: 503 }), new Response('', { status: 429 }), new Response('verified package')]);
  await setup.run();
  assert.deepEqual(setup.waits, [1000, 2000]);
  assert.equal(setup.requests.length, 3);
});

test('repeated transport failures stop after three attempts', async t => {
  const setup = fixture(t, [socketError(), socketError(), socketError()]);
  await assert.rejects(setup.run(), /https:\/\/packages.example\/runtime.deb after 3 attempt\(s\).*UND_ERR_SOCKET/);
  assert.equal(setup.requests.length, 3);
  assert.deepEqual(setup.waits, [1000, 2000]);
  assert.deepEqual(fs.readdirSync(setup.root), []);
});

test('a broken response stream is discarded before downloading again', async t => {
  let pull = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (pull++ === 0) controller.enqueue(new TextEncoder().encode('partial'));
      else controller.error(socketError());
    }
  });
  const setup = fixture(t, [new Response(stream), new Response('verified package')]);
  await setup.run();
  assert.equal(setup.requests.length, 2);
  assert.equal(fs.readFileSync(setup.destination, 'utf8'), 'verified package');
  assert.deepEqual(fs.readdirSync(setup.root), ['runtime.deb']);
});

test('checksum or package metadata failures are not retried or published', async t => {
  const setup = fixture(t, [new Response('tampered package')]);
  fs.writeFileSync(setup.destination, 'existing package');
  await assert.rejects(setup.run(), /checksum or metadata validation/);
  assert.equal(setup.requests.length, 1);
  assert.deepEqual(setup.waits, []);
  assert.equal(fs.readFileSync(setup.destination, 'utf8'), 'existing package');
  assert.deepEqual(fs.readdirSync(setup.root), ['runtime.deb']);
});

test('missing packages fail immediately with the URL and HTTP status', async t => {
  const setup = fixture(t, [new Response('', { status: 404 })]);
  await assert.rejects(setup.run(), /runtime.deb after 1 attempt\(s\): HTTP 404/);
  assert.equal(setup.requests.length, 1);
  assert.deepEqual(fs.readdirSync(setup.root), []);
});

test('certificate failures are not retried or hidden', async t => {
  const error = new TypeError('fetch failed', { cause: Object.assign(new Error('certificate expired'), { code: 'CERT_HAS_EXPIRED' }) });
  const setup = fixture(t, [error]);
  await assert.rejects(setup.run(), /CERT_HAS_EXPIRED: certificate expired/);
  assert.equal(setup.requests.length, 1);
  assert.deepEqual(setup.waits, []);
});

test('download timeouts are retried with a new abort signal', async t => {
  const setup = fixture(t, [new DOMException('timed out', 'TimeoutError'), new Response('verified package')]);
  await setup.run();
  assert.equal(setup.requests.length, 2);
  assert.notEqual(setup.requests[0].options.signal, setup.requests[1].options.signal);
});

test('aggregate network errors include the connection diagnostics', async t => {
  const error = new TypeError('fetch failed', { cause: new AggregateError([
    Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }),
    Object.assign(new Error('network unreachable'), { code: 'ENETUNREACH' })
  ]) });
  const setup = fixture(t, [error, new Response('verified package')]);
  await setup.run();
  assert.match(setup.messages[0], /ECONNRESET: connection reset/);
  assert.match(setup.messages[0], /ENETUNREACH: network unreachable/);
});

test('unexpected errors fail without an alternate download path', async t => {
  const setup = fixture(t, [new Error('unexpected failure')]);
  await assert.rejects(setup.run(), /unexpected failure/);
  assert.equal(setup.requests.length, 1);
});
