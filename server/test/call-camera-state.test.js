import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import ts from 'typescript';

const source = fs.readFileSync(new URL('../../src/lib/transport/call-telemetry.ts', import.meta.url), 'utf8');
const ast = ts.createSourceFile('call-telemetry.ts', source, ts.ScriptTarget.ES2022, true);
const body = ast.statements.filter(node => !ts.isImportDeclaration(node)).map(node => node.getText(ast)).join('\n');
const compiled = ts.transpileModule(body, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const telemetry = {};
new Function('exports', 'PostQuantumRandom', compiled)(telemetry, { randomBytes: size => new Uint8Array(randomBytes(size)) });

class LinkedStream {
  closed = false;
  queue = [];
  waiters = [];
  writes = [];
  dropCameraState = false;

  async write(frame) {
    if (this.closed) throw new Error('closed');
    this.writes.push(frame.slice());
    if (this.dropCameraState && telemetry.decodeCallTelemetryProbe(frame).type === 'camera-state') return;
    const copy = frame.slice();
    const resolve = this.peer.waiters.shift();
    if (resolve) resolve(copy);
    else this.peer.queue.push(copy);
  }

  async *[Symbol.asyncIterator]() {
    while (!this.closed) {
      const frame = this.queue.length ? this.queue.shift() : await new Promise(resolve => this.waiters.push(resolve));
      if (!frame) return;
      yield frame;
    }
  }

  close() {
    this.closed = true;
    for (const resolve of this.waiters.splice(0)) resolve(null);
  }
}

async function flush() {
  for (let count = 0; count < 50; count++) await Promise.resolve();
}

function pair(context, type = 'video') {
  const firstStream = new LinkedStream();
  const secondStream = new LinkedStream();
  firstStream.peer = secondStream;
  secondStream.peer = firstStream;
  const first = { enabled: true, received: [] };
  const second = { enabled: false, received: [] };
  for (const [state, stream, direction] of [[first, firstStream, 'outgoing'], [second, secondStream, 'incoming']]) {
    state.telemetry = new telemetry.CallTelemetry(
      '00112233445566778899aabbccddeeff', direction, type,
      { updatePrimaryPathRtt() {} }, stream, () => {},
      enabled => state.received.push(enabled), () => state.enabled,
    );
    state.telemetry.emit = () => {};
  }
  context.after(() => {
    first.telemetry.stop();
    second.telemetry.stop();
    firstStream.close();
    secondStream.close();
  });
  return { first, second, firstStream, secondStream };
}

test('camera state has an exact two-byte authenticated call-control payload', () => {
  for (const enabled of [false, true]) {
    const state = { type: 'camera-state', enabled };
    const frame = telemetry.encodeCallTelemetryProbe(state);
    assert.deepEqual(frame, Uint8Array.of(4, enabled ? 1 : 0));
    assert.deepEqual(telemetry.decodeCallTelemetryProbe(frame), state);
  }
  for (const frame of [Uint8Array.of(4), Uint8Array.of(4, 2), Uint8Array.of(4, 1, 0)]) {
    assert.throws(() => telemetry.decodeCallTelemetryProbe(frame), /Invalid call camera state/);
  }
  assert.throws(() => telemetry.encodeCallTelemetryProbe({ type: 'camera-state', enabled: 'true' }), /Invalid call camera state/);
});

test('connecting exchanges camera-on and camera-less states on the existing P2P stream', async context => {
  const { first, second } = pair(context);
  first.telemetry.start();
  second.telemetry.start();
  await flush();
  assert.deepEqual(first.received, [false]);
  assert.deepEqual(second.received, [true]);
  first.enabled = false;
  await first.telemetry.sendCameraState();
  await flush();
  assert.deepEqual(second.received, [true, false]);
  first.enabled = true;
  await first.telemetry.sendCameraState();
  await flush();
  assert.deepEqual(second.received, [true, false, true]);
});

test('periodic call control restores the current camera state after a dropped update', async context => {
  context.mock.timers.enable({ apis: ['setInterval'] });
  const { first, second, firstStream } = pair(context);
  first.telemetry.start();
  second.telemetry.start();
  await flush();
  firstStream.dropCameraState = true;
  first.enabled = false;
  await first.telemetry.sendCameraState();
  await flush();
  assert.deepEqual(second.received, [true]);
  firstStream.dropCameraState = false;
  context.mock.timers.tick(2000);
  await flush();
  assert.deepEqual(second.received, [true, false]);
});

test('audio calls never send or accept camera state and stopped calls cannot update peers', async context => {
  const audio = pair(context, 'audio');
  audio.first.telemetry.start();
  audio.second.telemetry.start();
  await audio.first.telemetry.sendCameraState();
  await audio.firstStream.write(telemetry.encodeCallTelemetryProbe({ type: 'camera-state', enabled: true }));
  await flush();
  assert.deepEqual(audio.second.received, []);
  assert.equal(audio.second.telemetry.protocolErrors, 1);
  assert.equal(audio.firstStream.writes.filter(frame => telemetry.decodeCallTelemetryProbe(frame).type === 'camera-state').length, 1);
  const video = pair(context);
  video.first.telemetry.stop();
  await video.first.telemetry.sendCameraState();
  assert.equal(video.firstStream.writes.length, 0);
  video.second.telemetry.stop();
  await video.firstStream.write(telemetry.encodeCallTelemetryProbe({ type: 'camera-state', enabled: true }));
  await flush();
  assert.deepEqual(video.second.received, []);
});
