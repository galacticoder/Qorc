import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';
import { handlePQBinaryCell, sendPQEncryptedResponse } from '../messaging/pq-envelope-handler.js';

function loadSource(file, dependencies = {}) {
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const body = ast.statements.filter((node) => !ts.isImportDeclaration(node)).map((node) => node.getText(ast)).join('\n');
  return compile(body, dependencies);
}

function compile(body, dependencies) {
  const compiled = ts.transpileModule(body, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
  return exports;
}

const isPlainObject = (value) => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const hasPrototypePollutionKeys = (value) => ['__proto__', 'prototype', 'constructor'].some((key) => Object.hasOwn(value, key));
const hasExactKeys = (value, keys) => Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const { SignalType } = loadSource('src/lib/types/signal-types.ts');
const { WebSocketMessageHandler } = loadSource('src/lib/websocket/message-handler.ts', { isPlainObject, hasPrototypePollutionKeys });

function loadConnection(dependencies) {
  const file = 'src/lib/websocket/websocket.ts';
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const declaration = ast.statements.find((node) => ts.isClassDeclaration(node) && node.name.text === 'WebSocketConnection');
  const names = new Set([
    'sendCoverTraffic', 'stopCoverTraffic', 'registerConnectionWaiterCancel', 'cancelConnectionWaiters',
    'replaceConsumedAccountAuthorizationToken', 'issueAccountAuthorizationReplacement',
  ]);
  const members = declaration.members.filter((node) => names.has(node.name?.getText(ast)));
  assert.equal(members.length, names.size);
  return compile(`export class Connection { ${members.map((node) => node.getText(ast)).join('\n')} }`, dependencies).Connection;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

async function flush() {
  for (let index = 0; index < 64; index += 1) await Promise.resolve();
}

function fixture(t, options = {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const calls = { cover: [], refresh: [], finalized: 0, replenished: 0, warnings: [] };
  const Connection = loadConnection({
    SignalType,
    websocket: { getState: async () => ({ queue_size: 0 }) },
    getBlindRoutingClient: () => ({ createCoverSealedEnvelope: () => ({ ciphertext: 'synthetic-cover' }) }),
    isPlainObject,
    hasPrototypePollutionKeys,
    hasExactKeys,
    isNativeWsConnectionToken: (value) => Number.isSafeInteger(value) && value > 0,
    operationAbortError: () => new DOMException('Connection changed', 'AbortError'),
    waitForAbortableDelay: (delay) => new Promise((resolve) => setTimeout(resolve, delay)),
    tokenVault: {
      isVaultUnlocked: () => true,
      prepareAuthorizedRefresh: async () => ({ blindedTokens: [Buffer.alloc(32, 1).toString('base64')], tokenEpoch: 1 }),
      finalizeAuthorizedRefresh: async () => { calls.finalized += 1; },
    },
    replenishResumePool: async () => { calls.replenished += 1; },
    decodeCanonicalBase64List: (values) => values.map((value) => new Uint8Array(Buffer.from(value, 'base64'))),
    decodeServerResponseBase64: (value) => new Uint8Array(Buffer.from(value, 'base64')),
    ACCOUNT_AUTH_REPLACEMENT_BATCH_SIZE: 1,
    WS_CONTROL_RESPONSE_TIMEOUT_MS: 180_000,
    WS_CONTROL_SEND_TIMEOUT_MS: 60_000,
    setTimeout: (...args) => setTimeout(...args),
    clearTimeout: (...args) => clearTimeout(...args),
    console: { info() {}, warn(...args) { calls.warnings.push(args); } },
  });
  const connection = Object.assign(new Connection(), {
    coverTrafficGeneration: 1,
    coverTrafficInFlightGeneration: null,
    cancelCoverAcknowledgement: null,
    coverTrafficTimer: null,
    connectionWaiterCancels: new Set(),
    lifecycleState: 'connected',
    sessionKeyMaterial: {},
    isApplicationAuthReady: () => true,
    lastAuthUsername: 'alice',
    nativeConnectionToken: 8,
    connectionOperationGeneration: 1,
    _username: 'alice',
    isInUnlinkedMode: true,
    unlinkedSessionReady: true,
    unlinkedAccountAuthorizationReady: true,
    messageHandler: new WebSocketMessageHandler(),
    torIntegration: { getAdaptedTimeout: (value) => value },
    dispatchPayload: async (payload) => {
      calls.cover.push(payload);
      return options.sendCover ? options.sendCover(payload) : null;
    },
    sendSecureControlMessage: async (payload, sendOptions) => {
      calls.refresh.push(payload);
      if (options.sendRefresh) await options.sendRefresh(payload, sendOptions);
    },
  });
  t.after(() => { connection.stopCoverTraffic(); connection.cancelConnectionWaiters(); });
  const acknowledgeCover = (changes = {}) => connection.messageHandler.handleMessage({
    type: SignalType.BLIND_ROUTE_ACK,
    requestId: calls.cover.at(-1).requestId,
    success: true,
    ...changes,
  });
  const acknowledgeRefresh = (requestId = calls.refresh.at(-1).requestId) => connection.messageHandler.handleMessage({
    type: SignalType.ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE,
    requestId,
    issuerEpoch: 1,
    signedBlindedTokens: [Buffer.alloc(32, 2).toString('base64')],
    proof: Buffer.alloc(64, 3).toString('base64'),
    publicKey: Buffer.alloc(32, 4).toString('base64'),
  });
  return { connection, calls, acknowledgeCover, acknowledgeRefresh };
}

test('an empty local socket queue cannot flood a backed-up Tor stream with cover packets', async (t) => {
  const f = fixture(t);
  for (let index = 0; index < 20; index += 1) {
    await f.connection.sendCoverTraffic(1);
    t.mock.timers.tick(30_000);
  }
  assert.equal(f.calls.cover.length, 1);
  assert.equal(f.connection.connectionWaiterCancels.size, 1);
  await f.acknowledgeCover();
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 2);
  assert.notEqual(f.calls.cover[0].requestId, f.calls.cover[1].requestId);
});

test('cover traffic yields while an authenticated control response is outstanding', async (t) => {
  const f = fixture(t);
  const release = f.connection.registerConnectionWaiterCancel(() => {});
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 0);
  release();
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 1);
});

test('only a matching well-formed cover ACK releases backpressure', async (t) => {
  const f = fixture(t);
  await f.connection.sendCoverTraffic(1);
  for (const changes of [
    { requestId: crypto.randomUUID() }, { success: 'true' }, { extra: 1 },
    { type: SignalType.OK }, { error: '' }, { error: 'x'.repeat(201) },
  ]) {
    await f.acknowledgeCover(changes);
    await f.connection.sendCoverTraffic(1);
    assert.equal(f.calls.cover.length, 1);
  }
  await f.acknowledgeCover({ success: false, error: 'busy' });
  assert.equal(f.connection.connectionWaiterCancels.size, 0);
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 2);
});

test('connection cancellation releases the cover waiter and rejects old ACKs', async (t) => {
  const f = fixture(t);
  await f.connection.sendCoverTraffic(1);
  const oldRequest = f.calls.cover[0].requestId;
  f.connection.stopCoverTraffic();
  f.connection.cancelConnectionWaiters();
  f.connection.nativeConnectionToken = 9;
  await f.connection.sendCoverTraffic(2);
  await f.acknowledgeCover({ requestId: oldRequest });
  await f.connection.sendCoverTraffic(2);
  assert.equal(f.calls.cover.length, 2);
  assert.equal(f.connection.connectionWaiterCancels.size, 1);
});

test('an ACK arriving before the native write completes is not lost', async (t) => {
  const write = deferred();
  const f = fixture(t, { sendCover: () => write.promise });
  const sent = f.connection.sendCoverTraffic(1);
  await flush();
  await f.acknowledgeCover();
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 1);
  write.resolve(null);
  await sent;
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 2);
});

test('a locally skipped cover send does not wait for an impossible ACK', async (t) => {
  const f = fixture(t, { sendCover: async () => undefined });
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.connection.connectionWaiterCancels.size, 0);
  assert.equal(f.connection.messageHandler.hasHandler(SignalType.BLIND_ROUTE_ACK), false);
});

test('an ambiguous cover write failure cannot start another cover packet on the same connection', async (t) => {
  const f = fixture(t, { sendCover: async () => { throw new Error('Write failed'); } });
  await f.connection.sendCoverTraffic(1);
  await f.connection.sendCoverTraffic(1);
  assert.equal(f.calls.cover.length, 1);
  f.connection.cancelConnectionWaiters();
  assert.equal(f.connection.messageHandler.hasHandler(SignalType.BLIND_ROUTE_ACK), false);
});

test('credential refresh retries retain their request ID and accept a late original response', async (t) => {
  const f = fixture(t);
  const result = f.connection.replaceConsumedAccountAuthorizationToken();
  await flush();
  const originalId = f.calls.refresh[0].requestId;
  t.mock.timers.tick(180_000);
  await flush();
  t.mock.timers.tick(750);
  await flush();
  assert.equal(f.calls.refresh.length, 2);
  assert.equal(f.calls.refresh[1].requestId, originalId);
  await f.acknowledgeRefresh(originalId);
  await result;
  assert.equal(f.calls.finalized, 1);
  assert.equal(f.calls.replenished, 1);
  assert.equal(f.connection.accountAuthReplacementConnectionToken, 8);
  assert.equal(f.connection.connectionWaiterCancels.size, 0);
});

test('a slow credential write does not consume its response deadline', async (t) => {
  const write = deferred();
  const f = fixture(t, { sendRefresh: () => write.promise });
  let settled = false;
  const result = f.connection.issueAccountAuthorizationReplacement(() => {}, crypto.randomUUID()).then((value) => {
    settled = true;
    return value;
  });
  await flush();
  t.mock.timers.tick(40_000);
  await flush();
  write.resolve();
  await flush();
  t.mock.timers.tick(40_000);
  await flush();
  assert.equal(settled, false);
  await f.acknowledgeRefresh();
  assert.equal(await result, true);
});

test('a credential reply racing its write completion does not leave a response timer', async (t) => {
  const write = deferred();
  const f = fixture(t, { sendRefresh: () => write.promise });
  const result = f.connection.issueAccountAuthorizationReplacement(() => {}, crypto.randomUUID());
  await flush();
  await f.acknowledgeRefresh();
  write.resolve();
  assert.equal(await result, true);
  t.mock.timers.tick(100_000);
  await flush();
  assert.equal(f.calls.warnings.length, 0);
  assert.equal(f.connection.connectionWaiterCancels.size, 0);
});

function cellFixture(t) {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args));
  const session = {
    sessionId: 'a'.repeat(32), fingerprint: 'b'.repeat(64),
    recvKey: new Uint8Array(32).fill(7), sendKey: new Uint8Array(32).fill(7),
    sendCounter: 0, remoteCounter: 0, confirmed: true,
  };
  const frames = [];
  const closed = [];
  const received = [];
  const ws = {
    readyState: 1, bufferedAmount: 0,
    _pqSessionId: session.sessionId, _pqSessionData: session,
    send(frame, callback) { frames.push(Buffer.from(frame)); callback(); },
    close(code, reason) { closed.push({ code, reason }); this.readyState = 3; },
  };
  const create = async (payload = { type: SignalType.PQ_HEARTBEAT_PING, timestamp: Date.now() }) => {
    assert.equal(await sendPQEncryptedResponse(ws, session, payload), true);
    return frames.at(-1);
  };
  const receive = (cell) => handlePQBinaryCell({
    ws, cell, context: {}, handleInnerMessage: async ({ parsed }) => received.push(parsed),
  });
  return { ws, session, create, receive, warnings, closed, received };
}

test('fixed-cell timestamp expiration is identified without extending the replay window', async (t) => {
  const f = cellFixture(t);
  const cell = await f.create();
  t.mock.timers.tick(300_001);
  assert.equal(await f.receive(cell), false);
  assert.deepEqual(f.warnings, [[
    '[PQ-CELL] Rejected encrypted WebSocket cell', { error: 'Fixed-cell timestamp outside replay window' },
  ]]);
  assert.equal(f.closed[0].code, 1008);
  assert.equal(f.received.length, 0);
  assert.equal(f.session.remoteCounter, 0);
});

test('a replayed fixed cell is rejected separately from malformed metadata', async (t) => {
  const f = cellFixture(t);
  const cell = await f.create();
  assert.equal(await f.receive(cell), true);
  assert.equal(await f.receive(cell), false);
  assert.equal(f.received.length, 1);
  assert.equal(f.warnings[0][1].error, 'Replayed or out-of-order fixed-cell counter');
  assert.equal(f.closed[0].code, 1008);
});

test('structurally invalid fixed-cell metadata still closes the connection', async (t) => {
  const f = cellFixture(t);
  const cell = await f.create();
  cell.writeUInt32BE(0, 92);
  assert.equal(await f.receive(cell), false);
  assert.equal(f.warnings[0][1].error, 'Invalid fixed-cell metadata');
  assert.equal(f.received.length, 0);
  assert.equal(f.closed[0].code, 1008);
});

test('delayed authenticated requests are measured and warnings are rate limited', async (t) => {
  const f = cellFixture(t);
  for (let index = 0; index < 4; index += 1) {
    const cell = await f.create();
    t.mock.timers.tick(30_000);
    assert.equal(await f.receive(cell), true);
  }
  assert.equal(f.received.length, 4);
  assert.equal(f.warnings.length, 2);
  assert.deepEqual(f.warnings[0], [
    '[PQ-CELL] Delayed authenticated request', { payloadType: SignalType.PQ_HEARTBEAT_PING, ageMs: 30_000, cells: 1 },
  ]);
  assert.equal(f.closed.length, 0);
});

test('tampered ciphertext cannot produce an authenticated request diagnostic', async (t) => {
  const f = cellFixture(t);
  const cell = await f.create();
  cell[172] ^= 1;
  t.mock.timers.tick(30_000);
  assert.equal(await f.receive(cell), false);
  assert.equal(f.warnings.length, 1);
  assert.equal(f.warnings[0][0], '[PQ-CELL] Rejected encrypted WebSocket cell');
  assert.equal(f.received.length, 0);
});

test('every peer signal waits past three seconds for a successful P2P dial', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { createPeerSignalSender } = loadSource('src/lib/transport/peer-signal-sender.ts');
  for (const type of [
    SignalType.MESSAGE, SignalType.CALL_SIGNAL, SignalType.FILE_MESSAGE_CHUNK,
    SignalType.RECEIPT_BATCH, SignalType.FILE_TRANSPORT_ACK, SignalType.FILE_CHUNK_NACK,
    SignalType.FILE_TRANSFER_CANCEL, SignalType.EDIT_MESSAGE, SignalType.DELETE_MESSAGE,
    SignalType.REACTION_ADD, SignalType.REACTION_REMOVE, SignalType.TYPING_START,
    SignalType.TYPING_STOP, SignalType.SESSION_RESET_REQUEST,
  ]) {
    const dial = deferred();
    let connected = false;
    let sent = 0;
    let settled = false;
    const sender = createPeerSignalSender({
      isCurrent: () => true,
      isPeerConnected: () => connected,
      connectToPeer: () => dial.promise,
      sendMessage: async () => { sent += 1; },
    });
    const result = sender('peer', {}, type).finally(() => { settled = true; });
    await flush();
    t.mock.timers.tick(75_000);
    await flush();
    assert.equal(settled, false, type);
    assert.equal(sent, 0, type);
    connected = true;
    dial.resolve();
    await result;
    assert.equal(sent, 1, type);
  }
});

test('P2P surfaces the actual bounded dial failure and never sends before readiness', async () => {
  const { createPeerSignalSender } = loadSource('src/lib/transport/peer-signal-sender.ts');
  let sent = false;
  const dial = deferred();
  const sender = createPeerSignalSender({
    isCurrent: () => true, isPeerConnected: () => false,
    connectToPeer: () => dial.promise, sendMessage: async () => { sent = true; },
  });
  const failed = assert.rejects(sender('peer', {}), /onion dial timed out/);
  dial.reject(new Error('onion dial timed out'));
  await failed;
  assert.equal(sent, false);
});

function heartbeatFixture(t, send = async () => {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const { WebSocketHeartbeat } = loadSource('src/lib/websocket/heartbeat.ts', {
    SignalType, HEARTBEAT_INTERVAL_MS: 35_000, HEARTBEAT_TIMEOUT_MS: 90_000, MAX_MISSED_HEARTBEATS: 4,
  });
  const calls = { sent: 0, lost: 0 };
  const heartbeat = new WebSocketHeartbeat({
    onSendHeartbeat: async () => { calls.sent += 1; await send(); },
    onConnectionLost: () => { calls.lost += 1; }, onRehandshakeNeeded() {},
    getLifecycleState: () => 'connected', getSessionId: () => 'session',
  });
  t.after(() => heartbeat.stop());
  const pong = () => heartbeat.handleResponse({ type: SignalType.PQ_HEARTBEAT_PONG, sessionId: 'session' });
  return { heartbeat, calls, pong };
}

test('heartbeats cannot pile up while waiting for the remote pong', async (t) => {
  const f = heartbeatFixture(t);
  await f.heartbeat.sendHeartbeat();
  for (let index = 0; index < 2; index += 1) {
    t.mock.timers.tick(35_000);
    await f.heartbeat.sendHeartbeat();
  }
  assert.equal(f.calls.sent, 1);
  f.pong();
  await f.heartbeat.sendHeartbeat();
  assert.equal(f.calls.sent, 2);
});

test('bounded heartbeat misses still detect a dead connection', async (t) => {
  const f = heartbeatFixture(t);
  for (let index = 0; index < 4; index += 1) {
    await f.heartbeat.sendHeartbeat();
    t.mock.timers.tick(90_000);
    await flush();
  }
  assert.equal(f.calls.sent, 4);
  assert.equal(f.calls.lost, 1);
});

test('heartbeat reset cannot let an old write clear a new connection deadline', async (t) => {
  const write = deferred();
  const f = heartbeatFixture(t, () => write.promise);
  const first = f.heartbeat.sendHeartbeat();
  await flush();
  f.heartbeat.reset();
  const second = f.heartbeat.sendHeartbeat();
  await flush();
  write.resolve();
  await Promise.all([first, second]);
  await f.heartbeat.sendHeartbeat();
  assert.equal(f.calls.sent, 2);
  f.pong();
  await f.heartbeat.sendHeartbeat();
  assert.equal(f.calls.sent, 3);
});

test('credential send timeout aborts queued work and frees its connection waiter', async (t) => {
  const write = deferred();
  let signal;
  const f = fixture(t, { sendRefresh: (_payload, options) => { signal = options.signal; return write.promise; } });
  const result = f.connection.issueAccountAuthorizationReplacement(() => {}, crypto.randomUUID());
  await flush();
  t.mock.timers.tick(60_000);
  assert.equal(await result, false);
  assert.equal(signal.aborted, true);
  assert.equal(f.connection.connectionWaiterCancels.size, 0);
  write.reject(new Error('Late write failure'));
  await flush();
  assert.equal(f.calls.warnings.length, 1);
});

function routeFixture(t) {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const cancels = new Set();
  let epoch = 1;
  const ws = {
    isConnectedToServer: () => true,
    captureConnectionPrivacyEpoch: () => epoch,
    registerConnectionWaiterCancel: (cancel) => { cancels.add(cancel); return () => cancels.delete(cancel); },
  };
  const file = 'src/lib/transport/unified-signal-transport.ts';
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const declaration = ast.statements.find((node) => ts.isClassDeclaration(node) && node.name.text === 'UnifiedSignalTransport');
  const method = declaration.members.find((node) => node.name?.getText(ast) === 'awaitBlindRouteAck');
  const { Transport } = compile(`export class Transport { ${method.getText(ast)} }`, {
    websocketClient: ws, WS_CONTROL_SEND_TIMEOUT_MS: 60_000,
    BLIND_ROUTE_ACK_LIVENESS_POLL_MS: 1000, MAX_BLIND_ACK_WAITERS: 512,
  });
  const transport = Object.assign(new Transport(), { blindAckWaiters: new Map(), checkBlindAckHandler: () => true });
  t.after(() => { for (const cancel of [...cancels]) cancel(); });
  const ack = () => transport.blindAckWaiters.get('request')?.({ acked: true, success: true });
  return { transport, ack, cancels, reconnect: () => { epoch += 1; for (const cancel of [...cancels]) cancel(); } };
}

test('routing has separate send and response budgets while accepting a slow valid ACK', async (t) => {
  const f = routeFixture(t);
  const write = deferred();
  let settled = false;
  const result = f.transport.awaitBlindRouteAck('request', 180_000, () => write.promise).finally(() => { settled = true; });
  await flush();
  t.mock.timers.tick(59_000);
  write.resolve(true);
  await flush();
  t.mock.timers.tick(140_000);
  await flush();
  assert.equal(settled, false);
  f.ack();
  assert.deepEqual(await result, { acked: true, success: true });
  assert.equal(f.cancels.size, 0);
});

test('a routing send timeout returns promptly and aborts its still-pending write', async (t) => {
  const f = routeFixture(t);
  const write = deferred();
  let signal;
  const result = f.transport.awaitBlindRouteAck('request', 180_000, (value) => { signal = value; return write.promise; });
  await flush();
  t.mock.timers.tick(60_000);
  assert.deepEqual(await result, { acked: false, error: 'send-timeout' });
  assert.equal(signal.aborted, true);
  assert.equal(f.cancels.size, 0);
  write.reject(new Error('Late native write rejection'));
  await flush();
});

test('routing reconnect cancellation is immediate even during a blocked write', async (t) => {
  const f = routeFixture(t);
  let signal;
  const write = deferred();
  const result = f.transport.awaitBlindRouteAck('request', 180_000, (value) => { signal = value; return write.promise; });
  await flush();
  f.reconnect();
  assert.deepEqual(await result, { acked: false, error: 'disconnected' });
  assert.equal(signal.aborted, true);
  assert.equal(f.cancels.size, 0);
  write.resolve(true);
  await flush();
  assert.equal(f.transport.blindAckWaiters.size, 0);
});

test('a routing ACK racing write completion leaves no timers or background waiter', async (t) => {
  const f = routeFixture(t);
  const write = deferred();
  const result = f.transport.awaitBlindRouteAck('request', 180_000, () => write.promise);
  await flush();
  f.ack();
  assert.deepEqual(await result, { acked: true, success: true });
  write.resolve(true);
  await flush();
  t.mock.timers.tick(240_000);
  assert.equal(f.cancels.size, 0);
  assert.equal(f.transport.blindAckWaiters.size, 0);
});
