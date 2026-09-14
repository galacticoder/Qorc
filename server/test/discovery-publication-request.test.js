import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import { getEventListeners } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import test, { after, before } from 'node:test';
import ts from 'typescript';
import { createServer } from 'vite';
import {
  DISCOVERY_PUBLICATION_DEDUP_TTL_MS,
  DISCOVERY_PUBLICATION_RETRY_TTL_MS,
} from '../../shared/discovery-constants.js';

let loader;
let requestDiscoveryResponse;
let DiscoveryRequestError;
let WS_CONTROL_RESPONSE_TIMEOUT_MS;
let parsePublicationAck;
let canReuseDiscoveryPublication;
let canRetryPreparedPublication;
let WebSocketConnection;
const secureEvent = 'edge:secure-server-message';
const transportEvent = 'edge:server-message';

before(async () => {
  loader = await createServer({
    configFile: false,
    root: process.cwd(),
    server: { middlewareMode: true, watch: { ignored: ['**/src-tauri/target/**', '**/node_modules/**', '**/dist/**'] } },
    appType: 'custom',
    logLevel: 'silent',
    optimizeDeps: { noDiscovery: true },
    resolve: { alias: { '@': path.join(process.cwd(), 'src') } },
  });
  ({ requestDiscoveryResponse, parsePublicationAck, DiscoveryRequestError } = await loader.ssrLoadModule('/src/lib/discovery/request.ts'));
  ({ WS_CONTROL_RESPONSE_TIMEOUT_MS } = await loader.ssrLoadModule('/src/lib/constants.ts'));
  ({ canReuseDiscoveryPublication, canRetryPreparedPublication } = await loader.ssrLoadModule('/src/lib/discovery/publication-retry.ts'));
  const source = fs.readFileSync('src/lib/websocket/websocket.ts', 'utf8');
  const ast = ts.createSourceFile('websocket.ts', source, ts.ScriptTarget.Latest, true);
  const declaration = ast.statements.find((node) => ts.isClassDeclaration(node) && node.name.text === 'WebSocketConnection');
  const methods = ['runOnSecureSendLane', 'dispatchPayload'].map((name) => {
    const method = declaration.members.find((member) => member.name?.getText(ast) === name);
    assert.ok(method);
    return method.getText(ast);
  });
  const compiled = ts.transpileModule(`class WebSocketConnection { secureSendLane = Promise.resolve(); ${methods.join('\n')} }`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  WebSocketConnection = new Function(
    'throwIfOperationAborted', 'isPlainObject', 'hasPrototypePollutionKeys',
    'UNLINKED_FORBIDDEN_ACCOUNT_TYPES', 'isNativeWsConnectionToken',
    `${compiled}; return WebSocketConnection;`,
  )((signal) => signal?.throwIfAborted(), (value) => value?.constructor === Object, () => false, new Set(), (token) => token === 3);
});

after(async () => { await loader?.close(); });

async function flush() {
  for (let i = 0; i < 12; i += 1) await Promise.resolve();
}

function fixture(overrides = {}) {
  const events = new EventTarget();
  const controller = new AbortController();
  const options = {
    operation: 'publish',
    events,
    signal: controller.signal,
    isCurrent: () => true,
    send: async () => {},
    parse: (detail) => parsePublicationAck(detail, 'pub-test'),
    ...overrides,
  };
  return {
    options,
    controller,
    respond: (detail = { type: 'ok', requestId: 'pub-test', op: 'publish-discovery', success: true }) => {
      events.dispatchEvent(new CustomEvent(secureEvent, { detail }));
    },
    assertClean: () => {
      assert.equal(getEventListeners(events, secureEvent).length, 0);
      assert.equal(getEventListeners(events, transportEvent).length, 0);
      assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    },
  };
}

test('publication response deadline starts only after a slow send completes', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let finishSend;
  let sendSignal;
  let settled = false;
  const f = fixture({ send: (signal) => {
    sendSignal = signal;
    return new Promise((resolve) => { finishSend = resolve; });
  } });
  const result = requestDiscoveryResponse(f.options).then((value) => { settled = true; return value; });
  await flush();
  t.mock.timers.tick(59_000);
  await flush();
  assert.equal(settled, false);
  assert.equal(sendSignal.aborted, false);
  finishSend();
  await flush();
  t.mock.timers.tick(59_000);
  await flush();
  assert.equal(settled, false);
  f.respond();
  assert.equal(await result, true);
  f.assertClean();
});

test('send timeout cancels work still waiting in the actual secure send lane', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const connection = new WebSocketConnection();
  Object.assign(connection, {
    isInUnlinkedMode: true,
    rateLimiter: { checkRateLimit: () => true },
    isGloballyRateLimited: () => false,
    lifecycleState: 'connected',
    torIntegration: { isCircuitHealthy: () => true },
    captureOutboundTransportContext: () => ({ connectionToken: 3 }),
    assertOutboundTransportContextCurrent: () => {},
    validateSessionKeys: async () => {},
    sessionKeyMaterial: {},
    encryption: { prepareSecureEnvelope: async () => [new Uint8Array([1])] },
    transmit: async () => { transmitted = true; },
  });
  let releaseLane;
  let transmitted = false;
  const blocker = connection.runOnSecureSendLane(() => new Promise((resolve) => { releaseLane = resolve; }));
  await flush();
  let sendSignal;
  const f = fixture({ send: (signal) => {
    sendSignal = signal;
    return connection.dispatchPayload({ type: 'publish-discovery' }, false, { signal });
  } });
  const failure = assert.rejects(requestDiscoveryResponse(f.options), { message: 'publish-send-timeout' });
  await flush();
  t.mock.timers.tick(60_000);
  await failure;
  assert.equal(sendSignal.aborted, true);
  releaseLane();
  await blocker;
  await flush();
  assert.equal(transmitted, false);
  f.assertClean();
});

test('response timeout is distinct from a send timeout and ignores late acknowledgements', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture();
  const failure = assert.rejects(requestDiscoveryResponse(f.options), { message: 'publish-response-timeout' });
  await flush();
  t.mock.timers.tick(WS_CONTROL_RESPONSE_TIMEOUT_MS);
  await failure;
  f.respond();
  f.assertClean();
});

test('cancellation during encryption wipes the prepared cells without transmitting', async () => {
  const controller = new AbortController();
  const cells = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
  let transmitted = false;
  const connection = Object.assign(new WebSocketConnection(), {
    isInUnlinkedMode: true,
    rateLimiter: { checkRateLimit: () => true },
    isGloballyRateLimited: () => false,
    lifecycleState: 'connected',
    torIntegration: { isCircuitHealthy: () => true },
    captureOutboundTransportContext: () => ({ connectionToken: 3 }),
    assertOutboundTransportContextCurrent: () => {},
    validateSessionKeys: async () => {},
    sessionKeyMaterial: {},
    encryption: { prepareSecureEnvelope: async () => { controller.abort(); return cells; } },
    transmit: async () => { transmitted = true; },
  });
  await assert.rejects(connection.dispatchPayload({ type: 'publish-discovery' }, false, { signal: controller.signal }), { name: 'AbortError' });
  assert.equal(transmitted, false);
  assert.ok(cells.every((cell) => cell.every((byte) => byte === 0)));
});

test('an acknowledgement racing the native write completion is accepted', async () => {
  let finishSend;
  const f = fixture({ send: () => new Promise((resolve) => { finishSend = resolve; }) });
  const result = requestDiscoveryResponse(f.options);
  await flush();
  f.respond();
  assert.equal(await result, true);
  finishSend();
  await flush();
  f.assertClean();
});

test('explicit server rejection preserves the specific error', async () => {
  const f = fixture();
  const failure = assert.rejects(requestDiscoveryResponse(f.options), { message: 'discovery_epoch_expired' });
  await flush();
  f.respond({ type: 'ok', requestId: 'pub-test', op: 'publish-discovery', success: false, error: 'discovery_epoch_expired' });
  await failure;
  f.assertClean();
});

test('transport errors retain their diagnostic cause', async () => {
  const f = fixture({ send: async () => { throw new Error('Tor circuit is not healthy'); } });
  await assert.rejects(requestDiscoveryResponse(f.options), (error) => {
    assert.equal(error.code, 'publish-send-failed');
    assert.equal(error.detail, 'Tor circuit is not healthy');
    return true;
  });
  f.assertClean();
});

test('unrelated responses are ignored but a malformed matching acknowledgement fails immediately', async () => {
  const f = fixture();
  const failure = assert.rejects(requestDiscoveryResponse(f.options), { message: 'publish-invalid-ack' });
  f.respond({ type: 'ok', requestId: 'pub-other', success: true });
  assert.equal(getEventListeners(f.options.events, secureEvent).length, 1);
  f.respond({ type: 'ok', requestId: 'pub-test', op: 'publish-discovery', success: true, extra: true });
  await failure;
  f.assertClean();
});

test('an acknowledgement from the unprotected event channel cannot complete a publication', async () => {
  const f = fixture();
  let settled = false;
  const result = requestDiscoveryResponse(f.options).then((value) => { settled = true; return value; });
  f.options.events.dispatchEvent(new CustomEvent(transportEvent, {
    detail: { type: 'ok', requestId: 'pub-test', op: 'publish-discovery', success: true },
  }));
  await flush();
  assert.equal(settled, false);
  f.respond();
  assert.equal(await result, true);
  f.assertClean();
});

test('logout aborts discovery requests and removes their listeners', async () => {
  let sendSignal;
  const f = fixture({ send: async (signal) => { sendSignal = signal; } });
  const failure = assert.rejects(requestDiscoveryResponse(f.options), { message: 'discovery-request-aborted' });
  await flush();
  f.controller.abort();
  await failure;
  assert.equal(sendSignal.aborted, true);
  f.assertClean();
});

test('connection replacement cancels a request instead of accepting an old reply', async () => {
  let current = true;
  const f = fixture({ isCurrent: () => current });
  const failure = assert.rejects(requestDiscoveryResponse(f.options), { message: 'discovery-transport-changed' });
  await flush();
  current = false;
  f.options.events.dispatchEvent(new CustomEvent(transportEvent, { detail: { type: '__ws_connection_closed' } }));
  await failure;
  f.respond();
  f.assertClean();
});

test('an already aborted request never sends', async () => {
  let sent = false;
  const f = fixture({ send: async () => { sent = true; } });
  f.controller.abort();
  await assert.rejects(requestDiscoveryResponse(f.options), { message: 'discovery-request-aborted' });
  await flush();
  assert.equal(sent, false);
  f.assertClean();
});

test('OPRF replies are allowed to arrive after the former ten-second deadline', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ operation: 'oprf', parse: (detail) => detail.type === 'oprf-discovery-public-key' ? detail : undefined });
  const result = requestDiscoveryResponse(f.options);
  await flush();
  t.mock.timers.tick(25_000);
  f.respond({ type: 'oprf-discovery-public-key', epoch: 1 });
  assert.deepEqual(await result, { type: 'oprf-discovery-public-key', epoch: 1 });
  f.assertClean();
});

test('a valid publication ACK arriving after two minutes completes without a retry', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture();
  let settled = false;
  const result = requestDiscoveryResponse(f.options).finally(() => { settled = true; });
  await flush();
  t.mock.timers.tick(138_000);
  await flush();
  assert.equal(settled, false);
  f.respond();
  assert.equal(await result, true);
  f.assertClean();
});

test('discovery holds cover traffic and cancels immediately with its native connection', async () => {
  const cancels = new Set();
  let sendSignal;
  const f = fixture({
    send: async (signal) => { sendSignal = signal; },
    registerConnectionCancel: (cancel) => { cancels.add(cancel); return () => cancels.delete(cancel); },
  });
  const failed = assert.rejects(requestDiscoveryResponse(f.options), { message: 'discovery-transport-changed' });
  await flush();
  assert.equal(cancels.size, 1);
  for (const cancel of [...cancels]) cancel();
  await failed;
  assert.equal(sendSignal.aborted, true);
  assert.equal(cancels.size, 0);
  f.assertClean();
});

test('prepared publications are scoped to current identity, avatar, epoch, connection and lifetime', () => {
  const prepared = {
    requestId: 'pub-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    publication: { epochId: '1000', publishId: 'id', bucketIds: [1] },
    encryptedBlob: 'ciphertext', powNonce: 'nonce', powSolution: 'solution',
    inputFingerprint: 'input', contextFingerprint: 'context', fingerprint: 'fingerprint',
    publicKey: 'key', connectionEpoch: 3, avatarStateVersion: 2, expiresAt: 300_000,
  };
  const current = { inputFingerprint: 'input', epochId: '1000', publicKey: 'key', connectionEpoch: 3, avatarStateVersion: 2 };
  assert.equal(canReuseDiscoveryPublication(prepared, current, 60_000), true);
  for (const changed of [
    { inputFingerprint: null }, { inputFingerprint: 'changed' }, { epochId: '2000' },
    { publicKey: 'changed' }, { connectionEpoch: 4 }, { connectionEpoch: null }, { avatarStateVersion: 3 },
  ]) assert.equal(canReuseDiscoveryPublication(prepared, { ...current, ...changed }, 60_000), false);
  assert.equal(canReuseDiscoveryPublication(prepared, current, 240_000), false);
  assert.equal(canReuseDiscoveryPublication(null, current, 60_000), false);
  assert.ok(DISCOVERY_PUBLICATION_RETRY_TTL_MS >= 300_000);
  assert.ok(DISCOVERY_PUBLICATION_DEDUP_TTL_MS > DISCOVERY_PUBLICATION_RETRY_TTL_MS + 120_000);
  assert.equal(canRetryPreparedPublication('publish-response-timeout'), true);
  assert.equal(canRetryPreparedPublication('publish-send-timeout'), true);
  assert.equal(canRetryPreparedPublication('discovery_work_replayed'), false);
  assert.equal(canRetryPreparedPublication('discovery_epoch_expired'), false);
});

test('a publication retry accepts the delayed original ACK and preserves its exact request', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const source = fs.readFileSync('src/hooks/discovery/useDiscovery.ts', 'utf8');
  const ast = ts.createSourceFile('useDiscovery.ts', source, ts.ScriptTarget.Latest, true);
  let initializer;
  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'sendPreparedPublication') initializer = node.initializer.getText(ast);
    ts.forEachChild(node, visit);
  }
  visit(ast);
  assert.ok(initializer);
  const events = new EventTarget();
  const prepared = {
    requestId: `pub-${nodeCrypto.randomUUID()}`,
    publication: { publishId: 'same-publication' }, encryptedBlob: 'same-ciphertext',
    powNonce: 'same-nonce', powSolution: 'same-work',
    contextFingerprint: 'context', fingerprint: 'fingerprint', avatarStateVersion: 1,
  };
  const requests = [];
  const preparedPublicationRef = { current: prepared };
  const lastPublishFailureRef = { current: null };
  const dependencies = {
    requestDiscoveryResponse, parsePublicationAck, DiscoveryRequestError, canRetryPreparedPublication,
    window: events, operationAbortSignal: new AbortController().signal,
    isCurrentOwner: () => true, isDiscoveryTransportReady: () => true,
    websocketClient: {
      sendSecureControlMessage: async (payload) => requests.push(payload),
      registerConnectionWaiterCancel: () => () => {},
    },
    SignalType: { PUBLISH_DISCOVERY: 'publish-discovery' },
    lastPublishedRef: {}, lastPublishedContextFingerprintRef: {},
    lastPublishedFingerprintRef: {}, lastPublishedAvatarStateVersionRef: {},
    lastPublishFailureRef, preparedPublicationRef,
    fail: (reason) => { lastPublishFailureRef.current = reason; return false; },
    console: { log() {}, warn() {} },
  };
  const compiled = ts.transpileModule(`const send = ${initializer};`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const send = new Function(...Object.keys(dependencies), `${compiled}; return send;`)(...Object.values(dependencies));
  const first = send(prepared, false);
  await flush();
  t.mock.timers.tick(WS_CONTROL_RESPONSE_TIMEOUT_MS);
  assert.equal(await first, false);
  assert.equal(lastPublishFailureRef.current, 'publish-response-timeout');
  assert.equal(preparedPublicationRef.current, prepared);
  const retry = send(prepared, true);
  await flush();
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[1], requests[0]);
  assert.equal(requests[0].requestId, prepared.requestId);
  events.dispatchEvent(new CustomEvent(secureEvent, {
    detail: { type: 'ok', op: 'publish-discovery', requestId: requests[0].requestId, success: true },
  }));
  assert.equal(await retry, true);
  assert.equal(preparedPublicationRef.current, null);
  assert.equal(lastPublishFailureRef.current, null);
  assert.equal(getEventListeners(events, secureEvent).length, 0);
});

test('server acknowledgement helper returns the real delivery result', async () => {
  const source = fs.readFileSync('server/server.js', 'utf8');
  const ast = ts.createSourceFile('server.js', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  let initializer;
  function visit(node) {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'sendPublishAck') initializer = node.initializer.getText(ast);
    ts.forEachChild(node, visit);
  }
  visit(ast);
  assert.ok(initializer);
  for (const delivered of [true, false]) {
    const logs = [];
    const send = new Function('requestId', 'SignalType', 'ws', 'sendSecureMessage', 'console', `return (${initializer});`)(
      'pub-test', { OK: 'ok', PUBLISH_DISCOVERY: 'publish-discovery' }, {}, async () => delivered,
      { log: (...args) => logs.push(args), warn: (...args) => logs.push(args) },
    );
    assert.equal(await send({ success: true }), delivered);
    assert.equal(logs[0][1].delivered, delivered);
    assert.equal(logs[0][1].requestId, 'pub-test');
  }
});

test('retrying an accepted publication after a lost ACK does not claim work or enqueue twice', async () => {
  const source = fs.readFileSync('server/server.js', 'utf8');
  const ast = ts.createSourceFile('server.js', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  let body;
  let dedupSource;
  function visit(node) {
    if (ts.isCaseClause(node) && node.expression.getText(ast) === 'SignalType.PUBLISH_DISCOVERY') body = node.statements[0].getText(ast);
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'discoveryPublicationDedupKey') dedupSource = node.getText(ast);
    ts.forEachChild(node, visit);
  }
  visit(ast);
  assert.ok(body && dedupSource);
  const dedup = new Function('nodeCrypto', 'SHA_256_ALGORITHM', 'PROTOCOL_KEYS', 'privateLookupId', `${dedupSource}; return discoveryPublicationDedupKey;`)(
    nodeCrypto, 'sha256', { DISCOVERY_PUBLISH_CONTENT: 'content', DISCOVERY_PUBLISH_DEDUP: 'dedup' }, (_, digest) => digest,
  );
  let now = 1_770_000_000_000;
  let claims = 0;
  let enqueues = 0;
  const acknowledgements = [];
  const recentPublishTokens = new Map();
  const dependencies = {
    ws: {},
    PUBLICATION_ID_RE: /^pub-[a-z0-9-]+$/,
    SignalType: { OK: 'ok', PUBLISH_DISCOVERY: 'publish-discovery' },
    sendSecureMessage: async (_, ack) => { acknowledgements.push(ack); return acknowledgements.length > 1; },
    hasAnonymousDeliveryAuthorization: () => true,
    hasExactPlainObjectKeys: (value, keys) => Object.keys(value).sort().join(',') === keys.slice().sort().join(','),
    getDiscoveryEpochInfo: () => ({ startedAt: 1_770_000_000_000, rotatesAt: 1_770_021_600_000 }),
    DISCOVERY_EPOCH_ID_RE: /^\d{13}$/,
    SESSION_FINGERPRINT_RE: /^[a-f0-9]{64}$/,
    isCanonicalDiscoveryBucketIds: () => true,
    isCanonicalDiscoveryBlob: () => true,
    isCanonicalBase64Bytes: () => true,
    POW_SEED_BYTES: 16,
    DISCOVERY_EPOCH_EXPIRED: 'discovery_epoch_expired',
    DISCOVERY_PUBLICATION_UNAVAILABLE: 'discovery_publication_unavailable',
    deriveAnonymousRequestPowSeed: () => 'seed',
    PROTOCOL_KEYS: { DISCOVERY_PUBLISH_POW: 'discovery-publish' },
    verifyPowSolution: () => true,
    DISCOVERY_PUBLISH_POW_DIFFICULTY: 18,
    discoveryPublicationDedupKey: dedup,
    recentPublishTokens,
    pendingPublishTokens: new Map(),
    DISCOVERY_PUBLICATION_DEDUP_TTL_MS,
    RECENT_PUBLISH_TOKEN_MAX: 2048,
    claimAnonymousRequestPow: async () => { claims += 1; return claims === 1 ? 'claimed' : 'replayed'; },
    enqueueDiscoveryPublication: async () => { enqueues += 1; return { queued: true }; },
    DISCOVERY_FORWARD_PUBLISH_WINDOW_MS: 86_400_000,
    rememberRecentPublishToken: (key, at) => recentPublishTokens.set(key, at),
    Date: { now: () => now },
    console: { log() {}, warn() {}, error() {} },
  };
  const execute = new (Object.getPrototypeOf(async function () {}).constructor)(
    ...Object.keys(dependencies), 'normalizedMessage', `switch ('publish-discovery') { case 'publish-discovery': ${body} }`,
  );
  const request = {
    type: 'publish-discovery', requestId: 'pub-first',
    publication: { epochId: '1770000000000', publishId: 'a'.repeat(64), bucketIds: [1, 2, 3, 4, 5, 6] },
    encryptedBlob: 'ciphertext', powNonce: 'nonce', powSolution: 'solution',
  };
  await execute(...Object.values(dependencies), request);
  now += 90_000;
  await execute(...Object.values(dependencies), { ...request, requestId: 'pub-retry' });
  assert.equal(claims, 1);
  assert.equal(enqueues, 1);
  assert.equal(acknowledgements.length, 2);
  assert.equal(acknowledgements[1].success, true);
  assert.equal(acknowledgements[1].requestId, 'pub-retry');
  assert.notEqual(dedup(request.publication, request.encryptedBlob), dedup(request.publication, 'different-ciphertext'));
});
