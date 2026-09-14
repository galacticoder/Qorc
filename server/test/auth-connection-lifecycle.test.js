import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { SignalType } from '../signals.js';
import { ML_KEM_1024_CIPHERTEXT_BYTES } from '../../shared/crypto-sizes.js';

function loadSource(file, dependencies) {
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const body = ast.statements.filter((node) => !ts.isImportDeclaration(node)).map((node) => node.getText(ast)).join('\n');
  const compiled = ts.transpileModule(body, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
  return exports;
}

async function flush() {
  for (let index = 0; index < 32; index += 1) await Promise.resolve();
}

function fixture(t, overrides = {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const handlers = new Map();
  const sent = [];
  const installed = [];
  const confirmed = [];
  const diagnostics = [];
  const { WebSocketHandshake } = loadSource('src/lib/websocket/handshake.ts', {
    PROTOCOL_KEYS,
    SignalType,
    EventType: { EDGE_SERVER_MESSAGE: 'edge', SECURE_SERVER_MESSAGE: 'secure', PQ_SESSION_ESTABLISHED: 'ready' },
    window: new EventTarget(),
    performance: { now: overrides.monotonicNow ?? (() => Date.now()) },
    ML_KEM_1024_CIPHERTEXT_BYTES,
    SESSION_REKEY_INTERVAL_MS: 3_600_000,
    PostQuantumRandom: { randomBytes: (size) => new Uint8Array(size).fill(1) },
    PostQuantumUtils: {
      bytesToHex: (bytes) => Buffer.from(bytes).toString('hex'),
      base64ToUint8Array: (value) => new Uint8Array(Buffer.from(value, 'base64')),
      clearMemory: (bytes) => bytes.fill(0),
    },
    Base64: { arrayBufferToBase64: (bytes) => Buffer.from(bytes).toString('base64') },
    PostQuantumHash: { blake3: () => new Uint8Array(32).fill(2), deriveKey: () => new Uint8Array(32).fill(3) },
    PostQuantumKEM: {
      encapsulate: async () => ({ ciphertext: new Uint8Array(1568), sharedSecret: new Uint8Array(32) }),
      generateKeyPair: async () => ({ publicKey: new Uint8Array(1568), secretKey: new Uint8Array(3168) }),
      decapsulate: async () => new Uint8Array(32),
    },
    PostQuantumSignature: { sizes: { signature: 4627 }, verify: overrides.verify ?? (async () => true) },
    generateX25519KeyPair: () => ({ publicKey: new Uint8Array(32), secretKey: new Uint8Array(32) }),
    computeX25519SharedSecret: () => new Uint8Array(32),
  });
  const handshake = new WebSocketHandshake({
    transmit: async () => {},
    transmitHandshake: async (value) => { sent.push(value); },
    runOnSecureSendLane: (operation) => operation(),
    registerMessageHandler: (type, handler) => handlers.set(type, handler),
    unregisterMessageHandler: (type) => handlers.delete(type),
    getTorAdaptedTimeout: (ms) => ms * (overrides.multiplier ?? 1.5),
    onSessionEstablished: (session) => installed.push(session),
    onAuthenticatedServerTime: (time) => confirmed.push(time),
    getTrustedNow: () => Date.now(),
    onDiagnostic: (phase, details) => diagnostics.push({ phase, ...details }),
    onHandshakeError: () => {},
    isConnected: async () => true,
  });
  handshake.setServerKeyMaterial({
    fingerprint: 'a'.repeat(64),
    kyberPublicKey: new Uint8Array(1568),
    dilithiumPublicKey: new Uint8Array(2592),
    x25519PublicKey: new Uint8Array(32),
  });
  t.after(() => handshake.reset());
  const acknowledge = () => {
    const request = sent[0].payload;
    handlers.get(SignalType.PQ_HANDSHAKE_ACK)({
      type: SignalType.PQ_HANDSHAKE_ACK,
      version: request.version,
      sessionId: request.sessionId,
      fingerprint: request.fingerprint,
      clientNonce: request.clientNonce,
      requestTimestamp: request.timestamp,
      requestDigest: '02'.repeat(32),
      responseKemCiphertext: Buffer.alloc(1568).toString('base64'),
      timestamp: Date.now(),
      serverTime: Date.now(),
      signature: Buffer.alloc(4627).toString('base64'),
    });
  };
  const confirm = (overrides = {}) => handlers.get(SignalType.PQ_HANDSHAKE_CONFIRMED)({
    ...sent.at(-1), type: SignalType.PQ_HANDSHAKE_CONFIRMED, ...overrides,
  });
  return { handshake, sent, installed, confirmed, diagnostics, handlers, acknowledge, confirm };
}

test('encrypted confirmation gets a complete phase budget after a delayed valid acknowledgement', async (t) => {
  const f = fixture(t);
  const operation = f.handshake.performHandshake(false);
  await flush();
  t.mock.timers.tick(80_000);
  f.acknowledge();
  await flush();
  assert.equal(f.installed.length, 1);
  assert.equal(f.confirmed.length, 0);
  assert.equal(f.sent.at(-1).type, SignalType.PQ_HANDSHAKE_CONFIRM);
  t.mock.timers.tick(80_000);
  await flush();
  f.confirm();
  await operation;
  assert.deepEqual(f.confirmed, [160_000]);
  assert.equal(f.handlers.size, 0);
});

test('signed server time advances through confirmation using a monotonic clock', async (t) => {
  let monotonicTime = 1_000;
  const f = fixture(t, { monotonicNow: () => monotonicTime });
  const operation = f.handshake.performHandshake(false);
  await flush();
  t.mock.timers.tick(10_000);
  f.acknowledge();
  await flush();
  t.mock.timers.setTime(Date.now() + 3_600_000);
  monotonicTime += 40_000;
  f.confirm();
  await operation;
  assert.deepEqual(f.confirmed, [50_000]);
});

test('missing encrypted confirmation reports that phase, not a missing acknowledgement', async (t) => {
  const f = fixture(t);
  const failed = assert.rejects(f.handshake.performHandshake(false), /Encrypted handshake confirmation timeout/);
  await flush();
  t.mock.timers.tick(10_000);
  f.acknowledge();
  await flush();
  t.mock.timers.tick(90_000);
  await failed;
  assert.equal(f.confirmed.length, 0);
  assert.equal(f.handlers.size, 0);
});

test('a missing handshake acknowledgement remains bounded', async (t) => {
  const f = fixture(t);
  const failed = assert.rejects(f.handshake.performHandshake(false), /Handshake acknowledgment timeout/);
  await flush();
  t.mock.timers.tick(90_000);
  await failed;
  assert.equal(f.installed.length, 0);
  assert.equal(f.handlers.size, 0);
});

test('late acknowledgement verification cannot install keys after its deadline', async (t) => {
  let verify;
  const f = fixture(t, { verify: () => new Promise((resolve) => { verify = resolve; }) });
  const failed = assert.rejects(f.handshake.performHandshake(false), /Handshake acknowledgment timeout/);
  await flush();
  f.acknowledge();
  t.mock.timers.tick(90_000);
  await failed;
  verify(true);
  await flush();
  assert.equal(f.installed.length, 0);
  assert.equal(f.sent.length, 1);
});

test('reset during confirmation cancels the handshake without authorizing its pending session', async (t) => {
  const f = fixture(t);
  const failed = assert.rejects(f.handshake.performHandshake(false), /cancelled by connection reset/);
  await flush();
  f.acknowledge();
  await flush();
  f.handshake.reset();
  await failed;
  assert.equal(f.confirmed.length, 0);
  assert.equal(f.handlers.size, 0);
});

test('wrong-session confirmations cannot activate the handshake', async (t) => {
  const f = fixture(t);
  const failed = assert.rejects(f.handshake.performHandshake(false), /Invalid encrypted handshake confirmation/);
  await flush();
  f.acknowledge();
  await flush();
  f.confirm({ sessionId: 'b'.repeat(32) });
  await failed;
  assert.equal(f.confirmed.length, 0);
});

test('Tor adaptation cannot extend a handshake phase beyond three minutes', async (t) => {
  const f = fixture(t, { multiplier: 6 });
  const failed = assert.rejects(f.handshake.performHandshake(false), /Handshake acknowledgment timeout/);
  await flush();
  t.mock.timers.tick(180_000);
  await failed;
});

test('auth exports the submit-state setter and signal wiring requires typed callbacks', () => {
  const source = fs.readFileSync('src/hooks/auth/useAuth.ts', 'utf8');
  const ast = ts.createSourceFile('useAuth.ts', source, ts.ScriptTarget.Latest, true);
  let returned;
  function visit(node) {
    if (ts.isReturnStatement(node) && node.expression && ts.isObjectLiteralExpression(node.expression)) {
      const names = node.expression.properties.map((property) => property.name?.getText(ast));
      if (names.includes('handleAccountSubmit')) returned = names;
    }
    ts.forEachChild(node, visit);
  }
  visit(ast);
  assert.ok(returned?.includes('setIsSubmittingAuth'));
  assert.match(fs.readFileSync('src/lib/types/signal-handler-types.ts', 'utf8'), /Authentication: AuthRefs;/);
});

test('an unlinked connection failure resets auth state and preserves its specific error event', async (t) => {
  const source = fs.readFileSync('src/lib/signals/auth-handlers.ts', 'utf8');
  const ast = ts.createSourceFile('auth-handlers.ts', source, ts.ScriptTarget.Latest, true);
  const handler = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === 'handleAuthFullSuccess');
  const operation = { requestId: 'request', account: 'self', signal: new AbortController().signal };
  const events = [];
  const dependencies = {
    captureAuthOperation: () => operation,
    assertAuthOperationCurrent: () => {},
    validateAuthCompletion: () => 'login',
    handlePrivacyPassIssuance: async () => {},
    replenishResumePool: async () => {},
    hasResumeToken: async () => true,
    keyTransparencyClient: { assertSecurityReady: async () => {} },
    getBlindRoutingClient: () => ({ setSendFunction() {} }),
    websocketClient: { markServerAuthGranted() {}, isServerEntryPromptPending: () => false, close: async () => {} },
    switchToUnlinkedModeOnce: async () => false,
    EventType: { AUTH_ERROR: 'auth-error' },
    window: { dispatchEvent: (event) => events.push(event.detail) },
  };
  const compiled = ts.transpileModule(handler.getText(ast).replace(/^export /, ''), {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const handle = new Function(...Object.keys(dependencies), `${compiled}; return handleAuthFullSuccess;`)(...Object.values(dependencies));
  const state = {};
  const auth = { loginUsernameRef: { current: 'self' } };
  for (const setter of ['setAuthStatus', 'setIsLoggedIn', 'setAccountAuthenticated', 'setIsSubmittingAuth', 'setLoginError']) {
    auth[setter] = (value) => { state[setter] = value; };
  }
  await handle({ authRequestId: 'request' }, auth);
  assert.equal(state.setAccountAuthenticated, false);
  assert.equal(state.setIsLoggedIn, false);
  assert.equal(state.setIsSubmittingAuth, false);
  assert.match(state.setLoginError, /Anonymous delivery connection/);
  assert.equal(events.length, 1);
  assert.equal(events[0].code, 'ANONYMOUS_SESSION_UNAVAILABLE');
});
