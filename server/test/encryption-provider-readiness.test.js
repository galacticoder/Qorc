import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';
import { DISCOVERY_LOOKUP_TIMEOUT_MS } from '../../shared/anonymous-transfer-policy.js';

function loadSource(file, dependencies = {}) {
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

const { EventType } = loadSource('src/lib/types/event-types.ts');
const { SignalType } = loadSource('src/lib/types/signal-types.ts');
const { createBoundedMapSetter } = loadSource('src/lib/utils/message-state-limits.ts');
const AUTH_USERNAME_REGEX = /^[a-z0-9]{3,32}$/;
const sanitizeMessageId = (value) => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value) ? value : undefined;
const hybridKeys = {
  kyberPublicBase64: 'verified-kyber',
  dilithiumPublicBase64: 'verified-dilithium',
  x25519PublicBase64: 'verified-x25519',
};
const material = {
  publicKeys: hybridKeys,
  fullBundle: { identityKeyBase64: 'verified-identity' },
  spoolDetectionKey: 'verified-detection-key',
};

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

async function flush() {
  for (let index = 0; index < 80; index += 1) await Promise.resolve();
}

function fixture(t, options = {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const window = Object.assign(new EventTarget(), {
    setTimeout: (...args) => setTimeout(...args),
  });
  const state = { session: true, staticKey: false, revoked: false, ...options.state };
  const calls = { discovery: 0, install: 0, encrypt: 0, nativeKey: 0, denials: [], errors: [] };
  let provider;
  const unifiedSignalTransport = {
    setEncryptionProvider(value) { provider = value; },
    noteEncryptionDenial(to, type, reason) { calls.denials.push({ to, type, reason }); },
    resetForAccountTransition() {},
    async send(to, payload, type) {
      const result = await provider(to, payload, type);
      return { success: !!result };
    },
  };
  const signal = {
    hasSession: async () => options.hasSession ? options.hasSession(state) : state.session,
    hasPeerStaticMlkemKey: async () => { calls.nativeKey += 1; return state.staticKey; },
    installTransparencyVerifiedPeerIdentity: async () => true,
    revokeTransparencyPeerIdentity: async () => {},
    processVerifiedPreKeyBundle: async (...args) => {
      calls.install += 1;
      if (options.install) return options.install(...args);
      state.session = true;
      state.staticKey = true;
      return true;
    },
    deleteAllSessions: async () => { state.session = false; state.staticKey = false; },
    encrypt: async () => {
      assert.equal(state.session, true);
      assert.equal(state.staticKey, true);
      calls.encrypt += 1;
      return 'ciphertext';
    },
  };
  const refs = [];
  let refIndex = 0;
  let cleanups = [];
  const { useEncryptionProvider } = loadSource('src/hooks/app/useEncryptionProvider.ts', {
    useRef(value) {
      const index = refIndex++;
      return refs[index] ??= { current: value };
    },
    useEffect(effect) { const cleanup = effect(); if (cleanup) cleanups.push(cleanup); },
    CryptoUtils: { Hybrid: { encryptForClient: async () => 'envelope' } },
    EventType,
    SignalType,
    DISCOVERY_LOOKUP_TIMEOUT_MS,
    isAckTrackedSignalType: () => false,
    unifiedSignalTransport,
    keyTransparencyClient: {
      restorePersistedAuthorizations: async () => {},
      isSecurityIncidentActive: () => false,
      getGossipHead: () => null,
    },
    isKeyTransparencyAuthorizedPeerKeySet: () => !state.revoked,
    isKeyTransparencyPeerRevoked: () => state.revoked,
    awaitPeerIdentityRevocation: async () => false,
    account: {},
    signal,
    shouldAttemptDiscovery: () => true,
    extractX25519FromSignalBundle: () => hybridKeys.x25519PublicBase64,
    loadTrustedPersistedDiscoveryMaterial: async () => null,
    resolveTrustedPeerHybridPublicKeys: async () => ({
      valid: options.trusted !== false,
      hybridKeys,
      peerCertificateFingerprint: 'certificate',
      identityRootFingerprint: 'root',
      identityBundleFingerprint: 'bundle',
    }),
    p2pTransport: { getLocalEndpointForIdentity: async () => undefined },
    isValidDilithiumPublicKeyBase64: (value) => value === hybridKeys.dilithiumPublicBase64,
    isValidKyberPublicKeyBase64: (value) => value === hybridKeys.kyberPublicBase64,
    isValidX25519PublicKeyBase64: (value) => value === hybridKeys.x25519PublicBase64,
    AUTH_USERNAME_REGEX,
    MAX_SIGNAL_PAYLOAD_JSON_BYTES: 65536,
    hasPrototypePollutionKeys: () => false,
    isPlainObject: (value) => value !== null && typeof value === 'object' && !Array.isArray(value),
    sanitizeMessageId,
    rememberPeerDetectionKey() {},
    clearPersistedDiscoveryMaterial: async () => {},
    createBoundedMapSetter,
    PROTOCOL_KEYS: {},
    window,
    setTimeout: (...args) => setTimeout(...args),
    clearTimeout: (...args) => clearTimeout(...args),
    console: { warn() {}, error(...args) { calls.errors.push(args); } },
  });
  const loginUsernameRef = { current: 'alice' };
  const props = {
    isLoggedIn: true,
    loginUsernameRef,
    getPeerHybridKeys: async () => options.routingKeys === false ? null : hybridKeys,
    getKeysOnDemand: async () => ({ native: true, dilithium: { publicKeyBase64: hybridKeys.dilithiumPublicBase64 } }),
    findUser: async () => { calls.discovery += 1; return options.findUser ? options.findUser() : material; },
  };
  const render = () => {
    for (const cleanup of cleanups) cleanup();
    cleanups = [];
    refIndex = 0;
    useEncryptionProvider(props);
  };
  render();
  t.after(() => { for (const cleanup of cleanups) cleanup(); });
  const encrypt = (type = SignalType.RECEIPT_BATCH) => provider('bob', { deliveredIds: ['a'.repeat(32)], readIds: [] }, type);
  return { calls, state, encrypt, window, render, loginUsernameRef, unifiedSignalTransport };
}

test('a first receipt waits for the peer static key instead of reporting no Signal session', async (t) => {
  const lookup = deferred();
  const f = fixture(t, { findUser: () => lookup.promise });
  let settled = false;
  const result = f.encrypt().then((value) => { settled = true; return value; });
  await flush();
  t.mock.timers.tick(30_000);
  await flush();
  assert.equal(settled, false);
  assert.equal(f.calls.discovery, 1);
  assert.equal(f.calls.encrypt, 0);
  assert.deepEqual(f.calls.denials, []);
  lookup.resolve(material);
  assert.equal((await result).encryptedPayload, 'envelope');
  assert.equal(f.calls.install, 1);
  assert.equal(f.calls.encrypt, 1);
});

test('the receipt batch does not spend retries while key setup is running', async (t) => {
  const lookup = deferred();
  const f = fixture(t, { findUser: () => lookup.promise });
  const { ReceiptBatcher } = loadSource('src/hooks/message-handling/receipt-batcher.ts', {
    SignalType,
    unifiedSignalTransport: f.unifiedSignalTransport,
    AUTH_USERNAME_REGEX,
    RECEIPT_BATCH_WINDOW_MS: 300,
    MAX_RECEIPT_BATCH_IDS: 64,
    sanitizeMessageId,
    EventType,
    window: f.window,
    setTimeout: (...args) => setTimeout(...args),
    clearTimeout: (...args) => clearTimeout(...args),
  });
  const batcher = new ReceiptBatcher();
  batcher.setActiveAccount('alice');
  t.after(() => batcher.setActiveAccount(null));
  const flushed = [];
  batcher.addFlushListener((...args) => flushed.push(args));
  assert.equal(batcher.queueDelivery('alice', 'bob', 'a'.repeat(32)), true);
  await flush();
  for (let attempt = 0; attempt < 10; attempt += 1) {
    t.mock.timers.tick(300);
    await flush();
  }
  assert.deepEqual(f.calls.denials, []);
  lookup.resolve(material);
  await flush();
  assert.deepEqual(flushed, [['alice', 'bob', ['a'.repeat(32)], []]]);
  assert.equal(f.calls.encrypt, 1);
});

test('parallel first replies share one key installation', async (t) => {
  const lookup = deferred();
  const f = fixture(t, { findUser: () => lookup.promise });
  const first = f.encrypt();
  const second = f.encrypt();
  await flush();
  assert.equal(f.calls.discovery, 1);
  lookup.resolve(material);
  assert.ok((await Promise.all([first, second])).every(Boolean));
  assert.equal(f.calls.install, 1);
  assert.equal(f.calls.encrypt, 2);
});

test('a restored native key needs no discovery or bundle installation', async (t) => {
  const f = fixture(t, { state: { staticKey: true } });
  assert.ok(await f.encrypt());
  assert.equal(f.calls.nativeKey, 1);
  assert.equal(f.calls.discovery, 0);
  assert.equal(f.calls.install, 0);
});

test('typing defers explicitly and a receipt joins its pending key installation', async (t) => {
  const lookup = deferred();
  const f = fixture(t, { findUser: () => lookup.promise });
  assert.equal(await f.encrypt(SignalType.TYPING_START), null);
  assert.equal(f.calls.denials.at(-1).reason, 'deferrable-signal-awaiting-peer-key-install');
  const receipt = f.encrypt();
  await flush();
  lookup.resolve(material);
  assert.ok(await receipt);
  assert.equal(f.calls.discovery, 1);
  assert.equal(f.calls.install, 1);
});

test('a failed native key installation is not cached as successful', async (t) => {
  const f = fixture(t, { install: async () => false });
  assert.equal(await f.encrypt(), null);
  assert.equal(await f.encrypt(), null);
  assert.equal(f.calls.install, 2);
  assert.equal(f.calls.encrypt, 0);
  assert.equal(f.calls.denials.at(-1).reason, 'no-signal-session');
});

test('untrusted discovery material cannot install keys or encrypt receipts', async (t) => {
  const f = fixture(t, { trusted: false });
  assert.equal(await f.encrypt(), null);
  assert.equal(f.calls.install, 0);
  assert.equal(f.calls.encrypt, 0);
});

test('an account transition during lookup prevents key installation and encryption', async (t) => {
  const lookup = deferred();
  const f = fixture(t, { findUser: () => lookup.promise });
  const receipt = f.encrypt();
  await flush();
  f.loginUsernameRef.current = 'carol';
  f.render();
  lookup.resolve(material);
  assert.equal(await receipt, null);
  assert.equal(f.calls.install, 0);
  assert.equal(f.calls.encrypt, 0);
  assert.equal(f.calls.denials.at(-1).reason, 'stale-operation');
});

test('an obsolete in-flight installation cannot repopulate the renderer key cache', async (t) => {
  const installation = deferred();
  const f = fixture(t, { install: () => installation.promise });
  const receipt = f.encrypt();
  await flush();
  assert.equal(f.calls.install, 1);
  f.window.dispatchEvent(new Event(EventType.HYBRID_KEYS_UPDATED));
  installation.resolve(true);
  assert.equal(await receipt, null);
  const checksBefore = f.calls.nativeKey;
  f.state.staticKey = true;
  assert.ok(await f.encrypt());
  assert.equal(f.calls.nativeKey, checksBefore + 1);
});

test('receipt discovery uses the full lookup deadline', async (t) => {
  const lookup = deferred();
  const f = fixture(t, { routingKeys: false, findUser: () => lookup.promise });
  let settled = false;
  const receipt = f.encrypt().then((value) => { settled = true; return value; });
  await flush();
  t.mock.timers.tick(5 * 60_000);
  await flush();
  assert.equal(settled, false);
  lookup.resolve(material);
  assert.ok(await receipt);
  assert.deepEqual(f.calls.denials, []);
});

test('an inbound session appearing during setup still installs the peer static key', async (t) => {
  let checks = 0;
  const f = fixture(t, {
    state: { session: false },
    hasSession(state) {
      checks += 1;
      if (checks > 1) state.session = true;
      return state.session;
    },
  });
  assert.ok(await f.encrypt());
  assert.equal(f.calls.install, 1);
  assert.equal(f.calls.encrypt, 1);
});

test('a failed session validation releases waiting sends without an eight-second timeout', async (t) => {
  const validation = deferred();
  let checks = 0;
  const f = fixture(t, {
    state: { session: false },
    hasSession(state) {
      checks += 1;
      return checks === 2 ? validation.promise : state.session;
    },
  });
  const first = f.encrypt();
  await flush();
  assert.equal(checks, 2);
  let nextSettled = false;
  const next = f.encrypt().then((value) => { nextSettled = true; return value; });
  await flush();
  assert.equal(nextSettled, false);
  f.state.session = true;
  f.state.staticKey = true;
  validation.reject(new Error('Native session read failed'));
  assert.equal(await first, null);
  await flush();
  assert.equal(nextSettled, true);
  assert.ok(await next);
});

test('revocation while a bundle is installing prevents encryption', async (t) => {
  const installation = deferred();
  const f = fixture(t, { install: () => installation.promise });
  const receipt = f.encrypt();
  await flush();
  f.state.revoked = true;
  installation.resolve(true);
  assert.equal(await receipt, null);
  assert.equal(f.calls.encrypt, 0);
});
