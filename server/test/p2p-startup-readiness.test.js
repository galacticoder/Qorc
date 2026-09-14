import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const read = (file) => fs.readFileSync(file, 'utf8');
const sourceFile = (file) => ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true);

function compile(body, dependencies = {}) {
  const compiled = ts.transpileModule(body, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
  return exports;
}

function load(file, dependencies = {}) {
  const ast = sourceFile(file);
  return compile(ast.statements.filter((node) => !ts.isImportDeclaration(node))
    .map((node) => node.getText(ast)).join('\n'), dependencies);
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function flush() {
  for (let index = 0; index < 64; index += 1) await Promise.resolve();
}

const certificate = {
  kyberPublicKey: 'kem', dilithiumPublicKey: 'sign', x25519PublicKey: 'exchange',
  issuedAt: 10, expiresAt: 20,
};

function certificateLoader(options = {}) {
  const calls = [];
  const { loadAuthorizedPeerCertificate } = load('src/lib/p2p/authorized-peer-certificate.ts', {
    loadPersistedPeerCert: async (...args) => { calls.push(['certificate', ...args]); return options.persisted ?? null; },
    loadTrustedPersistedDiscoveryMaterial: async (...args) => {
      calls.push(['discovery-cache', ...args]);
      return options.material ?? { peerCertificate: certificate };
    },
    computePeerCertificateFingerprint: () => 'fingerprint',
    isKeyTransparencyAuthorizedPeerCertificate: (input) => {
      calls.push(['authorize', input]);
      return options.authorized !== false;
    },
  });
  return { loadAuthorizedPeerCertificate, calls };
}

test('a discovered peer restores its certificate without a separate certificate record or network lookup', async () => {
  const f = certificateLoader();
  assert.equal(await f.loadAuthorizedPeerCertificate('alice', 'bob', () => true), certificate);
  assert.deepEqual(f.calls[0], ['certificate', 'alice', 'bob', true]);
  assert.deepEqual(f.calls[1], ['discovery-cache', 'alice', 'bob']);
  assert.equal(f.calls[2][1].peerCertificateFingerprint, 'fingerprint');
});

test('an authorized certificate record avoids reading discovery data again', async () => {
  const f = certificateLoader({ persisted: certificate });
  assert.equal(await f.loadAuthorizedPeerCertificate('alice', 'bob', () => true), certificate);
  assert.equal(f.calls.some(([kind]) => kind === 'discovery-cache'), false);
});

test('saved certificates cannot bypass transparency authorization', async () => {
  const f = certificateLoader({ persisted: certificate, authorized: false });
  assert.equal(await f.loadAuthorizedPeerCertificate('alice', 'bob', () => true), null);
});

test('account changes cancel local certificate restoration before using the result', async () => {
  const f = certificateLoader();
  let checks = 0;
  assert.equal(await f.loadAuthorizedPeerCertificate('alice', 'bob', () => ++checks === 1), null);
  assert.equal(f.calls.length, 1);
});

test('cache-only certificate preparation can use discovery data without fetching or rewriting it', async () => {
  const f = certificateLoader();
  let fetched = 0;
  let saved = 0;
  const { createGetPeerCertificate } = load('src/hooks/p2p/certificates.ts', {
    ...f,
    computePeerCertificateFingerprint: () => 'fingerprint',
    isKeyTransparencyAuthorizedPeerCertificate: () => true,
    P2P_PEER_CACHE_TTL_MS: 300_000,
    MAX_P2P_CERT_CACHE_SIZE: 128,
    savePersistedPeerCert: async () => { saved += 1; },
  });
  const cache = { current: new Map() };
  const get = createGetPeerCertificate({ peerCertificateCacheRef: cache }, {
    ownerUsername: 'alice', isCurrentOwner: () => true,
    fetchPeerCertificates: async () => { fetched += 1; return null; },
  });
  const cached = await get('bob', false, true);
  assert.deepEqual(cached, certificate);
  assert.equal(await get('bob'), cached);
  assert.equal(fetched, 0);
  assert.equal(saved, 0);
});

function inboundFixture(t, options = {}) {
  const calls = { restored: [], registered: [], handshakes: [], disconnected: [] };
  const blocked = new Set();
  const revoked = new Set();
  const ast = sourceFile('src/lib/transport/p2p-transport.ts');
  const declaration = ast.statements.find((node) => ts.isClassDeclaration(node) && node.name.text === 'P2PTransport');
  const names = new Set([
    'restoreInboundPeerTrust', 'processInboundBridgeEvent', 'releaseUnauthenticatedBridgeAlias',
    'getPeerIdentityEpoch', 'resolvePeerKey', 'resolveAppPeerId', 'connectionReadinessScore',
    'isCurrentConnection', 'enqueueInboundBridgeEvent', 'estimateBridgeEventBytes', 'drainInboundBridgeEventQueue',
  ]);
  const members = declaration.members.filter((node) => ts.isPropertyDeclaration(node) || names.has(node.name?.getText(ast)));
  const { P2PTransport } = compile(`export class P2PTransport { ${members.map((node) => node.getText(ast)).join('\n')} }`, {
    keyTransparencyClient: { restorePersistedAuthorizations: async () => {} },
    loadAuthorizedPeerCertificate: async (account, peer, isCurrent) => {
      calls.restored.push([account, peer]);
      if (options.pending) await options.pending;
      return isCurrent() ? (options.unknown ? null : certificate) : null;
    },
    isKeyTransparencyPeerRevoked: (_account, peer) => revoked.has(peer),
    blockingSystem: { isEnforcementReady: () => true, isBlockedSync: (peer) => blocked.has(peer) },
    isNativeConnectionToken: (token) => Number.isSafeInteger(token) && token > 0,
    p2p: { disconnect: async (...args) => { calls.disconnected.push(args); } },
    P2PConnection: class {
      state = 'handshaking';
      constructor(_key, identity) { this.peerIdentity = identity; }
      onStateChange() {}
      hasNativeConnectionGeneration() { return false; }
      attachBridgeConnection() {}
      handleBridgeEventMessage(message) { calls.handshakes.push(message); }
    },
  });
  const transport = Object.assign(new P2PTransport(), {
    initialized: true, localUsername: 'alice', localPeerId: 'alice', ownKeys: {},
    inferPeerFromHandshakeInit: (message) => message?.type === 'init' ? message.from : null,
    isOpaqueBridgeId: (id) => id.startsWith('inbound:'),
    isSafePeerId: () => true,
    registerUsernameAlias: () => true,
    validateCertifiedPeerIdentity: (_peer, identity) => identity,
    registerPeerCertificate: async (peer, cert) => {
      calls.registered.push([peer, cert]);
      transport.knownPeerIdentities.set(peer, { username: peer, certVerified: true });
    },
  });
  const receive = (peer = 'bob', token = 1) => transport.processInboundBridgeEvent({
    type: 'message', connectionId: `inbound:${token}`, connectionToken: token,
    data: { type: 'init', from: peer },
  });
  t.after(() => { for (const pending of transport.pendingInboundTrust.values()) pending.cancel(); });
  return { transport, calls, blocked, revoked, receive };
}

test('an inbound handshake restores local trust before admission without opening a conversation', async (t) => {
  const f = inboundFixture(t);
  f.receive();
  assert.equal(f.calls.handshakes.length, 0);
  await flush();
  assert.deepEqual(f.calls.restored, [['alice', 'bob']]);
  assert.equal(f.calls.registered[0][1], certificate);
  assert.equal(f.calls.handshakes.length, 1);
  assert.equal(f.calls.disconnected.length, 0);
  assert.equal(f.transport.pendingInboundTrust.size, 0);
});

test('an unknown inbound identity is rejected without network discovery', async (t) => {
  const f = inboundFixture(t, { unknown: true });
  f.receive();
  await flush();
  assert.equal(f.calls.registered.length, 0);
  assert.equal(f.calls.handshakes.length, 0);
  assert.deepEqual(f.calls.disconnected, [['inbound:1', 1]]);
});

for (const state of ['pending-dial', 'active-dial', 'established']) {
  test(`inbound collision arbitration handles a ${state} without replacing a working connection`, (t) => {
    const f = inboundFixture(t);
    let adopted = 0;
    const existing = {
      state: state === 'established' ? 'connected' : 'connecting',
      peerIdentity: { username: 'bob', certVerified: true },
      ownsBridgeConnection: () => false,
      ownsExactBridgeConnection: () => false,
      hasNativeConnectionGeneration: () => state !== 'pending-dial',
      getSession: () => state === 'established' ? {} : null,
      adoptIncomingBridgeConnection: () => { adopted += 1; },
      handleBridgeEventMessage: (message) => f.calls.handshakes.push(message),
    };
    f.transport.connections.set('bob', existing);
    f.receive();
    assert.equal(adopted, state === 'pending-dial' ? 1 : 0);
    assert.equal(f.calls.handshakes.length, state === 'pending-dial' ? 1 : 0);
    assert.equal(f.calls.disconnected.length, state === 'pending-dial' ? 0 : 1);
  });
}

test('an authenticated inbound connection releases the original send before an obsolete outbound dial finishes', async () => {
  const ast = sourceFile('src/lib/transport/p2p-transport.ts');
  const declaration = ast.statements.find((node) => ts.isClassDeclaration(node) && node.name.text === 'P2PConnection');
  const method = declaration.members.find((node) => node.name?.getText(ast) === 'connect');
  const { Connection } = compile(`export class Connection { ${method.getText(ast)} }`);
  const pending = deferred();
  const handlers = new Set();
  let dialCompleted = false;
  const connection = Object.assign(new Connection(), {
    _state: 'disconnected', session: null, connectPromise: null, incomingAdoptionVersion: 0,
    onStateChange: (handler) => { handlers.add(handler); return () => handlers.delete(handler); },
    setState: (state) => {
      connection._state = state;
      for (const handler of handlers) handler(state);
    },
    connectViaP2PBridge: async () => {
      await pending.promise;
      dialCompleted = true;
      throw new Error('obsolete dial failed');
    },
    waitForIncomingAdoption: async () => { assert.equal(connection._state, 'connected'); },
  });
  const first = connection.connect();
  const second = connection.connect();
  connection.incomingAdoptionVersion += 1;
  connection.role = 'responder';
  connection.session = {};
  connection.setState('connected');
  await Promise.all([first, second]);
  assert.equal(dialCompleted, false);
  assert.equal(handlers.size, 0);
  assert.equal(connection.connectPromise, null);
  pending.resolve();
  await flush();
  assert.equal(dialCompleted, true);
  assert.equal(connection._state, 'connected');
});

for (const transition of ['account', 'revoked', 'blocked', 'closed', 'replaced-identity']) {
  test(`inbound trust restoration cannot survive a ${transition} transition`, async (t) => {
    const pending = deferred();
    const f = inboundFixture(t, { pending: pending.promise });
    f.receive();
    await flush();
    if (transition === 'account') f.transport.lifecycleGeneration += 1;
    if (transition === 'revoked') f.revoked.add('bob');
    if (transition === 'blocked') f.blocked.add('bob');
    if (transition === 'replaced-identity') f.transport.peerIdentityEpochs.set('bob', 1);
    if (transition === 'closed') f.transport.processInboundBridgeEvent({
      type: '__p2p_closed', connectionId: 'inbound:1', connectionToken: 1,
    });
    pending.resolve();
    await flush();
    assert.equal(f.calls.registered.length, 0);
    assert.equal(f.calls.handshakes.length, 0);
    assert.equal(f.transport.pendingInboundTrust.size, 0);
  });
}

test('inbound trust restoration is deduplicated and bounded', async (t) => {
  const pending = deferred();
  const f = inboundFixture(t, { pending: pending.promise });
  f.receive();
  f.receive();
  await flush();
  assert.equal(f.calls.restored.length, 1);
  for (let token = 2; token <= 33; token += 1) f.receive(`peer${token}`, token);
  await flush();
  assert.equal(f.transport.pendingInboundTrust.size, 32);
  assert.deepEqual(f.calls.disconnected, [['inbound:33', 33]]);
  pending.resolve();
});

test('a stalled local trust read releases its inbound connection', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const pending = deferred();
  const f = inboundFixture(t, { pending: pending.promise });
  f.receive();
  await flush();
  t.mock.timers.tick(10_000);
  assert.equal(f.transport.pendingInboundTrust.size, 0);
  assert.deepEqual(f.calls.disconnected, [['inbound:1', 1]]);
  pending.resolve();
  await flush();
  assert.equal(f.calls.handshakes.length, 0);
});

function hookFixture(t, options = {}) {
  const events = new EventTarget();
  const refs = [];
  const effects = [];
  const cleanups = [];
  const calls = { certificates: [], connected: [], registered: [], refreshed: [] };
  const endpoints = new Map();
  const { EventType } = load('src/lib/types/event-types.ts');
  const { useP2PMessaging } = load('src/hooks/p2p/useP2PMessaging.ts', {
    useRef: (initial) => {
      const ref = { current: refs.length === 0 ? {} : initial };
      refs.push(ref);
      return ref;
    },
    useState: () => [{ isInitialized: true }, () => {}],
    useMemo: (callback) => callback(),
    useCallback: (callback) => callback,
    useLayoutEffect: (callback) => { const cleanup = callback(); if (cleanup) cleanups.push(cleanup); },
    useEffect: (callback) => effects.push(callback),
    createGetPeerCertificate: () => async (...args) => { calls.certificates.push(args); return certificate; },
    createDestroyService: () => async () => {},
    createInitializeP2P: () => async () => {},
    createIsPeerConnected: () => () => false,
    createConnectToPeer: () => async (peer) => {
      calls.connected.push([peer, endpoints.get(peer)]);
      if (options.connect) await options.connect(peer);
    },
    createHandleIncomingP2PMessage: () => async () => true,
    createP2PError: (message) => new Error(message),
    loadPersistedPeerEndpoint: async () => null,
    keyTransparencyClient: { restorePersistedAuthorizations: async () => {} },
    p2pTransport: {
      registerPeerCertificate: async (...args) => { calls.registered.push(args); },
      hasAuthenticatedEndpoint: (peer) => endpoints.has(peer),
      getAuthenticatedEndpoint: (peer) => endpoints.get(peer) ?? null,
    },
    invalidateDiscoveryCache: (peer) => calls.refreshed.push(peer),
    isPlainObject: (value) => value !== null && typeof value === 'object',
    hasPrototypePollutionKeys: () => false,
    isKeyTransparencyHash: () => true,
    isKeyTransparencyPeerRevoked: () => false,
    KEY_TRANSPARENCY_MAX_LOG_SIZE: 1_000_000,
    AUTH_USERNAME_REGEX: /^[a-z0-9]+$/,
    MAX_CONCURRENT_P2P_CONNECTS: 8,
    EventType,
    window: events,
    console: { error() {}, warn() {} },
  });
  const hook = useP2PMessaging('alice', { native: true }, {
    knownPeers: ['bob', 'carol'], fetchPeerCertificates: async () => null,
    onServiceReady() {}, handleEncryptedMessagePayload: async () => true,
  });
  for (const effect of effects) {
    const cleanup = effect();
    if (cleanup) cleanups.push(cleanup);
  }
  t.after(() => { for (const cleanup of cleanups) cleanup(); });
  const announce = (peer, endpoint, account = 'alice') => {
    endpoints.set(peer, endpoint);
    events.dispatchEvent(new CustomEvent(EventType.P2P_ENDPOINT_RECEIVED, { detail: { account, peer } }));
  };
  return { hook, calls, refs, announce };
}

test('startup preloads all known peers locally with no periodic forced discovery', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const f = hookFixture(t);
  await flush();
  assert.deepEqual(f.calls.certificates, [['bob', false, true], ['carol', false, true]]);
  assert.equal(f.calls.registered.length, 2);
  for (let index = 0; index < 10; index += 1) {
    t.mock.timers.tick(90_000);
    await flush();
  }
  assert.equal(f.calls.certificates.length, 2);
  assert.equal(f.calls.refreshed.length, 0);
});

test('authenticated endpoint receipt dials outside a selected conversation and only once per address', async (t) => {
  const f = hookFixture(t);
  f.announce('bob', 'new-address');
  await flush();
  f.announce('bob', 'new-address');
  await flush();
  assert.deepEqual(f.calls.connected, [['bob', 'new-address']]);
  f.announce('bob', 'newer-address');
  await flush();
  assert.deepEqual(f.calls.connected.at(-1), ['bob', 'newer-address']);
  assert.equal(f.calls.connected.length, 2);
});

test('an old account endpoint event cannot trigger a connection', async (t) => {
  const f = hookFixture(t);
  f.announce('bob', 'new-address', 'carol');
  await flush();
  assert.equal(f.calls.connected.length, 0);
});

test('a new endpoint waits for the old failed dial, then bypasses only that old cooldown', async (t) => {
  const pending = deferred();
  let attempt = 0;
  const f = hookFixture(t, { connect: async () => {
    if (++attempt === 1) {
      await pending.promise;
      throw new Error('onion dial failed: Host unreachable');
    }
  } });
  const old = f.hook.connectToPeer('bob');
  await flush();
  f.announce('bob', 'new-address');
  await flush();
  assert.equal(f.calls.connected.length, 1);
  pending.resolve();
  await assert.rejects(old, /Host unreachable/);
  await flush();
  assert.equal(f.calls.connected.length, 2);
  assert.deepEqual(f.calls.connected.at(-1), ['bob', 'new-address']);
  assert.equal(f.calls.refreshed.length, 0);
});

test('a dial cooldown rejects instead of claiming the peer is ready', async (t) => {
  const f = hookFixture(t, { connect: async () => { throw new Error('Host unreachable'); } });
  await assert.rejects(f.hook.connectToPeer('bob'), /Host unreachable/);
  await assert.rejects(f.hook.connectToPeer('bob'), /cooling down/);
  assert.equal(f.calls.connected.length, 1);
});

test('contact metadata updates do not recreate the certificate fetch callback', () => {
  const ast = sourceFile('src/pages/Index.tsx');
  let dependencyText;
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === 'fetchPeerCertificates') {
      dependencyText = node.initializer.arguments[1].getText(ast);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  assert.equal(dependencyText, '[findUser, Database.setUsers]');
});
