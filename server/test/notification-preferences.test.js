import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import ts from 'typescript';
import * as protocolKeys from '../../shared/protocol-keys.js';

function load(file, dependencies = {}) {
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const source = ast.statements.filter(node => !ts.isImportDeclaration(node)).map(node => node.getText(ast)).join('\n');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  new Function('exports', 'require', ...Object.keys(dependencies), compiled)(exports, createRequire(path.resolve(file)), ...Object.values(dependencies));
  return exports;
}

const keys = load('src/lib/database/storage-keys.ts');
const constants = load('src/lib/constants.ts', load('src/lib/config/protocol-keys.ts', protocolKeys));
const sanitizers = load('src/lib/sanitizers.ts', { ...constants, ...load('src/lib/types/signal-types.ts') });
const events = load('src/lib/types/event-types.ts');

async function flush() {
  for (let index = 0; index < 30; index++) await Promise.resolve();
}

async function fixture() {
  const storage = load('src/lib/database/encrypted-storage.ts', { ...constants, ...sanitizers, ...keys });
  const db = {
    data: new Map(),
    fail: false,
    isInitialized: () => true,
    async store(_table, key, value) {
      if (this.fail) throw new Error('write failed');
      this.data.set(key, value);
    },
    async retrieve(_table, key) { return this.data.get(key) ?? null; },
  };
  await storage.encryptedStorage.initialize(db);
  await storage.syncEncryptedStorage.initialize();
  const preferences = load('src/lib/ui/notification-preferences.ts', { ...storage, ...sanitizers, ...keys });
  return { ...storage, ...preferences, db };
}

test('message and call DND are independent and never replace conversation mutes', async () => {
  const f = await fixture();
  assert.deepEqual(f.getNotificationMutes('alice'), { messages: false, calls: false });
  f.setConversationNotificationMutes('alice', { messages: false, calls: true });
  f.setDoNotDisturb('messages', true);
  assert.deepEqual(f.getNotificationMutes('alice'), { messages: true, calls: true });
  assert.deepEqual(f.getNotificationMutes('bobby'), { messages: true, calls: false });
  f.setDoNotDisturb('messages', false);
  assert.deepEqual(f.getNotificationMutes('alice'), { messages: false, calls: true });
  f.setDoNotDisturb('calls', true);
  assert.deepEqual(f.getNotificationMutes('bobby'), { messages: false, calls: true });
});

test('each peer can mute messages, calls, both, or neither without changing other peers', async () => {
  const f = await fixture();
  f.setConversationNotificationMutes('bobby', { messages: true, calls: true });
  for (const messages of [false, true]) for (const calls of [false, true]) {
    f.setConversationNotificationMutes('alice', { messages, calls });
    assert.deepEqual(f.getNotificationMutes('alice'), { messages, calls });
    assert.deepEqual(f.getNotificationMutes('bobby'), { messages: true, calls: true });
  }
  f.setConversationNotificationMutes('alice', { messages: false, calls: false });
  assert.equal(f.readNotificationPreferences().conversations.some(entry => entry.username === 'alice'), false);
});

test('preferences reload from account storage and do not leak into a different account', async () => {
  const f = await fixture();
  f.setDoNotDisturb('calls', true);
  f.setConversationNotificationMutes('alice', { messages: true, calls: false });
  await flush();
  f.syncEncryptedStorage.reset();
  assert.deepEqual(f.getNotificationMutes('alice'), { messages: false, calls: false });
  await f.encryptedStorage.initialize({ ...f.db, data: new Map() });
  await f.syncEncryptedStorage.initialize();
  assert.deepEqual(f.getNotificationMutes('alice'), { messages: false, calls: false });
  f.syncEncryptedStorage.reset();
  await f.encryptedStorage.initialize(f.db);
  await f.syncEncryptedStorage.initialize();
  assert.deepEqual(f.getNotificationMutes('alice'), { messages: true, calls: true });
});

test('observers update immediately and receive persistence rollback and account reset', async t => {
  const f = await fixture();
  const changes = [];
  const unsubscribe = f.subscribeNotificationPreferences(() => changes.push(f.getNotificationMutes('alice')));
  f.setDoNotDisturb('messages', true);
  assert.deepEqual(changes.at(-1), { messages: true, calls: false });
  await flush();
  t.mock.method(console, 'error', () => {});
  f.db.fail = true;
  f.setDoNotDisturb('calls', true);
  assert.deepEqual(changes.at(-1), { messages: true, calls: true });
  await flush();
  assert.deepEqual(changes.at(-1), { messages: true, calls: false });
  f.syncEncryptedStorage.reset();
  assert.deepEqual(changes.at(-1), { messages: false, calls: false });
  unsubscribe();
  const count = changes.length;
  f.syncEncryptedStorage.reset();
  assert.equal(changes.length, count);
});

test('invalid preferences and duplicate or noncanonical usernames are rejected', async () => {
  const f = await fixture();
  const valid = { doNotDisturb: { messages: false, calls: false }, conversations: [] };
  for (const invalid of [
    {}, { ...valid, extra: true },
    { ...valid, doNotDisturb: { messages: 'true', calls: false } },
    { ...valid, conversations: [{ username: 'Alice', messages: true, calls: false }] },
    { ...valid, conversations: Array(2).fill({ username: 'alice', messages: true, calls: false }) },
    { ...valid, conversations: [{ username: 'alice', messages: true, calls: false, extra: true }] },
  ]) assert.throws(() => f.parseNotificationPreferences(JSON.stringify(invalid)));
  assert.throws(() => f.parseNotificationPreferences('{"__proto__":{},"conversations":[],"doNotDisturb":{"messages":false,"calls":false}}'));
  assert.throws(() => f.parseNotificationPreferences(' '.repeat(128 * 1024 + 1)));
  assert.throws(() => f.setConversationNotificationMutes(' Alice ', { messages: true, calls: true }));
});

test('message DND suppresses alerts without suppressing another peer or self-message checks', async () => {
  const f = await fixture();
  let alerts = 0;
  let badges = 0;
  const { showNotification } = load('src/hooks/message-handling/handlers.ts', {
    ...f,
    document: { hidden: true, hasFocus: () => false },
    notifications: { show: async () => { alerts++; } },
    tray: { incrementUnread: async () => { badges++; } },
  });
  f.setConversationNotificationMutes('alice', { messages: true, calls: false });
  showNotification({ from: 'alice' }, 'owner');
  showNotification({ from: 'owner' }, 'owner');
  assert.equal(alerts, 0);
  showNotification({ from: 'bobby' }, 'owner');
  assert.equal(alerts, 1);
  assert.equal(badges, 1);
  f.setDoNotDisturb('messages', true);
  showNotification({ from: 'bobby' }, 'owner');
  assert.equal(alerts, 1);
});

test('muted incoming calls retain call history but cannot trigger desktop alerts', async () => {
  const f = await fixture();
  const logs = [];
  let incoming;
  let pending = [];
  let alerts = 0;
  const { setupIncomingCallCallback } = load('src/hooks/calling/callbacks.ts', {
    ...f, ...events,
    document: { hidden: true, hasFocus: () => false },
    notifications: { show: async () => { alerts++; } },
    tray: { incrementUnread: async () => {} },
  });
  setupIncomingCallCallback(
    { onIncomingCall: callback => { incoming = callback; } },
    { eventDebouncer: { current: { enqueue: (...args) => logs.push(args) } } },
    { setPendingIncomingCalls: update => { pending = update(pending); } },
    'owner',
  );
  f.setConversationNotificationMutes('alice', { messages: false, calls: true });
  incoming({ id: 'first', peer: 'alice', type: 'audio', direction: 'incoming' });
  assert.equal(alerts, 0);
  assert.equal(pending.length, 1);
  assert.equal(logs[0][1].peer, 'alice');
  incoming({ id: 'second', peer: 'bobby', type: 'video', direction: 'incoming' });
  assert.equal(alerts, 1);
  f.setDoNotDisturb('calls', true);
  incoming({ id: 'third', peer: 'bobby', type: 'audio', direction: 'incoming' });
  assert.equal(alerts, 1);
  assert.equal(logs.length, 3);
});

test('calling UI filters muted ringing peers reactively without ending the active call', async () => {
  const f = await fixture();
  const activeCall = { id: 'active', peer: 'alice', status: 'connected', direction: 'outgoing' };
  const pending = ['alice', 'bobby'].map(peer => ({ id: peer, peer, status: 'ringing', direction: 'incoming' }));
  const actions = Object.fromEntries([
    'StartCall', 'AnswerCall', 'DeclineCall', 'EndCall', 'ToggleMute', 'ToggleVideo', 'SwitchCamera',
    'SwitchMicrophone', 'SwitchSpeaker', 'StartScreenShare', 'StopScreenShare',
  ].map(name => [`create${name}`, () => () => {}]));
  let stateIndex = 0;
  const { useCalling } = load('src/hooks/calling/useCalling.ts', {
    ...f, ...actions,
    useState: initial => [[null, activeCall, pending][stateIndex++] ?? initial, () => {}],
    useRef: current => ({ current }),
    useEffect: () => {},
    useCallback: callback => callback,
    useNotificationPreferences: f.readNotificationPreferences,
    debounceEventDispatcher: () => ({}),
  });
  const render = () => {
    stateIndex = 0;
    return useCalling({ username: 'owner', isLoggedIn: true, accountAuthenticated: true }, {});
  };
  assert.equal(render().pendingIncomingCalls.length, 2);
  f.setConversationNotificationMutes('alice', { messages: false, calls: true });
  assert.deepEqual(render().pendingIncomingCalls.map(call => call.peer), ['bobby']);
  f.setDoNotDisturb('calls', true);
  assert.equal(render().pendingIncomingCalls.length, 0);
  assert.equal(render().currentCall, activeCall);
  f.setDoNotDisturb('calls', false);
  assert.deepEqual(render().pendingIncomingCalls.map(call => call.peer), ['bobby']);
});
