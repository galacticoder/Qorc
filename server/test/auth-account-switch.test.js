import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import ts from 'typescript';

const oldOwner = 'a'.repeat(64);
const newOwner = 'b'.repeat(64);
const requestId = '00112233-4455-4677-8899-aabbccddeeff';
const quietConsole = { log() {}, warn() {}, error() {} };

function compile(body, dependencies) {
  const code = ts.transpileModule(body, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  new Function('exports', ...Object.keys(dependencies), code)(exports, ...Object.values(dependencies));
  return exports;
}

function declaration(file, name) {
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true);
  let result;
  const visit = node => {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === name) result = node.initializer;
    ts.forEachChild(node, visit);
  };
  visit(ast);
  assert.ok(result, `${name} must exist`);
  return result.getText(ast);
}

const { StaleAuthOperationError, isStaleAuthOperation, wipeStaleAuthResult } = compile(
  fs.readFileSync('src/lib/auth/auth-lifecycle.ts', 'utf8'), {},
);

function fixture(options = {}) {
  const values = {
    isLoggedIn: true, accountAuthenticated: true, vaultReady: false,
    showPassphrasePrompt: true, recoveryActive: true, tokenValidationInProgress: true,
  };
  const calls = [];
  const refs = {
    loginUsernameRef: { current: options.username ?? 'alice' },
    originalUsernameRef: { current: options.username ?? 'Alice' },
    passwordRef: { current: '' }, confirmPasswordRef: { current: '' },
    passphrasePlaintextRef: { current: '' }, hybridKeysRef: { current: { owner: 'alice' } },
    keyManagerOwnerRef: { current: oldOwner }, accountSubmitInFlightRef: { current: false },
    recoveryInFlightRef: { current: null }, getKeysPromiseRef: { current: null },
    authLifecycleStateRef: { current: {
      generation: 1, account: 'alice', requestId: '', controller: new AbortController(),
    } },
  };
  const setters = Object.fromEntries([
    'Username', 'Pseudonym', 'IsLoggedIn', 'IsGeneratingKeys', 'AuthStatus', 'LoginError',
    'IsSubmittingAuth', 'AccountAuthenticated', 'IsRegistrationMode', 'VaultReady',
    'TokenValidationInProgress', 'ShowPasswordPrompt', 'ShowPassphrasePrompt', 'RecoveryActive',
  ].map(name => [`set${name}`, value => { values[name[0].toLowerCase() + name.slice(1)] = value; }]));
  let unlocked = false;
  const dependencies = {
    ...refs, ...setters,
    account: { lock: async (...args) => { calls.push(['lock', ...args]); return true; } },
    invalidateResumePoolOperations: () => calls.push(['invalidate-resume']),
    unifiedSignalTransport: { resetForAccountTransition: () => calls.push(['reset-signals']) },
    deliveryReceiptOutbox: { setPersistence() {}, setActiveAccount() {} },
    receiptBatcher: { setActiveAccount() {} }, identityChangeStore: { clear() {} },
    blockingSystem: { setSecureDB() {} }, blockStatusCache: { clear() {} },
    profilePictureSystem: { setSecureDB() {} }, syncEncryptedStorage: { reset() {} },
    p2pTransport: { shutdown: async () => calls.push(['stop-p2p']) },
    resetAvatarStoreClient: () => calls.push(['reset-avatar']),
    resetBlindRoutingClient: () => calls.push(['reset-routing']),
    keyTransparencyClient: { destroy: () => calls.push(['reset-trust']) },
    keyTransparencyWarningStore: { clear() {} },
    useCallback: callback => callback,
    tokenVault: {
      lock() { unlocked = false; calls.push(['lock-tokens']); },
      isVaultUnlocked: () => unlocked,
      initialize: async () => { unlocked = true; calls.push(['open-tokens', refs.loginUsernameRef.current]); },
    },
  };
  const rotate = compile(`export const rotate = ${declaration('src/hooks/auth/useAuth.ts', 'rotateAuthLifecycle')};`, dependencies).rotate;
  const lifecycle = {
    begin: rotate,
    capture: () => {
      const current = refs.authLifecycleStateRef.current;
      return { ...current, signal: current.controller.signal };
    },
    isCurrent: operation => operation.signal === refs.authLifecycleStateRef.current.controller.signal && !operation.signal.aborted,
    assertCurrent(operation) { if (!this.isCurrent(operation)) throw new StaleAuthOperationError(); },
  };
  const { createHandleAccountSubmit } = compile(
    `export const createHandleAccountSubmit = ${declaration('src/hooks/auth/handlers.ts', 'createHandleAccountSubmit')};`, {
      ...dependencies, console: quietConsole,
      crypto: { randomUUID: () => requestId }, UUID_V4_RE: /^[a-f0-9-]{36}$/,
      isValidAccountCredential: () => true, PASSWORD_MAX_LENGTH: 256, PASSPHRASE_MAX_LENGTH: 256,
      PASSWORD_MIN_LENGTH: 12, PASSPHRASE_MIN_LENGTH: 16,
      StaleAuthOperationError, isStaleAuthOperation, wipeStaleAuthResult,
      computeBlindUserId: username => `blind-${username}`,
      startupConnection: { prepareAuthenticationTransport: async () => calls.push(['prepare-tor']) },
      websocketClient: {
        setUsername: username => calls.push(['username', username]),
        validateLinkedAuthenticationMode: async () => {
          calls.push(['linked', refs.loginUsernameRef.current]);
          throw options.connectionError ?? new Error('test-stop-linked');
        },
      },
      window: { dispatchEvent() {} }, EventType: { HYBRID_KEYS_UPDATED: 'keys' },
    },
  );
  const submit = createHandleAccountSubmit(refs, setters, { isSubmittingAuth: false }, {
    lifecycle,
    isLocalRecovery: () => values.recoveryActive,
    initializeKeys: async () => {
      calls.push(['unlock', refs.loginUsernameRef.current]);
      if (options.unlockError) throw options.unlockError;
      refs.keyManagerOwnerRef.current = refs.loginUsernameRef.current === 'alice' ? oldOwner : newOwner;
    },
    attemptAuthRecovery: async () => { calls.push(['recover', refs.loginUsernameRef.current]); return true; },
  });
  return { submit, refs, values, calls, lifecycle };
}

test('a different username bypasses the previous account local unlock and recovery', async () => {
  const f = fixture({ unlockError: 'the old vault must not be opened for a new username' });
  const oldSignal = f.lifecycle.capture().signal;
  await f.submit('login', 'Bob', 'correct-password', 'correct-passphrase');
  assert.equal(oldSignal.aborted, true);
  assert.equal(f.refs.loginUsernameRef.current, 'bob');
  assert.deepEqual(f.calls.filter(([name]) => ['unlock', 'recover', 'open-tokens'].includes(name)), []);
  assert.ok(f.calls.some(([name, username]) => name === 'linked' && username === 'bob'));
  assert.equal(f.values.loginError, 'test-stop-linked');
  for (const key of ['isLoggedIn', 'accountAuthenticated', 'vaultReady', 'showPassphrasePrompt', 'recoveryActive', 'tokenValidationInProgress', 'isSubmittingAuth']) {
    assert.equal(f.values[key], false, key);
  }
  assert.equal(f.refs.accountSubmitInFlightRef.current, false);
});

test('account switching detaches old runtime state without deleting old account credentials', async () => {
  const f = fixture();
  await f.submit('login', 'bob', 'correct-password', 'correct-passphrase');
  for (const name of ['reset-signals', 'stop-p2p', 'reset-avatar', 'reset-routing', 'reset-trust']) {
    assert.ok(f.calls.some(([call]) => call === name), name);
  }
  assert.deepEqual(f.calls.filter(([name]) => name === 'lock'), [['lock', oldOwner]]);
  assert.equal(f.refs.keyManagerOwnerRef.current, '');
  assert.equal(f.refs.hybridKeysRef.current, null);
});

test('the original account still uses its local unlock and resume path', async () => {
  const f = fixture();
  await f.submit('login', 'ALICE', 'correct-password', 'correct-passphrase');
  assert.deepEqual(f.calls.filter(([name]) => ['unlock', 'open-tokens', 'recover'].includes(name)), [
    ['unlock', 'alice'], ['open-tokens', 'alice'], ['recover', 'alice'],
  ]);
  assert.equal(f.calls.some(([name]) => name === 'linked'), false);
  assert.equal(f.values.showPassphrasePrompt, false);
  assert.equal(f.values.recoveryActive, false);
  assert.equal(f.calls.some(([name]) => name === 'lock'), false);
});

test('a failed switched login remains retryable without reusing the old recovery mode', async () => {
  const f = fixture();
  for (let index = 0; index < 3; index++) {
    await f.submit('login', 'bob', 'wrong-password', 'wrong-passphrase');
    assert.equal(f.values.isSubmittingAuth, false);
    assert.equal(f.refs.accountSubmitInFlightRef.current, false);
    assert.equal(f.refs.passwordRef.current, '');
    assert.equal(f.refs.passphrasePlaintextRef.current, '');
  }
  assert.equal(f.calls.filter(([name]) => name === 'linked').length, 3);
  assert.equal(f.calls.some(([name]) => name === 'unlock' || name === 'recover'), false);
});

test('native credential errors are not disguised as connection failures', async () => {
  const f = fixture({ unlockError: 'Native account decryption failed' });
  await f.submit('login', 'alice', 'wrong-password', 'wrong-passphrase');
  assert.equal(f.values.loginError, 'Incorrect username, password, or passphrase.');
  assert.equal(f.values.isSubmittingAuth, false);
});

function connection(methods) {
  const file = 'src/lib/websocket/websocket.ts';
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true);
  const declaration = ast.statements.find(node => ts.isClassDeclaration(node) && node.name?.text === 'WebSocketConnection');
  const body = declaration.members.filter(node => methods.includes(node.name?.getText(ast))).map(node => node.getText(ast)).join('\n');
  const { Connection } = compile(`export class Connection { ${body} }`, {
    throwIfOperationAborted: signal => { if (signal?.aborted) throw new DOMException('canceled', 'AbortError'); },
  });
  const instance = new Connection();
  instance.lifecycleState = 'idle';
  return instance;
}

for (const entry of ['validateLinkedAuthenticationMode', 'switchToLinkedAuthenticationMode']) {
  test(`${entry} does not inherit a previous login cancellation`, async () => {
    const instance = connection(['validateLinkedAuthenticationMode', 'switchToLinkedAuthenticationMode']);
    let transitions = 0;
    instance.performSwitchToLinkedAuthenticationMode = async () => { transitions++; instance.lifecycleState = 'connected'; };
    const previous = Promise.resolve().then(() => {
      instance.privacyBoundaryTransition = null;
      throw new DOMException('old login canceled', 'AbortError');
    });
    instance.privacyBoundaryTransition = { targetMode: 'linked', promise: previous };
    await instance[entry](new AbortController().signal);
    assert.equal(transitions, 1);
    assert.equal(instance.lifecycleState, 'connected');
  });

  test(`${entry} still stops for its own cancellation or a real connection failure`, async () => {
    for (const ownAbort of [false, true]) {
      const instance = connection(['validateLinkedAuthenticationMode', 'switchToLinkedAuthenticationMode']);
      instance.performSwitchToLinkedAuthenticationMode = () => assert.fail('failed or canceled authentication must not connect');
      const controller = new AbortController();
      const previous = Promise.resolve().then(() => {
        instance.privacyBoundaryTransition = null;
        if (ownAbort) controller.abort();
        throw ownAbort ? new DOMException('old login canceled', 'AbortError') : new Error('server unreachable');
      });
      instance.privacyBoundaryTransition = { targetMode: 'linked', promise: previous };
      await assert.rejects(instance[entry](controller.signal), ownAbort ? { name: 'AbortError' } : /server unreachable/);
    }
  });
}
