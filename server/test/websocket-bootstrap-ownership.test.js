import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createServer } from 'vite';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { encodeServerProfileTranscript } from '../../shared/server-profile.js';

const repoRoot = path.resolve(import.meta.dirname, '..', '..');

test('transport ingress activates server identity before releasing bootstrap', async () => {
  const originalBrowserWindow = globalThis.window;
  globalThis.window = new EventTarget();
  const server = await createServer({
    configFile: false,
    root: repoRoot,
    server: {
      middlewareMode: true,
      watch: { ignored: ['**/src-tauri/target/**', '**/dist/**', '**/node_modules/**'] }
    },
    appType: 'custom',
    logLevel: 'silent',
    optimizeDeps: { noDiscovery: true },
    resolve: { alias: { '@': path.join(repoRoot, 'src') } }
  });

  try {
    const websocketModule = await server.ssrLoadModule('/src/lib/websocket/websocket.ts');
    const { WebSocketConnection } = websocketModule;
    const { PinnedServer } = await server.ssrLoadModule('/src/lib/utils/auth-utils.ts');
    const { PostQuantumSignature } = await server.ssrLoadModule('/src/lib/cryptography/signature.ts');
    const connection = new WebSocketConnection();
    const events = [];
    const originalEstablish = PinnedServer.establish;
    const originalVerify = PostQuantumSignature.verify;
    const pair = ml_dsa87.keygen(new Uint8Array(32).fill(0x43));
    const bootstrap = {
      type: 'server-public-key',
      serverId: 'server-test',
      serverTime: Date.now(),
      requiresServerPassword: false,
      serverProfile: { name: 'Test server', icon: null },
      hybridKeys: {
        kyberPublicBase64: Buffer.alloc(1568, 0x11).toString('base64'),
        dilithiumPublicBase64: Buffer.from(pair.publicKey).toString('base64'),
        x25519PublicBase64: Buffer.alloc(32, 0x33).toString('base64')
      }
    };
    const signature = ml_dsa87.sign(encodeServerProfileTranscript(bootstrap), pair.secretKey);
    bootstrap.serverProfileSignature = Buffer.from(signature).toString('base64');
    signature.fill(0);
    pair.secretKey.fill(0);
    PostQuantumSignature.verify = async (signature, transcript, publicKey) => {
      events.push('verify');
      return ml_dsa87.verify(signature, transcript, publicKey);
    };

    clearInterval(websocketModule.default.diagMonitorTimer);
    websocketModule.default.diagMonitorTimer = null;
    clearInterval(connection.diagMonitorTimer);
    connection.diagMonitorTimer = null;

    connection.nativeConnectionToken = 17;
    connection.isManualClose = false;
    connection.setServerKeyMaterial = () => {
      events.push('activate');
      assert.equal(connection.serverBootstrapConnectionToken, null);
      return 'activated';
    };
    connection.dispatchToFrontend = () => events.push('dispatch');
    PinnedServer.establish = async (_keys, isCurrent) => {
      assert.equal(isCurrent(), true);
      events.push('pin');
    };

    try {
      const handled = await connection.handleEdgeServerMessage(bootstrap, false, 17);

      assert.equal(handled, true);
      assert.deepEqual(events, ['verify', 'pin', 'activate', 'dispatch']);
      assert.equal(connection.serverBootstrapConnectionToken, 17);
      assert.deepEqual(connection.serverProfile, bootstrap.serverProfile);

      events.length = 0;
      const originalClose = connection.close;
      const originalWindow = globalThis.window;
      globalThis.window = { dispatchEvent: () => events.push('reject') };
      connection.close = async () => events.push('close');
      try {
        await connection.handleEdgeServerMessage({ ...bootstrap, serverProfile: { name: 'Forged name', icon: null } }, false, 17);
        assert.deepEqual(events, ['verify', 'close', 'reject']);
        assert.deepEqual(connection.serverProfile, bootstrap.serverProfile);
      } finally {
        connection.close = originalClose;
        if (originalWindow === undefined) delete globalThis.window;
        else globalThis.window = originalWindow;
      }

      events.length = 0;
      PostQuantumSignature.verify = async () => {
        events.push('verify');
        connection.nativeConnectionToken = 18;
        return true;
      };
      await connection.handleEdgeServerMessage(bootstrap, false, 17);
      assert.deepEqual(events, ['verify']);
    } finally {
      PinnedServer.establish = originalEstablish;
      PostQuantumSignature.verify = originalVerify;
      await connection.close({ killSession: true });
    }
  } finally {
    await server.close();
    await new Promise((resolve) => setImmediate(resolve));
    if (originalBrowserWindow === undefined) delete globalThis.window;
    else globalThis.window = originalBrowserWindow;
  }
});

test('client crypto worker accepts a correctly sized ML-KEM decapsulation request', async () => {
  const server = await createServer({
    configFile: false,
    root: repoRoot,
    server: {
      middlewareMode: true,
      watch: { ignored: ['**/src-tauri/target/**', '**/dist/**', '**/node_modules/**'] }
    },
    appType: 'custom',
    logLevel: 'silent',
    optimizeDeps: { noDiscovery: true },
    resolve: { alias: { '@': path.join(repoRoot, 'src') } }
  });

  const ciphertext = new Uint8Array(1568);
  const secretKey = new Uint8Array(3168);
  try {
    const { validateWorkerRequest } = await server.ssrLoadModule(
      '/src/lib/cryptography/worker-request-validation.ts'
    );
    assert.doesNotThrow(() => validateWorkerRequest({
      id: '00000000-0000-4000-8000-000000000000',
      type: 'kem.decapsulate',
      auth: '00'.repeat(32),
      ciphertext,
      secretKey
    }));
  } finally {
    ciphertext.fill(0);
    secretKey.fill(0);
    await server.close();
  }
});

test('privacy-boundary reconnects have one reconnect owner', () => {
  const source = fs.readFileSync(
    path.join(repoRoot, 'src/lib/websocket/websocket.ts'),
    'utf8'
  );
  const unlinkedStart = source.indexOf('private async performSwitchToUnlinkedMode');
  const linkedStart = source.indexOf('private async performSwitchToLinkedAuthenticationMode');
  const unlinked = source.slice(unlinkedStart, linkedStart);
  const linked = source.slice(linkedStart, source.indexOf('resetConnectionPrivacyMode', linkedStart));

  assert.match(unlinked, /connectTransport\(\{ autoReconnectOnFailure: false \}\)/);
  assert.match(linked, /connectTransport\(\{ autoReconnectOnFailure: false \}\)/);
});
