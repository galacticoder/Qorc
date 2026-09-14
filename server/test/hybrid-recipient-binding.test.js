import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createServer } from 'vite';
import { X25519_KEY_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES, ML_KEM_1024_CIPHERTEXT_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, HASH_OUTPUT_BYTES } from '../../shared/crypto-sizes.js';

async function withHybridModules(fn) {
  const root = process.cwd();
  const server = await createServer({
    configFile: false,
    root,
    server: {
      middlewareMode: true,
      watch: { ignored: ['**/src-tauri/target/**', '**/dist/**', '**/node_modules/**'] }
    },
    appType: 'custom',
    logLevel: 'silent',
    optimizeDeps: { noDiscovery: true },
    resolve: { alias: { '@': path.join(root, 'src') } }
  });

  try {
    const [hybrid, constants, tauri, protocol] = await Promise.all([
      server.ssrLoadModule('/src/lib/cryptography/hybrid.ts'),
      server.ssrLoadModule('/src/lib/constants.ts'),
      server.ssrLoadModule('/src/lib/tauri-bindings.ts'),
      server.ssrLoadModule('/src/lib/config/protocol-keys.ts'),
    ]);
    await fn(hybrid.Hybrid, constants, tauri, protocol.PROTOCOL_KEYS);
  } finally {
    await server.close();
  }
}

const encoded = (length, byte) => Buffer.alloc(length, byte).toString('base64');

test('native and renderer hybrid envelope names agree', () => {
  const constants = fs.readFileSync(
    path.join(process.cwd(), 'src/lib/config/protocol-keys.ts'),
    'utf8',
  );
  const native = fs.readFileSync(
    path.join(process.cwd(), 'src-tauri/src/protocol_keys.rs'),
    'utf8',
  );
  const rendererInner = constants.match(/INNER_ENVELOPE_PROTOCOL:\s*'([^']+)'/)?.[1];
  const nativeInner = native.match(/const INNER_ENVELOPE_PROTOCOL:\s*&str\s*=\s*"([^"]+)"/)?.[1];

  assert.ok(rendererInner, 'renderer inner-envelope protocol constant is missing');
  assert.ok(nativeInner, 'native inner-envelope protocol constant is missing');
  assert.equal(nativeInner, rendererInner);
});

test('hybrid envelopes bind outgoing recipient and delegate incoming identity checks to native code', async () => {
  await withHybridModules(async (Hybrid, constants, tauri, protocol) => {
    const sender = encoded(ML_DSA_87_PUBLIC_KEY_BYTES, 1);
    const recipient = encoded(ML_DSA_87_PUBLIC_KEY_BYTES, 2);
    const wrongRecipient = encoded(ML_DSA_87_PUBLIC_KEY_BYTES, 3);

    await assert.rejects(
      Hybrid.encryptForClient(
        { secret: 'must not be encrypted under mismatched routing' },
        {
          kyberPublicBase64: encoded(ML_KEM_1024_PUBLIC_KEY_BYTES, 4),
          x25519PublicBase64: encoded(X25519_KEY_BYTES, 5),
          dilithiumPublicBase64: recipient
        },
        {
          to: wrongRecipient,
          from: sender,
          type: 'libsignal-message',
          senderDilithiumPublicKey: sender,
          signRoutingHeader: async () => encoded(ML_DSA_87_SIGNATURE_BYTES, 9),
        }
      ),
      /Routing recipient does not match recipient certificate key/
    );

    const envelope = {
      version: protocol.HYBRID_ENVELOPE_PROTOCOL,
      routing: {
        to: recipient,
        from: sender,
        type: 'libsignal-message',
        timestamp: Date.now(),
        size: 1
      },
      routingSignature: {
        algorithm: 'ML-DSA-87',
        signature: encoded(ML_DSA_87_SIGNATURE_BYTES, 6)
      },
      algorithms: {
        outer: 'ML-KEM-1024',
        inner: 'X25519',
        aead: 'AES-256-GCM+XChaCha20-Poly1305',
        mac: 'BLAKE3-256'
      },
      kemCiphertext: encoded(ML_KEM_1024_CIPHERTEXT_BYTES, 7),
      outer: {
        salt: encoded(32, 8),
        nonce: encoded(12, 9),
        ciphertext: encoded(1, 10),
        tag: encoded(16, 11),
        mac: encoded(HASH_OUTPUT_BYTES, 12)
      }
    };

    const originalDecrypt = tauri.account.decryptHybrid;
    let observedSender = null;
    tauri.account.decryptHybrid = async (_envelope, expectedSender) => {
      observedSender = expectedSender;
      return {
        routing: envelope.routing,
        payloadBase64: encoded(1, 42),
        payloadType: 'binary',
      };
    };
    try {
      const result = await Hybrid.decryptIncoming(envelope, {
        senderDilithiumPublicKey: sender,
      });
      assert.equal(observedSender, sender);
      assert.equal(result.payload.length, 1);
      assert.equal(result.payload[0], 42);
    } finally {
      tauri.account.decryptHybrid = originalDecrypt;
    }
  });
});
