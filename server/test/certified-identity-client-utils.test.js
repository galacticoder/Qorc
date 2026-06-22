import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createServer } from 'vite';

async function withClientModules(fn) {
  const root = process.cwd();
  const server = await createServer({
    configFile: false,
    root,
    server: {
      middlewareMode: true,
      watch: {
        ignored: ['**/src-tauri/target/**', '**/dist/**', '**/node_modules/**']
      }
    },
    appType: 'custom',
    logLevel: 'silent',
    optimizeDeps: { noDiscovery: true },
    resolve: { alias: { '@': path.join(root, 'src') } }
  });
  try {
    const [identity, peer, crypto] = await Promise.all([
      server.ssrLoadModule('/src/lib/utils/certified-identity-utils.ts'),
      server.ssrLoadModule('/src/lib/utils/peer-certificate-utils.ts'),
      server.ssrLoadModule('/src/lib/utils/crypto-utils.ts')
    ]);
    return await fn({ identity, peer, crypto: crypto.CryptoUtils });
  } finally {
    await server.close();
  }
}

function signalIdentityBundle(crypto, x25519PublicBase64) {
  const raw = crypto.Base64.base64ToUint8Array(x25519PublicBase64);
  const serialized = new Uint8Array(33);
  serialized[0] = 0x05;
  serialized.set(raw, 1);
  return {
    registrationId: 1,
    deviceId: 1,
    identityKeyBase64: crypto.Base64.arrayBufferToBase64(serialized),
    preKey: null,
    signedPreKey: {
      keyId: 1,
      publicKeyBase64: x25519PublicBase64,
      signatureBase64: ''
    },
    kyberPreKey: null,
    pqKyber: null
  };
}

async function buildPeerCertificate({ crypto, peer, keys, username, inboxId }) {
  const issuedAt = Date.now();
  const unsigned = {
    username,
    inboxId,
    dilithiumPublicKey: keys.dilithium.publicKeyBase64,
    kyberPublicKey: keys.kyber.publicKeyBase64,
    x25519PublicKey: keys.x25519.publicKeyBase64,
    proof: keys.dilithium.publicKeyBase64,
    issuedAt,
    expiresAt: issuedAt + 60_000,
    signature: ''
  };
  const signature = await crypto.Dilithium.sign(
    keys.dilithium.secretKey,
    peer.encodePeerCertificateSigningPayload(unsigned)
  );
  return {
    ...unsigned,
    signature: crypto.Base64.arrayBufferToBase64(signature)
  };
}

test('certified identity signs Signal identity and hybrid transport keys as separate bindings', async () => {
  const originalWarn = console.warn;
  console.warn = (...args) => {
    if (String(args[0] || '').includes('Worker failed, falling back to local keygen')) return;
    originalWarn(...args);
  };
  try {
    await withClientModules(async ({ identity, peer, crypto }) => {
      const username = 'alice';
      const inboxId = 'inbox-1';
      const deviceKeys = await crypto.Hybrid.generateHybridKeyPair();
      const signalKeys = await crypto.Hybrid.generateHybridKeyPair();
      const fullBundle = signalIdentityBundle(crypto, signalKeys.x25519.publicKeyBase64);
      const peerCertificate = await buildPeerCertificate({
        crypto,
        peer,
        keys: deviceKeys,
        username,
        inboxId
      });
      const publicKeys = {
        kyberPublicBase64: deviceKeys.kyber.publicKeyBase64,
        dilithiumPublicBase64: deviceKeys.dilithium.publicKeyBase64,
        x25519PublicBase64: deviceKeys.x25519.publicKeyBase64
      };

      const certified = await identity.buildCertifiedPeerBundleV2({
        username,
        inboxId,
        publicKeys,
        fullBundle,
        peerCertificate,
        accountRootPublicKey: deviceKeys.accountRoot.publicKeyBase64,
        accountRootSecretKey: deviceKeys.accountRoot.secretKey,
        deviceDilithiumSecretKey: deviceKeys.dilithium.secretKey
      });

      assert.notEqual(
        certified.subkeyBinding.signalIdentityX25519PublicKey,
        certified.subkeyBinding.x25519PublicKey
      );
      assert.equal(certified.subkeyBinding.signalIdentityX25519PublicKey, signalKeys.x25519.publicKeyBase64);
      assert.equal(certified.subkeyBinding.x25519PublicKey, deviceKeys.x25519.publicKeyBase64);

      const valid = await identity.validateCertifiedPeerBundleV2(certified, {
        targetHandle: username,
        inboxId,
        publicKeys,
        fullBundle,
        peerCertificate
      });
      assert.equal(valid.valid, true);

      const otherSignalKeys = await crypto.Hybrid.generateHybridKeyPair();
      const wrongSignalBundle = signalIdentityBundle(crypto, otherSignalKeys.x25519.publicKeyBase64);
      const wrongSignal = await identity.validateCertifiedPeerBundleV2(certified, {
        targetHandle: username,
        inboxId,
        publicKeys,
        fullBundle: wrongSignalBundle,
        peerCertificate
      });
      assert.equal(wrongSignal.valid, false);
      assert.equal(wrongSignal.reason, 'CERTIFIED_IDENTITY_SIGNAL_BINDING_MISMATCH');

      const wrongTransport = await identity.validateCertifiedPeerBundleV2(certified, {
        targetHandle: username,
        inboxId,
        publicKeys: {
          ...publicKeys,
          x25519PublicBase64: signalKeys.x25519.publicKeyBase64
        },
        fullBundle,
        peerCertificate
      });
      assert.equal(wrongTransport.valid, false);
      assert.equal(wrongTransport.reason, 'CERTIFIED_IDENTITY_DISCOVERY_KEY_MISMATCH');

      const tampered = structuredClone(certified);
      tampered.subkeyBinding.signalIdentityX25519PublicKey = otherSignalKeys.x25519.publicKeyBase64;
      const tamperedBinding = await identity.validateCertifiedPeerBundleV2(tampered, {
        targetHandle: username,
        inboxId,
        publicKeys,
        peerCertificate
      });
      assert.equal(tamperedBinding.valid, false);
      assert.match(
        tamperedBinding.reason,
        /CERTIFIED_IDENTITY_BINDING_(PAYLOAD_DIGEST|DEVICE_SIGNATURE|FINGERPRINT)_MISMATCH/
      );
    });
  } finally {
    console.warn = originalWarn;
  }
});
