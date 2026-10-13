import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import ts from 'typescript';
import { randomBytes } from 'node:crypto';
import { createServer } from 'vite';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

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
    const [identity, peer, crypto, verified] = await Promise.all([
      server.ssrLoadModule('/src/lib/utils/certified-identity-utils.ts'),
      server.ssrLoadModule('/src/lib/utils/peer-certificate-utils.ts'),
      server.ssrLoadModule('/src/lib/utils/crypto-utils.ts'),
      server.ssrLoadModule('/src/lib/key-transparency/verified-material.ts')
    ]);
    const cryptoUtils = crypto.CryptoUtils;
    cryptoUtils.Dilithium.sign = async (secretKey, message) =>
      new Uint8Array(ml_dsa87.sign(message, secretKey));
    cryptoUtils.Dilithium.verify = async (signature, message, publicKey) =>
      ml_dsa87.verify(signature, message, publicKey);
    cryptoUtils.Hybrid.generateHybridKeyPair = async () => {
      const kem = ml_kem1024.keygen();
      const signature = ml_dsa87.keygen();
      const accountRoot = ml_dsa87.keygen();
      const x25519Secret = new Uint8Array(randomBytes(32));
      const x25519Public = new Uint8Array(x25519.getPublicKey(x25519Secret));
      return {
        kyber: {
          publicKeyBase64: cryptoUtils.Base64.arrayBufferToBase64(kem.publicKey),
          secretKey: new Uint8Array(kem.secretKey),
          version: 1024
        },
        dilithium: {
          publicKeyBase64: cryptoUtils.Base64.arrayBufferToBase64(signature.publicKey),
          secretKey: new Uint8Array(signature.secretKey)
        },
        accountRoot: {
          publicKeyBase64: cryptoUtils.Base64.arrayBufferToBase64(accountRoot.publicKey),
          secretKey: new Uint8Array(accountRoot.secretKey)
        },
        x25519: {
          publicKeyBase64: cryptoUtils.Base64.arrayBufferToBase64(x25519Public),
          private: x25519Secret
        }
      };
    };
    return await fn({ identity, peer, crypto: cryptoUtils, verified });
  } finally {
    await server.close();
  }
}

function signalIdentityBundle(crypto, x25519PublicBase64, kyberPublicBase64) {
  const raw = crypto.Base64.base64ToUint8Array(x25519PublicBase64);
  const serialized = new Uint8Array(33);
  serialized[0] = 0x05;
  serialized.set(raw, 1);
  const rawMlKem = crypto.Base64.base64ToUint8Array(kyberPublicBase64);
  const serializedMlKem = new Uint8Array(1569);
  serializedMlKem[0] = 0x0a;
  serializedMlKem.set(rawMlKem, 1);
  const signalSignature = Buffer.alloc(64).toString('base64');
  return {
    registrationId: 1,
    deviceId: 1,
    identityKeyBase64: crypto.Base64.arrayBufferToBase64(serialized),
    signedPreKey: {
      keyId: 1,
      publicKeyBase64: crypto.Base64.arrayBufferToBase64(serialized),
      signatureBase64: signalSignature
    },
    mlKemPreKey: {
      keyId: 1,
      publicKeyBase64: crypto.Base64.arrayBufferToBase64(serializedMlKem),
      signatureBase64: signalSignature
    },
    staticMlKem: {
      publicKeyBase64: kyberPublicBase64,
      signatureBase64: Buffer.alloc(64).toString('base64')
    }
  };
}

function loadSignalBundleUtilities(dependencies) {
  const file = 'src/lib/utils/signal-bundle-utils.ts';
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const body = ast.statements.filter(node => !ts.isImportDeclaration(node)).map(node => node.getText(ast)).join('\n');
  const compiled = ts.transpileModule(body, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const exports = {};
  new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
  return exports;
}

async function buildPeerCertificate({ crypto, peer, keys, username }) {
  const issuedAt = Date.now();
  const unsigned = {
    username,
    dilithiumPublicKey: keys.dilithium.publicKeyBase64,
    kyberPublicKey: keys.kyber.publicKeyBase64,
    x25519PublicKey: keys.x25519.publicKeyBase64,
    proof: keys.dilithium.publicKeyBase64,
    issuedAt,
    expiresAt: issuedAt + 24 * 60 * 60 * 1000,
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
    await withClientModules(async ({ identity, peer, crypto, verified }) => {
      const username = 'alice';
      const deviceKeys = await crypto.Hybrid.generateHybridKeyPair();
      const signalKeys = await crypto.Hybrid.generateHybridKeyPair();
      const fullBundle = signalIdentityBundle(
        crypto,
        signalKeys.x25519.publicKeyBase64,
        deviceKeys.kyber.publicKeyBase64
      );
      const peerCertificate = await buildPeerCertificate({
        crypto,
        peer,
        keys: deviceKeys,
        username
      });
      const publicKeys = {
        kyberPublicBase64: deviceKeys.kyber.publicKeyBase64,
        dilithiumPublicBase64: deviceKeys.dilithium.publicKeyBase64,
        x25519PublicBase64: deviceKeys.x25519.publicKeyBase64
      };

      const certified = await identity.buildCertifiedPeerBundle({
        username,
        publicKeys,
        fullBundle,
        peerCertificate,
        accountRootPublicKey: deviceKeys.accountRoot.publicKeyBase64,
        signAccountRoot: async (payload) => crypto.Base64.arrayBufferToBase64(
          await crypto.Dilithium.sign(deviceKeys.accountRoot.secretKey, payload)
        ),
        signDevice: async (payload) => crypto.Base64.arrayBufferToBase64(
          await crypto.Dilithium.sign(deviceKeys.dilithium.secretKey, payload)
        )
      });

      assert.notEqual(
        certified.subkeyBinding.signalIdentityX25519PublicKey,
        certified.subkeyBinding.x25519PublicKey
      );
      assert.equal(certified.subkeyBinding.signalIdentityX25519PublicKey, signalKeys.x25519.publicKeyBase64);
      assert.equal(certified.subkeyBinding.x25519PublicKey, deviceKeys.x25519.publicKeyBase64);

      const valid = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
        publicKeys,
        fullBundle,
        peerCertificate
      });
      assert.equal(valid.valid, true);

      const otherSignalKeys = await crypto.Hybrid.generateHybridKeyPair();
      const wrongSignalBundle = signalIdentityBundle(
        crypto,
        otherSignalKeys.x25519.publicKeyBase64,
        deviceKeys.kyber.publicKeyBase64
      );
      const wrongSignal = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
        publicKeys,
        fullBundle: wrongSignalBundle,
        peerCertificate
      });
      assert.equal(wrongSignal.valid, false);
      assert.equal(wrongSignal.reason, 'CERTIFIED_IDENTITY_SIGNAL_BINDING_MISMATCH');

      const wrongStaticMlKemBundle = signalIdentityBundle(
        crypto,
        signalKeys.x25519.publicKeyBase64,
        otherSignalKeys.kyber.publicKeyBase64
      );
      const wrongStaticMlKem = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
        publicKeys,
        fullBundle: wrongStaticMlKemBundle,
        peerCertificate
      });
      assert.equal(wrongStaticMlKem.valid, false);
      assert.equal(
        wrongStaticMlKem.reason,
        'CERTIFIED_IDENTITY_STATIC_ML_KEM_BINDING_MISMATCH'
      );

      const tamperedPreKeyBundle = structuredClone(fullBundle);
      tamperedPreKeyBundle.signedPreKey.keyId = 2;
      const wrongPreKeyBundle = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
        publicKeys,
        fullBundle: tamperedPreKeyBundle,
        peerCertificate
      });
      assert.equal(wrongPreKeyBundle.valid, false);
      assert.equal(
        wrongPreKeyBundle.reason,
        'CERTIFIED_IDENTITY_SIGNAL_PREKEY_BUNDLE_MISMATCH'
      );

      const wrongTransport = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
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
      const tamperedBinding = await identity.validateCertifiedPeerBundle(tampered, {
        targetHandle: username,
        publicKeys,
        fullBundle,
        peerCertificate
      });
      assert.equal(tamperedBinding.valid, false);
      assert.equal(tamperedBinding.reason, 'CERTIFIED_IDENTITY_SIGNAL_BINDING_MISMATCH');

      const unknownField = structuredClone(certified);
      unknownField.unexpected = true;
      const unknownFieldResult = await identity.validateCertifiedPeerBundle(unknownField, {
        targetHandle: username,
        publicKeys,
        fullBundle,
        peerCertificate
      });
      assert.equal(unknownFieldResult.valid, false);
      assert.equal(unknownFieldResult.reason, 'CERTIFIED_IDENTITY_SCHEMA_INVALID');

      const inconsistentUsername = structuredClone(certified);
      inconsistentUsername.accountRoot.username = 'mallory';
      const inconsistentUsernameResult = await identity.validateCertifiedPeerBundle(
        inconsistentUsername,
        { targetHandle: username, publicKeys, fullBundle, peerCertificate }
      );
      assert.equal(inconsistentUsernameResult.valid, false);
      assert.equal(
        inconsistentUsernameResult.reason,
        'CERTIFIED_IDENTITY_CHAIN_USERNAME_MISMATCH'
      );

      const afterExpiry = peerCertificate.expiresAt + 2 * 60 * 1000 + 1;
      const expiredDiscovery = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
        publicKeys,
        fullBundle,
        peerCertificate,
        now: afterExpiry
      });
      assert.equal(expiredDiscovery.valid, false);
      assert.equal(expiredDiscovery.reason, 'CERTIFIED_IDENTITY_CERTIFICATE_MISSING');

      const authorizedCachedIdentity = await identity.validateCertifiedPeerBundle(certified, {
        targetHandle: username,
        publicKeys,
        fullBundle,
        peerCertificate,
        now: afterExpiry,
        allowExpired: true
      });
      assert.equal(authorizedCachedIdentity.valid, true);

      const authorizedMaterial = {
        publicKeys,
        peerCertificateFingerprint: certified.peerCertificateFingerprint,
        identityRootFingerprint: certified.identityRootFingerprint,
        identityBundleFingerprint: certified.bundleFingerprint
      };
      const verifiedAt = Date.now();
      verified.markKeyTransparencyVerifiedMaterial(
        authorizedMaterial,
        'owner',
        username,
        { rootCommitment: 'a'.repeat(128), version: 1 }
      );
      const originalNow = Date.now;
      try {
        Date.now = () => verifiedAt + 30 * 24 * 60 * 60 * 1000;
        assert.equal(
          verified.isKeyTransparencyVerifiedMaterial(authorizedMaterial, 'owner', username),
          true
        );
        const snapshot = verified.exportKeyTransparencyAuthorizations('owner');
        assert.ok(snapshot.authorized[0].verifiedAt >= verifiedAt);
        assert.ok(snapshot.authorized[0].verifiedAt < Date.now());
        assert.equal(Object.hasOwn(snapshot.authorized[0], 'expiresAt'), false);
        verified.clearKeyTransparencyVerifiedMaterials();
        assert.equal(verified.importKeyTransparencyAuthorizations('owner', snapshot), 1);
        const restoredMaterial = structuredClone(authorizedMaterial);
        assert.equal(
          verified.hydrateKeyTransparencyVerifiedMaterial(restoredMaterial, 'owner', username),
          true
        );
        assert.equal(
          verified.isKeyTransparencyVerifiedMaterial(restoredMaterial, 'owner', username),
          true
        );
      } finally {
        Date.now = originalNow;
        verified.clearKeyTransparencyVerifiedMaterials();
      }
    });
  } finally {
    console.warn = originalWarn;
  }
});

test('restored peer keys survive certificate expiry without accepting expired new discoveries', async () => {
  await withClientModules(async ({ identity, peer, crypto, verified }) => {
    const username = 'alice';
    const owner = 'owner';
    const keys = await crypto.Hybrid.generateHybridKeyPair();
    const signalKeys = await crypto.Hybrid.generateHybridKeyPair();
    const publicKeys = {
      kyberPublicBase64: keys.kyber.publicKeyBase64,
      dilithiumPublicBase64: keys.dilithium.publicKeyBase64,
      x25519PublicBase64: keys.x25519.publicKeyBase64,
    };
    const fullBundle = signalIdentityBundle(crypto, signalKeys.x25519.publicKeyBase64, keys.kyber.publicKeyBase64);
    const peerCertificate = await buildPeerCertificate({ crypto, peer, keys, username });
    const certifiedPeerBundle = await identity.buildCertifiedPeerBundle({
      username, publicKeys, fullBundle, peerCertificate,
      accountRootPublicKey: keys.accountRoot.publicKeyBase64,
      signAccountRoot: async payload => crypto.Base64.arrayBufferToBase64(await crypto.Dilithium.sign(keys.accountRoot.secretKey, payload)),
      signDevice: async payload => crypto.Base64.arrayBufferToBase64(await crypto.Dilithium.sign(keys.dilithium.secretKey, payload)),
    });
    const material = {
      publicKeys, fullBundle, peerCertificate, certifiedPeerBundle,
      spoolDetectionKey: 'd'.repeat(64),
      peerCertificateFingerprint: certifiedPeerBundle.peerCertificateFingerprint,
      identityRootFingerprint: certifiedPeerBundle.identityRootFingerprint,
      identityBundleFingerprint: certifiedPeerBundle.bundleFingerprint,
    };
    const contact = { rootCommitment: 'a'.repeat(128), version: 1 };
    verified.markKeyTransparencyVerifiedMaterial(material, owner, username, contact);
    const snapshot = verified.exportKeyTransparencyAuthorizations(owner);
    const originalNow = Date.now;
    let record = { material: structuredClone(material), transparency: contact };
    const utils = loadSignalBundleUtilities({
      ...verified,
      shouldAttemptDiscovery: () => true,
      extractX25519FromSignalBundle: peer.extractX25519FromSignalBundle,
      validateCertifiedPeerBundle: identity.validateCertifiedPeerBundle,
      loadPersistedDiscoveryMaterial: async () => record,
      discoveryMaterialStillVouchedFor: (saved, live) => saved?.transparency.rootCommitment === live?.rootCommitment &&
        saved?.transparency.version === live?.version ? saved.material : null,
      persistPeerDetectionKey: async () => {},
    });
    try {
      Date.now = () => peerCertificate.expiresAt + 24 * 60 * 60 * 1000;
      verified.clearKeyTransparencyVerifiedMaterials();
      assert.equal(verified.importKeyTransparencyAuthorizations(owner, snapshot), 1);
      const restored = await utils.loadTrustedPersistedDiscoveryMaterial(owner, username);
      assert.ok(restored);
      assert.equal((await utils.resolveTrustedPeerHybridPublicKeys(owner, username, restored)).valid, true);
      assert.equal((await utils.validateSignalBundleForPeerIdentity(owner, username, fullBundle, [], async () => {
        throw new Error('Restored peer must not require a network lookup');
      })).valid, true);

      const fresh = structuredClone(material);
      verified.markKeyTransparencyVerifiedMaterial(fresh, owner, username, contact);
      const expired = await utils.resolveTrustedPeerHybridPublicKeys(owner, username, fresh);
      assert.equal(expired.valid, false);
      assert.equal(expired.reason, 'CERTIFIED_IDENTITY_CERTIFICATE_MISSING');
      assert.equal((await utils.resolveTrustedPeerHybridPublicKeys('another', username, restored)).valid, false);

      record = { material: structuredClone(material), transparency: { ...contact, version: 2 } };
      assert.equal(await utils.loadTrustedPersistedDiscoveryMaterial(owner, username), null);
      record = { material: structuredClone(material), transparency: contact };
      record.material.certifiedPeerBundle.subkeyBinding.deviceSignature = Buffer.alloc(4627).toString('base64');
      assert.equal(await utils.loadTrustedPersistedDiscoveryMaterial(owner, username), null);

      verified.revokeKeyTransparencyPeerAuthorization(owner, username, { ...contact, version: 2 });
      assert.equal((await utils.resolveTrustedPeerHybridPublicKeys(owner, username, restored)).valid, false);
      assert.equal(await utils.loadTrustedPersistedDiscoveryMaterial(owner, username), null);
    } finally {
      Date.now = originalNow;
      verified.clearKeyTransparencyVerifiedMaterials();
    }
  });
});
