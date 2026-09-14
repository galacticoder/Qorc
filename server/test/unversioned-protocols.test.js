import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { PROTOCOL_KEYS as serverKeys } from '../config/protocol-keys.js';
import { REDIS_KEYS } from '../config/redis-keys.js';
import * as sharedKeys from '../../shared/protocol-keys.js';
import { REQUIRED_WS_PQ_HANDSHAKE, validatePqHandshakePolicy } from '../security/layer-agreement-policy.js';
import { SEALED_STANDARD_CIPHERTEXT_BYTES, validateSealedEnvelope } from '../routing/sealed-sender.js';
import { ML_KEM_1024_CIPHERTEXT_BYTES, SEALED_NONCE_BYTES } from '../../shared/crypto-sizes.js';
import { PRIVATE_AUTH_TRANSCRIPT_BYTES } from '../../shared/private-auth-protocol.js';
import { AUTH_CHANNEL_BINDING_BYTES } from '../../shared/auth-channel-binding.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const versionedName = /(?:[-_:/ ]v\d+(?=[^a-z0-9]|$)|(?:QSS|QDB)v\d+|pq-ws-\d+)/i;
let vite;
let clientKeys;
let storage;

before(async () => {
  vite = await createServer({
    root,
    configFile: false,
    appType: 'custom',
    logLevel: 'silent',
    server: { middlewareMode: true, watch: null },
    optimizeDeps: { noDiscovery: true },
  });
  clientKeys = (await vite.ssrLoadModule('/src/lib/config/protocol-keys.ts')).PROTOCOL_KEYS;
  storage = await vite.ssrLoadModule('/src/lib/database/storage-keys.ts');
});

after(async () => {
  await vite?.close();
});

function nativeKeys(filename) {
  const source = fs.readFileSync(path.join(root, 'src-tauri/src', filename), 'utf8');
  return Object.fromEntries([...source.matchAll(/pub const ([A-Z0-9_]+): [^=]+ = b?"((?:[^"\\]|\\.)*)";/g)]
    .map(([, name, value]) => [name, JSON.parse(`"${value.replaceAll('\\0', '\\u0000')}"`)]));
}

test('all first-party key registries use unversioned names without collisions', () => {
  const registries = {
    client: clientKeys,
    server: serverKeys,
    shared: sharedKeys,
    redis: REDIS_KEYS,
    native: nativeKeys('protocol_keys.rs'),
    nativeStorage: nativeKeys('storage_keys.rs'),
    ...storage,
  };
  for (const [registry, keys] of Object.entries(registries)) {
    const entries = Object.entries(keys);
    assert.ok(entries.length > 0, registry);
    const values = entries.map(([, value]) => value);
    assert.equal(new Set(values).size, values.length, `${registry} has a label collision`);
    for (const [name, value] of entries) {
      assert.equal(typeof value, 'string', `${registry}.${name}`);
      assert.doesNotMatch(value, versionedName, `${registry}.${name}`);
      assert.doesNotMatch(name, /(?:_VERSION|_V\d+)$/, `${registry}.${name}`);
    }
  }
});

test('client, server and native protocol labels agree byte for byte', () => {
  let compared = 0;
  for (const counterpart of [serverKeys, nativeKeys('protocol_keys.rs'), sharedKeys]) {
    for (const name of Object.keys(counterpart)) {
      if (!Object.hasOwn(clientKeys, name)) continue;
      assert.equal(clientKeys[name], counterpart[name], name);
      compared++;
    }
  }
  assert.ok(compared >= 40, `Only compared ${compared} shared labels`);
  const native = nativeKeys('protocol_keys.rs');
  assert.equal(clientKeys.HYBRID_INNER_KDF_PREFIX, `${native.HYBRID_INNER_KDF}:`);
  assert.equal(clientKeys.HYBRID_OUTER_KDF_PREFIX, `${native.HYBRID_OUTER_KDF}:`);
  assert.equal(`${storage.STORAGE_KEY_DOMAINS.DATABASE_OWNER}\0`, native.DATABASE_OWNER);
  for (const [name, value] of Object.entries(nativeKeys('storage_keys.rs'))) {
    if (Object.hasOwn(storage.STORAGE_KEYS, name)) assert.equal(storage.STORAGE_KEYS[name], value, name);
    if (name.endsWith('_PREFIX') && Object.hasOwn(storage.STORAGE_PREFIXES, name.slice(0, -7))) {
      assert.equal(storage.STORAGE_PREFIXES[name.slice(0, -7)], value, name);
    }
  }
});

test('renamed binary identifiers preserve framing widths and authentication transcript sizing', () => {
  for (const magic of [
    clientKeys.PQ_ANONYMOUS_HTTP_REQUEST_MAGIC,
    clientKeys.PQ_ANONYMOUS_HTTP_RESPONSE_MAGIC,
    sharedKeys.PRIVATE_AUTH_PIR_RECORD_MAGIC,
    nativeKeys('protocol_keys.rs').ACCOUNT_VAULT_PAYLOAD_MAGIC,
  ]) {
    assert.match(magic, /^[A-Z]{8}$/);
    assert.equal(Buffer.byteLength(magic), 8);
  }
  assert.equal(Buffer.byteLength(nativeKeys('protocol_keys.rs').NATIVE_MESSAGE_CONTENT_MAGIC), 4);
  assert.equal(PRIVATE_AUTH_TRANSCRIPT_BYTES,
    Buffer.byteLength(sharedKeys.OPAQUE_AUTH_SIGNATURE_CONTEXT) + 32 + AUTH_CHANNEL_BINDING_BYTES);
});

test('WebSocket handshake accepts the unversioned protocol and rejects versioned names', () => {
  const required = REQUIRED_WS_PQ_HANDSHAKE;
  const handshake = {
    version: clientKeys.WS_PQ_PROTOCOL,
    algorithms: {
      kem: required.kem,
      signature: required.signature,
      classicalKeyAgreement: required.classicalKeyAgreement,
      kdf: required.kdf,
      aead: required.aead,
    },
    clientKemPublicKey: 'kem-key',
    clientNonce: 'nonce',
    clientX25519PublicKey: 'x25519-key',
    fingerprint: 'fingerprint',
    kemCiphertext: 'ciphertext',
    sessionId: 'session',
    timestamp: Date.now(),
  };
  assert.equal(handshake.version, 'pq-ws');
  assert.equal(validatePqHandshakePolicy(handshake).valid, true);
  for (const version of ['pq-ws-8', `${handshake.version}-v1`, '', undefined]) {
    assert.equal(validatePqHandshakePolicy({ ...handshake, version }).valid, false);
  }
});

test('sealed envelopes accept the unversioned protocol and reject versioned names', () => {
  const envelope = {
    version: clientKeys.SEALED_ENVELOPE_PROTOCOL,
    ciphertext: Buffer.alloc(SEALED_STANDARD_CIPHERTEXT_BYTES).toString('base64'),
    ephemeralKey: Buffer.alloc(ML_KEM_1024_CIPHERTEXT_BYTES).toString('base64'),
    nonce: Buffer.alloc(SEALED_NONCE_BYTES).toString('base64'),
    tag: '00'.repeat(8),
    probe: '00'.repeat(32),
  };
  assert.equal(envelope.version, 'sealed-sender');
  assert.equal(validateSealedEnvelope(envelope).valid, true);
  for (const version of ['ss-v2', `${envelope.version}-v1`, '', undefined]) {
    assert.equal(validateSealedEnvelope({ ...envelope, version }).valid, false);
  }
});
