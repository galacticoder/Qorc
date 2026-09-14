import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import ts from 'typescript';
import { createServer } from 'vite';
import * as sizes from '../../shared/crypto-sizes.js';
import * as layout from '../../shared/anonymous-http-layout.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const root = path.resolve(import.meta.dirname, '../..');

function sourceFiles(directory, result = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (['node_modules', 'tor', 'test', 'tests', 'dist', '.cache'].includes(entry.name)) continue;
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) sourceFiles(filename, result);
    else if (/\.(?:ts|tsx|js|cjs|mjs)$/.test(entry.name)) result.push(filename);
  }
  return result;
}

function walk(node, visit) {
  visit(node);
  ts.forEachChild(node, child => walk(child, visit));
}

const files = ['src', 'server', 'shared', 'scripts'].flatMap(directory => sourceFiles(path.join(root, directory)));

test('app-owned constant declarations do not introduce forwarding aliases', () => {
  const failures = [];
  const isConstantReference = node => ts.isIdentifier(node)
    ? /^[A-Z][A-Z0-9_]*$/.test(node.text)
    : ts.isPropertyAccessExpression(node)
      && /^[A-Z][A-Z0-9_]*$/.test(node.name.text)
      && isConstantReference(node.expression);
  for (const filename of files) {
    const source = ts.createSourceFile(filename, fs.readFileSync(filename, 'utf8'), ts.ScriptTarget.Latest, true);
    walk(source, node => {
      if ((ts.isVariableDeclaration(node) || ts.isPropertyDeclaration(node))
        && node.initializer && isConstantReference(node.initializer)
        && ts.isIdentifier(node.name) && /^[A-Z][A-Z0-9_]*$/.test(node.name.text)) {
        failures.push(`${path.relative(root, filename)}: ${node.getText(source)}`);
      }
    });
  }
  assert.deepEqual(failures, []);
});

test('app-owned named imports resolve to real exports after alias removal', () => {
  const config = ts.readConfigFile(path.join(root, 'tsconfig.app.json'), ts.sys.readFile).config;
  const options = ts.convertCompilerOptionsFromJson(config.compilerOptions, root).options;
  const program = ts.createProgram(files, { ...options, allowJs: true, checkJs: false });
  const checker = program.getTypeChecker();
  const failures = [];
  for (const filename of files) {
    const source = program.getSourceFile(filename);
    for (const statement of source.statements) {
      if (!ts.isImportDeclaration(statement) || !statement.moduleSpecifier.text.startsWith('.')) continue;
      const bindings = statement.importClause?.namedBindings;
      if (!bindings || !ts.isNamedImports(bindings)) continue;
      const module = checker.getSymbolAtLocation(statement.moduleSpecifier);
      if (!module) continue;
      const exports = new Set(checker.getExportsOfModule(module).map(symbol => symbol.name));
      for (const binding of bindings.elements) {
        const name = (binding.propertyName ?? binding.name).text;
        if (!exports.has(name)) failures.push(`${path.relative(root, filename)}: ${name} from ${statement.moduleSpecifier.text}`);
      }
    }
  }
  assert.deepEqual(failures, []);
});

test('shared anonymous HTTP framing retains its exact wire positions and size classes', () => {
  assert.deepEqual({ ...layout }, {
    ANONYMOUS_HTTP_WIRE_VERSION: 1,
    ANONYMOUS_HTTP_REQUEST_SMALL_BYTES: 65536,
    ANONYMOUS_HTTP_REQUEST_LARGE_BYTES: 524288,
    ANONYMOUS_HTTP_REQUEST_PIR_BYTES: 2097152,
    ANONYMOUS_HTTP_RESPONSE_SMALL_BYTES: 65536,
    ANONYMOUS_HTTP_RESPONSE_TAG_INDEX_BYTES: 524288,
    ANONYMOUS_HTTP_RESPONSE_PIR_BYTES: 1048576,
    ANONYMOUS_HTTP_RESPONSE_AVATAR_BYTES: 4194304,
    ANONYMOUS_HTTP_REQUEST_POW_NONCE_OFFSET: 3252,
    ANONYMOUS_HTTP_REQUEST_POW_SOLUTION_OFFSET: 3268,
    ANONYMOUS_HTTP_REQUEST_PREFIX_BYTES: 3276,
    ANONYMOUS_HTTP_REQUEST_TAG_OFFSET: 3312,
    ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET: 3344,
    ANONYMOUS_HTTP_RESPONSE_PREFIX_BYTES: 1652,
    ANONYMOUS_HTTP_RESPONSE_TAG_OFFSET: 1688,
    ANONYMOUS_HTTP_RESPONSE_SIGNATURE_OFFSET: 1720,
    ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET: 6347,
  });
  for (const file of ['src/lib/transport/pq-anonymous-http.ts', 'server/routes/pq-anonymous-http.js']) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    assert.match(source, /shared\/anonymous-http-layout\.js/);
    assert.doesNotMatch(source, /const (?:REQUEST|RESPONSE)_(?:PREFIX_BYTES|\w+_OFFSET)\s*=/);
  }
});

test('central crypto sizes preserve the current algorithms', () => {
  assert.equal(sizes.ML_KEM_1024_PUBLIC_KEY_BYTES, 1568);
  assert.equal(sizes.ML_KEM_1024_SECRET_KEY_BYTES, 3168);
  assert.equal(sizes.ML_KEM_1024_CIPHERTEXT_BYTES, 1568);
  assert.equal(sizes.ML_DSA_87_PUBLIC_KEY_BYTES, 2592);
  assert.equal(sizes.ML_DSA_87_SECRET_KEY_BYTES, 4896);
  assert.equal(sizes.ML_DSA_87_SIGNATURE_BYTES, 4627);
  assert.equal(sizes.HASH_OUTPUT_BYTES, 32);
  assert.equal(sizes.POST_QUANTUM_AEAD_NONCE_BYTES, 36);
  assert.equal(sizes.POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES, 32);
});

test('client and server AEAD agree byte for byte and reject tampering', async () => {
  const loader = await createServer({
    configFile: false, root, appType: 'custom', logLevel: 'silent',
    server: { middlewareMode: true, watch: null },
    optimizeDeps: { noDiscovery: true },
  });
  try {
    const { PostQuantumAEAD } = await loader.ssrLoadModule('/src/lib/cryptography/aead.ts');
    const key = new Uint8Array(sizes.HASH_OUTPUT_BYTES).fill(3);
    const nonce = new Uint8Array(sizes.POST_QUANTUM_AEAD_NONCE_BYTES).fill(7);
    const aad = new TextEncoder().encode('constant-ownership-test');
    for (const length of [0, 1, 1024, 65536]) {
      const plaintext = new Uint8Array(length).fill(11);
      const client = PostQuantumAEAD.encrypt(plaintext, key, aad, nonce);
      const server = CryptoUtils.PostQuantumAEAD.encrypt(plaintext, key, aad, nonce);
      assert.deepEqual(client.ciphertext, new Uint8Array(server.ciphertext));
      assert.deepEqual(client.tag, new Uint8Array(server.tag));
      assert.equal(client.ciphertext.length, length + sizes.POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES);
      assert.deepEqual(PostQuantumAEAD.decrypt(server.ciphertext, server.nonce, server.tag, key, aad), plaintext);
      assert.deepEqual(new Uint8Array(CryptoUtils.PostQuantumAEAD.decrypt(client.ciphertext, client.nonce, client.tag, key, aad)), plaintext);
      client.tag[0] ^= 1;
      assert.throws(() => PostQuantumAEAD.decrypt(client.ciphertext, client.nonce, client.tag, key, aad));
      assert.throws(() => CryptoUtils.PostQuantumAEAD.decrypt(client.ciphertext, client.nonce, client.tag, key, aad));
    }
  } finally {
    await loader.close();
  }
});

test('native transport bounds use their existing constants directly', () => {
  const discovery = fs.readFileSync(path.join(root, 'src-tauri/src/commands/discovery.rs'), 'utf8');
  const signal = fs.readFileSync(path.join(root, 'src-tauri/src/signal_protocol/mod.rs'), 'utf8');
  assert.doesNotMatch(discovery, /const MAX_RESPONSE_BYTES:/);
  assert.match(discovery, /\*size <= RESPONSE_DISCOVERY_BYTES/);
  assert.doesNotMatch(signal, /const MAX_PENDING_DECRYPT_PLAINTEXT_BYTES:/);
  assert.match(signal, /entry\.plaintext\.len\(\) > MAX_SIGNAL_PLAINTEXT_BYTES/);
});
