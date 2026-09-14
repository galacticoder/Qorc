import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { REDIS_KEYS } from '../config/redis-keys.js';

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const registryPaths = new Set([
  path.join(serverRoot, 'config/protocol-keys.js'),
  path.join(serverRoot, 'config/redis-keys.js')
]);

function literalValues(source) {
  const values = new Set();
  const visit = (node) => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node)) {
      values.add(node.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(ts.createSourceFile('source.js', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS));
  return values;
}

function productionJavaScriptFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'secrets', 'test', 'tests', 'tor'].includes(entry.name)) continue;
      files.push(...productionJavaScriptFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.js') && !registryPaths.has(fullPath)) {
      files.push(fullPath);
    }
  }
  return files;
}

test('server protocol key values have one canonical owner', () => {
  const entries = Object.entries(PROTOCOL_KEYS);
  const values = entries.map(([, value]) => value);

  assert.equal(Object.isFrozen(PROTOCOL_KEYS), true);
  assert.equal(entries.length > 0, true);
  assert.equal(values.every((value) => typeof value === 'string' && value.length > 0), true);
  assert.equal(new Set(values).size, values.length);

  for (const filePath of productionJavaScriptFiles(serverRoot)) {
    const valuesInSource = literalValues(fs.readFileSync(filePath, 'utf8'));
    for (const [name, value] of entries) {
      assert.equal(valuesInSource.has(value), false, `${name} is duplicated in ${path.relative(serverRoot, filePath)}`);
    }
  }
});

test('server Redis key values have one canonical owner', () => {
  const entries = Object.entries(REDIS_KEYS);
  const values = entries.map(([, value]) => value);

  assert.equal(Object.isFrozen(REDIS_KEYS), true);
  assert.equal(entries.length > 0, true);
  assert.equal(values.every((value) => typeof value === 'string' && value.length > 0), true);
  assert.equal(new Set(values).size, values.length);

  for (const filePath of productionJavaScriptFiles(serverRoot)) {
    const source = fs.readFileSync(filePath, 'utf8');
    for (const [name, value] of entries) {
      assert.equal(source.includes(value), false, `${name} is duplicated in ${path.relative(serverRoot, filePath)}`);
    }
  }
});

test('WebSocket key derivation uses the protocol registry for its name and salt fragments', () => {
  const policy = fs.readFileSync(path.join(serverRoot, 'security/layer-agreement-policy.js'), 'utf8');
  const handler = fs.readFileSync(path.join(serverRoot, 'messaging/pq-envelope-handler.js'), 'utf8');

  assert.match(policy, /version: PROTOCOL_KEYS\.WS_PQ_PROTOCOL/);
  assert.match(handler, /baseInfo\}\$\{PROTOCOL_KEYS\.WS_PQ_BASE_SALT_SUFFIX\}/);
  assert.match(handler, /responseKemCiphertextBase64\}\$\{PROTOCOL_KEYS\.WS_PQ_FINAL_SALT_SUFFIX\}/);
  assert.match(handler, /finalContext\}\$\{PROTOCOL_KEYS\.WS_PQ_CLIENT_SEND_SALT_SUFFIX\}/);
  assert.match(handler, /finalContext\}\$\{PROTOCOL_KEYS\.WS_PQ_CLIENT_RECV_SALT_SUFFIX\}/);
});

test('server Redis consumers use the Redis key registry', () => {
  const cluster = fs.readFileSync(path.join(serverRoot, 'cluster/cluster-manager.js'), 'utf8');
  const throttle = fs.readFileSync(path.join(serverRoot, 'security/auth-throttle.js'), 'utf8');
  const listener = fs.readFileSync(path.join(serverRoot, 'load-balancer/lb-command-listener.js'), 'utf8');

  for (const name of ['CLUSTER_CONFIG', 'CLUSTER_HEALTH', 'CLUSTER_KEYS', 'CLUSTER_MESSAGES', 'CLUSTER_PENDING', 'CLUSTER_TOKENS']) {
    assert.equal(cluster.includes(`REDIS_KEYS.${name}`), true);
  }
  assert.match(throttle, /recordEvent\(REDIS_KEYS\.AUTH_FAILURE_PREFIX\)/);
  assert.match(throttle, /getRecentCount\(REDIS_KEYS\.AUTH_PIR_REQUEST_PREFIX\)/);
  assert.doesNotMatch(throttle, /const \w+ = REDIS_KEYS\./);
  assert.equal((listener.match(/REDIS_KEYS\.LB_ENCRYPTED_COMMAND_CHANNEL/g) || []).length, 3);
});
