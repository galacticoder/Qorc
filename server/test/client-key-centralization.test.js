import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function sourceFiles(directory, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) sourceFiles(target, output);
    else if (/\.(?:ts|tsx)$/.test(entry.name)) output.push(target);
  }
  return output;
}

function literalEntries(source) {
  return [...source.matchAll(/^\s+([A-Z0-9_]+):\s*'((?:[^'\\]|\\.)*)',?$/gm)]
    .map((match) => ({ name: match[1], value: match[2] }));
}

function isOwnedIdentifier(value) {
  return value.length >= 8 &&
    /(?:[Vv][0-9]|qorc|qorc|PrivacyPass|OPAQUE|ws-pq|session-key|securedb|route-proof|device-envelope|p2p-transcript|spool|peercert|discmat|registration|settings|history|storage|pending|outbox|metadata)/.test(value);
}

test('client protocol and storage identifiers have one owner', () => {
  const owners = [
    path.join(repoRoot, 'src/lib/config/protocol-keys.ts'),
    path.join(repoRoot, 'src/lib/database/storage-keys.ts'),
  ];
  const files = sourceFiles(path.join(repoRoot, 'src'));

  for (const owner of owners) {
    const entries = literalEntries(fs.readFileSync(owner, 'utf8')).filter(({ value }) => isOwnedIdentifier(value));
    assert.ok(entries.length > 20);
    for (const entry of entries) {
      for (const file of files) {
        if (file === owner) continue;
        const source = fs.readFileSync(file, 'utf8');
        assert.equal(
          source.includes(`'${entry.value}'`) ||
            source.includes(`"${entry.value}"`) ||
            source.includes(`\`${entry.value}`),
          false,
          `${entry.name} is redefined in ${path.relative(repoRoot, file)}`,
        );
      }
    }
  }
});

test('client anonymous audiences have one owner', () => {
  const owner = path.join(repoRoot, 'src/lib/config/audiences.ts');
  const entries = [...fs.readFileSync(owner, 'utf8').matchAll(/^export const ([A-Z0-9_]+) = '([^']+)';$/gm)]
    .map((match) => ({ name: match[1], value: match[2] }));

  assert.ok(entries.length > 10);
  for (const entry of entries) {
    for (const file of sourceFiles(path.join(repoRoot, 'src'))) {
      if (file === owner) continue;
      const source = fs.readFileSync(file, 'utf8');
      assert.equal(
        source.includes(`'${entry.value}'`) || source.includes(`"${entry.value}"`),
        false,
        `${entry.name} is redefined in ${path.relative(repoRoot, file)}`,
      );
    }
  }
});

test('client consumers use centralized key objects directly', () => {
  const ownerFiles = new Set([
    path.join(repoRoot, 'src/lib/config/protocol-keys.ts'),
    path.join(repoRoot, 'src/lib/database/storage-keys.ts'),
  ]);
  const audienceSource = fs.readFileSync(path.join(repoRoot, 'src/lib/config/audiences.ts'), 'utf8');
  const audienceNames = [...audienceSource.matchAll(/^export const ([A-Z0-9_]+) =/gm)]
    .map((match) => match[1]);
  const forwardingAlias = new RegExp(
    `(?:const|readonly)\\s+[A-Za-z_$][A-Za-z0-9_$]*\\s*=\\s*(?:(?:PROTOCOL_KEYS|STORAGE_KEYS|STORAGE_PREFIXES|STORAGE_KEY_DOMAINS|STORAGE_STORES)\\.[A-Z0-9_]+|${audienceNames.join('|')})`,
  );

  for (const file of sourceFiles(path.join(repoRoot, 'src'))) {
    if (ownerFiles.has(file)) continue;
    assert.doesNotMatch(
      fs.readFileSync(file, 'utf8'),
      forwardingAlias,
      `centralized key is hidden behind an alias in ${path.relative(repoRoot, file)}`,
    );
  }
});

test('native client keys have centralized owners and no forwarding aliases', () => {
  const owners = new Set([
    path.join(repoRoot, 'src-tauri/src/protocol_keys.rs'),
    path.join(repoRoot, 'src-tauri/src/storage_keys.rs'),
  ]);
  const files = [];
  const collect = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) collect(target);
      else if (entry.name.endsWith('.rs')) files.push(target);
    }
  };
  collect(path.join(repoRoot, 'src-tauri/src'));

  const ownedValues = [];
  for (const owner of owners) {
    for (const match of fs.readFileSync(owner, 'utf8').matchAll(/= b?"([^"\r\n]+)";/g)) {
      ownedValues.push(match[1]);
    }
  }
  for (const file of files) {
    if (owners.has(file)) continue;
    const source = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(
      source,
      /const\s+[A-Z0-9_]+[^=]*=\s*crate::(?:protocol_keys|storage_keys)::[A-Z0-9_]+/,
      `native key is hidden behind an alias in ${path.relative(repoRoot, file)}`,
    );
    for (const value of ownedValues) {
      assert.equal(
        source.includes(`"${value}"`),
        false,
        `native key is redefined in ${path.relative(repoRoot, file)}`,
      );
    }
  }
});

test('client key owners expose the current wire values', () => {
  const protocol = fs.readFileSync(path.join(repoRoot, 'src/lib/config/protocol-keys.ts'), 'utf8');
  const storage = fs.readFileSync(path.join(repoRoot, 'src/lib/database/storage-keys.ts'), 'utf8');

  assert.match(protocol, /WS_PQ_PROTOCOL: 'pq-ws'/);
  assert.match(protocol, /PQ_ANONYMOUS_HTTP_PROTOCOL: 'qorc-pq-anonymous-http'/);
  assert.match(protocol, /DISCOVERY_BUCKET_MANIFEST: 'qorc-discovery-bucket-manifest'/);
  assert.match(protocol, /SEALED_ENVELOPE_PROTOCOL: 'sealed-sender'/);
  assert.match(storage, /SPOOL_DETECTION: 'spooldet:'/);
  assert.match(storage, /PEER_CERTIFICATE: 'peercert:'/);
});
