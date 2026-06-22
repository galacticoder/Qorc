#!/usr/bin/env node

// Verifies the hintless PIR worker pin

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const hintlessDir = path.join(repoRoot, 'workers/hintless');
const lock = JSON.parse(fs.readFileSync(path.join(hintlessDir, 'hintless.lock.json'), 'utf8'));

let failed = false;

for (const dep of lock.vendoredThirdParty || []) {
  const file = path.join(hintlessDir, dep.file);
  let digest;
  try {
    digest = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  } catch (error) {
    console.error(`[PIR-PIN] Cannot read ${dep.file}: ${error.message}`);
    failed = true;
    continue;
  }
  if (digest !== dep.sha256) {
    console.error(`[PIR-PIN] Hash mismatch for ${dep.file}`);
    console.error(`[PIR-PIN] Expected: ${dep.sha256}`);
    console.error(`[PIR-PIN] Actual:   ${digest}`);
    failed = true;
  } else {
    console.log(`[PIR-PIN] OK ${dep.name} ${dep.version} (${dep.file})`);
  }
}

if (!lock.upstream?.commit) {
  console.error('[PIR-PIN] Lock is missing upstream.commit');
  failed = true;
} else {
  console.log(`[PIR-PIN] upstream ${lock.upstream.repo}@${lock.upstream.commit} (${lock.upstream.buildConfig})`);
  console.log(`[PIR-PIN] scheme=${lock.scheme} parameterId=${lock.parameterId}`);
}

process.exit(failed ? 1 : 0);
