#!/usr/bin/env node

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const binDir = path.join(repoRoot, 'src-tauri', 'binaries');
const suffix = process.platform === 'win32' ? '.exe' : '';

const required = [
  path.join(binDir, `qor-pir-client${suffix}`),
];

function isValidClientBinary(file) {
  try {
    fs.accessSync(file, process.platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK);
    const stdout = execFileSync(file, [], {
      input: '{"operation":"ping"}',
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
      timeout: 10000,
      windowsHide: true
    });
    return JSON.parse(stdout).success === true;
  } catch {
    return false;
  }
}

const missing = required.filter((file) => !isValidClientBinary(file));

if (missing.length === 0) {
  console.log('[PIR-BINARIES] Local pinned PIR client binary is present and runnable');
  process.exit(0);
}

console.log('[PIR-BINARIES] Missing or invalid local pinned PIR client binary. building from workers/hintless');
execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'build-pir-client.cjs')], {
  cwd: repoRoot,
  stdio: 'inherit',
  env: process.env,
});

const stillMissing = required.filter((file) => !isValidClientBinary(file));
if (stillMissing.length > 0) {
  console.error('[PIR-BINARIES] Failed to produce a runnable PIR client binary:');
  for (const file of stillMissing) {
    console.error(`  - ${path.relative(repoRoot, file)}`);
  }
  process.exit(1);
}
