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

const missing = required.filter((file) => {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return false;
  } catch {
    return true;
  }
});

if (missing.length === 0) {
  console.log('[PIR-BINARIES] Local pinned PIR client binary is present');
  process.exit(0);
}

console.log('[PIR-BINARIES] Missing local pinned PIR client binary. building from workers/hintless');
execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'build-pir-client.cjs')], {
  cwd: repoRoot,
  stdio: 'inherit',
  env: process.env,
});
